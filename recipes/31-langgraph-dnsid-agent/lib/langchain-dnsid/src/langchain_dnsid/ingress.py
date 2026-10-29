"""Inbound: ASGI middleware that admits only DNSid-signed requests.

Every request must carry an RFC 9421 signature that verifies against the
sender's DNS-published keys, and each signature is accepted only once. The
verified domain is put on the request as ``request.state.dnsid_caller``;
nothing the client sends can set it.
"""

import asyncio
import logging
import time
from urllib.parse import urlsplit

from dnsid import (
    DNSidError,
    HttpMessageSignatureConfig,
    HttpSignatureProfile,
    IdentityManager,
)
from dnsid.models import HttpRequest, HttpVerificationOptions, SignatureParams
from starlette.requests import Request
from starlette.responses import JSONResponse

from .egress import TAG

log = logging.getLogger("langchain_dnsid")

MAX_BODY_BYTES = 8 * 1024 * 1024  # the SDK's own verification limit
REQUIRED_COMPONENTS = ["@method", "@authority", "@target-uri", "content-type"]


class DnsidAuthMiddleware:
    """Verify every HTTP request; reject unsigned or unverifiable ones with 401.

    ``public_url`` is this service's external HTTPS origin (default
    ``https://<idm domain>``). The signed ``@authority`` and ``@target-uri``
    are checked against it, never against client-supplied Host headers.
    """

    def __init__(self, app, idm: IdentityManager, *, public_url: str | None = None) -> None:
        self._app = app
        self._domain = idm.local_domain
        self._sig_config = HttpMessageSignatureConfig()
        self._http_sig = HttpSignatureProfile.from_identity_manager(idm, self._sig_config)
        self._seen: dict[str, float] = {}  # nonce -> forget after
        origin = urlsplit(public_url or f"https://{self._domain}")
        if origin.scheme != "https" or not origin.hostname or origin.username is not None:
            raise ValueError("public_url must be an HTTPS origin")
        self._authority = origin.netloc

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        # content-digest commits to the exact bytes: read the whole body first.
        body = b""
        async for chunk in Request(scope, receive).stream():
            body += chunk
            if len(body) > MAX_BODY_BYTES:
                return await JSONResponse({"error": "request body too large"}, 413)(scope, receive, send)

        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        headers["host"] = self._authority
        query = scope.get("query_string", b"").decode("latin-1")
        path = (scope.get("raw_path") or scope["path"].encode()).decode("latin-1")
        url = f"https://{self._authority}{path}" + (f"?{query}" if query else "")
        # ASGI can't tell an empty body from none; a content-digest says one was signed.
        # The SDK itself rejects a body the signature doesn't cover.
        signed_body = body if body or "content-digest" in headers else None

        try:
            verified = await asyncio.to_thread(
                self._http_sig.verify_signed_http_request,
                HttpRequest(method=scope["method"], url=url, headers=headers, body=signed_body),
                HttpVerificationOptions(required_components=REQUIRED_COMPONENTS, required_tag=TAG),
            )
        except DNSidError as exc:
            return await JSONResponse({"error": str(exc)}, 401)(scope, receive, send)

        # Replay protection. A signature stays valid for max_age (default 300s)
        # and the SDK does not check nonce reuse, so a captured request could be
        # resent unchanged and would verify again. Accept each nonce once.
        if replay_error := self._check_replay(headers):
            return await JSONResponse({"error": replay_error}, 401)(scope, receive, send)

        log.info("[%s] verified %s %s from %s", self._domain, scope["method"], scope["path"], verified.domain)
        scope = {**scope, "state": {**scope.get("state", {}), "dnsid_caller": verified.domain}}

        # We read the body, so hand it to the app; after that, the real receive().
        pending = [{"type": "http.request", "body": body, "more_body": False}]

        async def replay():
            return pending.pop() if pending else await receive()

        await self._app(scope, replay, send)

    def _check_replay(self, headers: dict[str, str]) -> str | None:
        """Record the nonces of the signatures with our tag; error if one was seen.

        The SDK verified exactly one of them, but doesn't say which, so record
        them all. Nonces are random, so a nonce alone identifies a signature.
        No await in here, so check-and-record is atomic on the event loop.
        """
        # ponytail: in-memory and per process. Behind several replicas, use a
        # shared store instead (e.g. Redis SET key NX EX max_age).
        now = time.time()
        self._seen = {n: until for n, until in self._seen.items() if until > now}
        params = [p for p in SignatureParams.parse_dictionary(headers["signature-input"]).values() if p.tag == TAG]
        if any(not p.nonce for p in params):
            return "signature has no nonce; replay protection requires one"
        if any(p.nonce in self._seen for p in params):
            return "replayed request: signature nonce already used"
        max_age = self._sig_config.max_age.total_seconds()
        for p in params:
            self._seen[p.nonce] = (p.created or now) + max_age + 1
        return None

