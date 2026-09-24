"""Ingress verification: ASGI middleware that authenticates every inbound POST.

Same verification pattern as recipe 12, used twice in this recipe:

  - in front of the LangGraph agent's A2A routes (with the A2A negotiation
    header checks), and
  - in front of the plain-HTTP tool server (signature verification only).

Both ingresses do the same dance on every POST: verify the RFC 9421 HTTP
Message Signature against the sender's DNSid-published keys — the SDK resolves
_dnsid.<sender> in DNS, follows its ku= tag to the sender's JWKS, checks live
status via su=, and validates the signature over the required covered
components (including content-digest, so the body can't be swapped). Only a
verified request reaches the app, carrying the cryptographically verified
sender domain in the ASGI scope.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from a2a.auth.user import UnauthenticatedUser, User
from a2a.server.context import ServerCallContext
from a2a.server.routes import ServerCallContextBuilder
from starlette.requests import Request
from starlette.responses import JSONResponse

from dnsid.http_signatures import HttpSignatureProfile
from dnsid.models import HttpRequest as DnsidRequest
from dnsid.models import HttpVerificationOptions

from agent_card import (
    A2A_VERSION,
    DNSID_A2A_EXTENSION_URI,
    DNSID_A2A_SIGNATURE_TAG,
    REQUIRED_SIG_COMPONENTS,
)

# Verification contract for the A2A ingress (graph.dev.dnsid.test).
A2A_VERIFY_OPTS = HttpVerificationOptions(
    required_components=REQUIRED_SIG_COMPONENTS,
    required_tag=DNSID_A2A_SIGNATURE_TAG,
)

# Verification contract for the plain-HTTP tools ingress (tools.dev.dnsid.test).
# No A2A headers here — but content-digest stays required: the tool server
# must know the body it acts on is the body the caller signed.
TOOLS_SIGNATURE_TAG = "dnsid-tools-http-sig-v1"
TOOLS_REQUIRED_SIG_COMPONENTS = [
    "@method",
    "@target-uri",
    "content-type",
    "content-digest",
]
TOOLS_VERIFY_OPTS = HttpVerificationOptions(
    required_components=TOOLS_REQUIRED_SIG_COMPONENTS,
    required_tag=TOOLS_SIGNATURE_TAG,
)


class VerifiedSenderUser(User):
    """Wraps a dnsid-verified sender domain as an a2a-sdk User."""

    def __init__(self, domain: str) -> None:
        self._domain = domain

    @property
    def is_authenticated(self) -> bool:
        return bool(self._domain)

    @property
    def user_name(self) -> str:
        return self._domain


class DnsidServerCallContextBuilder(ServerCallContextBuilder):
    """Reads the dnsid-verified sender set by the signature middleware."""

    def build(self, request: Request) -> ServerCallContext:
        sender = request.scope.get("_dnsid_sender")
        return ServerCallContext(
            user=sender or UnauthenticatedUser(),
            state={"headers": dict(request.headers)},
        )


class DnsidSignatureMiddleware:
    """ASGI middleware that verifies inbound HTTP message signatures via dnsid.

    ``require_a2a_headers`` enables the A2A protocol negotiation checks
    (A2A-Version / A2A-Extensions) in addition to signature verification —
    on for the agent's A2A ingress, off for the plain-HTTP tools ingress.
    """

    def __init__(
        self,
        app,
        domain: str,
        http_sig: HttpSignatureProfile,
        verify_opts: HttpVerificationOptions,
        *,
        public_url: str,
        require_a2a_headers: bool = False,
    ) -> None:
        self._app = app
        self._domain = domain
        self._http_sig = http_sig
        self._verify_opts = verify_opts
        self._require_a2a_headers = require_a2a_headers
        origin = urlsplit(public_url)
        if origin.scheme != "https" or not origin.hostname or origin.username is not None:
            raise ValueError("public_url must have a trusted HTTPS origin")
        self._origin = f"https://{origin.netloc}"
        self._authority = origin.netloc

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self._app(scope, receive, send)
            return

        # Buffer the body: the signature's content-digest commits to the exact
        # bytes, so verification needs the whole body before dispatch.
        chunks: list[bytes] = []
        more = True
        while more:
            msg = await receive()
            chunks.append(msg.get("body", b""))
            more = msg.get("more_body", False)
        body = b"".join(chunks)

        headers_raw = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        path = scope.get("path", "/")
        query = scope.get("query_string", b"").decode("latin-1")
        url = f"{self._origin}{path}" + (f"?{query}" if query else "")
        headers_raw["host"] = self._authority  # Never trust client-supplied Host / X-Forwarded-*.

        if self._require_a2a_headers:
            a2a_version = headers_raw.get("a2a-version", "")
            if a2a_version != A2A_VERSION:
                response = JSONResponse(
                    {"error": f"A2A-Version must be {A2A_VERSION}, got {a2a_version!r}"},
                    status_code=400,
                )
                await response(scope, receive, send)
                return

            requested_extensions = [
                e.strip()
                for e in headers_raw.get("a2a-extensions", "").split(",")
                if e.strip()
            ]
            if DNSID_A2A_EXTENSION_URI not in requested_extensions:
                response = JSONResponse(
                    {"error": f"A2A-Extensions must include {DNSID_A2A_EXTENSION_URI}"},
                    status_code=400,
                )
                await response(scope, receive, send)
                return

        dnsid_req = DnsidRequest(method=scope["method"], url=url, headers=headers_raw, body=body)
        try:
            verified = await asyncio.to_thread(
                self._http_sig.verify_signed_http_request, dnsid_req, self._verify_opts
            )
            scope = {**scope, "_dnsid_sender": VerifiedSenderUser(verified.domain)}
            print(f"[{self._domain}] verified signed POST {path} from {verified.domain}")
        except Exception as exc:
            response = JSONResponse({"error": str(exc)}, status_code=401)
            await response(scope, receive, send)
            return

        body_sent = False

        async def replay_receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self._app(scope, replay_receive, send)
