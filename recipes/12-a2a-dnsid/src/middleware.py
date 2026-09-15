"""Ingress verification: ASGI middleware that authenticates every inbound POST.

This is the trust boundary of the whole recipe. Before any A2A message
reaches the agent, the middleware:

  1. Checks the A2A protocol negotiation headers (A2A-Version and
     A2A-Extensions must name the DNSid extension) — a 400 otherwise.
  2. Verifies the RFC 9421 HTTP Message Signature on the request against the
     sender's DNSid-published keys: the SDK resolves _dnsid.<sender> in DNS,
     follows its ku= tag to the sender's JWKS, checks live status via su=,
     and validates the signature over the required covered components —
     a 401 otherwise.

Only after both checks does the request reach the a2a-sdk routes, carrying
the cryptographically verified sender domain in the ASGI scope. The executor
reads it via the a2a-sdk call context; nothing downstream can forge it.
"""

from __future__ import annotations

import asyncio

from a2a.auth.user import UnauthenticatedUser, User
from a2a.server.context import ServerCallContext
from a2a.server.routes import ServerCallContextBuilder
from starlette.requests import Request
from starlette.responses import JSONResponse

from dnsid import IdentityManager
from dnsid.http_signatures import HttpSignatureProfile
from dnsid.models import HttpRequest as DnsidRequest
from dnsid.models import HttpVerificationOptions

from agent_card import (
    A2A_VERSION,
    DNSID_A2A_EXTENSION_URI,
    DNSID_A2A_SIGNATURE_TAG,
    REQUIRED_SIG_COMPONENTS,
)

VERIFY_OPTS = HttpVerificationOptions(
    required_components=REQUIRED_SIG_COMPONENTS,
    required_tag=DNSID_A2A_SIGNATURE_TAG,
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
    """ASGI middleware that verifies inbound HTTP message signatures via dnsid."""

    def __init__(self, app, idm: IdentityManager, http_sig: HttpSignatureProfile) -> None:
        self._app = app
        self._idm = idm
        self._http_sig = http_sig

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
            k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        scheme = scope.get("scheme", "https")
        forwarded_proto = headers_raw.get("x-forwarded-proto", scheme)
        host = headers_raw.get("x-forwarded-host") or headers_raw.get("host") or "localhost"
        path = scope.get("path", "/")
        query = scope.get("query_string", b"").decode("latin-1")
        url = f"{forwarded_proto}://{host}{path}" + (f"?{query}" if query else "")
        headers_raw["host"] = host

        # Validate A2A-Version header.
        a2a_version = headers_raw.get("a2a-version", "")
        if a2a_version != A2A_VERSION:
            response = JSONResponse(
                {"error": f"A2A-Version must be {A2A_VERSION}, got {a2a_version!r}"},
                status_code=400,
            )
            await response(scope, receive, send)
            return

        # Validate A2A-Extensions header — must include the DNSid extension URI.
        requested_extensions = [
            e.strip() for e in headers_raw.get("a2a-extensions", "").split(",") if e.strip()
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
                self._http_sig.verify_signed_http_request, dnsid_req, VERIFY_OPTS
            )
            scope = {**scope, "_dnsid_sender": VerifiedSenderUser(verified.domain)}
            print(
                f"[{self._idm.local_domain}] verified signed POST {path} from {verified.domain}"
            )
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
