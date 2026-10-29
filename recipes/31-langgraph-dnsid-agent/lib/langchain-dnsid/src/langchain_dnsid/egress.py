"""Outbound: one httpx client that verifies the peer, then signs the request.

Signing and peer verification live on the client's transport path, not in
tool code, so every tool that uses the client gets both and no tool can
forget either. A tool that builds its own ``httpx.AsyncClient`` gets neither.
"""

import asyncio
import logging

import httpx
from dnsid import DNSidError, HttpSignatureProfile, IdentityManager
from dnsid.models import HttpSigningOptions
from langchain_core.tools import BaseTool, tool

# RFC 9421 `tag`: names the application the signature is for. Signer and
# verifier must agree; DnsidAuthMiddleware requires the same one.
TAG = "dnsid-langchain-http-v1"

log = logging.getLogger("langchain_dnsid")


class UnverifiedPeerError(Exception):
    """The destination host is not an active, verifiable DNSid identity."""

    def __init__(self, host: str, reason: object) -> None:
        super().__init__(f"{host} is not a verified DNSid identity: {reason}")


def dnsid_client(idm: IdentityManager) -> httpx.AsyncClient:
    """An httpx client for talking to other DNSid identities.

    Every request is signed as ``idm``'s domain, and goes only over HTTPS to a
    host that verifies as a live DNSid identity. Otherwise it raises
    :class:`UnverifiedPeerError` and no bytes leave the process. That means it
    refuses ordinary APIs on purpose: use a separate, plain client for those.
    """
    client = HttpSignatureProfile.from_identity_manager(idm).create_signed_async_http_client(
        # Always present, so it can always be covered by the signature.
        base_headers={"content-type": "application/json"},
        opts=HttpSigningOptions(additional_components=["content-type"], tag=TAG),
    )

    async def verify_peer(request: httpx.Request) -> None:
        host = request.url.host
        # DNSid proves who signed, not who answered. TLS protects the reply.
        if request.url.scheme != "https":
            raise UnverifiedPeerError(host, "not HTTPS")
        try:
            # verify_domain is blocking (DNS, JWKS, status, log) and cached.
            await asyncio.to_thread(idm.verify_domain, host)
        except DNSidError as exc:
            log.warning("[%s] refused peer %s: %s", idm.local_domain, host, exc)
            raise UnverifiedPeerError(host, exc) from exc
        log.info("[%s] verified peer %s", idm.local_domain, host)

    client.event_hooks["request"] = [verify_peer]
    return client


def fetch_tool(client: httpx.AsyncClient) -> BaseTool:
    """A read-only HTTP tool over ``client``: the model picks the URL, not the trust.

    GET only. Every request is signed as this agent, so a tool that could POST
    would let any caller do what a restricted tool does (POST /order) under
    the agent's name.
    """

    @tool
    async def fetch(url: str) -> str:
        """GET a URL from another agent or service. Returns status and body."""
        resp = await client.get(url)
        return f"{resp.status_code} {resp.text}"

    return fetch
