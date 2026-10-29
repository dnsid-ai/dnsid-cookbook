"""Offline check of langchain_dnsid: no registry, no network.

Run: uv run python lib/langchain-dnsid/tests/test_langchain_dnsid.py
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dnsid import JWKS, HttpSignatureProfile, VerificationCode, VerificationError
from dnsid._crypto import ed25519_public_jwk_dict, jwk_from_dict
from dnsid.models import HttpRequest, HttpSigningOptions
from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langchain_dnsid import (
    TAG,
    DnsidAuthMiddleware,
    DnsidContext,
    DnsidToolPolicyMiddleware,
    UnverifiedPeerError,
    dnsid_client,
    fetch_tool,
)

calls: list[str] = []
seen_tools: list[list[str]] = []


@tool
def secret() -> str:
    """Restricted tool."""
    calls.append("secret")
    return "secret ran"


@tool
def remote() -> str:
    """A tool whose peer fails DNSid verification."""
    raise UnverifiedPeerError("rogue.test", VerificationError(VerificationCode.DNS_RESOLUTION, "NXDOMAIN"))


class Model(GenericFakeChatModel):
    """Always calls `wanted`, bound or not: a model that invents tool calls."""

    wanted: str = ""

    def bind_tools(self, tools, **kwargs):
        seen_tools.append([t.name for t in tools])
        return self


def run(caller: str | None, wanted: str) -> str:
    replies = iter([AIMessage("", tool_calls=[{"name": wanted, "args": {}, "id": "c1"}]), AIMessage("end")])
    agent = create_agent(
        Model(messages=replies, wanted=wanted),
        tools=[secret, remote],
        middleware=[DnsidToolPolicyMiddleware(restricted={"secret": {"peer.test"}})],
        context_schema=DnsidContext,
    )
    ctx = DnsidContext(caller=caller) if caller else None
    out = asyncio.run(agent.ainvoke({"messages": [HumanMessage("go")]}, context=ctx))
    return out["messages"][2].content  # the ToolMessage


assert run("peer.test", "secret") == "secret ran"
assert seen_tools[-1] == ["secret", "remote"]

# Not allowlisted: hidden from the model, and refused when invented anyway.
assert "not available" in run("outsider.test", "secret")
assert seen_tools[-1] == ["remote"]
# No context at all fails closed.
assert "not available" in run(None, "secret")
assert calls == ["secret"], calls

# A peer that fails verification becomes a tool error, not a crash.
assert run("peer.test", "remote").startswith("refused: rogue.test is not a verified DNSid identity")

print("ok: langchain_dnsid agent middleware")

# --- HTTP: real signatures, an in-memory identity resolver ---

key = Ed25519PrivateKey.generate()
jwk = jwk_from_dict(ed25519_public_jwk_dict(key, "k1"))
resolver = SimpleNamespace(verify_domain=lambda d: SimpleNamespace(domain=d, jwks=JWKS(keys=[jwk])))
peer = HttpSignatureProfile(resolver, SimpleNamespace(signing_key=lambda: jwk, sign=key.sign), "peer.test")
tools_idm = SimpleNamespace(local_domain="tools.test", verify_domain=lambda d: None)


def signed(body: bytes) -> HttpRequest:
    """A request to tools.test, signed by peer.test."""
    return peer.create_signed_http_request(
        HttpRequest(method="POST", url="https://tools.test/x", headers={"content-type": "application/json"}, body=body),
        HttpSigningOptions(additional_components=["content-type"], tag=TAG),
    )


async def ok(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def http_checks():
    with patch.object(HttpSignatureProfile, "from_identity_manager", return_value=peer):
        app = DnsidAuthMiddleware(ok, tools_idm)
        client = dnsid_client(tools_idm)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as asgi:

        async def status(req):
            return (await asgi.post(req.url, headers=req.headers, content=req.body or b"")).status_code

        # Each signature works once.
        req = signed(b"{}")
        assert [await status(req), await status(req)] == [200, 401]
        # A correctly signed empty body verifies.
        assert await status(signed(b"")) == 200

    # The signed client won't send over plain HTTP.
    try:
        await client.get("http://tools.test/catalog")
        raise AssertionError("sent over plain HTTP")
    except UnverifiedPeerError as exc:
        assert "not HTTPS" in str(exc)

    # fetch can only GET: it must not be able to do what a restricted tool does.
    assert set(fetch_tool(client).args) == {"url"}


asyncio.run(http_checks())
print("ok: langchain_dnsid HTTP middleware and client")
