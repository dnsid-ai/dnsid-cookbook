"""The tools API for tools.dev.dnsid.test: a plain HTTP service that verifies callers.

This is deliberately NOT an agent and NOT A2A — it's the kind of ordinary
internal HTTP API an agent's tools call. Its whole security story is the same
middleware the graph's A2A ingress uses: every inbound POST must carry an
RFC 9421 signature that resolves, via DNS, to a published DNSid identity.
The server needs no API keys for its callers and no caller onboarding — a
new caller works the moment its `_dnsid` record is live, and revocation
propagates through DNS.

Note what this server does NOT do: it doesn't decide which callers may place
orders. That authorization lives with the graph agent (graph.py) — this
server just refuses to act for anyone unverified, and logs who each request
verifiably came from.
"""

from __future__ import annotations

from itertools import count

from fastapi import FastAPI
from pydantic import BaseModel

from dnsid.http_signatures import HttpSignatureProfile

from lifecycle import AgentIdentity
from middleware import TOOLS_VERIFY_OPTS, DnsidSignatureMiddleware
from wellknown import add_wellknown_routes

PRICES = {"widgets": 4.25, "gadgets": 17.5}


class PriceRequest(BaseModel):
    item: str


class OrderRequest(BaseModel):
    item: str
    quantity: int


def build_tools_app(identity: AgentIdentity) -> DnsidSignatureMiddleware:
    app = FastAPI(title="Tools API", version="1.0.0")
    add_wellknown_routes(app, identity.idm)
    order_ids = count(1)

    @app.post("/price")
    async def price(req: PriceRequest):
        return {"item": req.item, "price": PRICES.get(req.item, 9.99)}

    @app.post("/order")
    async def order(req: OrderRequest):
        return {
            "order_id": f"ord-{next(order_ids)}",
            "item": req.item,
            "quantity": req.quantity,
            "status": "accepted",
        }

    http_sig = HttpSignatureProfile.from_identity_manager(identity.idm)
    return DnsidSignatureMiddleware(
        app,
        identity.domain,
        http_sig,
        TOOLS_VERIFY_OPTS,
        public_url=identity.public_url or f"https://{identity.domain}",
        # Plain HTTP ingress: signature verification only, no A2A headers.
        require_a2a_headers=False,
    )
