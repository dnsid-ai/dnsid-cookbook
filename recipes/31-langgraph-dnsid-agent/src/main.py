#!/usr/bin/env python3
"""The recipe's three roles. Each runs under `dnsid local run <name>`, which
injects that identity's DNSID_* environment.

    tools             the tools API (tools.test): verifies every caller
    graph             the LangGraph agent (graph.test): verifies its callers,
                      signs its tool calls, verifies who it calls
    ask <fqdn> <text> send one signed request to an agent, print the reply
"""

import asyncio
import logging
import os
import sys
from itertools import count
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import uvicorn
from dnsid import identity_manager_from_environment
from fastapi import FastAPI, HTTPException, Request
from langchain_dnsid import DnsidAuthMiddleware, dnsid_client
from pydantic import BaseModel

from graph import ask, build_agent

TOOLS_URL = "https://tools.test"
ORDERING_AGENT = "graph.test"  # the only caller the tools API takes orders from


class Order(BaseModel):
    item: str
    quantity: int


class Ask(BaseModel):
    text: str


def tools_app(idm) -> DnsidAuthMiddleware:
    """An ordinary HTTP API: the middleware says who's calling, the routes decide what they may do."""
    app = FastAPI()
    order_ids = count(1)

    @app.get("/catalog")
    async def catalog():
        return {"widgets": 4.25, "gadgets": 17.5}

    @app.post("/order")
    async def order(req: Order, request: Request):
        if request.state.dnsid_caller != ORDERING_AGENT:
            raise HTTPException(403, f"only {ORDERING_AGENT} may place orders")
        return {"order_id": f"ord-{next(order_ids)}", **req.model_dump(), "status": "accepted"}

    return DnsidAuthMiddleware(app, idm)


def graph_app(idm) -> DnsidAuthMiddleware:
    app = FastAPI()
    agent = build_agent(dnsid_client(idm), TOOLS_URL)

    @app.post("/ask")
    async def handle(req: Ask, request: Request):
        caller = request.state.dnsid_caller  # set only by DnsidAuthMiddleware
        return {"reply": f"[{idm.local_domain} -> {caller}] {await ask(agent, caller, req.text)}"}

    return DnsidAuthMiddleware(app, idm)


async def send(idm, fqdn: str, text: str) -> None:
    async with dnsid_client(idm) as client:  # verifies fqdn before sending
        # A real model (especially a local one) can take well over httpx's 5s default.
        resp = await client.post(f"https://{fqdn}/ask", json={"text": text}, timeout=120)
    print(f"{resp.status_code} {resp.json()}")


def main() -> None:
    logging.basicConfig(format="%(message)s")
    logging.getLogger("langchain_dnsid").setLevel(logging.INFO)
    idm = identity_manager_from_environment()
    role, *args = sys.argv[1:] or [""]

    if role in ("tools", "graph"):
        app = tools_app(idm) if role == "tools" else graph_app(idm)
        port = int(os.environ["DNSID_AGENT_PORT"])
        print(f"{idm.local_domain} listening on :{port}", flush=True)
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
    elif role == "ask" and len(args) >= 2:
        asyncio.run(send(idm, args[0], " ".join(args[1:])))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
