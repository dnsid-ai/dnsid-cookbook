#!/usr/bin/env python3
"""Entry point for the three roles in this recipe.

Roles (each process runs under `dnsid testnet run <name>`, which injects the
DNSID_* environment for that identity):

    tools                     the plain-HTTP tools API (tools.dev.dnsid.test)
    graph                     the LangGraph A2A agent (graph.dev.dnsid.test)
    send <graph-fqdn> <text>  verify the graph agent, send one signed A2A
                              message as the current identity, print the reply

Usage:
    dnsid testnet run tools --upstream http://localhost:3103 -- \
        uv run python -u src/main.py tools

    dnsid testnet run graph --upstream http://localhost:3101 -- \
        uv run python -u src/main.py graph

    dnsid testnet run peer --upstream http://localhost:3102 -- \
        uv run python -u src/main.py send graph.dev.dnsid.test "Please order 3 widgets"
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import uuid
from pathlib import Path

# Allow sibling-module imports regardless of working directory.
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI

from dnsid import async_retry_transient

from client import A2AClient
from executor import GraphExecutor
from graph import make_signed_tools_client, make_tools
from lifecycle import (
    AgentIdentity,
    await_self_resolvable,
    load_identity,
    register_and_publish,
)
from server import A2AAgentServer, A2AServerOptions
from tools_server import build_tools_app
from wellknown import UvicornRunner, add_wellknown_routes

TOOLS_FQDN = os.environ.get("DNSID_RECIPE_TOOLS_FQDN", "tools.dev.dnsid.test")


async def wait_for_shutdown() -> None:
    loop = asyncio.get_running_loop()
    shutdown = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown.set)
    await shutdown.wait()


async def publish(identity: AgentIdentity) -> None:
    """Publish this identity and wait until its own record verifies end-to-end."""
    await register_and_publish(identity)
    await await_self_resolvable(identity)


async def verify_peer(identity: AgentIdentity, peer_fqdn: str) -> None:
    """First-contact verification: resolve and verify a peer before talking to it."""
    await async_retry_transient(
        lambda: asyncio.to_thread(identity.idm.verify_domain, peer_fqdn),
        max_attempts=20,
        base_delay=0.5,
        max_delay=5.0,
    )
    print(f"verified: {identity.domain} -> {peer_fqdn}")


async def run_tools() -> None:
    identity = load_identity()
    runner = UvicornRunner(build_tools_app(identity), identity.agent_port)
    await runner.start()
    print(f"{identity.agent_name or identity.domain} -> https://{identity.domain}")
    await publish(identity)
    await wait_for_shutdown()
    await runner.stop()


async def run_graph_agent() -> None:
    identity = load_identity()

    # One signed httpx client for every tool call this agent ever makes
    # (invariant 5); built before the graph exists.
    signed_client = make_signed_tools_client(identity.idm)
    tools_by_name = make_tools(signed_client, f"https://{TOOLS_FQDN}")

    executor = GraphExecutor(identity.domain, tools_by_name)
    server = await A2AAgentServer.create(
        executor, identity.idm, identity.agent_port, A2AServerOptions(identity.public_url)
    )
    await server.start()
    print(f"{identity.agent_name or identity.domain} -> {server.url}")
    await asyncio.sleep(1.0)

    await publish(identity)
    # First-contact trust in the tool server, before the first tool call.
    await verify_peer(identity, TOOLS_FQDN)

    await wait_for_shutdown()
    await signed_client.aclose()
    await server.stop()


async def run_send(graph_fqdn: str, text: str) -> None:
    identity = load_identity()

    # Even a send-only caller serves its JWKS and status: that's where the
    # graph's verifier fetches this identity's keys from.
    app = FastAPI(title="A2A Caller", version="1.0.0")
    add_wellknown_routes(app, identity.idm)
    runner = UvicornRunner(app, identity.agent_port)
    await runner.start()
    print(f"{identity.agent_name or identity.domain} -> https://{identity.domain}")
    await publish(identity)

    await verify_peer(identity, graph_fqdn)

    from dnsid.http_signatures import HttpSignatureProfile

    http_sig = HttpSignatureProfile.from_identity_manager(identity.idm)
    client = A2AClient(http_sig, f"https://{graph_fqdn}")
    try:
        result = await client.send_message(
            {
                "messageId": str(uuid.uuid4()),
                "role": "ROLE_USER",
                "parts": [{"text": text}],
            }
        )
        reply = " ".join(p.get("text", "") for p in result.get("parts", []) if "text" in p)
        print(f'reply: "{reply}"')
    finally:
        await client.aclose()
        await runner.stop()


async def main() -> None:
    role = sys.argv[1] if len(sys.argv) > 1 else ""
    if role == "tools":
        await run_tools()
    elif role == "graph":
        await run_graph_agent()
    elif role == "send":
        if len(sys.argv) < 4:
            raise SystemExit("usage: main.py send <graph-fqdn> <text>")
        await run_send(sys.argv[2], " ".join(sys.argv[3:]))
    else:
        raise SystemExit("usage: main.py tools | graph | send <graph-fqdn> <text>")


if __name__ == "__main__":
    asyncio.run(main())
