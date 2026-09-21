#!/usr/bin/env python3
"""Alice/Bob entry point.

Starts an echo agent that:
  - Serves JWKS, status, and an A2A agent card over HTTP
  - Verifies RFC 9421 HTTP Message Signatures on every inbound POST
  - Echoes messages back with the verified sender identity

When a peer FQDN is given as an argument, Alice sends one signed message to
that peer then exits. Without an argument the agent stays running (Bob mode).

Usage:
    dnsid local run bob --upstream http://localhost:3002 -- \
        uv run python src/main.py

    dnsid local run alice --upstream http://localhost:3001 -- \
        uv run python src/main.py bob.dev.dnsid.test

All DNSID_* variables must be present in the process environment before
startup — `dnsid local run` injects them. DNS routing and TLS trust are
wired automatically from DNSID_DNS_SERVER and DNSID_CA_BUNDLE; no boilerplate
needed in application code.
"""

from __future__ import annotations

import asyncio
import signal
import sys
import uuid
from pathlib import Path

# Allow sibling-module imports regardless of working directory.
sys.path.insert(0, str(Path(__file__).parent))

from dnsid import async_retry_transient

from executor import echo_executor
from identity import await_self_resolvable, load_identity, register_and_publish
from server import EchoAgent, EchoAgentOptions


async def start_agent() -> tuple[object, EchoAgent]:
    """Provision the identity, start the server, and publish the identity.

    The server starts before registration so the registry's callbacks (agent
    card fetch, upstream health) can reach it.
    """
    identity = load_identity()

    agent = await EchoAgent.create(
        echo_executor(identity.domain),
        identity.idm,
        identity.agent_port,
        EchoAgentOptions(public_url=identity.public_url),
    )
    await agent.start()
    print(f"{identity.agent_name or identity.domain} -> {agent.url}")
    await asyncio.sleep(1.0)

    await register_and_publish(identity)
    await await_self_resolvable(identity)

    return identity, agent


async def send_hello(identity, agent: EchoAgent, peer_fqdn: str) -> None:
    """Verify the peer's identity on first contact, then send one signed message."""
    idm = identity.idm
    await async_retry_transient(
        lambda: asyncio.to_thread(idm.verify_domain, peer_fqdn),
        max_attempts=20,
        base_delay=0.5,
        max_delay=5.0,
    )
    print(f"verified: {identity.domain} -> {peer_fqdn}\n")

    client = agent.create_client(f"https://{peer_fqdn}")
    result = await client.send_message(
        {
            "messageId": str(uuid.uuid4()),
            "role": "ROLE_USER",
            "parts": [{"text": f"hello from {identity.domain}"}],
        }
    )
    reply = " ".join(p.get("text", "") for p in result.get("parts", []) if "text" in p)
    print(f'reply: "{reply}"')


async def wait_for_shutdown(agent: EchoAgent) -> None:
    loop = asyncio.get_running_loop()
    shutdown = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown.set)
    await shutdown.wait()
    await agent.stop()


async def main() -> None:
    identity, agent = await start_agent()

    peer_fqdn = sys.argv[1] if len(sys.argv) > 1 else None
    if peer_fqdn:
        await send_hello(identity, agent, peer_fqdn)
        await agent.stop()
        return

    await wait_for_shutdown(agent)


if __name__ == "__main__":
    asyncio.run(main())
