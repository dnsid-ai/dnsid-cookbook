"""The A2A server for the LangGraph agent: a2a-sdk routes behind DNSid verification.

Route map (same shape as recipe 12):

  GET  /.well-known/agent-card.json  the signed A2A agent card
  GET  /.well-known/jwks.json        the agent's public keys (the ku= target)
  GET  /.well-known/status.json      live identity status (the su= target)
  POST /                             A2A JSON-RPC — signature-verified ingress

The executor plugged in here is the LangGraph executor (executor.py); the
server itself neither knows nor cares that a graph is behind it.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import uvicorn
from a2a.server.agent_execution import AgentExecutor
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types.a2a_pb2 import AgentCard
from fastapi import FastAPI

from dnsid import IdentityManager, active_status_document
from dnsid.http_signatures import HttpSignatureProfile
from dnsid.jose import JoseProfile

from agent_card import build_agent_card, sign_agent_card
from client import A2AClient
from middleware import (
    A2A_VERIFY_OPTS,
    DnsidServerCallContextBuilder,
    DnsidSignatureMiddleware,
)


@dataclass
class A2AServerOptions:
    """Options for :class:`A2AAgentServer`."""

    public_url: str | None = None


class A2AAgentServer:
    """HTTP agent server: verifies inbound signatures via dnsid, delegates to a2a-sdk."""

    def __init__(
        self,
        idm: IdentityManager,
        jose: JoseProfile,
        http_sig: HttpSignatureProfile,
        port: int,
        executor: AgentExecutor,
        card: AgentCard,
    ) -> None:
        self._idm = idm
        self._jose = jose
        self._http_sig = http_sig
        self._port = port
        self._executor = executor
        self._card = card
        self._server: uvicorn.Server | None = None
        self._serve_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._clients: dict[str, A2AClient] = {}

    @classmethod
    async def create(
        cls,
        executor: AgentExecutor,
        idm: IdentityManager,
        port: int,
        options: A2AServerOptions = A2AServerOptions(),
    ) -> A2AAgentServer:
        public_url = options.public_url or f"https://{idm.local_domain}"
        provider_url = (
            public_url
            if ":" in idm.config.identity.governance_id
            else f"https://{idm.config.identity.governance_id}"
        )
        card = build_agent_card(idm.local_domain, public_url, provider_url)

        jose = JoseProfile.from_identity_manager(idm)
        http_sig = HttpSignatureProfile.from_identity_manager(idm)

        await sign_agent_card(card, jose, idm.local_domain)

        return cls(idm, jose, http_sig, port, executor, card)

    @property
    def url(self) -> str:
        if self._card.supported_interfaces:
            return self._card.supported_interfaces[0].url
        return f"https://{self._idm.local_domain}"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        app = self._build_app()
        config = uvicorn.Config(app, host="0.0.0.0", port=self._port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._serve_task = asyncio.create_task(self._server.serve())
        while not self._server.started:
            await asyncio.sleep(0.05)

    async def stop(self) -> None:
        for c in self._clients.values():
            await c.aclose()
        self._clients.clear()
        if self._server:
            self._server.should_exit = True
        if self._serve_task:
            await self._serve_task

    # ------------------------------------------------------------------
    # A2A client: send signed messages to a peer agent
    # ------------------------------------------------------------------

    def create_client(self, target_base_url: str) -> A2AClient:
        """Return a cached A2AClient for *target_base_url*, creating one on first use."""
        key = target_base_url.rstrip("/")
        if key not in self._clients:
            self._clients[key] = A2AClient(self._http_sig, target_base_url)
        return self._clients[key]

    def _build_app(self) -> DnsidSignatureMiddleware:
        idm = self._idm
        card = self._card
        executor = self._executor

        task_store = InMemoryTaskStore()
        request_handler = DefaultRequestHandler(
            agent_executor=executor,
            task_store=task_store,
            agent_card=card,
        )
        context_builder = DnsidServerCallContextBuilder()

        sdk_routes = create_agent_card_routes(
            card, card_url="/.well-known/agent-card.json"
        ) + create_jsonrpc_routes(
            request_handler,
            rpc_url="/",
            context_builder=context_builder,
            enable_v0_3_compat=False,
        )

        app = FastAPI(title="A2A Agent Server", version="1.0.0", routes=sdk_routes)

        @app.get("/.well-known/jwks.json", include_in_schema=False)
        async def get_jwks():
            return idm.get_key_set().to_dict()

        @app.get("/.well-known/status.json", include_in_schema=False)
        async def get_status():
            return active_status_document()

        return DnsidSignatureMiddleware(
            app,
            idm.local_domain,
            self._http_sig,
            A2A_VERIFY_OPTS,
            require_a2a_headers=True,
        )
