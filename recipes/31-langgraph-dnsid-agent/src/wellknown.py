"""Well-known identity routes and a small uvicorn runner, shared by roles.

Every identity in this recipe serves the two endpoints a DNSid verifier
follows from the `_dnsid` record: the JWKS at ku= and the status document at
su=. The tools server adds its tool endpoints on top; the peer/outsider
serve only these while sending.
"""

from __future__ import annotations

import asyncio

import uvicorn
from fastapi import FastAPI

from dnsid import IdentityManager, active_status_document


def add_wellknown_routes(app: FastAPI, idm: IdentityManager) -> None:
    @app.get("/.well-known/jwks.json", include_in_schema=False)
    async def get_jwks():
        return idm.get_key_set().to_dict()

    @app.get("/.well-known/status.json", include_in_schema=False)
    async def get_status():
        return active_status_document()


class UvicornRunner:
    """Start/stop an ASGI app on a background task."""

    def __init__(self, app, port: int) -> None:
        self._config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task | None = None  # type: ignore[type-arg]

    async def start(self) -> None:
        self._server = uvicorn.Server(self._config)
        self._task = asyncio.create_task(self._server.serve())
        while not self._server.started:
            await asyncio.sleep(0.05)

    async def stop(self) -> None:
        if self._server:
            self._server.should_exit = True
        if self._task:
            await self._task
