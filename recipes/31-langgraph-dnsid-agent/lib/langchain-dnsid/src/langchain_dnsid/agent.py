"""Agent side: the verified caller, and tools scoped to it.

Your server passes the verified caller as LangGraph *runtime context*
(``context=`` at invoke time). Graph state is written by node outputs, which
are downstream of model output; context is set only by the invoking code and
is not saved in checkpoints.
"""

import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass

from langchain.agents.middleware import (
    AgentMiddleware,
    AgentState,
    ModelRequest,
    ToolCallRequest,
)
from langchain_core.messages import ToolMessage

from .egress import UnverifiedPeerError

log = logging.getLogger("langchain_dnsid")


@dataclass(frozen=True)
class DnsidContext:
    """Per-invocation context: the DNSid-verified domain of whoever asked."""

    caller: str | None = None


class DnsidToolPolicyMiddleware(AgentMiddleware[AgentState, DnsidContext]):
    """Scope tools to the verified caller, and report refused peers to the model.

    ``restricted`` maps a tool name to the callers allowed to use it; tools not
    listed are available to every verified caller. A restricted tool is removed
    from the model's tool list for anyone else, and refused at execution too,
    so a tool call the model invents anyway still never runs.

    Pass ``context_schema=DnsidContext`` (or a subclass) to ``create_agent``.
    """

    def __init__(self, restricted: Mapping[str, set[str]] | None = None) -> None:
        super().__init__()
        self.restricted = dict(restricted or {})

    def _caller(self, runtime) -> str | None:
        return getattr(runtime.context, "caller", None)

    def _allowed(self, tool_name: str, runtime) -> bool:
        if tool_name not in self.restricted:
            return True
        return self._caller(runtime) in self.restricted[tool_name]  # no caller: fail closed

    async def awrap_model_call(self, request: ModelRequest, handler: Callable[[ModelRequest], Awaitable]):
        tools = [t for t in request.tools if self._allowed(_name(t), request.runtime)]
        if hidden := sorted({_name(t) for t in request.tools} - {_name(t) for t in tools}):
            log.info("[policy] hid %s from %s", ", ".join(hidden), self._caller(request.runtime))
        return await handler(request.override(tools=tools))

    async def awrap_tool_call(self, request: ToolCallRequest, handler: Callable[[ToolCallRequest], Awaitable]):
        call = request.tool_call
        if not self._allowed(call["name"], request.runtime):
            log.warning("[policy] blocked %s for %s", call["name"], self._caller(request.runtime))
            return ToolMessage(f"tool {call['name']} is not available to this caller", tool_call_id=call["id"], status="error")
        try:
            return await handler(request)
        except UnverifiedPeerError as exc:
            return ToolMessage(f"refused: {exc}", tool_call_id=call["id"], status="error")


def _name(tool) -> str:
    return tool["name"] if isinstance(tool, dict) else tool.name
