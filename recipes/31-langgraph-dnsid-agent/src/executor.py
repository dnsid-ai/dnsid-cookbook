"""The A2A executor: the seam between verified ingress and the graph.

This is where invariant 1 is enforced in practice: the executor reads the
cryptographically verified caller from the a2a-sdk call context (set by the
signature middleware — see middleware.py) and threads it into the graph via
``config["configurable"]``, never via graph state. Every inbound A2A call
passes through this path, so every graph invocation re-derives its caller
from a fresh signature verification — no trust is inherited from earlier
requests or resumed checkpoints.
"""

from __future__ import annotations

from a2a.helpers.proto_helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from langchain_core.tools import BaseTool

from graph import run_graph


class GraphExecutor(AgentExecutor):
    """Runs each verified A2A message through the LangGraph graph."""

    def __init__(self, graph_domain: str, tools_by_name: dict[str, BaseTool]) -> None:
        self._domain = graph_domain
        self._tools_by_name = tools_by_name

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        text = context.get_user_input()
        # Set by the signature middleware after verification — not a header
        # the caller controls.
        caller = context.call_context.user.user_name
        print(f'[{self._domain}] handling message from verified caller {caller}: "{text}"')

        reply = await run_graph(self._tools_by_name, caller, text)

        reply_text = f"[from: {self._domain}; verified caller: {caller}] {reply}"
        print(f'[{self._domain}] replying to {caller}: "{reply_text}"')
        response = new_text_message(
            reply_text,
            context_id=context.context_id,
            task_id=context.task_id,
        )
        await event_queue.enqueue_event(response)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        pass
