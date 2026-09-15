"""The agent's behavior: an echo executor that reads the verified sender.

The executor is deliberately trivial — this recipe is about identity, not
agent logic. The one thing worth studying here is where the sender identity
comes from: `context.call_context.user.user_name` is set by the signature
middleware after cryptographic verification (see middleware.py). It is not a
header the caller controls; an unsigned or badly signed request never reaches
this code.
"""

from __future__ import annotations

from a2a.helpers.proto_helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue_v2 import EventQueue


def echo_executor(agent_id: str) -> AgentExecutor:
    """Return an AgentExecutor that echoes messages back with the verified sender identity."""

    class _EchoExecutor(AgentExecutor):
        async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
            text = context.get_user_input()
            sender_id = context.call_context.user.user_name
            print(f'[{agent_id}] handling message from verified sender {sender_id}: "{text}"')
            reply_text = f"[from: {agent_id}; verified sender: {sender_id}] {text}"
            print(f'[{agent_id}] sending response to {sender_id}: "{reply_text}"')
            response = new_text_message(
                reply_text,
                context_id=context.context_id,
                task_id=context.task_id,
            )
            await event_queue.enqueue_event(response)

        async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
            pass

    return _EchoExecutor()
