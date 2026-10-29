"""The LangGraph agent: create_agent + langchain_dnsid, and nothing else.

The LLM is never in the trust path. It chooses tool arguments; signing, peer
verification, caller identity, and tool exposure are code in langchain_dnsid.
"""

import os

import httpx
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langchain_dnsid import DnsidContext, DnsidToolPolicyMiddleware, fetch_tool
from langgraph.checkpoint.memory import InMemorySaver

# Only these verified callers ever see place_order. Authorization is code,
# keyed on a domain the middleware verified, never on anything in the prompt.
PLACE_ORDER_ALLOWLIST = {"peer.test"}


def build_agent(client: httpx.AsyncClient, tools_url: str):
    """The agent. Every tool goes through ``client``, the one DNSid client."""

    @tool
    async def place_order(item: str, quantity: int) -> str:
        """Place an order for a quantity of an item."""
        resp = await client.post(f"{tools_url}/order", json={"item": item, "quantity": quantity})
        return resp.text

    return create_agent(
        # Any LangChain model, as "provider:model", e.g. "anthropic:claude-sonnet-5".
        model=os.environ["DNSID_RECIPE_MODEL"],
        tools=[place_order, fetch_tool(client)],
        system_prompt="You are an order-desk agent. Use your tools to answer.",
        middleware=[DnsidToolPolicyMiddleware(restricted={"place_order": PLACE_ORDER_ALLOWLIST})],
        context_schema=DnsidContext,
        checkpointer=InMemorySaver(),
    )


async def ask(agent, caller: str, text: str) -> str:
    """Run one verified request. ``caller`` comes from DnsidAuthMiddleware."""
    result = await agent.ainvoke(
        {"messages": [HumanMessage(text)]},
        # Identity goes in context, out of the model's reach. The thread is
        # keyed by caller, so no caller can resume another's conversation.
        context=DnsidContext(caller=caller),
        config={"configurable": {"thread_id": caller}},
    )
    return result["messages"][-1].text  # text only, no thinking blocks
