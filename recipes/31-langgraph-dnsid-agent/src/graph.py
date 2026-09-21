"""The LangGraph agent: a model node, a tool node, and caller-gated tools.

Security invariants implemented here (the README walks through each):

1. The verified caller lives in ``config["configurable"]``, never in graph
   state. Graph state is writable by node return values, which are downstream
   of model output — a state-carried identity is a prompt-injection-to-
   authorization-bypass path. Nodes read the caller from config; nothing
   writes it.
2. Tool exposure is computed from the verified caller BEFORE the model runs:
   ``allowed_tools`` filters the tool set, and the sensitive tool is absent
   from the model's bound tools for non-allowlisted callers — not merely
   refused when called.
3. ``thread_id`` is derived from the verified caller domain, so one caller
   cannot resume another's thread. Nothing else is trusted across requests.
5. One signed httpx client, injected — the tools close over the client that
   ``make_signed_tools_client`` built once. A tool that constructs its own
   client would ship unsigned traffic silently.

The LLM is never in the trust path: it chooses tool arguments; identity,
verification, and the tool allowlist are code.
"""

from __future__ import annotations

import os
import re

import httpx
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool, tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from dnsid import IdentityManager
from dnsid.models import HttpSigningOptions

from dnsid_identity import load_identity
from middleware import TOOLS_SIGNATURE_TAG

# The model id used when ANTHROPIC_API_KEY is set — the recipe's single place
# to change it. Check https://docs.claude.com for newer models.
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5"

# Callers allowed to see (not just call) the sensitive place_order tool.
# Authorization is code and config, never model output.
PLACE_ORDER_ALLOWLIST = {"peer.dev.dnsid.test"}


# ---------------------------------------------------------------------------
# Egress: one signed client for every tool (invariant 5)
# ---------------------------------------------------------------------------


def make_signed_tools_client(idm: IdentityManager) -> httpx.AsyncClient:
    """Build the single httpx client that signs every outbound tool call.

    The SDK client signs the exact bytes sent, so the tool server's required
    ``content-digest`` component verifies. It inherits the manager's local registry
    DNS server and CA bundle.
    """
    bundle = load_identity(source="manager", manager=idm)
    signing_opts = HttpSigningOptions(
        additional_components=["content-type"],
        tag=TOOLS_SIGNATURE_TAG,
    )
    return bundle.http_sig.create_signed_async_http_client(
        base_headers={"content-type": "application/json"},
        opts=signing_opts,
    )


def make_tools(client: httpx.AsyncClient, tools_base_url: str) -> dict[str, BaseTool]:
    """Build the tool set. Every tool closes over the one injected signed client."""

    @tool
    async def get_price(item: str) -> str:
        """Look up the current price of an item."""
        resp = await client.post(f"{tools_base_url}/price", json={"item": item})
        resp.raise_for_status()
        return resp.text

    @tool
    async def place_order(item: str, quantity: int) -> str:
        """Place an order for a quantity of an item. Requires authorization."""
        resp = await client.post(
            f"{tools_base_url}/order", json={"item": item, "quantity": quantity}
        )
        resp.raise_for_status()
        return resp.text

    return {"get_price": get_price, "place_order": place_order}


# ---------------------------------------------------------------------------
# Authorization: tool exposure from the verified caller (invariant 2)
# ---------------------------------------------------------------------------


def allowed_tools(caller: str, tools_by_name: dict[str, BaseTool]) -> list[BaseTool]:
    """The tool set this caller gets. Computed before the model ever runs."""
    tools = [tools_by_name["get_price"]]
    if caller in PLACE_ORDER_ALLOWLIST:
        tools.append(tools_by_name["place_order"])
    return tools


# ---------------------------------------------------------------------------
# The model node: scripted by default, Claude when a key is present
# ---------------------------------------------------------------------------


class ScriptedToolCallingModel(BaseChatModel):
    """Deterministic stand-in for an LLM, so `make verify` needs no API key.

    Behaves like a tool-calling model: given "order N <item>" it calls
    place_order if (and only if) that tool is bound; after a tool result it
    produces a final answer. Deterministic in, deterministic out — CI-safe.
    """

    tool_names: list[str] = []

    @property
    def _llm_type(self) -> str:
        return "scripted-tool-caller"

    def bind_tools(self, tools, **kwargs):
        names = [getattr(t, "name", str(t)) for t in tools]
        return ScriptedToolCallingModel(tool_names=names)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=self._respond(messages))])

    def _respond(self, messages) -> AIMessage:
        last = messages[-1]
        if isinstance(last, ToolMessage):
            return AIMessage(content=f"done: {last.content}")

        text = ""
        for m in reversed(messages):
            if isinstance(m, HumanMessage):
                text = str(m.content).lower()
                break

        order = re.search(r"order (\d+) (\w+)", text)
        if order:
            if "place_order" in self.tool_names:
                return AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "place_order",
                            "args": {"item": order.group(2), "quantity": int(order.group(1))},
                            "id": "call_place_order",
                        }
                    ],
                )
            return AIMessage(
                content="cannot place order: the place_order tool is not available to this caller"
            )

        price = re.search(r"price of (\w+)", text)
        if price and "get_price" in self.tool_names:
            return AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "get_price",
                        "args": {"item": price.group(1)},
                        "id": "call_get_price",
                    }
                ],
            )

        return AIMessage(
            content=f"available tools: {', '.join(sorted(self.tool_names)) or 'none'}"
        )


def make_model(tools: list[BaseTool]) -> BaseChatModel:
    """Scripted model by default; a real Claude model when ANTHROPIC_API_KEY is set."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        from langchain_anthropic import ChatAnthropic

        base = ChatAnthropic(model=os.environ.get("DNSID_RECIPE_MODEL", DEFAULT_ANTHROPIC_MODEL))
    else:
        base = ScriptedToolCallingModel()
    return base.bind_tools(tools)


# ---------------------------------------------------------------------------
# The graph
# ---------------------------------------------------------------------------

# Shared across requests; threads are isolated by thread_id (invariant 3).
CHECKPOINTER = InMemorySaver()


def build_graph(model: BaseChatModel, tools: list[BaseTool]):
    """A minimal agent loop: model decides, ToolNode executes, model concludes."""

    async def call_model(state: MessagesState, config: RunnableConfig):
        # The verified caller comes from config — out-of-band, set by the
        # executor at invoke time. It is NOT graph state: nothing the model
        # or the tools return can overwrite it (invariant 1).
        caller = config["configurable"]["dnsid_caller"]
        system = SystemMessage(
            "You are an order-desk agent. Use your tools to answer. "
            f"You are serving the verified caller {caller}."
        )
        response = await model.ainvoke([system] + state["messages"], config)
        return {"messages": [response]}

    builder = StateGraph(MessagesState)
    builder.add_node("agent", call_model)
    builder.add_node("tools", ToolNode(tools))
    builder.add_edge(START, "agent")
    builder.add_conditional_edges("agent", tools_condition, {"tools": "tools", END: END})
    builder.add_edge("tools", "agent")
    return builder.compile(checkpointer=CHECKPOINTER)


async def run_graph(tools_by_name: dict[str, BaseTool], caller: str, text: str) -> str:
    """Run one verified request through the graph and return the reply text.

    Built per request from the caller's allowed tool set: for a caller off the
    allowlist, place_order does not exist — it is not bound to the model, and
    it is not in the ToolNode.
    """
    tools = allowed_tools(caller, tools_by_name)
    graph = build_graph(make_model(tools), tools)
    result = await graph.ainvoke(
        {"messages": [HumanMessage(text)]},
        config={
            "configurable": {
                "dnsid_caller": caller,
                # Thread identity is derived from the verified caller, so a
                # caller can only ever resume its own thread (invariant 3).
                "thread_id": f"a2a:{caller}",
            }
        },
    )
    reply = result["messages"][-1].content
    return reply if isinstance(reply, str) else str(reply)
