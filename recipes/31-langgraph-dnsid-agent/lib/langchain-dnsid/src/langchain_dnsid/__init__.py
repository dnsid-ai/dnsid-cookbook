"""DNSid identity for LangChain / LangGraph agents.

- ``dnsid_client`` / ``fetch_tool`` — outbound: verify the peer, sign as this agent.
- ``DnsidAuthMiddleware`` — inbound: admit only DNSid-signed requests (ASGI).
- ``DnsidContext`` / ``DnsidToolPolicyMiddleware`` — the verified caller as runtime
  context, and tools scoped to it (``create_agent`` middleware).

Depends only on dnsid, langchain, httpx, and starlette; nothing here knows about the recipe.
"""

from .agent import DnsidContext, DnsidToolPolicyMiddleware
from .egress import TAG, UnverifiedPeerError, dnsid_client, fetch_tool
from .ingress import DnsidAuthMiddleware

__all__ = [
    "TAG",
    "DnsidAuthMiddleware",
    "DnsidContext",
    "DnsidToolPolicyMiddleware",
    "UnverifiedPeerError",
    "dnsid_client",
    "fetch_tool",
]
