#!/usr/bin/env python3
from __future__ import annotations

from orders_client.action import sign_action
from orders_client.identity import CallerIdentity
from orders_client.mcp import McpClient, tool_result
from orders_common.config import load_settings
from orders_common.jwt import decode_claims
from scripts.common import load_json


def main() -> None:
    settings = load_settings()
    state = load_json(settings.state_path)
    identity = CallerIdentity(settings)
    token = identity.mint_token(state["audience"])
    claims = decode_claims(token)
    client = McpClient(state["gateway_url"], token)
    client.initialize()
    order = {"sku": "LABEL-CASE", "quantity": 2}
    proof = sign_action(
        identity.jose,
        subject=identity.domain,
        audience=state["audience"],
        token_jti=claims["jti"],
        session_id=client.session_id,
        tool_name="place_order",
        arguments=order,
    )
    result = tool_result(client.call_tool(state["target_name"], order, proof))
    if not result.get("ok"):
        raise RuntimeError(f"order was denied: {result}")
    print(f"✓ AgentCore accepted the DNSid OIDC token for {identity.domain}")
    print("✓ interceptor resolved the DNSid key and verified the signed action")
    print(f"✓ order accepted: {result['quantity']} × {result['sku']}")


if __name__ == "__main__":
    main()
