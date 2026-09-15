#!/usr/bin/env python3
from __future__ import annotations

from orders_client.action import sign_action
from orders_client.identity import CallerIdentity
from orders_client.mcp import McpClient, tool_result
from orders_common.config import load_settings
from orders_common.jwt import decode_claims
from scripts.common import load_json


def error_code(response: dict) -> str:
    return str(response.get("body", {}).get("error", {}).get("code", ""))


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
    accepted = tool_result(client.call_tool(state["target_name"], order, proof))
    tampered = client.call_tool(state["target_name"], {**order, "quantity": 3}, proof)
    replayed = client.call_tool(state["target_name"], order, proof)

    assert accepted.get("ok") is True, accepted
    assert error_code(tampered) == "action_proof_denied", tampered
    assert error_code(replayed) == "action_proof_denied", replayed
    print(f"✓ valid DNSid action accepted for {identity.domain}")
    print("✓ modified order denied: action proof does not match arguments_hash")
    print("✓ repeated action denied: nonce already used")


if __name__ == "__main__":
    main()
