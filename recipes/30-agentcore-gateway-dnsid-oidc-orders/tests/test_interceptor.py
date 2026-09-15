from __future__ import annotations

import base64
import json
import time

from orders_common.proof import ActionPayload, arguments_hash, encode_payload, sha256
from orders_interceptor.lambda_handler import transform_request
from orders_interceptor.proof import ProofVerifier
from orders_interceptor.replay import MemoryReplayStore


def token(claims: dict) -> str:
    part = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{part}.signature"


def event(proof: str, arguments: dict) -> dict:
    return {
        "mcp": {
            "gatewayRequest": {
                "headers": {
                    "authorization": f"Bearer {token({'sub': 'agent.bank-a.example', 'aud': 'https://gateway.example/mcp', 'jti': 'token-1'})}",
                    "mcp-session-id": "session-1",
                    "x-action-proof": proof,
                    "x-dnsid-sub": "attacker.example",
                    "x-gateway-sentinel": "forged",
                },
                "body": {
                    "jsonrpc": "2.0",
                    "id": "call",
                    "method": "tools/call",
                    "params": {"name": "OrderTarget___place_order", "arguments": arguments},
                },
            }
        }
    }


def test_interceptor_injects_trust_only_after_dnsid_verification(jose_profiles) -> None:
    signer, profile = jose_profiles()
    arguments = {"sku": "LABEL-CASE", "quantity": 2}
    proof = signer.create_jws(
        encode_payload(
            ActionPayload(
                subject="agent.bank-a.example",
                audience="https://gateway.example/mcp",
                token_jti_hash=sha256("token-1"),
                tool_name="place_order",
                arguments_hash=arguments_hash(arguments),
                session_hash=sha256("session-1"),
                timestamp=int(time.time()),
                nonce="nonce-1",
            )
        )
    )
    verifier = ProofVerifier(profile, MemoryReplayStore())

    accepted = transform_request(event(proof, arguments), verifier, "agent.bank-a.example", "trusted")
    headers = accepted["mcp"]["transformedGatewayRequest"]["headers"]
    assert headers["x-dnsid-sub"] == "agent.bank-a.example"
    assert headers["x-gateway-sentinel"] == "trusted"
    assert "authorization" not in headers
    assert "x-action-proof" not in headers

    denied = transform_request(
        event(proof, {**arguments, "quantity": 3}),
        ProofVerifier(profile, MemoryReplayStore()),
        "agent.bank-a.example",
        "trusted",
    )
    assert denied["mcp"]["transformedGatewayResponse"]["statusCode"] == 403
