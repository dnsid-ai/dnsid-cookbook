from __future__ import annotations

import json

from orders_target.lambda_handler import lambda_handler


def call(monkeypatch, headers: dict, body: dict) -> tuple[int, dict]:
    monkeypatch.setenv("GATEWAY_SENTINEL", "trusted")
    result = lambda_handler({"headers": headers, "body": json.dumps(body)}, None)
    return result["statusCode"], json.loads(result["body"])


def test_target_accepts_only_verified_small_orders(monkeypatch) -> None:
    order = {"sku": "LABEL-CASE", "quantity": 2}
    status, body = call(
        monkeypatch,
        {"x-gateway-sentinel": "trusted", "x-dnsid-status": "active", "x-dnsid-sub": "agent.bank-a.example"},
        order,
    )
    assert status == 200
    assert body["dnsid_sub"] == "agent.bank-a.example"

    assert call(monkeypatch, {"x-gateway-sentinel": "forged"}, order)[0] == 403
    assert call(
        monkeypatch,
        {"x-gateway-sentinel": "trusted", "x-dnsid-status": "active"},
        {**order, "quantity": 11},
    )[0] == 400
