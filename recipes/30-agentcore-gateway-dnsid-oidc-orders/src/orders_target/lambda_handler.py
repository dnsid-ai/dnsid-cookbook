from __future__ import annotations

import hmac
import json
import os
from typing import Any


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    headers = {str(key).lower(): str(value) for key, value in (event.get("headers") or {}).items()}
    expected = os.environ.get("GATEWAY_SENTINEL", "")
    if not expected or not hmac.compare_digest(headers.get("x-gateway-sentinel", ""), expected):
        return response(403, {"ok": False, "reason": "request did not pass the DNSid interceptor"})
    if headers.get("x-dnsid-status") != "active":
        return response(403, {"ok": False, "reason": "DNSid identity is not active"})
    body = event.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            body = None
    if not isinstance(body, dict):
        return response(400, {"ok": False, "reason": "order must be a JSON object"})
    sku, quantity = body.get("sku"), body.get("quantity")
    if not isinstance(sku, str) or not sku or len(sku) > 64:
        return response(400, {"ok": False, "reason": "sku must be 1-64 characters"})
    if isinstance(quantity, bool) or not isinstance(quantity, int) or not 1 <= quantity <= 10:
        return response(400, {"ok": False, "reason": "quantity must be an integer from 1 to 10"})
    return response(
        200,
        {
            "ok": True,
            "message": "order accepted",
            "dnsid_sub": headers.get("x-dnsid-sub"),
            "sku": sku,
            "quantity": quantity,
        },
    )


def response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {"statusCode": status, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}
