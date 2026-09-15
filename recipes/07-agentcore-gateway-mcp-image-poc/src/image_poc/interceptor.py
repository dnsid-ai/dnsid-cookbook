from __future__ import annotations

import base64
import json
import os
import time
import uuid
from typing import Any


class InterceptorError(Exception):
    pass


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    mcp = event.get("mcp") or {}
    if mcp.get("gatewayResponse") is not None:
        return transform_response(event)
    return transform_request(event)


def transform_request(event: dict[str, Any]) -> dict[str, Any]:
    gateway_request = (event.get("mcp") or {}).get("gatewayRequest") or {}
    try:
        headers = normalize_headers(gateway_request.get("headers"))
        claims = claims_from_authorization(headers.get("authorization", ""))
        validate_claims(claims)
        trusted_headers = trusted_headers_from_claims(claims, gateway_request)
    except InterceptorError as exc:
        return {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayResponse": {
                    "statusCode": 403,
                    "body": {
                        "jsonrpc": "2.0",
                        "id": jsonrpc_id(gateway_request.get("body")),
                        "error": {
                            "code": "trusted_context_error",
                            "message": str(exc),
                        },
                    },
                }
            }
        }

    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayRequest": {
                "body": gateway_request.get("body"),
                "headers": trusted_headers,
            }
        }
    }


def transform_response(event: dict[str, Any]) -> dict[str, Any]:
    mcp = event.get("mcp") or {}
    gateway_request = mcp.get("gatewayRequest") or {}
    source_response = mcp.get("gatewayResponse") or {}
    status_code = source_response.get("statusCode", 200)
    body = source_response.get("body") or {}
    if should_filter_tools(gateway_request, body):
        body = filter_tools_body(body)
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": status_code,
                "body": body,
            }
        },
    }


def normalize_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if value is None:
            continue
        normalized[str(key).lower()] = str(value)
    return normalized


def claims_from_authorization(value: str) -> dict[str, Any]:
    prefix = "Bearer "
    if not value.startswith(prefix):
        raise InterceptorError("Missing bearer token.")
    token = value[len(prefix) :].strip()
    parts = token.split(".")
    if len(parts) < 2:
        raise InterceptorError("Bearer token is not a JWT.")
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        claims = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise InterceptorError("Bearer token claims are unreadable.") from exc
    if not isinstance(claims, dict):
        raise InterceptorError("Bearer token claims must be an object.")
    return claims


def validate_claims(claims: dict[str, Any]) -> None:
    expected_sub = required_env("EXPECTED_DNSID_SUB")
    expected_issuer = required_env("EXPECTED_DNSID_ISS")
    expected_audience = required_env("EXPECTED_GATEWAY_AUDIENCE")

    if expected_sub and claims.get("sub") != expected_sub:
        raise InterceptorError("Unexpected DNSid subject.")
    if expected_issuer and claims.get("iss") != expected_issuer:
        raise InterceptorError("Unexpected DNSid issuer.")
    if expected_audience and not audience_matches(claims.get("aud"), expected_audience):
        raise InterceptorError("Unexpected DNSid audience.")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or exp <= time.time():
        raise InterceptorError("Bearer token is expired or missing exp.")
    if not claims.get("jti"):
        raise InterceptorError("Bearer token is missing jti.")


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise InterceptorError(f"Missing interceptor configuration {name}.")
    return value


def audience_matches(actual: Any, expected: str) -> bool:
    if isinstance(actual, str):
        return actual == expected
    if isinstance(actual, list):
        return expected in actual
    return False


def trusted_headers_from_claims(
    claims: dict[str, Any],
    gateway_request: dict[str, Any],
) -> dict[str, str]:
    sub = str(claims["sub"])
    scope = claims.get("scope", "")
    if isinstance(scope, list):
        scope = " ".join(str(value) for value in scope)
    audience = claims.get("aud", "")
    if isinstance(audience, list):
        audience = " ".join(str(value) for value in audience)
    headers = {
        "x-dnsid-sub": sub,
        "x-dnsid-iss": str(claims.get("iss", "")),
        "x-dnsid-aud": str(audience),
        "x-dnsid-jti": str(claims.get("jti", "")),
        "x-dnsid-domain": str(claims.get("dnsid") or claims.get("fqdn") or sub),
        "x-dnsid-scope": str(scope),
        "x-dnsid-auth-mode": "gateway-dnsid-lab",
        "x-dnsid-verified-at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "x-gateway-request-id": gateway_request_id(gateway_request),
        "x-correlation-id": uuid.uuid4().hex,
    }
    return {key: value for key, value in headers.items() if value}


def gateway_request_id(gateway_request: dict[str, Any]) -> str:
    for key in ("requestId", "request_id", "id"):
        value = gateway_request.get(key)
        if value:
            return str(value)
    context = gateway_request.get("requestContext") or {}
    if isinstance(context, dict) and context.get("requestId"):
        return str(context["requestId"])
    return ""


def should_filter_tools(gateway_request: dict[str, Any], body: Any) -> bool:
    if os.environ.get("FILTER_TOOLS_LIST", "").lower() != "true":
        return False
    if not isinstance(body, dict):
        return False
    request_body = gateway_request.get("body")
    return isinstance(request_body, dict) and request_body.get("method") == "tools/list"


def filter_tools_body(body: dict[str, Any]) -> dict[str, Any]:
    allowed_suffixes = {
        value.strip()
        for value in os.environ.get(
            "ALLOWED_TOOL_SUFFIXES", "generate_image,whoami_dnsid"
        ).split(",")
        if value.strip()
    }
    result = body.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        return body
    tools = [
        tool
        for tool in result["tools"]
        if isinstance(tool, dict) and tool_name_allowed(str(tool.get("name", "")), allowed_suffixes)
    ]
    return {**body, "result": {**result, "tools": tools}}


def tool_name_allowed(name: str, suffixes: set[str]) -> bool:
    return any(name == suffix or name.endswith(f"___{suffix}") for suffix in suffixes)


def jsonrpc_id(body: Any) -> Any:
    if isinstance(body, dict):
        return body.get("id")
    return None
