#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import sys
import urllib.error
import urllib.request
from typing import Any

from oidc_image.bedrock_image import png_dimensions
from oidc_image.config import load_dnsid_settings
from oidc_image.identity import mint_dnsid_token

from gateway_resources import (
    PROVISIONAL_AUDIENCE,
    TARGET_NAME,
    load_state,
    protected_resource_metadata,
)


def main() -> int:
    state = load_state()
    gateway_url = require_state(state, "gateway_url")
    audience = require_state(state, "gateway_audience")
    if protected_resource_metadata(gateway_url).get("resource") != audience:
        raise RuntimeError("Gateway protected-resource metadata does not match state audience.")

    missing = rpc(gateway_url, {"jsonrpc": "2.0", "id": "missing", "method": "tools/list"})
    if missing["http_status"] != 401:
        raise RuntimeError(f"Missing token returned HTTP {missing['http_status']}, expected 401.")

    dnsid = load_dnsid_settings(require_https=True)
    wrong_token = mint_dnsid_token(dnsid, wrong_audience(audience))
    wrong = rpc(
        gateway_url,
        {"jsonrpc": "2.0", "id": "wrong-aud", "method": "tools/list"},
        token=wrong_token,
    )
    assert_auth_denied(wrong, "wrong-audience token")

    token = mint_dnsid_token(dnsid, audience)
    decoded_claims = decode_claims(token)
    unsigned = rpc(
        gateway_url,
        {
            "jsonrpc": "2.0",
            "id": "unsigned-token",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "dnsid-oidc-image-verify", "version": "0.1.0"},
            },
        },
        token=unsigned_jwt_from_claims(decoded_claims),
    )
    assert_auth_denied(unsigned, "unsigned JWT")

    init = rpc(
        gateway_url,
        {
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "dnsid-oidc-image-verify", "version": "0.1.0"},
            },
        },
        token=token,
    )
    assert_success(init, "initialize")
    session_id = header_value(init["headers"], "mcp-session-id")
    if not session_id:
        raise RuntimeError("Gateway did not return an MCP session ID.")

    initialized = rpc(
        gateway_url,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        token=token,
        session_id=session_id,
    )
    if initialized["http_status"] >= 400:
        raise RuntimeError(
            f"notifications/initialized failed with HTTP {initialized['http_status']}."
        )

    tools_response = rpc(
        gateway_url,
        {"jsonrpc": "2.0", "id": "tools", "method": "tools/list"},
        token=token,
        session_id=session_id,
    )
    assert_success(tools_response, "tools/list")
    tool_names = tool_names_from_response(tools_response["body"])
    generate_tool = find_tool(tool_names, "generate_image", TARGET_NAME)

    generated = call_tool(
        gateway_url,
        token,
        session_id,
        generate_tool,
        {
            "prompt": "A polished product render of a secure OIDC image gateway",
            "style": "product",
            "size": "1024x1024",
        },
    )
    body = extract_tool_json(generated["body"])
    image_bytes = base64.b64decode(require_body(body, "image_base64"), validate=True)
    width, height = png_dimensions(image_bytes)
    assert_generated_contract(body, width, height)

    print(
        json.dumps(
            {
                "status": "ok",
                "gateway_url": gateway_url,
                "gateway_audience": audience,
                "token_claims": safe_claims(decoded_claims),
                "missing_token_status": missing["http_status"],
                "wrong_audience_status": wrong["http_status"],
                "unsigned_token_status": unsigned["http_status"],
                "session_id_present": bool(session_id),
                "tools": tool_names,
                "artifact": {
                    "image_sha256": body.get("image_sha256"),
                    "mime_type": body.get("mime_type"),
                    "width": width,
                    "height": height,
                    "model_id": body.get("model_id"),
                    "model_region": body.get("model_region"),
                    "request_id": body.get("request_id"),
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def require_state(state: dict[str, Any], key: str) -> str:
    value = state.get(key)
    if not value:
        raise RuntimeError(f"Missing {key} in Gateway state. Run make deploy-gateway.")
    return str(value)


def decode_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))


def safe_claims(claims: dict[str, Any]) -> dict[str, Any]:
    return {
        "iss": claims.get("iss"),
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
        "jti_present": bool(claims.get("jti")),
        "scope": claims.get("scope"),
    }


def unsigned_jwt_from_claims(claims: dict[str, Any]) -> str:
    return ".".join(
        (
            base64url_json({"alg": "none", "typ": "JWT"}),
            base64url_json(claims),
            "",
        )
    )


def base64url_json(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def wrong_audience(audience: str) -> str:
    if audience != PROVISIONAL_AUDIENCE:
        return PROVISIONAL_AUDIENCE
    return f"{audience}:wrong"


def rpc(
    gateway_url: str,
    payload: dict[str, Any],
    token: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    request = urllib.request.Request(
        gateway_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return {
                "http_status": response.status,
                "headers": dict(response.headers.items()),
                "body": parse_response_body(response.read().decode("utf-8", errors="replace")),
            }
    except urllib.error.HTTPError as exc:
        return {
            "http_status": exc.code,
            "headers": dict(exc.headers.items()),
            "body": parse_response_body(exc.read().decode("utf-8", errors="replace")),
        }


def call_tool(
    gateway_url: str,
    token: str,
    session_id: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    response = rpc(
        gateway_url,
        {
            "jsonrpc": "2.0",
            "id": tool_name,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        },
        token=token,
        session_id=session_id,
    )
    assert_success(response, f"tools/call {tool_name}")
    return response


def parse_response_body(body_text: str) -> Any:
    text = body_text.strip()
    if not text:
        return {}
    try:
        if text.startswith("event:") or text.startswith("data:"):
            for line in text.splitlines():
                if line.startswith("data:"):
                    return json.loads(line.removeprefix("data:").strip())
        return json.loads(text)
    except json.JSONDecodeError:
        return {"text": text[:200]}


def assert_success(response: dict[str, Any], label: str) -> None:
    if response["http_status"] >= 400:
        raise RuntimeError(f"{label} failed with HTTP {response['http_status']}.")
    body = response.get("body", {})
    if isinstance(body, dict) and "error" in body:
        raise RuntimeError(f"{label} returned JSON-RPC error: {body['error']}")


def assert_auth_denied(response: dict[str, Any], label: str) -> None:
    if response["http_status"] not in {401, 403}:
        raise RuntimeError(
            f"{label} returned HTTP {response['http_status']}, expected Gateway auth denial."
        )


def header_value(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def tool_names_from_response(body: Any) -> list[str]:
    result = body.get("result", {}) if isinstance(body, dict) else {}
    tools = result.get("tools", [])
    return [tool.get("name", "") for tool in tools if isinstance(tool, dict)]


def find_tool(tool_names: list[str], suffix: str, target_name: str) -> str:
    expected = f"{target_name}___{suffix}"
    matches = [name for name in tool_names if name == expected]
    if len(matches) != 1:
        raise RuntimeError(f"Could not find exactly one MCP tool named {expected}: {tool_names}")
    return matches[0]


def extract_tool_json(body: Any) -> dict[str, Any]:
    result = body.get("result", {}) if isinstance(body, dict) else {}
    if "structuredContent" in result and isinstance(result["structuredContent"], dict):
        return result["structuredContent"]
    content = result.get("content")
    if isinstance(content, list) and content:
        first = content[0]
        if isinstance(first, dict) and isinstance(first.get("text"), str):
            return json.loads(first["text"])
    if isinstance(result, dict):
        return result
    raise RuntimeError("Tool response did not include JSON content.")


def require_body(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"generate_image response missing {key}.")
    return value


def assert_generated_contract(body: dict[str, Any], png_width: int, png_height: int) -> None:
    if body.get("ok") is not True:
        raise RuntimeError("generate_image response did not report ok=true.")
    if body.get("mime_type") != "image/png":
        raise RuntimeError(f"generate_image returned unexpected MIME type: {body.get('mime_type')}")
    for field in ("image_sha256", "request_id", "model_id", "model_region"):
        if not body.get(field):
            raise RuntimeError(f"generate_image response missing {field}.")
    if body.get("width") != png_width or body.get("height") != png_height:
        raise RuntimeError("generate_image metadata dimensions did not match PNG bytes.")
    if (png_width, png_height) != (1024, 1024):
        raise RuntimeError(f"generate_image returned unexpected PNG dimensions: {png_width}x{png_height}.")
    forbidden_identity_keys = {"dnsid_context", "trusted_identity", "x-dnsid-sub"}
    present = sorted(key for key in forbidden_identity_keys if key in body)
    if present:
        raise RuntimeError(f"generate_image response claimed target-side identity context: {present}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"verify-gateway failed: {exc}", file=sys.stderr)
        raise
