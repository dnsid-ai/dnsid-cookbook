#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any

import boto3

from image_poc.bedrock_image import png_dimensions
from image_poc.gateway_mcp import open_no_redirect, validate_gateway_url

from gateway_resources import (
    DNSID_CLI,
    DNSID_ISSUER,
    EXPECTED_DNSID_SUB,
    PROVISIONAL_AUDIENCE,
    REGION,
    load_state,
    protected_resource_metadata,
    require_dnsid_agent_domain,
)


def main() -> int:
    global EXPECTED_DNSID_SUB
    EXPECTED_DNSID_SUB = require_dnsid_agent_domain()
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt", default="A polished product render of a secure image gateway")
    args = parser.parse_args()
    state = load_state()
    gateway_url = require_state(state, "gateway_url")
    audience = require_state(state, "gateway_audience")
    target_name = require_state(state, "gateway_target_name")
    validate_gateway_url(gateway_url, audience)

    metadata = protected_resource_metadata(gateway_url)
    if metadata.get("resource") != audience:
        raise RuntimeError("Gateway protected-resource metadata does not match state audience.")
    validate_gateway_url(gateway_url, str(metadata["resource"]))

    missing = rpc(gateway_url, {"jsonrpc": "2.0", "id": "missing", "method": "tools/list"})
    if missing["http_status"] != 401:
        raise RuntimeError(f"Missing token returned HTTP {missing['http_status']}, expected 401.")

    wrong_token = mint_token(wrong_audience(audience))
    wrong = rpc(
        gateway_url,
        {"jsonrpc": "2.0", "id": "wrong-aud", "method": "tools/list"},
        token=wrong_token,
    )
    if wrong["http_status"] < 400:
        raise RuntimeError("Wrong-audience token was accepted.")

    token = mint_token(audience)
    decoded_claims = decode_claims(token)
    claims = safe_claims(decoded_claims)
    unsigned = rpc(
        gateway_url,
        {
            "jsonrpc": "2.0",
            "id": "unsigned-token",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "dnsid-image-poc-verify", "version": "0.1.0"},
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
                "clientInfo": {"name": "dnsid-image-poc-verify", "version": "0.1.0"},
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
    no_session = rpc(
        gateway_url,
        {"jsonrpc": "2.0", "id": "no-session", "method": "tools/list"},
        token=token,
    )
    if no_session["http_status"] < 400:
        raise RuntimeError("Session-enabled Gateway accepted tools/list without a session ID.")

    tools_response = rpc(
        gateway_url,
        {"jsonrpc": "2.0", "id": "tools", "method": "tools/list"},
        token=token,
        session_id=session_id,
    )
    assert_success(tools_response, "tools/list")
    tool_names = tool_names_from_response(tools_response["body"])
    assert_only_allowed_tools(tool_names, target_name)
    generate_tool = find_tool(tool_names, "generate_image", target_name)
    whoami_tool = find_tool(tool_names, "whoami_dnsid", target_name)

    whoami = call_tool(
        gateway_url,
        token,
        session_id,
        whoami_tool,
        {},
        extra_headers={"x-dnsid-sub": "spoofed.example"},
    )
    whoami_body = extract_tool_json(whoami["body"])
    if whoami_body.get("sub") != EXPECTED_DNSID_SUB:
        raise RuntimeError("whoami_dnsid did not return the trusted lab DNSid subject.")

    generated = call_tool(
        gateway_url,
        token,
        session_id,
        generate_tool,
        {
            "prompt": args.prompt,
            "style": "product",
            "size": "1024x1024",
            "client_context": {"identity": {"sub": "spoofed.example"}},
        },
    )
    generated_body = extract_tool_json(generated["body"])
    context = generated_body.get("dnsid_context") or {}
    if context.get("sub") != EXPECTED_DNSID_SUB:
        raise RuntimeError("generate_image did not preserve trusted DNSid subject.")
    if "client_context.identity.sub" not in generated_body.get("ignored_identity_args", []):
        raise RuntimeError("generate_image did not report ignored identity-like args.")

    artifact_bytes = fetch_artifact(generated_body.get("artifact_url", ""))
    width, height = png_dimensions(artifact_bytes)
    assert_generated_contract(generated_body, width, height)
    audit_record = fetch_audit_record(generated_body.get("audit_s3_uri", ""))
    assert_audit_contract(audit_record, generated_body, decoded_claims)

    filtered_tool = sibling_tool_name(generate_tool, "generate_image", "debug_denied")
    filtered = call_tool(
        gateway_url,
        token,
        session_id,
        filtered_tool,
        {},
        allow_error=True,
    )
    assert_json_rpc_error(filtered.get("body"))

    output = {
        "status": "ok",
        "gateway_url": gateway_url,
        "gateway_audience": audience,
        "token_claims": claims,
        "missing_token_status": missing["http_status"],
        "wrong_audience_status": wrong["http_status"],
        "unsigned_token_status": unsigned["http_status"],
        "missing_session_status": no_session["http_status"],
        "session_id_present": bool(session_id),
        "tools": tool_names,
        "discovery_filter_mode": state.get("discovery_filter_mode", "unknown"),
        "whoami_sub": whoami_body.get("sub"),
        "artifact": {
            "artifact_id": generated_body.get("artifact_id"),
            "artifact_s3_uri": generated_body.get("artifact_s3_uri"),
            "audit_s3_uri": generated_body.get("audit_s3_uri"),
            "audit_verified": True,
            "width": width,
            "height": height,
            "mime_type": generated_body.get("mime_type"),
            "request_id": generated_body.get("request_id"),
            "audit_id": generated_body.get("audit_id"),
        },
        "filtered_tool_status": filtered["http_status"],
        "filtered_tool_error_present": True,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


def require_state(state: dict[str, Any], key: str) -> str:
    value = state.get(key)
    if not value:
        raise RuntimeError(f"Missing {key} in Gateway state. Run make deploy-gateway.")
    return str(value)


def mint_token(audience: str) -> str:
    result = subprocess.run(
        [
            DNSID_CLI,
            "--server",
            DNSID_ISSUER,
            "token",
            "--domain",
            EXPECTED_DNSID_SUB,
            "--audience",
            audience,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    token = result.stdout.strip()
    if not token:
        raise RuntimeError("DNSid CLI returned an empty token.")
    return token


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
        "token_type": claims.get("token_type"),
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
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(
        gateway_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with open_no_redirect(request, 180) as response:
            body = parse_response_body(response.read().decode("utf-8", errors="replace"))
            return {
                "http_status": response.status,
                "headers": dict(response.headers.items()),
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        return {
            "http_status": exc.code,
            "headers": dict(exc.headers.items()),
            "body": parse_response_body(body_text),
        }
    except urllib.error.URLError as exc:
        raise RuntimeError("Gateway MCP request failed.") from exc


def call_tool(
    gateway_url: str,
    token: str,
    session_id: str | None,
    tool_name: str,
    arguments: dict[str, Any],
    extra_headers: dict[str, str] | None = None,
    allow_error: bool = False,
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
        extra_headers=extra_headers,
    )
    if not allow_error:
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


def assert_only_allowed_tools(tool_names: list[str], target_name: str) -> None:
    allowed = {
        f"{target_name}___generate_image",
        f"{target_name}___whoami_dnsid",
    }
    unexpected = [name for name in tool_names if name not in allowed]
    if unexpected:
        raise RuntimeError(f"Gateway tools/list exposed unexpected tools: {unexpected}")


def sibling_tool_name(name: str, old_suffix: str, new_suffix: str) -> str:
    if name.endswith(old_suffix):
        return name[: -len(old_suffix)] + new_suffix
    return new_suffix


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


def assert_generated_contract(body: dict[str, Any], png_width: int, png_height: int) -> None:
    if body.get("ok") is not True:
        raise RuntimeError("generate_image response did not report ok=true.")
    if body.get("mime_type") != "image/png":
        raise RuntimeError(f"generate_image returned unexpected MIME type: {body.get('mime_type')}")
    for field in (
        "artifact_id",
        "artifact_s3_uri",
        "artifact_url",
        "audit_s3_uri",
        "request_id",
        "audit_id",
        "model_id",
        "model_region",
        "correlation_id",
    ):
        if not body.get(field):
            raise RuntimeError(f"generate_image response missing {field}.")
    if body.get("width") != png_width or body.get("height") != png_height:
        raise RuntimeError("generate_image metadata dimensions did not match fetched PNG.")
    if (png_width, png_height) != (1024, 1024):
        raise RuntimeError(f"generate_image returned unexpected PNG dimensions: {png_width}x{png_height}.")


def assert_audit_contract(
    audit: dict[str, Any],
    generated: dict[str, Any],
    claims: dict[str, Any],
) -> None:
    expected = {
        "audit_id": generated.get("audit_id"),
        "tool_name": "generate_image",
        "result_status": "success",
        "artifact_id": generated.get("artifact_id"),
        "artifact_s3_uri": generated.get("artifact_s3_uri"),
        "model_id": generated.get("model_id"),
        "model_region": generated.get("model_region"),
        "request_id": generated.get("request_id"),
        "correlation_id": generated.get("correlation_id"),
        "token_jti": claims.get("jti"),
    }
    for field, value in expected.items():
        if audit.get(field) != value:
            raise RuntimeError(f"S3 audit record {field} did not match generate_image response.")
    trusted_identity = audit.get("trusted_identity")
    if not isinstance(trusted_identity, dict) or trusted_identity.get("sub") != EXPECTED_DNSID_SUB:
        raise RuntimeError("S3 audit record did not include the trusted DNSid subject.")
    if not str(audit.get("prompt_hash", "")).startswith("sha256:"):
        raise RuntimeError("S3 audit record did not include a prompt hash.")
    if "recorded_at" not in audit:
        raise RuntimeError("S3 audit record did not include recorded_at.")


def assert_json_rpc_error(body: Any) -> None:
    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
        raise RuntimeError("Known-filtered debug_denied tool call did not return a JSON-RPC error envelope.")
    error = body.get("error")
    if not isinstance(error, dict) or not isinstance(error.get("message"), str):
        raise RuntimeError("Known-filtered debug_denied tool call returned a malformed JSON-RPC error.")
    if "code" not in error:
        raise RuntimeError("Known-filtered debug_denied tool call returned a JSON-RPC error without a code.")


def fetch_artifact(url: str) -> bytes:
    if not url:
        raise RuntimeError("Tool response did not include an artifact URL.")
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Artifact fetch failed with HTTP {exc.code}.") from exc


def fetch_audit_record(s3_uri: str) -> dict[str, Any]:
    if not s3_uri:
        raise RuntimeError("Tool response did not include an audit S3 URI.")
    bucket, key = parse_s3_uri(s3_uri)
    response = boto3.client("s3", region_name=REGION).get_object(Bucket=bucket, Key=key)
    record = json.loads(response["Body"].read().decode("utf-8"))
    if not isinstance(record, dict):
        raise RuntimeError("S3 audit record was not a JSON object.")
    return record


def parse_s3_uri(s3_uri: str) -> tuple[str, str]:
    prefix = "s3://"
    if not s3_uri.startswith(prefix):
        raise RuntimeError(f"Audit URI is not an S3 URI: {s3_uri}")
    bucket_and_key = s3_uri[len(prefix) :]
    bucket, separator, key = bucket_and_key.partition("/")
    if not bucket or not separator or not key:
        raise RuntimeError(f"Audit URI is missing bucket or key: {s3_uri}")
    return bucket, key


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"verify-gateway failed: {exc}", file=sys.stderr)
        raise
