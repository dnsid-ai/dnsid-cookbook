from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from dnsid import (
    DNSidError,
    OIDCConfig,
    OIDCProfile,
    OIDCTokenExchangeOptions,
    identity_manager_from_dnsid,
)

from image_poc.config import DnsidSettings
from image_poc.validation import GenerateRequest


GATEWAY_AUTH_MODE = "gateway-dnsid"
GATEWAY_WARNING = (
    "Gateway DNSid mode: token minting and MCP calls happen in the local backend; "
    "the browser receives only a local preview URL."
)
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


class GatewayMcpError(Exception):
    def __init__(self, code: str, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class GatewayState:
    gateway_url: str
    gateway_audience: str
    artifact_bucket: str
    region: str
    gateway_target_name: str = "ImageApiTarget"


@dataclass(frozen=True)
class GatewayGenerateResult:
    image_bytes: bytes
    remote_artifact_id: str
    mime_type: str
    width: int
    height: int
    model_id: str
    model_region: str
    request_id: str
    correlation_id: str
    audit_id: str
    auth_mode: str
    dnsid_context: dict[str, Any]
    ignored_identity_args: list[str]
    options: dict[str, Any]


RpcCall = Callable[
    [str, dict[str, Any], str | None, str | None, dict[str, str] | None],
    dict[str, Any],
]


def load_gateway_state(path: Path) -> GatewayState:
    if not path.exists():
        raise GatewayMcpError(
            "gateway_unavailable",
            "Gateway state is unavailable; restore the Gateway state file or run the "
            "documented deploy step only when intentionally provisioning the cookbook.",
            status=503,
        )
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GatewayMcpError(
            "gateway_unavailable",
            "Gateway state is not valid JSON.",
            status=503,
        ) from exc
    gateway_url = required_state(state, "gateway_url")
    gateway_audience = required_state(state, "gateway_audience")
    validate_gateway_url(gateway_url, gateway_audience)
    return GatewayState(
        gateway_url=gateway_url,
        gateway_audience=gateway_audience,
        artifact_bucket=required_state(state, "artifact_bucket"),
        region=required_state(state, "region"),
        gateway_target_name=safe_str(state.get("gateway_target_name")) or "ImageApiTarget",
    )


def required_state(state: dict[str, Any], key: str) -> str:
    value = state.get(key)
    if not isinstance(value, str) or not value.strip():
        raise GatewayMcpError(
            "gateway_unavailable",
            f"Gateway state is missing {key}.",
            status=503,
        )
    return value.strip()


def validate_gateway_url(gateway_url: str, audience: str) -> None:
    parsed = urlparse(gateway_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise GatewayMcpError(
            "gateway_unavailable",
            "Gateway state URL must be an https URL.",
            status=503,
        )
    host = (parsed.hostname or "").lower()
    if not (
        host.endswith(".gateway.bedrock-agentcore.us-east-1.amazonaws.com")
        or host.endswith(".gateway.bedrock-agentcore.us-west-2.amazonaws.com")
    ):
        raise GatewayMcpError(
            "gateway_unavailable",
            "Gateway state URL host is not an AgentCore Gateway host.",
            status=503,
        )
    if audience != gateway_url:
        raise GatewayMcpError(
            "gateway_unavailable",
            "Gateway state URL does not match the discovered audience.",
            status=503,
        )


def mint_dnsid_token(dnsid: DnsidSettings, audience: str) -> str:
    try:
        manager = identity_manager_from_dnsid()
        if manager.local_domain.rstrip(".").casefold() != dnsid.agent_domain.rstrip(
            "."
        ).casefold():
            raise ValueError("DNSID_AGENT_DOMAIN does not match the loaded identity")
        token = OIDCProfile.from_identity_manager(
            manager,
            OIDCConfig(default_server_url=dnsid.server, timeout=30.0),
        ).mint_oidc_token(
            OIDCTokenExchangeOptions(audience=audience, scope=["openid", "dnsid"])
        ).access_token
    except (DNSidError, OSError, ValueError) as exc:
        raise GatewayMcpError(
            "dnsid_token_error",
            "DNSid token minting failed.",
        ) from exc
    if token.count(".") != 2:
        raise GatewayMcpError(
            "dnsid_token_error",
            "DNSid SDK did not return a JWT.",
        )
    return token


class GatewayMcpClient:
    def __init__(
        self,
        state: GatewayState,
        dnsid: DnsidSettings,
        expected_sub: str | None = None,
        token_minter: Callable[[str], str] | None = None,
        rpc_call: RpcCall | None = None,
        artifact_fetcher: Callable[[str], bytes] | None = None,
    ) -> None:
        self.state = state
        self.dnsid = dnsid
        self.expected_sub = expected_sub or dnsid.agent_domain
        self.token_minter = token_minter or (
            lambda audience: mint_dnsid_token(self.dnsid, audience)
        )
        self.rpc_call = rpc_call or rpc
        self.artifact_fetcher = artifact_fetcher or (
            lambda url: fetch_remote_artifact(url, self.state)
        )

    def generate_image(self, request: GenerateRequest) -> GatewayGenerateResult:
        token = self.token_minter(self.state.gateway_audience)
        session_id = self.initialize(token)
        tool_names = self.list_tools(token, session_id)
        generate_tool = find_tool(tool_names, "generate_image", self.state.gateway_target_name)
        whoami_tool = find_tool(tool_names, "whoami_dnsid", self.state.gateway_target_name)
        whoami = self.call_tool(token, session_id, whoami_tool, {})
        whoami_body = extract_tool_json(whoami.get("body"))
        assert_expected_sub(whoami_body, self.expected_sub, "whoami_dnsid")
        generated = self.call_tool(
            token,
            session_id,
            generate_tool,
            {
                "prompt": request.prompt,
                "style": request.style,
                "size": request.size,
            },
        )
        generated_body = extract_tool_json(generated.get("body"))
        return self.result_from_body(generated_body)

    def initialize(self, token: str) -> str:
        init = self.rpc_call(
            self.state.gateway_url,
            {
                "jsonrpc": "2.0",
                "id": "init",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "dnsid-image-poc-ui", "version": "0.1.0"},
                },
            },
            token,
            None,
            None,
        )
        assert_success(init, "initialize")
        session_id = header_value(init.get("headers", {}), "mcp-session-id")
        if not session_id:
            raise GatewayMcpError(
                "gateway_mcp_error",
                "Gateway did not return an MCP session ID.",
            )
        initialized = self.rpc_call(
            self.state.gateway_url,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            token,
            session_id,
            None,
        )
        if initialized.get("http_status", 500) >= 400:
            raise GatewayMcpError(
                "gateway_mcp_error",
                "Gateway rejected MCP initialized notification.",
            )
        return session_id

    def list_tools(self, token: str, session_id: str) -> list[str]:
        response = self.rpc_call(
            self.state.gateway_url,
            {"jsonrpc": "2.0", "id": "tools", "method": "tools/list"},
            token,
            session_id,
            None,
        )
        assert_success(response, "tools/list")
        tool_names = tool_names_from_response(response.get("body"))
        assert_only_allowed_tools(tool_names, self.state.gateway_target_name)
        return tool_names

    def call_tool(
        self,
        token: str,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        response = self.rpc_call(
            self.state.gateway_url,
            {
                "jsonrpc": "2.0",
                "id": tool_name,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            },
            token,
            session_id,
            None,
        )
        assert_success(response, f"tools/call {tool_name}")
        return response

    def result_from_body(self, body: dict[str, Any]) -> GatewayGenerateResult:
        if body.get("ok") is not True:
            raise GatewayMcpError(
                "gateway_contract_error",
                "Gateway generate_image response did not report ok=true.",
            )
        context = body.get("dnsid_context")
        if not isinstance(context, dict):
            raise GatewayMcpError(
                "gateway_contract_error",
                "Gateway generate_image response did not include DNSid context.",
            )
        assert_expected_sub(context, self.expected_sub, "generate_image")
        artifact_url = safe_str(body.get("artifact_url"))
        if not artifact_url:
            raise GatewayMcpError(
                "gateway_contract_error",
                "Gateway generate_image response did not include an artifact URL.",
            )
        image_bytes = self.artifact_fetcher(artifact_url)
        ignored = body.get("ignored_identity_args")
        return GatewayGenerateResult(
            image_bytes=image_bytes,
            remote_artifact_id=required_body(body, "artifact_id"),
            mime_type=required_body(body, "mime_type"),
            width=required_int(body, "width"),
            height=required_int(body, "height"),
            model_id=required_body(body, "model_id"),
            model_region=required_body(body, "model_region"),
            request_id=required_body(body, "request_id"),
            correlation_id=required_body(body, "correlation_id"),
            audit_id=required_body(body, "audit_id"),
            auth_mode=required_body(body, "auth_mode"),
            dnsid_context=context,
            ignored_identity_args=[str(value) for value in ignored]
            if isinstance(ignored, list)
            else [],
            options=body.get("options") if isinstance(body.get("options"), dict) else {},
        )


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
    except (urllib.error.URLError, OSError, UnicodeDecodeError) as exc:
        raise GatewayMcpError(
            "gateway_mcp_error",
            "Gateway MCP request failed.",
        ) from exc


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
    status = int(response.get("http_status", 500))
    if status >= 400:
        raise GatewayMcpError(
            "gateway_mcp_error",
            f"{label} failed with HTTP {status}.",
        )
    body = response.get("body", {})
    if isinstance(body, dict) and "error" in body:
        raise GatewayMcpError(
            "gateway_mcp_error",
            f"{label} returned a Gateway JSON-RPC error.",
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
        raise GatewayMcpError(
            "gateway_contract_error",
            f"Gateway tools/list did not expose exactly one {expected}.",
        )
    return matches[0]


def assert_only_allowed_tools(tool_names: list[str], target_name: str) -> None:
    allowed = {
        f"{target_name}___generate_image",
        f"{target_name}___whoami_dnsid",
    }
    unexpected = [name for name in tool_names if name not in allowed]
    if unexpected:
        raise GatewayMcpError(
            "gateway_contract_error",
            "Gateway tools/list exposed unexpected tools.",
        )


def extract_tool_json(body: Any) -> dict[str, Any]:
    result = body.get("result", {}) if isinstance(body, dict) else {}
    if "structuredContent" in result and isinstance(result["structuredContent"], dict):
        return result["structuredContent"]
    content = result.get("content")
    if isinstance(content, list) and content:
        first = content[0]
        if isinstance(first, dict) and isinstance(first.get("text"), str):
            try:
                parsed = json.loads(first["text"])
            except json.JSONDecodeError as exc:
                raise GatewayMcpError(
                    "gateway_contract_error",
                    "Tool response text was not JSON.",
                ) from exc
            if isinstance(parsed, dict):
                return parsed
    if isinstance(result, dict):
        return result
    raise GatewayMcpError(
        "gateway_contract_error",
        "Tool response did not include JSON content.",
    )


def assert_expected_sub(body: dict[str, Any], expected_sub: str, label: str) -> None:
    if body.get("sub") != expected_sub:
        raise GatewayMcpError(
            "gateway_contract_error",
            f"{label} did not return the expected DNSid subject.",
        )


def required_body(body: dict[str, Any], key: str) -> str:
    value = safe_str(body.get(key))
    if not value:
        raise GatewayMcpError(
            "gateway_contract_error",
            f"Gateway generate_image response missing {key}.",
        )
    return value


def required_int(body: dict[str, Any], key: str) -> int:
    value = body.get(key)
    if not isinstance(value, int):
        raise GatewayMcpError(
            "gateway_contract_error",
            f"Gateway generate_image response missing numeric {key}.",
        )
    return value


def safe_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirectHandler)


def open_no_redirect(request: urllib.request.Request, timeout: int):
    return _NO_REDIRECT_OPENER.open(request, timeout=timeout)


def fetch_remote_artifact(
    url: str,
    state: GatewayState,
    open_url: Callable[[urllib.request.Request, int], Any] = open_no_redirect,
    max_bytes: int = MAX_ARTIFACT_BYTES,
) -> bytes:
    validate_artifact_url(url, state)
    request = urllib.request.Request(url, headers={"Accept": "image/*"}, method="GET")
    try:
        with open_url(request, 60) as response:
            final_url = response.geturl() if hasattr(response, "geturl") else url
            validate_artifact_url(final_url, state)
            content_type = str(response.headers.get("Content-Type", "")).split(";", 1)[0]
            data = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise GatewayMcpError(
            "gateway_artifact_error",
            f"Gateway artifact fetch failed with HTTP {exc.code}.",
        ) from exc
    except (urllib.error.URLError, OSError) as exc:
        raise GatewayMcpError(
            "gateway_artifact_error",
            "Gateway artifact fetch failed.",
        ) from exc
    if len(data) > max_bytes:
        raise GatewayMcpError(
            "gateway_artifact_error",
            "Gateway artifact exceeded the local preview size limit.",
        )
    if not is_image_content(content_type, data):
        raise GatewayMcpError(
            "gateway_artifact_error",
            "Gateway artifact was not an image.",
        )
    return data


def validate_artifact_url(url: str, state: GatewayState) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise GatewayMcpError(
            "gateway_contract_error",
            "Gateway artifact URL was not an allowed HTTPS S3 URL.",
        )
    host = parsed.hostname.lower()
    bucket = state.artifact_bucket
    region = state.region
    virtual_hosts = {
        f"{bucket}.s3.amazonaws.com",
        f"{bucket}.s3.{region}.amazonaws.com",
        f"{bucket}.s3-{region}.amazonaws.com",
    }
    path_hosts = {
        "s3.amazonaws.com",
        f"s3.{region}.amazonaws.com",
        f"s3-{region}.amazonaws.com",
    }
    if host in virtual_hosts:
        return
    if host in path_hosts and parsed.path.startswith(f"/{bucket}/"):
        return
    raise GatewayMcpError(
        "gateway_contract_error",
        "Gateway artifact URL host was not allowed.",
    )


def is_image_content(content_type: str, data: bytes) -> bool:
    if content_type.lower().startswith("image/"):
        return True
    return data.startswith(b"\x89PNG\r\n\x1a\n")
