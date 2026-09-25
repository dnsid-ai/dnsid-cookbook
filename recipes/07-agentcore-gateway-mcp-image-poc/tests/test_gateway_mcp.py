import io
import urllib.error
import urllib.request

import pytest

from image_poc import gateway_mcp
from image_poc.config import DnsidSettings
from image_poc.gateway_mcp import (
    GatewayMcpClient,
    GatewayMcpError,
    GatewayState,
    fetch_remote_artifact,
    load_gateway_state,
    mint_dnsid_token,
)
from image_poc.validation import validate_generate_payload


def png_bytes():
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + (1024).to_bytes(
        4, "big"
    ) + (1024).to_bytes(4, "big") + b"\x08\x02\x00\x00\x00"


def state():
    gateway_url = "https://test.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"
    return GatewayState(
        gateway_url=gateway_url,
        gateway_audience=gateway_url,
        artifact_bucket="bucket",
        region="us-east-1",
    )


def dnsid():
    return DnsidSettings(
        cli="/opt/dnsid/bin/dnsid",
        server="https://dnsid.example.test",
        agent_domain="agent.example.test",
    )


def test_load_gateway_state_requires_existing_complete_state(tmp_path):
    missing = tmp_path / "state.json"
    with pytest.raises(GatewayMcpError, match="Gateway state is unavailable"):
        load_gateway_state(missing)

    path = tmp_path / "state.json"
    path.write_text('{"gateway_url": "https://gateway.example/mcp"}')
    with pytest.raises(GatewayMcpError, match="gateway_audience"):
        load_gateway_state(path)


def test_load_gateway_state_rejects_non_agentcore_urls(tmp_path):
    def write_state(gateway_url, audience=None):
        path = tmp_path / "state.json"
        path.write_text(
            (
                '{"gateway_url": "%s", "gateway_audience": "%s", '
                '"artifact_bucket": "bucket", "region": "us-east-1"}'
            )
            % (gateway_url, audience or gateway_url)
        )
        return path

    with pytest.raises(GatewayMcpError, match="https"):
        load_gateway_state(write_state("http://test.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"))

    with pytest.raises(GatewayMcpError, match="AgentCore Gateway host"):
        load_gateway_state(write_state("https://attacker.example/mcp"))

    with pytest.raises(GatewayMcpError, match="does not match"):
        load_gateway_state(
            write_state(
                "https://test.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp",
                "https://other.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp",
            )
        )


def test_mint_dnsid_token_uses_sdk_and_loaded_identity(monkeypatch):
    class Manager:
        local_domain = "agent.example.test"

    class Profile:
        def mint_oidc_token(self, options):
            assert options.audience == "audience"
            assert options.scope == ["openid", "dnsid"]
            return type("Response", (), {"access_token": "header.payload.sig"})()

    monkeypatch.setattr(gateway_mcp, "identity_manager_from_dnsid", Manager)
    monkeypatch.setattr(
        gateway_mcp.OIDCProfile,
        "from_identity_manager",
        lambda manager, config: Profile(),
    )

    assert mint_dnsid_token(dnsid(), "audience") == "header.payload.sig"


def test_mint_dnsid_token_rejects_the_wrong_loaded_identity(monkeypatch):
    class Manager:
        local_domain = "other.example.test"

    monkeypatch.setattr(gateway_mcp, "identity_manager_from_dnsid", Manager)

    with pytest.raises(GatewayMcpError, match="token minting failed"):
        mint_dnsid_token(dnsid(), "audience")


def test_gateway_client_calls_whoami_before_generate_and_sanitizes_flow():
    rpc_calls = []
    artifact_urls = []

    def fake_rpc(gateway_url, payload, token, session_id, extra_headers):
        rpc_calls.append((payload, token, session_id))
        method = payload["method"]
        if method == "initialize":
            return {"http_status": 200, "headers": {"Mcp-Session-Id": "session"}, "body": {}}
        if method == "notifications/initialized":
            return {"http_status": 202, "headers": {}, "body": {}}
        if method == "tools/list":
            return {
                "http_status": 200,
                "headers": {},
                "body": {
                    "result": {
                        "tools": [
                            {"name": "ImageApiTarget___generate_image"},
                            {"name": "ImageApiTarget___whoami_dnsid"},
                        ]
                    }
                },
            }
        if method == "tools/call":
            name = payload["params"]["name"]
            if name.endswith("whoami_dnsid"):
                return {
                    "http_status": 200,
                    "headers": {},
                    "body": {
                        "result": {
                            "structuredContent": {
                                "sub": "agent.example.test",
                                "iss": "https://dnsid.example.test",
                            }
                        }
                    },
                }
            assert payload["params"]["arguments"] == {
                "prompt": "hello",
                "style": "product",
                "size": "1024x1024",
            }
            return {
                "http_status": 200,
                "headers": {},
                "body": {
                    "result": {
                        "structuredContent": {
                            "ok": True,
                            "artifact_url": "https://bucket.s3.amazonaws.com/key.png?X-Amz-Signature=secret",
                            "artifact_s3_uri": "s3://bucket/key.png",
                            "audit_s3_uri": "s3://bucket/audit.json",
                            "artifact_id": "remote-artifact",
                            "mime_type": "image/png",
                            "width": 1024,
                            "height": 1024,
                            "model_id": "model",
                            "model_region": "us-west-2",
                            "request_id": "request",
                            "correlation_id": "remote-correlation",
                            "audit_id": "audit",
                            "auth_mode": "gateway-dnsid-lab",
                            "dnsid_context": {
                                "sub": "agent.example.test",
                                "iss": "https://dnsid.example.test",
                            },
                            "ignored_identity_args": [],
                            "options": {"style": "product", "size": "1024x1024"},
                        }
                    }
                },
            }
        raise AssertionError(f"unexpected method {method}")

    def fake_fetch(url):
        artifact_urls.append(url)
        return png_bytes()

    client = GatewayMcpClient(
        state(),
        dnsid(),
        token_minter=lambda audience: "header.payload.sig",
        rpc_call=fake_rpc,
        artifact_fetcher=fake_fetch,
    )
    result = client.generate_image(validate_generate_payload({"prompt": "hello"}))

    assert result.remote_artifact_id == "remote-artifact"
    assert result.image_bytes.startswith(b"\x89PNG")
    assert artifact_urls == ["https://bucket.s3.amazonaws.com/key.png?X-Amz-Signature=secret"]
    tool_call_names = [
        call[0]["params"]["name"]
        for call in rpc_calls
        if call[0]["method"] == "tools/call"
    ]
    assert tool_call_names == [
        "ImageApiTarget___whoami_dnsid",
        "ImageApiTarget___generate_image",
    ]


def test_gateway_client_rejects_unexpected_whoami_subject():
    def fake_rpc(gateway_url, payload, token, session_id, extra_headers):
        method = payload["method"]
        if method == "initialize":
            return {"http_status": 200, "headers": {"mcp-session-id": "session"}, "body": {}}
        if method == "notifications/initialized":
            return {"http_status": 202, "headers": {}, "body": {}}
        if method == "tools/list":
            return {
                "http_status": 200,
                "headers": {},
                "body": {
                    "result": {
                        "tools": [
                            {"name": "ImageApiTarget___generate_image"},
                            {"name": "ImageApiTarget___whoami_dnsid"},
                        ]
                    }
                },
            }
        return {
            "http_status": 200,
            "headers": {},
            "body": {"result": {"structuredContent": {"sub": "other.example.test"}}},
        }

    client = GatewayMcpClient(
        state(),
        dnsid(),
        token_minter=lambda audience: "header.payload.sig",
        rpc_call=fake_rpc,
        artifact_fetcher=lambda url: png_bytes(),
    )

    with pytest.raises(GatewayMcpError, match="expected DNSid subject"):
        client.generate_image(validate_generate_payload({"prompt": "hello"}))


def test_gateway_client_rejects_duplicate_tool_suffixes():
    def fake_rpc(gateway_url, payload, token, session_id, extra_headers):
        method = payload["method"]
        if method == "initialize":
            return {"http_status": 200, "headers": {"mcp-session-id": "session"}, "body": {}}
        if method == "notifications/initialized":
            return {"http_status": 202, "headers": {}, "body": {}}
        return {
            "http_status": 200,
            "headers": {},
            "body": {
                "result": {
                    "tools": [
                        {"name": "ImageApiTarget___generate_image"},
                        {"name": "OtherTarget___generate_image"},
                        {"name": "ImageApiTarget___whoami_dnsid"},
                    ]
                }
            },
        }

    client = GatewayMcpClient(
        state(),
        dnsid(),
        token_minter=lambda audience: "header.payload.sig",
        rpc_call=fake_rpc,
        artifact_fetcher=lambda url: png_bytes(),
    )

    with pytest.raises(GatewayMcpError, match="unexpected tools"):
        client.generate_image(validate_generate_payload({"prompt": "hello"}))


def test_gateway_rpc_does_not_follow_redirects(monkeypatch):
    calls = []

    def fake_open(request: urllib.request.Request, timeout: int):
        calls.append(request.full_url)
        raise urllib.error.HTTPError(
            request.full_url,
            302,
            "Found",
            {},
            io.BytesIO(b""),
        )

    monkeypatch.setattr(gateway_mcp, "open_no_redirect", fake_open)

    response = gateway_mcp.rpc(
        "https://test.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp",
        {"jsonrpc": "2.0", "id": "x", "method": "tools/list"},
        token="header.payload.sig",
    )

    assert response["http_status"] == 302
    assert calls == ["https://test.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"]


class FakeResponse:
    def __init__(self, url, data, content_type="image/png"):
        self.url = url
        self.data = data
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, size=-1):
        return self.data[:size]


def test_fetch_remote_artifact_allows_expected_s3_host():
    requests = []

    def open_url(request: urllib.request.Request, timeout: int):
        requests.append((request.full_url, timeout))
        return FakeResponse(request.full_url, png_bytes())

    data = fetch_remote_artifact(
        "https://bucket.s3.amazonaws.com/phase3/images/image.png?X-Amz-Signature=secret",
        state(),
        open_url=open_url,
    )

    assert data.startswith(b"\x89PNG")
    assert requests[0][1] == 60


def test_fetch_remote_artifact_rejects_unexpected_host():
    with pytest.raises(GatewayMcpError, match="host was not allowed"):
        fetch_remote_artifact(
            "https://attacker.example/image.png",
            state(),
            open_url=lambda request, timeout: FakeResponse(request.full_url, png_bytes()),
        )
