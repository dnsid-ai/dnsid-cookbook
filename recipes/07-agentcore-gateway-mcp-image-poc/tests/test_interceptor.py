import base64
import json

from image_poc.interceptor import lambda_handler


def jwt(claims):
    def enc(value):
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{enc({'alg': 'none'})}.{enc(claims)}.signature"


def request_event(token_claims, headers=None):
    request_headers = {
        "Authorization": f"Bearer {jwt(token_claims)}",
        "x-dnsid-sub": "spoofed.example",
    }
    if headers:
        request_headers.update(headers)
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayResponse": None,
            "gatewayRequest": {
                "headers": request_headers,
                "body": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            }
        },
    }


def test_request_interceptor_injects_trusted_headers(monkeypatch):
    monkeypatch.setenv("EXPECTED_DNSID_SUB", "agent.example.com")
    monkeypatch.setenv("EXPECTED_DNSID_ISS", "https://api.dnsid.dev")
    monkeypatch.setenv("EXPECTED_GATEWAY_AUDIENCE", "https://gateway.example/mcp")
    token_claims = {
        "sub": "agent.example.com",
        "iss": "https://api.dnsid.dev",
        "aud": "https://gateway.example/mcp",
        "jti": "token-id",
        "exp": 4102444800,
    }

    response = lambda_handler(request_event(token_claims), None)

    transformed = response["mcp"]["transformedGatewayRequest"]
    assert transformed["body"]["method"] == "tools/list"
    assert transformed["headers"]["x-dnsid-sub"] == "agent.example.com"
    assert transformed["headers"]["x-dnsid-jti"] == "token-id"
    assert "Authorization" not in transformed["headers"]


def test_request_interceptor_denies_wrong_subject(monkeypatch):
    monkeypatch.setenv("EXPECTED_DNSID_SUB", "agent.example.com")
    monkeypatch.setenv("EXPECTED_DNSID_ISS", "https://api.dnsid.dev")
    monkeypatch.setenv("EXPECTED_GATEWAY_AUDIENCE", "https://gateway.example/mcp")
    token_claims = {
        "sub": "attacker.example",
        "iss": "https://api.dnsid.dev",
        "aud": "https://gateway.example/mcp",
        "jti": "token-id",
        "exp": 4102444800,
    }

    response = lambda_handler(request_event(token_claims), None)

    denied = response["mcp"]["transformedGatewayResponse"]
    assert denied["statusCode"] == 403
    assert denied["body"]["error"]["code"] == "trusted_context_error"


def test_request_interceptor_denies_missing_required_configuration(monkeypatch):
    monkeypatch.delenv("EXPECTED_DNSID_SUB", raising=False)
    monkeypatch.setenv("EXPECTED_DNSID_ISS", "https://api.dnsid.dev")
    monkeypatch.setenv("EXPECTED_GATEWAY_AUDIENCE", "https://gateway.example/mcp")
    token_claims = {
        "sub": "agent.example.com",
        "iss": "https://api.dnsid.dev",
        "aud": "https://gateway.example/mcp",
        "jti": "token-id",
        "exp": 4102444800,
    }

    response = lambda_handler(request_event(token_claims), None)

    denied = response["mcp"]["transformedGatewayResponse"]
    assert denied["statusCode"] == 403
    assert "Missing interceptor configuration" in denied["body"]["error"]["message"]


def test_response_interceptor_filters_tools(monkeypatch):
    monkeypatch.setenv("FILTER_TOOLS_LIST", "true")
    event = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {
                "body": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            },
            "gatewayResponse": {
                "statusCode": 200,
                "body": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "tools": [
                            {"name": "ImageApiTarget___generate_image"},
                            {"name": "ImageApiTarget___debug_denied"},
                        ]
                    },
                },
            },
        },
    }

    response = lambda_handler(event, None)

    tools = response["mcp"]["transformedGatewayResponse"]["body"]["result"]["tools"]
    assert tools == [{"name": "ImageApiTarget___generate_image"}]


def test_response_interceptor_omits_passthrough_headers(monkeypatch):
    monkeypatch.setenv("FILTER_TOOLS_LIST", "false")
    event = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {"body": {"jsonrpc": "2.0", "id": "init"}},
            "gatewayResponse": {
                "statusCode": 200,
                "headers": {"Mcp-Session-Id": "session-id"},
                "body": {"jsonrpc": "2.0", "id": "init", "result": {}},
            },
        },
    }

    transformed = lambda_handler(event, None)["mcp"]["transformedGatewayResponse"]

    assert transformed == {
        "statusCode": 200,
        "body": {"jsonrpc": "2.0", "id": "init", "result": {}},
    }
