import pytest

from image_poc.trusted_context import (
    TrustedContextError,
    find_identity_like_keys,
    parse_trusted_context,
)


def trusted_headers(**overrides):
    headers = {
        "x-dnsid-sub": "agent.example.com",
        "x-dnsid-iss": "https://api.dnsid.dev",
        "x-dnsid-aud": "https://gateway.example/mcp",
        "x-dnsid-jti": "token-id",
        "x-dnsid-domain": "agent.example.com",
        "x-dnsid-auth-mode": "gateway-dnsid-lab",
        "x-dnsid-verified-at": "2026-05-28T02:00:00Z",
        "x-gateway-request-id": "gateway-request",
        "x-correlation-id": "correlation-id",
    }
    headers.update(overrides)
    return headers


def test_parse_trusted_context_accepts_case_insensitive_headers():
    context = parse_trusted_context(
        {key.title(): value for key, value in trusted_headers().items()},
        expected_sub="agent.example.com",
    )

    assert context.sub == "agent.example.com"
    assert context.issuer == "https://api.dnsid.dev"
    assert context.audience == "https://gateway.example/mcp"
    assert context.jti == "token-id"
    assert context.gateway_request_id == "gateway-request"
    assert context.to_public_dict()["accountable_entity"] == "agent.example.com"


def test_parse_trusted_context_rejects_missing_required_header():
    headers = trusted_headers()
    headers.pop("x-dnsid-jti")

    with pytest.raises(TrustedContextError, match="x-dnsid-jti"):
        parse_trusted_context(headers)


def test_parse_trusted_context_rejects_wrong_subject():
    with pytest.raises(TrustedContextError, match="Unexpected DNSid subject"):
        parse_trusted_context(trusted_headers(), expected_sub="other.example")


def test_parse_trusted_context_rejects_control_characters():
    headers = trusted_headers(**{"x-dnsid-domain": "bad\nvalue"})

    with pytest.raises(TrustedContextError, match="printable ASCII"):
        parse_trusted_context(headers)


def test_find_identity_like_keys_recurses():
    payload = {
        "prompt": "safe",
        "identity": {"sub": "spoofed"},
        "nested": [{"x_dnsid_sub": "spoofed"}],
    }

    assert find_identity_like_keys(payload) == ["identity", "identity.sub", "nested[0].x_dnsid_sub"]
