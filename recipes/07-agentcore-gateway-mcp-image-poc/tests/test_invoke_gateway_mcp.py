import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import invoke_gateway_mcp  # noqa: E402
from invoke_gateway_mcp import (  # noqa: E402
    assert_auth_denied,
    assert_audit_contract,
    assert_generated_contract,
    assert_json_rpc_error,
    assert_only_allowed_tools,
    decode_claims,
    find_tool,
    parse_s3_uri,
    unsigned_jwt_from_claims,
)


@pytest.fixture(autouse=True)
def dnsid_subject(monkeypatch):
    monkeypatch.setattr(invoke_gateway_mcp, "EXPECTED_DNSID_SUB", "agent.example.com")


def generated_body(**overrides):
    body = {
        "ok": True,
        "artifact_id": "artifact-id",
        "artifact_s3_uri": "s3://bucket/phase3/images/artifact-id.png",
        "artifact_url": "https://signed.example/artifact-id.png",
        "audit_s3_uri": "s3://bucket/phase3/audit/2026-05-28/audit-id.json",
        "request_id": "bedrock-request",
        "audit_id": "audit-id",
        "model_id": "stability.sd3-5-large-v1:0",
        "model_region": "us-west-2",
        "mime_type": "image/png",
        "width": 1024,
        "height": 1024,
        "correlation_id": "correlation-id",
    }
    body.update(overrides)
    return body


def test_assert_generated_contract_requires_model_metadata():
    with pytest.raises(RuntimeError, match="model_id"):
        assert_generated_contract(generated_body(model_id=""), 1024, 1024)

    with pytest.raises(RuntimeError, match="model_region"):
        assert_generated_contract(generated_body(model_region=""), 1024, 1024)


def test_assert_generated_contract_accepts_complete_gateway_response():
    assert_generated_contract(generated_body(), 1024, 1024)


def test_assert_audit_contract_requires_deployed_audit_fields():
    generated = generated_body()
    audit = {
        "audit_id": "audit-id",
        "tool_name": "generate_image",
        "result_status": "success",
        "artifact_id": "artifact-id",
        "artifact_s3_uri": "s3://bucket/phase3/images/artifact-id.png",
        "model_id": "stability.sd3-5-large-v1:0",
        "model_region": "us-west-2",
        "request_id": "bedrock-request",
        "correlation_id": "correlation-id",
        "token_jti": "token-id",
        "trusted_identity": {"sub": "agent.example.com"},
        "prompt_hash": "sha256:abc",
        "recorded_at": "2026-05-28T00:00:00+00:00",
    }

    assert_audit_contract(audit, generated, {"jti": "token-id"})

    with pytest.raises(RuntimeError, match="token_jti"):
        assert_audit_contract({**audit, "token_jti": "other"}, generated, {"jti": "token-id"})


def test_parse_s3_uri_requires_bucket_and_key():
    assert parse_s3_uri("s3://bucket/phase3/audit/audit-id.json") == (
        "bucket",
        "phase3/audit/audit-id.json",
    )

    with pytest.raises(RuntimeError, match="not an S3 URI"):
        parse_s3_uri("https://example.test/object")

    with pytest.raises(RuntimeError, match="missing bucket or key"):
        parse_s3_uri("s3://bucket")


def test_assert_json_rpc_error_requires_json_rpc_envelope():
    with pytest.raises(RuntimeError, match="envelope"):
        assert_json_rpc_error({"error": {"code": -32601, "message": "not found"}})


def test_assert_json_rpc_error_rejects_malformed_error():
    with pytest.raises(RuntimeError, match="malformed"):
        assert_json_rpc_error({"jsonrpc": "2.0", "error": {"code": -32601}})


def test_assert_json_rpc_error_accepts_structured_error():
    assert_json_rpc_error(
        {"jsonrpc": "2.0", "id": "debug", "error": {"code": -32601, "message": "not found"}}
    )


def test_unsigned_jwt_from_claims_has_no_signature():
    token = unsigned_jwt_from_claims({"sub": "agent.example.com", "aud": "audience"})

    assert token.endswith(".")
    assert decode_claims(token)["sub"] == "agent.example.com"


def test_assert_auth_denied_requires_gateway_auth_status():
    assert_auth_denied({"http_status": 401}, "unsigned JWT")
    assert_auth_denied({"http_status": 403}, "unsigned JWT")

    with pytest.raises(RuntimeError, match="expected Gateway auth denial"):
        assert_auth_denied({"http_status": 400}, "unsigned JWT")


def test_gateway_tool_discovery_requires_exact_target_tools():
    tools = ["ImageApiTarget___generate_image", "ImageApiTarget___whoami_dnsid"]

    assert_only_allowed_tools(tools, "ImageApiTarget")
    assert find_tool(tools, "generate_image", "ImageApiTarget") == "ImageApiTarget___generate_image"

    with pytest.raises(RuntimeError, match="unexpected tools"):
        assert_only_allowed_tools(
            tools + ["OtherTarget___generate_image"],
            "ImageApiTarget",
        )

    with pytest.raises(RuntimeError, match="exactly one"):
        find_tool(["generate_image", "ImageApiTarget___whoami_dnsid"], "generate_image", "ImageApiTarget")
