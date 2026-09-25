import base64
import json
import logging

import pytest

from image_poc.aws_handler import build_default_handler, make_handler
from image_poc.bedrock_image import GeneratedImage, ImageGenerationError


def png_bytes():
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + (1024).to_bytes(
        4, "big"
    ) + (1024).to_bytes(4, "big") + b"\x08\x02\x00\x00\x00"


class FakeGenerator:
    def generate(self, request):
        return GeneratedImage(
            image_bytes=png_bytes(),
            mime_type="image/png",
            width=1024,
            height=1024,
            model_id="stability.sd3-5-large-v1:0",
            model_region="us-west-2",
            request_id="bedrock-request",
        )


class FailingGenerator:
    model_id = "stability.sd3-5-large-v1:0"
    region = "us-west-2"

    def generate(self, request):
        raise ImageGenerationError("secret model detail")


class FakeStore:
    def __init__(self):
        self.audit_events = []

    def write_image(self, image_bytes):
        assert image_bytes.startswith(b"\x89PNG")
        return type(
            "Artifact",
            (),
            {
                "artifact_id": "artifact-id",
                "s3_uri": "s3://bucket/images/artifact-id.png",
                "artifact_url": "https://signed.example/artifact-id.png",
                "expires_in": 900,
            },
        )()

    def record_audit(self, event):
        self.audit_events.append(event)
        return "audit-id"


class FailingWriteStore(FakeStore):
    def write_image(self, image_bytes):
        raise RuntimeError("private s3 detail")


class FailingAuditStore(FakeStore):
    def record_audit(self, event):
        raise RuntimeError("private audit detail")


def event(path, payload, headers=None):
    default_headers = {
        "x-dnsid-sub": "agent.example.com",
        "x-dnsid-iss": "https://api.dev.dnsid.ai",
        "x-dnsid-aud": "https://gateway.example/mcp",
        "x-dnsid-jti": "token-id",
        "x-dnsid-domain": "agent.example.com",
        "x-dnsid-auth-mode": "gateway-dnsid-lab",
        "x-dnsid-verified-at": "2026-05-28T02:00:00Z",
        "x-gateway-request-id": "gateway-request",
        "x-correlation-id": "correlation-id",
    }
    if headers:
        default_headers.update(headers)
    return {
        "path": path,
        "httpMethod": "POST",
        "headers": default_headers,
        "body": json.dumps(payload),
        "isBase64Encoded": False,
        "requestContext": {"requestId": "api-request"},
    }


def decode(response):
    body = response["body"]
    if response.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    return response["statusCode"], json.loads(body)


def test_generate_image_returns_artifact_and_trusted_identity():
    store = FakeStore()
    handler = make_handler(FakeGenerator(), store, expected_sub="agent.example.com")

    status, body = decode(handler(event("/generate-image", {"prompt": "a bright robot"}), None))

    assert status == 200
    assert body["ok"] is True
    assert body["artifact_id"] == "artifact-id"
    assert "audit_s3_uri" not in body
    assert body["dnsid_context"]["sub"] == "agent.example.com"
    assert store.audit_events[0]["trusted_identity"]["jti"] == "token-id"


def test_generate_image_logs_sanitized_success(caplog):
    caplog.set_level(logging.INFO, logger="image_poc.aws_handler")
    handler = make_handler(FakeGenerator(), FakeStore(), expected_sub="agent.example.com")

    status, body = decode(handler(event("/generate-image", {"prompt": "secret prompt"}), None))

    assert status == 200
    record = success_log_record(caplog)
    assert record["event"] == "phase3_generate_success"
    assert record["auth_mode"] == "gateway-dnsid-lab"
    assert record["dnsid_sub"] == "agent.example.com"
    assert record["dnsid_issuer"] == "https://api.dev.dnsid.ai"
    assert record["token_jti_present"] is True
    assert record["gateway_request_id"] == "gateway-request"
    assert record["correlation_id"] == body["correlation_id"]
    assert record["request_id"] == "bedrock-request"
    assert record["artifact_id"] == "artifact-id"
    assert "secret prompt" not in caplog.text
    assert "token-id" not in caplog.text


def test_whoami_returns_phase3_fields():
    handler = make_handler(FakeGenerator(), FakeStore(), expected_sub="agent.example.com")

    status, body = decode(handler(event("/whoami-dnsid", {}), None))

    assert status == 200
    assert body["sub"] == "agent.example.com"
    assert body["accountable_entity"] == "agent.example.com"
    assert body["dnsid_status"] == "not_checked_phase3"
    assert body["gateway_request_id"] == "gateway-request"


def test_generate_image_rejects_missing_trusted_context():
    handler = make_handler(FakeGenerator(), FakeStore(), expected_sub="agent.example.com")

    status, body = decode(handler(event("/generate-image", {"prompt": "hello"}, headers={"x-dnsid-jti": ""}), None))

    assert status == 403
    assert body["error"]["code"] == "trusted_context_error"


def test_generate_image_ignores_identity_like_body_fields():
    store = FakeStore()
    handler = make_handler(FakeGenerator(), store, expected_sub="agent.example.com")

    status, body = decode(
        handler(
            event(
                "/generate-image",
                {"prompt": "hello", "identity": {"sub": "spoofed.example"}},
            ),
            None,
        )
    )

    assert status == 200
    assert body["dnsid_context"]["sub"] == "agent.example.com"
    assert body["ignored_identity_args"] == ["identity", "identity.sub"]


def test_generate_image_redacts_model_error_details():
    handler = make_handler(
        FailingGenerator(),
        FakeStore(),
        expected_sub="agent.example.com",
    )

    status, body = decode(handler(event("/generate-image", {"prompt": "hello"}), None))

    assert status == 502
    assert body["error"]["code"] == "bedrock_error"
    assert body["error"]["message"] == "Image generation failed."
    assert "secret" not in json.dumps(body)


def test_generate_image_logs_sanitized_model_failure(caplog):
    caplog.set_level(logging.WARNING, logger="image_poc.aws_handler")
    handler = make_handler(
        FailingGenerator(),
        FakeStore(),
        expected_sub="agent.example.com",
    )

    status, body = decode(handler(event("/generate-image", {"prompt": "secret prompt"}), None))

    assert status == 502
    record = failure_log_record(caplog)
    assert record["error_category"] == "bedrock_error"
    assert record["tool_name"] == "generate_image"
    assert record["model_id"] == "stability.sd3-5-large-v1:0"
    assert record["model_region"] == "us-west-2"
    assert record["gateway_request_id"] == "gateway-request"
    assert record["api_request_id"] == "api-request"
    assert record["trusted_identity"]["sub"] == "agent.example.com"
    assert record["token_jti"] == "token-id"
    assert record["correlation_id"] == body["correlation_id"]
    assert record["prompt_hash"].startswith("sha256:")
    assert "secret prompt" not in caplog.text
    assert "secret model detail" not in caplog.text


def test_generate_image_logs_sanitized_target_failure(caplog):
    caplog.set_level(logging.WARNING, logger="image_poc.aws_handler")
    handler = make_handler(
        FakeGenerator(),
        FailingWriteStore(),
        expected_sub="agent.example.com",
    )

    status, body = decode(handler(event("/generate-image", {"prompt": "secret prompt"}), None))

    assert status == 500
    record = failure_log_record(caplog)
    assert record["error_category"] == "target_error"
    assert record["exception_type"] == "RuntimeError"
    assert record["model_id"] == "stability.sd3-5-large-v1:0"
    assert record["correlation_id"] == body["correlation_id"]
    assert "private s3 detail" not in caplog.text
    assert "secret prompt" not in caplog.text


def test_generate_image_logs_artifact_context_when_audit_write_fails(caplog):
    caplog.set_level(logging.WARNING, logger="image_poc.aws_handler")
    handler = make_handler(
        FakeGenerator(),
        FailingAuditStore(),
        expected_sub="agent.example.com",
    )

    status, body = decode(handler(event("/generate-image", {"prompt": "secret prompt"}), None))

    assert status == 500
    record = failure_log_record(caplog)
    assert record["error_category"] == "target_error"
    assert record["artifact_id"] == "artifact-id"
    assert record["artifact_s3_uri"] == "s3://bucket/images/artifact-id.png"
    assert record["correlation_id"] == body["correlation_id"]
    assert "private audit detail" not in caplog.text
    assert "secret prompt" not in caplog.text


def failure_log_record(caplog):
    records = [
        record.message.split(" ", 1)[1]
        for record in caplog.records
        if record.message.startswith("phase3_generate_failure ")
    ]
    assert len(records) == 1
    return json.loads(records[0])


def success_log_record(caplog):
    records = [
        record.message.split(" ", 1)[1]
        for record in caplog.records
        if record.message.startswith("phase3_generate_success ")
    ]
    assert len(records) == 1
    return json.loads(records[0])


def test_default_handler_requires_expected_subject(monkeypatch):
    monkeypatch.setenv("ARTIFACT_BUCKET", "bucket")
    monkeypatch.delenv("EXPECTED_DNSID_SUB", raising=False)

    with pytest.raises(RuntimeError, match="EXPECTED_DNSID_SUB"):
        build_default_handler()
