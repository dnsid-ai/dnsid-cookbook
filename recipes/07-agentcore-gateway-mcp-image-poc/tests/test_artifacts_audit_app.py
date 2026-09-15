from pathlib import Path

from image_poc.app import GatewayImageApp, LocalImageApp
from image_poc.artifacts import ArtifactError, ArtifactStore
from image_poc.audit import AuditError, AuditStore
from image_poc.bedrock_image import GeneratedImage, ImageGenerationError
from image_poc.gateway_mcp import GatewayGenerateResult, GatewayMcpError


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
    def generate(self, request):
        raise ImageGenerationError("model unavailable")


class FailingArtifacts:
    def write_image(self, image_bytes):
        raise ArtifactError("disk full")


class FailingAudit:
    def record(self, event):
        raise AuditError("cannot append")


class FakeGatewayClient:
    def __init__(self):
        self.calls = []

    def generate_image(self, request):
        self.calls.append(request)
        return GatewayGenerateResult(
            image_bytes=png_bytes(),
            remote_artifact_id="remote-artifact",
            mime_type="image/png",
            width=1024,
            height=1024,
            model_id="stability.sd3-5-large-v1:0",
            model_region="us-west-2",
            request_id="bedrock-request",
            correlation_id="remote-correlation",
            audit_id="remote-audit",
            auth_mode="gateway-dnsid-lab",
            dnsid_context={
                "sub": "agent.example.test",
                "dnsid": "agent.example.test",
                "accountable_entity": "agent.example.test",
                "iss": "https://dnsid.example.test",
                "aud": "https://gateway.example/mcp",
                "jti": "token-jti",
                "gateway_request_id": "gateway-request",
            },
            ignored_identity_args=[],
            options={
                "style": "product",
                "size": "1024x1024",
                "artifact_s3_uri": "s3://bucket/key.png",
                "artifact_url": "https://bucket.s3.amazonaws.com/key.png?X-Amz-Signature=secret",
            },
        )


class FailingGatewayClient:
    def generate_image(self, request):
        raise GatewayMcpError(
            "gateway_mcp_error",
            "Gateway failed with X-Amz-Signature=secret artifact_s3_uri Bearer token",
        )


def test_artifact_store_writes_image(tmp_path):
    store = ArtifactStore(tmp_path)

    artifact = store.write_image(b"image")

    assert artifact.artifact_path.read_bytes() == b"image"
    assert artifact.artifact_url == f"/artifacts/{artifact.artifact_id}.png"
    assert store.path_for(artifact.artifact_id) == artifact.artifact_path


def test_artifact_store_rejects_invalid_artifact_id(tmp_path):
    store = ArtifactStore(tmp_path)

    try:
        store.path_for("abc")
    except ArtifactError as exc:
        assert "Invalid artifact ID" in str(exc)
    else:
        raise AssertionError("expected invalid artifact ID")


def test_audit_store_appends_record_without_raw_prompt(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditStore(path)

    audit_id = audit.record({"prompt_hash": "sha256:abc", "result_status": "success"})

    line = path.read_text()
    assert audit_id in line
    assert "sha256:abc" in line
    assert "secret prompt" not in line


def test_local_image_app_success_response_contains_local_metadata(tmp_path):
    app = LocalImageApp(
        generator=FakeGenerator(),
        artifacts=ArtifactStore(tmp_path / "images"),
        audit=AuditStore(tmp_path / "audit.jsonl"),
    )

    status, response = app.handle_generate({"prompt": "a dns label", "style": "product"})

    assert status == 200
    assert response["ok"] is True
    assert response["auth_mode"] == "local-test"
    assert "dnsid" not in response
    assert response["artifact_url"].startswith("/artifacts/")
    assert response["mime_type"] == "image/png"
    assert response["width"] == 1024
    assert response["height"] == 1024
    assert response["model_id"] == "stability.sd3-5-large-v1:0"
    assert response["request_id"] == "bedrock-request"
    assert response["audit_id"]
    assert Path(tmp_path / "audit.jsonl").read_text()


def test_local_image_app_validation_error():
    app = LocalImageApp(
        generator=FakeGenerator(),
        artifacts=ArtifactStore(Path("/tmp/unused")),
        audit=AuditStore(Path("/tmp/unused/audit.jsonl")),
    )

    status, response = app.handle_generate({"prompt": ""})

    assert status == 400
    assert response["ok"] is False
    assert response["error"]["code"] == "validation_error"
    assert response["auth_mode"] == "local-test"
    assert response["audit_id"]


def test_local_image_app_model_error(tmp_path):
    app = LocalImageApp(
        generator=FailingGenerator(),
        artifacts=ArtifactStore(tmp_path / "images"),
        audit=AuditStore(tmp_path / "audit.jsonl"),
    )

    status, response = app.handle_generate({"prompt": "hello"})

    assert status == 502
    assert response["error"]["code"] == "bedrock_error"
    assert response["audit_id"]


def test_local_image_app_artifact_error(tmp_path):
    app = LocalImageApp(
        generator=FakeGenerator(),
        artifacts=FailingArtifacts(),
        audit=AuditStore(tmp_path / "audit.jsonl"),
    )

    status, response = app.handle_generate({"prompt": "hello"})

    assert status == 500
    assert response["error"]["code"] == "artifact_error"
    assert response["audit_id"]


def test_local_image_app_audit_error(tmp_path):
    app = LocalImageApp(
        generator=FakeGenerator(),
        artifacts=ArtifactStore(tmp_path / "images"),
        audit=FailingAudit(),
    )

    status, response = app.handle_generate({"prompt": "hello"})

    assert status == 500
    assert response["error"]["code"] == "audit_error"


def test_gateway_image_app_success_sanitizes_browser_response(tmp_path):
    app = GatewayImageApp(
        gateway=FakeGatewayClient(),
        artifacts=ArtifactStore(tmp_path / "images"),
    )

    status, response = app.handle_generate({"prompt": "a dns label", "style": "product"})

    serialized = str(response)
    assert status == 200
    assert response["ok"] is True
    assert response["auth_mode"] == "gateway-dnsid"
    assert response["artifact_url"].startswith("/artifacts/")
    assert response["artifact_id"] != response["remote_artifact_id"]
    assert response["remote_artifact_id"] == "remote-artifact"
    assert response["audit_id"] == "remote-audit"
    assert response["dnsid_sub"] == "agent.example.test"
    assert response["dnsid_issuer"] == "https://dnsid.example.test"
    assert response["gateway_request_id"] == "gateway-request"
    assert "artifact_s3_uri" not in response
    assert "audit_s3_uri" not in response
    assert "X-Amz" not in serialized
    assert "token-jti" not in serialized
    assert response["options"] == {"style": "product", "size": "1024x1024"}
    assert (tmp_path / "images").exists()


def test_gateway_image_app_validation_error_does_not_mint_token(tmp_path):
    gateway = FakeGatewayClient()
    app = GatewayImageApp(gateway=gateway, artifacts=ArtifactStore(tmp_path / "images"))

    status, response = app.handle_generate({"prompt": ""})

    assert status == 400
    assert response["error"]["code"] == "validation_error"
    assert response["auth_mode"] == "gateway-dnsid"
    assert gateway.calls == []


def test_gateway_image_app_returns_sanitized_gateway_error(tmp_path):
    app = GatewayImageApp(
        gateway=FailingGatewayClient(),
        artifacts=ArtifactStore(tmp_path / "images"),
    )

    status, response = app.handle_generate({"prompt": "hello"})

    assert status == 502
    assert response["error"]["code"] == "gateway_mcp_error"
    assert response["error"]["message"] == "Gateway MCP call failed."
    serialized = str(response)
    assert "X-Amz" not in serialized
    assert "artifact_s3_uri" not in serialized
    assert "Bearer" not in serialized
    assert response["auth_mode"] == "gateway-dnsid"
