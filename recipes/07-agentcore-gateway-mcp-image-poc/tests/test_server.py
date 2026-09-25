import json
import threading
import urllib.error
import urllib.request

from image_poc.app import LocalImageApp
from image_poc.artifacts import ArtifactStore
from image_poc.audit import AuditStore
from image_poc.bedrock_image import GeneratedImage
from image_poc.server import LocalHTTPServer, build_application, log_generate_result, make_handler


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


def serve(tmp_path):
    artifacts = ArtifactStore(tmp_path / "images")
    app = LocalImageApp(FakeGenerator(), artifacts, AuditStore(tmp_path / "audit.jsonl"))
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>ok</title>")
    server = LocalHTTPServer(
        ("127.0.0.1", 0),
        make_handler(app, artifacts, static_root),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://{server.server_address[0]}:{server.server_address[1]}"


def request_json(base_url, path, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base_url + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


def post_raw(base_url, path, body, headers):
    request = urllib.request.Request(base_url + path, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_server_health_and_generate(tmp_path):
    server, base_url = serve(tmp_path)
    try:
        health_status, health = request_json(base_url, "/api/health")
        status, generated = request_json(base_url, "/api/generate", {"prompt": "hello"})
        with urllib.request.urlopen(base_url + generated["artifact_url"]) as response:
            artifact = response.read()
    finally:
        server.shutdown()

    assert health_status == 200
    assert health["auth_mode"] == "local-test"
    assert health["ok"] is True
    assert "warning" in health
    assert status == 200
    assert generated["auth_mode"] == "local-test"
    assert generated["artifact_url"].startswith("/artifacts/")
    assert artifact.startswith(b"\x89PNG")


def test_server_validation_error(tmp_path):
    server, base_url = serve(tmp_path)
    try:
        status, body = request_json(base_url, "/api/generate", {"prompt": ""})
    finally:
        server.shutdown()

    assert status == 400
    assert body["ok"] is False
    assert body["error"]["code"] == "validation_error"


def test_local_generate_result_log_is_sanitized(capsys):
    log_generate_result(
        200,
        {
            "ok": True,
            "auth_mode": "gateway-dnsid",
            "dnsid_sub": "agent.example.test",
            "dnsid_issuer": "https://api.dev.dnsid.ai",
            "gateway_request_id": "gateway-request",
            "correlation_id": "correlation-id",
            "request_id": "bedrock-request",
            "artifact_id": "artifact-id",
            "artifact_url": "/artifacts/artifact-id.png",
            "options": {"prompt": "secret prompt"},
        },
    )

    output = capsys.readouterr().out
    record = json.loads(output)
    assert record == {
        "event": "local_generate_result",
        "status": 200,
        "ok": True,
        "auth_mode": "gateway-dnsid",
        "dnsid_sub": "agent.example.test",
        "dnsid_issuer": "https://api.dev.dnsid.ai",
        "gateway_request_id": "gateway-request",
        "correlation_id": "correlation-id",
        "request_id": "bedrock-request",
        "artifact_id": "artifact-id",
        "error_code": "",
    }
    assert "secret prompt" not in output


def test_server_rejects_non_json_content_type(tmp_path):
    server, base_url = serve(tmp_path)
    try:
        status, body = post_raw(
            base_url,
            "/api/generate",
            b'{"prompt":"hello"}',
            {"Content-Type": "text/plain"},
        )
    finally:
        server.shutdown()

    assert status == 400
    assert body["error"]["code"] == "invalid_json"


def test_server_rejects_cross_origin_generation(tmp_path):
    server, base_url = serve(tmp_path)
    try:
        status, body = post_raw(
            base_url,
            "/api/generate",
            json.dumps({"prompt": "hello"}).encode("utf-8"),
            {
                "Content-Type": "application/json",
                "Origin": "https://attacker.example",
            },
        )
    finally:
        server.shutdown()

    assert status == 403
    assert body["error"]["code"] == "forbidden_origin"


def test_gateway_mode_missing_state_returns_sanitized_503(monkeypatch, tmp_path):
    monkeypatch.setenv("IMAGE_POC_MODE", "gateway")
    monkeypatch.setenv("DNSID_AGENT_DOMAIN", "agent.example.com")
    monkeypatch.setenv("GATEWAY_STATE_PATH", str(tmp_path / "missing-state.json"))
    monkeypatch.setenv("ARTIFACT_DIR", str(tmp_path / "images"))
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    app, artifacts = build_application()
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>ok</title>")
    server = LocalHTTPServer(
        ("127.0.0.1", 0),
        make_handler(app, artifacts, static_root),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
    try:
        health_status, health = request_json(base_url, "/api/health")
        generate_status, generated = request_json(base_url, "/api/generate", {"prompt": "hello"})
    finally:
        server.shutdown()

    assert health_status == 503
    assert health["ok"] is False
    assert health["error"]["code"] == "gateway_unavailable"
    assert generate_status == 503
    assert generated["error"] == {
        "code": "gateway_unavailable",
        "message": "Gateway state is unavailable.",
    }
