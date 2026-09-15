from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from image_poc.app import GatewayImageApp, LocalImageApp, UnavailableGatewayApp
from image_poc.artifacts import ArtifactError, ArtifactStore
from image_poc.audit import AuditStore
from image_poc.bedrock_image import BedrockImageGenerator
from image_poc.config import GATEWAY_MODE, load_settings
from image_poc.gateway_mcp import GatewayMcpClient, GatewayMcpError, load_gateway_state


STATIC_ROOT = Path(__file__).with_name("static")
MAX_BODY_BYTES = 64 * 1024


class LocalHTTPServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


def content_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".html":
        return "text/html; charset=utf-8"
    if suffix == ".css":
        return "text/css; charset=utf-8"
    if suffix == ".js":
        return "application/javascript; charset=utf-8"
    if suffix == ".png":
        return "image/png"
    return "application/octet-stream"


def safe_child(root: Path, raw_path: str) -> Path | None:
    candidate = (root / raw_path.lstrip("/")).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def allowed_origin(host_header: str | None, origin: str | None) -> bool:
    if not origin:
        return True
    if not host_header:
        return False
    parsed = urlparse(origin)
    return parsed.scheme in {"http", "https"} and parsed.netloc == host_header


def make_handler(
    application: Any,
    artifacts: ArtifactStore,
    static_root: Path = STATIC_ROOT,
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "ImagePoC/0.1"

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path in ("/", "/index.html"):
                self._send_file(static_root / "index.html")
                return
            if parsed.path.startswith("/assets/"):
                asset = safe_child(static_root, parsed.path.removeprefix("/assets/"))
                if asset is None:
                    self._send_error(HTTPStatus.NOT_FOUND, "not_found", "Asset not found.")
                    return
                self._send_file(asset)
                return
            if parsed.path.startswith("/artifacts/"):
                artifact_id = unquote(parsed.path.removeprefix("/artifacts/")).removesuffix(
                    ".png"
                )
                try:
                    artifact_path = artifacts.path_for(artifact_id)
                except ArtifactError:
                    self._send_error(
                        HTTPStatus.NOT_FOUND,
                        "not_found",
                        "Artifact not found.",
                    )
                    return
                self._send_file(artifact_path)
                return
            if parsed.path == "/api/health":
                health = application.health()
                status = HTTPStatus.OK if health.get("ok") else HTTPStatus.SERVICE_UNAVAILABLE
                self._send_json(status, health)
                return
            self._send_error(HTTPStatus.NOT_FOUND, "not_found", "Route not found.")

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/api/generate":
                self._send_error(HTTPStatus.NOT_FOUND, "not_found", "Route not found.")
                return
            if not allowed_origin(self.headers.get("Host"), self.headers.get("Origin")):
                self._send_error(
                    HTTPStatus.FORBIDDEN,
                    "forbidden_origin",
                    "Cross-origin generation requests are not allowed.",
                )
                return
            try:
                payload = self._read_json_body()
            except ValueError as exc:
                self._send_error(HTTPStatus.BAD_REQUEST, "invalid_json", str(exc))
                return
            status, response = application.handle_generate(payload)
            self._send_json(HTTPStatus(status), response)
            log_generate_result(status, response)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_json_body(self) -> dict[str, Any]:
            content_type = self.headers.get("Content-Type", "")
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                raise ValueError("Content-Type must be application/json.")
            length_header = self.headers.get("Content-Length", "0")
            try:
                length = int(length_header)
            except ValueError as exc:
                raise ValueError("Invalid Content-Length.") from exc
            if length > MAX_BODY_BYTES:
                raise ValueError("Request body is too large.")
            raw = self.rfile.read(length)
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("Request body must be valid JSON.") from exc
            if not isinstance(parsed, dict):
                raise ValueError("Request body must be a JSON object.")
            return parsed

        def _send_file(self, path: Path) -> None:
            if not path.exists() or not path.is_file():
                self._send_error(HTTPStatus.NOT_FOUND, "not_found", "File not found.")
                return
            data = path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type(path))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            data = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _send_error(self, status: HTTPStatus, code: str, message: str) -> None:
            self._send_json(status, {"ok": False, "error": {"code": code, "message": message}})

    return Handler


def build_application() -> tuple[Any, ArtifactStore]:
    settings = load_settings()
    artifacts = ArtifactStore(settings.artifact_dir)
    if settings.image_poc_mode == GATEWAY_MODE:
        try:
            state = load_gateway_state(settings.gateway_state_path)
        except GatewayMcpError as exc:
            return UnavailableGatewayApp(exc), artifacts
        app = GatewayImageApp(
            gateway=GatewayMcpClient(
                state=state,
                dnsid=settings.dnsid,
            ),
            artifacts=artifacts,
        )
        return app, artifacts
    app = LocalImageApp(
        generator=BedrockImageGenerator(
            model_id=settings.bedrock_model_id,
            region=settings.aws_region,
        ),
        artifacts=artifacts,
        audit=AuditStore(settings.audit_path),
    )
    return app, artifacts


def log_generate_result(status: int, response: dict[str, Any]) -> None:
    error = response.get("error") if isinstance(response.get("error"), dict) else {}
    record = {
        "event": "local_generate_result",
        "status": status,
        "ok": bool(response.get("ok")),
        "auth_mode": response.get("auth_mode", ""),
        "dnsid_sub": response.get("dnsid_sub", ""),
        "dnsid_issuer": response.get("dnsid_issuer", ""),
        "gateway_request_id": response.get("gateway_request_id", ""),
        "correlation_id": response.get("correlation_id", ""),
        "request_id": response.get("request_id", ""),
        "artifact_id": response.get("artifact_id", ""),
        "error_code": error.get("code", ""),
    }
    print(json.dumps(record, sort_keys=True), flush=True)


def main() -> int:
    settings = load_settings()
    app, artifacts = build_application()
    server = LocalHTTPServer(
        (settings.host, settings.port),
        make_handler(app, artifacts),
    )
    print(f"local image PoC listening on http://{settings.host}:{settings.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
