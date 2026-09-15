from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict
from typing import Any

from image_poc.artifacts import ArtifactError, ArtifactStore
from image_poc.audit import AuditError, AuditStore
from image_poc.bedrock_image import BedrockImageGenerator, ImageGenerationError
from image_poc.gateway_mcp import (
    GATEWAY_AUTH_MODE,
    GATEWAY_WARNING,
    GatewayMcpClient,
    GatewayMcpError,
)
from image_poc.validation import (
    LOCAL_TEST_AUTH_MODE,
    LOCAL_TEST_WARNING,
    ValidationError,
    validate_generate_payload,
)


class LocalImageApp:
    def __init__(
        self,
        generator: BedrockImageGenerator,
        artifacts: ArtifactStore,
        audit: AuditStore,
    ) -> None:
        self.generator = generator
        self.artifacts = artifacts
        self.audit = audit

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "auth_mode": LOCAL_TEST_AUTH_MODE,
            "warning": LOCAL_TEST_WARNING,
        }

    def handle_generate(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        correlation_id = uuid.uuid4().hex
        try:
            request = validate_generate_payload(payload)
            generated = self.generator.generate(request)
            artifact = self.artifacts.write_image(generated.image_bytes)
            prompt_hash = hashlib.sha256(request.prompt.encode("utf-8")).hexdigest()
            audit_id = self.audit.record(
                {
                    "auth_mode": LOCAL_TEST_AUTH_MODE,
                    "tool_name": "generate_image",
                    "prompt_hash": f"sha256:{prompt_hash}",
                    "style": request.style,
                    "size": request.size,
                    "model_id": generated.model_id,
                    "model_region": generated.model_region,
                    "artifact_id": artifact.artifact_id,
                    "artifact_path": str(artifact.artifact_path),
                    "mime_type": generated.mime_type,
                    "width": generated.width,
                    "height": generated.height,
                    "request_id": generated.request_id,
                    "correlation_id": correlation_id,
                    "result_status": "success",
                }
            )
        except ValidationError as exc:
            audit_id = self._record_failure(
                "validation_error",
                correlation_id,
                str(exc),
                field=exc.field,
            )
            return self._error(
                400, "validation_error", str(exc), correlation_id, exc.field, audit_id
            )
        except ImageGenerationError as exc:
            audit_id = self._record_failure("bedrock_error", correlation_id, str(exc))
            return self._error(502, "bedrock_error", str(exc), correlation_id, audit_id=audit_id)
        except ArtifactError as exc:
            audit_id = self._record_failure("artifact_error", correlation_id, str(exc))
            return self._error(
                500, "artifact_error", str(exc), correlation_id, audit_id=audit_id
            )
        except AuditError as exc:
            return self._error(500, "audit_error", str(exc), correlation_id)

        response = {
            "ok": True,
            "artifact_url": artifact.artifact_url,
            "artifact_id": artifact.artifact_id,
            "mime_type": generated.mime_type,
            "width": generated.width,
            "height": generated.height,
            "model_id": generated.model_id,
            "model_region": generated.model_region,
            "request_id": generated.request_id,
            "correlation_id": correlation_id,
            "audit_id": audit_id,
            "auth_mode": LOCAL_TEST_AUTH_MODE,
            "warning": LOCAL_TEST_WARNING,
            "options": asdict(request),
        }
        response["options"].pop("prompt", None)
        return 200, response

    def _error(
        self,
        status: int,
        code: str,
        message: str,
        correlation_id: str,
        field: str | None = None,
        audit_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        error: dict[str, Any] = {"code": code, "message": message}
        if field:
            error["field"] = field
        response: dict[str, Any] = {
            "ok": False,
            "error": error,
            "correlation_id": correlation_id,
            "auth_mode": LOCAL_TEST_AUTH_MODE,
            "warning": LOCAL_TEST_WARNING,
        }
        if audit_id:
            response["audit_id"] = audit_id
        return status, response

    def _record_failure(
        self,
        code: str,
        correlation_id: str,
        message: str,
        field: str | None = None,
    ) -> str | None:
        event: dict[str, Any] = {
            "auth_mode": LOCAL_TEST_AUTH_MODE,
            "tool_name": "generate_image",
            "correlation_id": correlation_id,
            "result_status": "failure",
            "error_category": code,
            "error_message": message,
        }
        if field:
            event["error_field"] = field
        try:
            return self.audit.record(event)
        except AuditError:
            return None


class GatewayImageApp:
    def __init__(
        self,
        gateway: GatewayMcpClient,
        artifacts: ArtifactStore,
    ) -> None:
        self.gateway = gateway
        self.artifacts = artifacts

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "auth_mode": GATEWAY_AUTH_MODE,
            "warning": GATEWAY_WARNING,
        }

    def handle_generate(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        try:
            request = validate_generate_payload(payload)
            generated = self.gateway.generate_image(request)
            artifact = self.artifacts.write_image(generated.image_bytes)
        except ValidationError as exc:
            return self._error(400, "validation_error", str(exc), field=exc.field)
        except GatewayMcpError as exc:
            return self._error(exc.status, exc.code, browser_gateway_error_message(exc))
        except ArtifactError:
            return self._error(500, "artifact_error", "Local preview artifact write failed.")

        dnsid_context = browser_dnsid_context(generated.dnsid_context)
        response: dict[str, Any] = {
            "ok": True,
            "artifact_url": artifact.artifact_url,
            "artifact_id": artifact.artifact_id,
            "remote_artifact_id": generated.remote_artifact_id,
            "mime_type": generated.mime_type,
            "width": generated.width,
            "height": generated.height,
            "model_id": generated.model_id,
            "model_region": generated.model_region,
            "request_id": generated.request_id,
            "correlation_id": generated.correlation_id,
            "audit_id": generated.audit_id,
            "auth_mode": GATEWAY_AUTH_MODE,
            "warning": GATEWAY_WARNING,
            "dnsid_context": dnsid_context,
            "dnsid_sub": dnsid_context.get("sub", ""),
            "dnsid_issuer": dnsid_context.get("iss", ""),
            "gateway_request_id": dnsid_context.get("gateway_request_id", ""),
            "ignored_identity_args": generated.ignored_identity_args,
            "options": {"style": request.style, "size": request.size},
        }
        return 200, response

    def _error(
        self,
        status: int,
        code: str,
        message: str,
        field: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        error: dict[str, Any] = {"code": code, "message": message}
        if field:
            error["field"] = field
        return status, {
            "ok": False,
            "error": error,
            "auth_mode": GATEWAY_AUTH_MODE,
            "warning": GATEWAY_WARNING,
        }


class UnavailableGatewayApp:
    def __init__(self, error: GatewayMcpError) -> None:
        self.error = error

    def health(self) -> dict[str, Any]:
        return {
            "ok": False,
            "auth_mode": GATEWAY_AUTH_MODE,
            "warning": GATEWAY_WARNING,
            "error": {
                "code": self.error.code,
                "message": browser_gateway_error_message(self.error),
            },
        }

    def handle_generate(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return self.error.status, {
            "ok": False,
            "error": {
                "code": self.error.code,
                "message": browser_gateway_error_message(self.error),
            },
            "auth_mode": GATEWAY_AUTH_MODE,
            "warning": GATEWAY_WARNING,
        }


def browser_gateway_error_message(error: GatewayMcpError) -> str:
    messages = {
        "dnsid_token_error": "DNSid token minting failed.",
        "gateway_unavailable": "Gateway state is unavailable.",
        "gateway_mcp_error": "Gateway MCP call failed.",
        "gateway_contract_error": "Gateway response contract check failed.",
        "gateway_artifact_error": "Gateway artifact fetch failed.",
    }
    return messages.get(error.code, "Gateway mode failed.")


def browser_dnsid_context(context: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "sub",
        "dnsid",
        "accountable_entity",
        "iss",
        "scope",
        "auth_mode",
        "verified_at",
        "gateway_request_id",
        "correlation_id",
    )
    return {key: context[key] for key in allowed if key in context}
