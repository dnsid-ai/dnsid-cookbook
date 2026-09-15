from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from dataclasses import asdict
from typing import Any, Callable

from image_poc.bedrock_image import BedrockImageGenerator, ImageGenerationError
from image_poc.s3_store import S3Store
from image_poc.trusted_context import (
    TrustedContextError,
    find_identity_like_keys,
    parse_trusted_context,
)
from image_poc.validation import ValidationError, validate_generate_payload


LOGGER = logging.getLogger(__name__)


def make_handler(
    generator: Any,
    store: Any,
    expected_sub: str | None = None,
) -> Callable[[dict[str, Any], Any], dict[str, Any]]:
    def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
        path = str(event.get("path") or event.get("rawPath") or "")
        method = str(event.get("httpMethod") or event.get("requestContext", {}).get("http", {}).get("method") or "")
        if method.upper() != "POST":
            return response(405, {"ok": False, "error": {"code": "method_not_allowed"}})

        if path.endswith("/whoami-dnsid"):
            return handle_whoami(event, expected_sub)
        if path.endswith("/generate-image"):
            return handle_generate(event, generator, store, expected_sub)
        if path.endswith("/debug-denied"):
            return response(403, {"ok": False, "error": {"code": "debug_denied"}})
        return response(404, {"ok": False, "error": {"code": "not_found"}})

    return handler


def handle_whoami(
    event: dict[str, Any],
    expected_sub: str | None,
) -> dict[str, Any]:
    try:
        trusted = parse_trusted_context(event.get("headers"), expected_sub=expected_sub)
    except TrustedContextError as exc:
        return error_response(403, "trusted_context_error", str(exc))
    return response(200, {"ok": True, **trusted.to_public_dict()})


def handle_generate(
    event: dict[str, Any],
    generator: Any,
    store: Any,
    expected_sub: str | None,
) -> dict[str, Any]:
    correlation_id = uuid.uuid4().hex
    trusted = None
    request = None
    generated = None
    artifact = None
    audit_s3_uri = ""
    try:
        trusted = parse_trusted_context(event.get("headers"), expected_sub=expected_sub)
        payload = read_json_body(event)
        identity_like_keys = find_identity_like_keys(payload)
        request = validate_generate_payload(payload)
        generated = generator.generate(request)
        artifact = store.write_image(generated.image_bytes)
        prompt_hash = hashlib.sha256(request.prompt.encode("utf-8")).hexdigest()
        audit_id = store.record_audit(
            {
                "auth_mode": trusted.auth_mode,
                "tool_name": "generate_image",
                "trusted_identity": trusted.to_public_dict(),
                "token_jti": trusted.jti,
                "prompt_hash": f"sha256:{prompt_hash}",
                "style": request.style,
                "size": request.size,
                "model_id": generated.model_id,
                "model_region": generated.model_region,
                "artifact_id": artifact.artifact_id,
                "artifact_s3_uri": artifact.s3_uri,
                "mime_type": generated.mime_type,
                "width": generated.width,
                "height": generated.height,
                "request_id": generated.request_id,
                "correlation_id": correlation_id,
                "result_status": "success",
                "ignored_identity_args": identity_like_keys,
            }
        )
        audit_id, audit_s3_uri = audit_result_fields(audit_id)
        log_success(event, correlation_id, trusted, generated, artifact, audit_id)
    except TrustedContextError as exc:
        log_failure(
            event, "trusted_context_error", correlation_id, generator, trusted, request, generated, artifact, exc
        )
        return error_response(403, "trusted_context_error", str(exc), correlation_id)
    except ValueError as exc:
        log_failure(event, "invalid_json", correlation_id, generator, trusted, request, generated, artifact, exc)
        return error_response(400, "invalid_json", str(exc), correlation_id)
    except ValidationError as exc:
        log_failure(
            event, "validation_error", correlation_id, generator, trusted, request, generated, artifact, exc
        )
        return error_response(400, "validation_error", str(exc), correlation_id, exc.field)
    except ImageGenerationError as exc:
        log_failure(event, "bedrock_error", correlation_id, generator, trusted, request, generated, artifact, exc)
        return error_response(502, "bedrock_error", "Image generation failed.", correlation_id)
    except Exception as exc:
        log_failure(event, "target_error", correlation_id, generator, trusted, request, generated, artifact, exc)
        return error_response(500, "target_error", "Target execution failed.", correlation_id)

    body = {
        "ok": True,
        "artifact_url": artifact.artifact_url,
        "artifact_s3_uri": artifact.s3_uri,
        "artifact_url_expires_in": artifact.expires_in,
        "artifact_id": artifact.artifact_id,
        "mime_type": generated.mime_type,
        "width": generated.width,
        "height": generated.height,
        "model_id": generated.model_id,
        "model_region": generated.model_region,
        "request_id": generated.request_id,
        "correlation_id": correlation_id,
        "audit_id": audit_id,
        "auth_mode": trusted.auth_mode,
        "dnsid_context": trusted.to_public_dict(),
        "ignored_identity_args": identity_like_keys,
        "options": public_options(request),
    }
    if audit_s3_uri:
        body["audit_s3_uri"] = audit_s3_uri
    return response(
        200,
        body,
    )


def read_json_body(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("body")
    if body is None:
        return {}
    if event.get("isBase64Encoded"):
        raise ValueError("Base64 request bodies are not supported.")
    try:
        decoded = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError("Request body must be valid JSON.") from exc
    if not isinstance(decoded, dict):
        raise ValueError("Request body must be a JSON object.")
    return decoded


def public_options(request: Any) -> dict[str, Any]:
    options = asdict(request)
    options.pop("prompt", None)
    return options


def audit_result_fields(result: Any) -> tuple[str, str]:
    audit_id = getattr(result, "audit_id", None)
    if audit_id:
        return str(audit_id), str(getattr(result, "s3_uri", ""))
    return str(result), ""


def log_success(
    event: dict[str, Any],
    correlation_id: str,
    trusted: Any,
    generated: Any,
    artifact: Any,
    audit_id: str,
) -> None:
    record = {
        "event": "phase3_generate_success",
        "result_status": "success",
        "tool_name": "generate_image",
        "auth_mode": trusted.auth_mode,
        "dnsid_sub": trusted.sub,
        "dnsid_issuer": trusted.issuer,
        "dnsid_domain": trusted.dnsid_domain,
        "dnsid_audience": trusted.audience,
        "dnsid_status": "not_checked_phase3",
        "token_jti_present": bool(trusted.jti),
        "gateway_request_id": trusted.gateway_request_id,
        "api_request_id": str((event.get("requestContext") or {}).get("requestId") or ""),
        "correlation_id": correlation_id,
        "model_id": generated.model_id,
        "model_region": generated.model_region,
        "request_id": generated.request_id,
        "artifact_id": artifact.artifact_id,
        "artifact_s3_uri": artifact.s3_uri,
        "audit_id": audit_id,
    }
    LOGGER.warning("phase3_generate_success %s", json.dumps(record, sort_keys=True))


def log_failure(
    event: dict[str, Any],
    error_category: str,
    correlation_id: str,
    generator: Any,
    trusted: Any | None,
    request: Any | None,
    generated: Any | None,
    artifact: Any | None,
    exc: Exception,
) -> None:
    record = {
        "event": "phase3_generate_failure",
        "result_status": "failure",
        "tool_name": "generate_image",
        "error_category": error_category,
        "exception_type": type(exc).__name__,
        "correlation_id": correlation_id,
        "api_request_id": str((event.get("requestContext") or {}).get("requestId") or ""),
        "gateway_request_id": getattr(trusted, "gateway_request_id", ""),
        "model_id": getattr(generated, "model_id", None)
        or getattr(generator, "model_id", ""),
        "model_region": getattr(generated, "model_region", None)
        or getattr(generator, "region", ""),
        "token_jti": getattr(trusted, "jti", ""),
        "trusted_identity": trusted.to_public_dict() if trusted else {},
    }
    if request is not None:
        record["style"] = request.style
        record["size"] = request.size
        record["prompt_hash"] = (
            f"sha256:{hashlib.sha256(request.prompt.encode('utf-8')).hexdigest()}"
        )
    if artifact is not None:
        record["artifact_id"] = getattr(artifact, "artifact_id", "")
        record["artifact_s3_uri"] = getattr(artifact, "s3_uri", "")
    LOGGER.warning("phase3_generate_failure %s", json.dumps(record, sort_keys=True))


def response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        },
        "body": json.dumps(body, sort_keys=True),
        "isBase64Encoded": False,
    }


def error_response(
    status_code: int,
    code: str,
    message: str,
    correlation_id: str | None = None,
    field: str | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if field:
        error["field"] = field
    body: dict[str, Any] = {"ok": False, "error": error}
    if correlation_id:
        body["correlation_id"] = correlation_id
    return response(status_code, body)


def build_default_handler() -> Callable[[dict[str, Any], Any], dict[str, Any]]:
    bucket = os.environ["ARTIFACT_BUCKET"]
    prefix = os.environ.get("ARTIFACT_PREFIX", "phase3")
    bedrock_region = os.environ.get("BEDROCK_REGION", "us-west-2")
    model_id = os.environ.get("BEDROCK_IMAGE_MODEL_ID", "stability.sd3-5-large-v1:0")
    expected_sub = os.environ.get("EXPECTED_DNSID_SUB")
    if not expected_sub:
        raise RuntimeError("Missing EXPECTED_DNSID_SUB.")
    return make_handler(
        BedrockImageGenerator(model_id=model_id, region=bedrock_region),
        S3Store(bucket=bucket, prefix=prefix),
        expected_sub=expected_sub,
    )


_DEFAULT_HANDLER: Callable[[dict[str, Any], Any], dict[str, Any]] | None = None


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    global _DEFAULT_HANDLER
    if _DEFAULT_HANDLER is None:
        _DEFAULT_HANDLER = build_default_handler()
    return _DEFAULT_HANDLER(event, context)
