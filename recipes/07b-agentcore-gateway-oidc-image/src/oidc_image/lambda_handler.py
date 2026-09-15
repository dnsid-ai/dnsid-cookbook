from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import asdict
from typing import Any, Callable

from oidc_image.bedrock_image import BedrockImageGenerator, ImageGenerationError
from oidc_image.config import DEFAULT_BEDROCK_IMAGE_MODEL_ID, DEFAULT_BEDROCK_REGION
from oidc_image.validation import ValidationError, validate_generate_payload


def make_handler(generator: Any) -> Callable[[dict[str, Any], Any], dict[str, Any]]:
    def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
        tool_name = gateway_tool_name(context)
        if tool_name and not tool_name.endswith("generate_image"):
            return error_response("unknown_tool", f"Unsupported tool: {tool_name}")
        try:
            request = validate_generate_payload(event)
            generated = generator.generate(request)
        except ValidationError as exc:
            return error_response("validation_error", str(exc), field=exc.field)
        except ImageGenerationError:
            return error_response("bedrock_error", "Image generation failed.")

        image_base64 = base64.b64encode(generated.image_bytes).decode("ascii")
        options = asdict(request)
        options.pop("prompt", None)
        return {
            "ok": True,
            "image_base64": image_base64,
            "image_sha256": hashlib.sha256(generated.image_bytes).hexdigest(),
            "mime_type": generated.mime_type,
            "width": generated.width,
            "height": generated.height,
            "model_id": generated.model_id,
            "model_region": generated.model_region,
            "request_id": generated.request_id,
            "tool_name": tool_name,
            "options": options,
        }

    return handler


def gateway_tool_name(context: Any) -> str:
    client_context = getattr(context, "client_context", None)
    custom = getattr(client_context, "custom", None)
    if isinstance(custom, dict):
        return str(custom.get("bedrockAgentCoreToolName") or "")
    return ""


def error_response(code: str, message: str, field: str | None = None) -> dict[str, Any]:
    error: dict[str, str] = {"code": code, "message": message}
    if field:
        error["field"] = field
    return {"ok": False, "error": error}


def build_default_handler() -> Callable[[dict[str, Any], Any], dict[str, Any]]:
    return make_handler(
        BedrockImageGenerator(
            model_id=os.environ.get("BEDROCK_IMAGE_MODEL_ID", DEFAULT_BEDROCK_IMAGE_MODEL_ID),
            region=os.environ.get("BEDROCK_REGION", DEFAULT_BEDROCK_REGION),
        )
    )


lambda_handler = build_default_handler()
