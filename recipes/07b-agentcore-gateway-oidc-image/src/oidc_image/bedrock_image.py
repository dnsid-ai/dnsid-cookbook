from __future__ import annotations

import base64
import binascii
import json
import struct
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from oidc_image.validation import GenerateRequest


class ImageGenerationError(Exception):
    pass


@dataclass(frozen=True)
class GeneratedImage:
    image_bytes: bytes
    mime_type: str
    width: int
    height: int
    model_id: str
    model_region: str
    request_id: str


def build_stability_payload(request: GenerateRequest) -> dict[str, Any]:
    return {
        "prompt": request.styled_prompt,
        "aspect_ratio": request.aspect_ratio,
        "output_format": "png",
    }


def png_dimensions(image_bytes: bytes) -> tuple[int, int]:
    if len(image_bytes) < 24 or not image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ImageGenerationError("Bedrock returned non-PNG image bytes.")
    if image_bytes[12:16] != b"IHDR":
        raise ImageGenerationError("Bedrock returned a PNG without an IHDR header.")
    try:
        return struct.unpack(">II", image_bytes[16:24])
    except struct.error as exc:
        raise ImageGenerationError("Bedrock returned truncated PNG metadata.") from exc


class BedrockImageGenerator:
    def __init__(
        self,
        model_id: str,
        region: str,
        client: Any | None = None,
    ) -> None:
        self.model_id = model_id
        self.region = region
        self.client = client or boto3.client(
            "bedrock-runtime",
            region_name=region,
            config=Config(
                connect_timeout=10,
                read_timeout=120,
                retries={"max_attempts": 1},
            ),
        )

    def generate(self, request: GenerateRequest) -> GeneratedImage:
        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(build_stability_payload(request)),
            )
            body = json.loads(response["body"].read().decode("utf-8"))
        except (BotoCoreError, ClientError, KeyError, ValueError) as exc:
            raise ImageGenerationError(
                f"Bedrock invocation failed for {self.model_id} in {self.region}: {exc}"
            ) from exc

        finish_reasons = body.get("finish_reasons") or []
        if any(reason is not None for reason in finish_reasons):
            raise ImageGenerationError(
                f"Bedrock rejected generation for {self.model_id}: {finish_reasons}"
            )

        images = body.get("images") or []
        if not images:
            raise ImageGenerationError(
                f"Bedrock response for {self.model_id} did not include an image."
            )

        try:
            image_bytes = base64.b64decode(images[0], validate=True)
            width, height = png_dimensions(image_bytes)
        except (binascii.Error, ValueError, TypeError, ImageGenerationError) as exc:
            raise ImageGenerationError(
                f"Bedrock returned an unreadable image for {self.model_id}: {exc}"
            ) from exc

        request_id = response.get("ResponseMetadata", {}).get("RequestId", "")
        return GeneratedImage(
            image_bytes=image_bytes,
            mime_type="image/png",
            width=width,
            height=height,
            model_id=self.model_id,
            model_region=self.region,
            request_id=request_id,
        )
