#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from image_poc.bedrock_image import ImageGenerationError, png_dimensions


REGION = os.environ.get("AWS_REGION", "us-west-2")
CANDIDATES = (
    "stability.sd3-5-large-v1:0",
    "stability.stable-image-core-v1:1",
)
PROMPT = (
    "A clean product-style illustration of a small DNS label transforming "
    "into a glowing image tile, crisp edges, bright studio lighting"
)
ARTIFACT_DIR = Path(".artifacts/probe")


class ProbeFailure(Exception):
    pass


def stability_payload(prompt: str) -> dict[str, Any]:
    return {
        "prompt": prompt,
        "aspect_ratio": "1:1",
        "output_format": "png",
    }


def invoke_model(client: Any, model_id: str) -> dict[str, Any]:
    response = client.invoke_model(
        modelId=model_id,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(stability_payload(PROMPT)),
    )
    body = json.loads(response["body"].read().decode("utf-8"))
    finish_reasons = body.get("finish_reasons") or []
    if any(reason is not None for reason in finish_reasons):
        raise ProbeFailure(f"model returned finish_reasons={finish_reasons!r}")
    images = body.get("images") or []
    if not images:
        raise ProbeFailure("model response did not include images")
    image_bytes = base64.b64decode(images[0])
    try:
        width, height = png_dimensions(image_bytes)
    except ImageGenerationError as exc:
        raise ProbeFailure(str(exc)) from exc
    request_id = response.get("ResponseMetadata", {}).get("RequestId", "")
    return {
        "image_bytes": image_bytes,
        "width": width,
        "height": height,
        "request_id": request_id,
        "response_keys": sorted(body.keys()),
    }


def main() -> int:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    client = boto3.client(
        "bedrock-runtime",
        region_name=REGION,
        config=Config(connect_timeout=10, read_timeout=120, retries={"max_attempts": 1}),
    )

    failures: list[dict[str, str]] = []
    for model_id in CANDIDATES:
        started = time.time()
        try:
            result = invoke_model(client, model_id)
        except (BotoCoreError, ClientError, ProbeFailure, ValueError, KeyError) as exc:
            failures.append(
                {
                    "model_id": model_id,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
            continue

        artifact_path = ARTIFACT_DIR / f"{model_id.replace(':', '_').replace('.', '_')}.png"
        artifact_path.write_bytes(result["image_bytes"])
        summary = {
            "status": "ok",
            "selected_model_id": model_id,
            "region": REGION,
            "request_shape": stability_payload("<prompt>"),
            "mime_type": "image/png",
            "width": result["width"],
            "height": result["height"],
            "request_id": result["request_id"],
            "response_keys": result["response_keys"],
            "artifact_path": str(artifact_path),
            "elapsed_seconds": round(time.time() - started, 2),
            "fallback_failures": failures,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    print(
        json.dumps(
            {"status": "failed", "region": REGION, "failures": failures},
            indent=2,
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
