#!/usr/bin/env python3
from __future__ import annotations

import json
import os

from oidc_image.bedrock_image import BedrockImageGenerator
from oidc_image.config import DEFAULT_BEDROCK_IMAGE_MODEL_ID, DEFAULT_BEDROCK_REGION
from oidc_image.validation import validate_generate_payload


def main() -> int:
    region = os.environ.get("BEDROCK_REGION", DEFAULT_BEDROCK_REGION)
    model_id = os.environ.get("BEDROCK_IMAGE_MODEL_ID", DEFAULT_BEDROCK_IMAGE_MODEL_ID)
    request = validate_generate_payload(
        {
            "prompt": "A small secure image gateway rendered as a clean product icon",
            "style": "product",
            "size": "1024x1024",
        }
    )
    generated = BedrockImageGenerator(model_id=model_id, region=region).generate(request)
    print(
        json.dumps(
            {
                "status": "ok",
                "selected_model_id": generated.model_id,
                "region": generated.model_region,
                "mime_type": generated.mime_type,
                "width": generated.width,
                "height": generated.height,
                "request_id": generated.request_id,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
