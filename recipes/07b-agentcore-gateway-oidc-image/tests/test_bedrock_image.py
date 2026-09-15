import base64
import json

import pytest

from oidc_image.bedrock_image import (
    BedrockImageGenerator,
    ImageGenerationError,
    build_stability_payload,
    png_dimensions,
)
from oidc_image.validation import validate_generate_payload


def png_bytes(width=1024, height=1024):
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + width.to_bytes(
        4, "big"
    ) + height.to_bytes(4, "big") + b"\x08\x02\x00\x00\x00"


class Body:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class FakeClient:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def invoke_model(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "body": Body(self.payload),
            "ResponseMetadata": {"RequestId": "req-123"},
        }


def test_build_stability_payload_uses_styled_prompt_and_png():
    request = validate_generate_payload({"prompt": "a dns image", "style": "natural"})

    payload = build_stability_payload(request)

    assert payload == {
        "prompt": request.styled_prompt,
        "aspect_ratio": "1:1",
        "output_format": "png",
    }
    assert "natural lighting" in payload["prompt"]


def test_png_dimensions_reads_ihdr():
    assert png_dimensions(png_bytes(640, 768)) == (640, 768)


def test_bedrock_generator_decodes_success_response():
    encoded = base64.b64encode(png_bytes(640, 768)).decode("ascii")
    client = FakeClient({"images": [encoded], "finish_reasons": [None]})
    generator = BedrockImageGenerator(
        model_id="stability.sd3-5-large-v1:0",
        region="us-west-2",
        client=client,
    )

    image = generator.generate(validate_generate_payload({"prompt": "hello"}))

    assert image.mime_type == "image/png"
    assert image.width == 640
    assert image.height == 768
    assert image.request_id == "req-123"
    assert client.calls[0]["modelId"] == "stability.sd3-5-large-v1:0"
    assert json.loads(client.calls[0]["body"])["output_format"] == "png"


@pytest.mark.parametrize(
    "payload",
    [
        {"finish_reasons": ["Filter reason: prompt"]},
        {"images": [], "finish_reasons": [None]},
        {"images": ["not base64!!!"], "finish_reasons": [None]},
        {"images": [base64.b64encode(b"\x89PNG\r\n\x1a\nshort").decode("ascii")]},
    ],
)
def test_bedrock_generator_rejects_unusable_model_responses(payload):
    generator = BedrockImageGenerator("model", "region", client=FakeClient(payload))

    with pytest.raises(ImageGenerationError):
        generator.generate(validate_generate_payload({"prompt": "hello"}))
