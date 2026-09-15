from types import SimpleNamespace

from oidc_image.bedrock_image import GeneratedImage, ImageGenerationError
from oidc_image.lambda_handler import make_handler

from test_bedrock_image import png_bytes


class FakeGenerator:
    def __init__(self, image_bytes=None, error=None):
        self.image_bytes = image_bytes or png_bytes()
        self.error = error
        self.requests = []

    def generate(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return GeneratedImage(
            image_bytes=self.image_bytes,
            mime_type="image/png",
            width=1024,
            height=1024,
            model_id="model-id",
            model_region="us-west-2",
            request_id="req-123",
        )


def context(tool_name="ImageLambdaTarget___generate_image"):
    return SimpleNamespace(
        client_context=SimpleNamespace(
            custom={"bedrockAgentCoreToolName": tool_name}
        )
    )


def test_handler_returns_image_contract_without_identity_claims():
    generator = FakeGenerator()
    handler = make_handler(generator)

    response = handler({"prompt": "hello", "style": "natural"}, context())

    assert response["ok"] is True
    assert response["mime_type"] == "image/png"
    assert response["width"] == 1024
    assert response["height"] == 1024
    assert response["model_id"] == "model-id"
    assert response["model_region"] == "us-west-2"
    assert response["request_id"] == "req-123"
    assert response["tool_name"] == "ImageLambdaTarget___generate_image"
    assert response["options"] == {"style": "natural", "size": "1024x1024"}
    assert "image_base64" in response
    assert "image_sha256" in response
    assert "dnsid_context" not in response
    assert "trusted_identity" not in response


def test_handler_rejects_unknown_tool():
    response = make_handler(FakeGenerator())({"prompt": "hello"}, context("Other___tool"))

    assert response == {
        "ok": False,
        "error": {
            "code": "unknown_tool",
            "message": "Unsupported tool: Other___tool",
        },
    }


def test_handler_returns_validation_error():
    response = make_handler(FakeGenerator())({"prompt": ""}, context())

    assert response["ok"] is False
    assert response["error"]["code"] == "validation_error"
    assert response["error"]["field"] == "prompt"


def test_handler_hides_bedrock_error_details():
    response = make_handler(FakeGenerator(error=ImageGenerationError("secret detail")))(
        {"prompt": "hello"},
        context(),
    )

    assert response == {
        "ok": False,
        "error": {"code": "bedrock_error", "message": "Image generation failed."},
    }
