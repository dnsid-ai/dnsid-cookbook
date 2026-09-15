import pytest

from oidc_image.validation import (
    MAX_PROMPT_CHARS,
    ValidationError,
    validate_generate_payload,
)


def test_validate_generate_payload_defaults_and_normalizes_prompt():
    request = validate_generate_payload({"prompt": "  secure   image gateway  "})

    assert request.prompt == "secure image gateway"
    assert request.style == "product"
    assert request.size == "1024x1024"
    assert request.aspect_ratio == "1:1"
    assert "studio lighting" in request.styled_prompt


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({}, "prompt"),
        ({"prompt": "   "}, "prompt"),
        ({"prompt": "x", "style": "watercolor"}, "style"),
        ({"prompt": "x", "size": "2048x2048"}, "size"),
    ],
)
def test_validate_generate_payload_rejects_invalid_inputs(payload, field):
    with pytest.raises(ValidationError) as excinfo:
        validate_generate_payload(payload)

    assert excinfo.value.field == field


def test_validate_generate_payload_rejects_long_prompt():
    with pytest.raises(ValidationError) as excinfo:
        validate_generate_payload({"prompt": "x" * (MAX_PROMPT_CHARS + 1)})

    assert excinfo.value.field == "prompt"
