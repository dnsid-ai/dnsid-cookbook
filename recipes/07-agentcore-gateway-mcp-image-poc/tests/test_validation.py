import pytest

from image_poc.validation import ValidationError, validate_generate_payload


def test_validate_generate_payload_defaults_options():
    request = validate_generate_payload({"prompt": "  a bright image   of dns  "})

    assert request.prompt == "a bright image of dns"
    assert request.style == "product"
    assert request.size == "1024x1024"
    assert request.aspect_ratio == "1:1"


def test_validate_generate_payload_rejects_empty_prompt():
    with pytest.raises(ValidationError) as excinfo:
        validate_generate_payload({"prompt": "   "})

    assert excinfo.value.field == "prompt"
    assert "required" in str(excinfo.value)


def test_validate_generate_payload_rejects_invalid_style():
    with pytest.raises(ValidationError) as excinfo:
        validate_generate_payload({"prompt": "hello", "style": "dnsid"})

    assert excinfo.value.field == "style"


def test_validate_generate_payload_rejects_invalid_size():
    with pytest.raises(ValidationError) as excinfo:
        validate_generate_payload({"prompt": "hello", "size": "4096x4096"})

    assert excinfo.value.field == "size"
