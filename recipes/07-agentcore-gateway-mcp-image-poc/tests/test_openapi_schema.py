import json
from pathlib import Path


def test_generate_image_schema_does_not_advertise_spoofable_identity_fields():
    schema_path = Path(__file__).resolve().parents[1] / "infra/openapi/image-api.openapi.json"
    openapi = json.loads(schema_path.read_text(encoding="utf-8"))

    schema = openapi["components"]["schemas"]["GenerateImageRequest"]
    properties = schema["properties"]

    assert schema["additionalProperties"] is False
    assert properties["client_context"]["additionalProperties"] is True
    assert "Ignored for identity" in properties["client_context"]["description"]
    assert "identity" not in properties
    assert "dnsid" not in properties
    assert "sub" not in properties
    assert "x_dnsid_sub" not in properties
