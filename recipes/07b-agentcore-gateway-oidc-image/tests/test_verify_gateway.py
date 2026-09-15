import json

import pytest

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import verify_gateway  # noqa: E402


def test_parse_response_body_handles_json_and_sse_data():
    assert verify_gateway.parse_response_body('{"ok": true}') == {"ok": True}
    assert verify_gateway.parse_response_body('event: message\ndata: {"ok": true}\n') == {
        "ok": True
    }


def test_assert_generated_contract_rejects_identity_claims():
    body = {
        "ok": True,
        "mime_type": "image/png",
        "image_sha256": "hash",
        "request_id": "req",
        "model_id": "model",
        "model_region": "region",
        "width": 1024,
        "height": 1024,
        "dnsid_context": {"sub": "agent.example"},
    }

    with pytest.raises(RuntimeError):
        verify_gateway.assert_generated_contract(body, 1024, 1024)


def test_extract_tool_json_reads_structured_content_before_text():
    body = {
        "result": {
            "structuredContent": {"ok": True},
            "content": [{"text": json.dumps({"ok": False})}],
        }
    }

    assert verify_gateway.extract_tool_json(body) == {"ok": True}
