#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from image_poc.config import load_mode


HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8787"))
BASE_URL = f"http://{HOST}:{PORT}"
IMAGE_POC_MODE = load_mode()
EXPECTED_AUTH_MODE = "local-test" if IMAGE_POC_MODE == "local-test" else "gateway-dnsid"


def request_json(path: str, payload: dict | None = None) -> tuple[int, dict]:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE_URL + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def main() -> int:
    health_status, health = request_json("/api/health")
    if health_status != 200 or not health.get("ok"):
        print(f"health failed: {health_status} {health}", file=sys.stderr)
        return 1
    if health.get("auth_mode") != EXPECTED_AUTH_MODE:
        print(f"unexpected health auth_mode: {health}", file=sys.stderr)
        return 1

    status, generated = request_json(
        "/api/generate",
        {
            "prompt": "A compact visual metaphor for DNS identity unlocking image generation",
            "style": "product",
            "size": "1024x1024",
        },
    )
    if status != 200 or not generated.get("ok"):
        print(f"generation failed: {status} {generated}", file=sys.stderr)
        return 1

    required = [
        "artifact_url",
        "artifact_id",
        "mime_type",
        "width",
        "height",
        "model_id",
        "model_region",
        "request_id",
        "correlation_id",
        "audit_id",
        "auth_mode",
    ]
    missing = [field for field in required if field not in generated]
    if missing:
        print(f"generation response missing fields: {missing}", file=sys.stderr)
        return 1
    if generated["auth_mode"] != EXPECTED_AUTH_MODE:
        print(f"unexpected auth_mode: {generated['auth_mode']}", file=sys.stderr)
        return 1
    if not str(generated["artifact_url"]).startswith("/artifacts/"):
        print(f"artifact_url was not local-only: {generated['artifact_url']}", file=sys.stderr)
        return 1
    serialized = json.dumps(generated, sort_keys=True)
    forbidden = [
        "Authorization",
        "Bearer ",
        "X-Amz-Signature",
        "X-Amz-Credential",
        "artifact_s3_uri",
        "audit_s3_uri",
        "artifact_url_expires_in",
        "remote_artifact_url",
    ]
    leaked = [text for text in forbidden if text in serialized]
    if leaked:
        print(f"generation response exposed forbidden fields: {leaked}", file=sys.stderr)
        return 1
    if IMAGE_POC_MODE == "gateway":
        gateway_required = [
            "remote_artifact_id",
            "dnsid_context",
            "dnsid_sub",
            "dnsid_issuer",
        ]
        gateway_missing = [field for field in gateway_required if not generated.get(field)]
        if gateway_missing:
            print(f"gateway response missing fields: {gateway_missing}", file=sys.stderr)
            return 1

    with urllib.request.urlopen(BASE_URL + generated["artifact_url"], timeout=30) as response:
        image = response.read()
        content_type = response.headers.get("Content-Type")
    if content_type != "image/png" or not image.startswith(b"\x89PNG\r\n\x1a\n"):
        print("artifact did not load as PNG", file=sys.stderr)
        return 1

    error_status, error = request_json("/api/generate", {"prompt": ""})
    if error_status != 400 or error.get("error", {}).get("code") != "validation_error":
        print(f"validation error path failed: {error_status} {error}", file=sys.stderr)
        return 1

    output_fields = list(required)
    if IMAGE_POC_MODE == "gateway":
        output_fields.extend(["remote_artifact_id", "dnsid_sub", "dnsid_issuer"])
    print(
        json.dumps(
            {
                "status": "ok",
                "health": health,
                "generated": {
                    key: generated[key]
                    for key in output_fields
                    if key in generated
                },
                "artifact_bytes": len(image),
                "validation_error": error["error"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
