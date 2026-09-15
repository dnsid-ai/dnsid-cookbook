#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import Session

from gateway_resources import (
    DNSID_ISSUER,
    EXPECTED_DNSID_SUB,
    REGION,
    load_state,
    require_dnsid_agent_domain,
)


def main() -> int:
    global EXPECTED_DNSID_SUB
    EXPECTED_DNSID_SUB = require_dnsid_agent_domain()
    state = load_state()
    api_base_url = state.get("api_base_url")
    if not api_base_url:
        raise RuntimeError("Missing api_base_url in Gateway state. Run make deploy-gateway.")

    direct_status = direct_unsigned_rest_status(f"{api_base_url}/whoami-dnsid")
    if direct_status != 403:
        raise RuntimeError(f"Direct unsigned API Gateway call returned {direct_status}, expected 403.")
    audience = state.get("gateway_audience")
    if not audience:
        raise RuntimeError("Missing gateway_audience in Gateway state. Run make deploy-gateway.")
    signed_valid_context_status = direct_signed_valid_context_rest_status(
        f"{api_base_url}/whoami-dnsid",
        str(audience),
    )
    if signed_valid_context_status != 403:
        raise RuntimeError(
            "Direct signed API Gateway call with valid-looking trusted headers returned "
            f"{signed_valid_context_status}, expected 403."
        )

    try:
        result = subprocess.run(
            [sys.executable, "scripts/invoke_gateway_mcp.py"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        if exc.stdout:
            print(exc.stdout, file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        raise
    mcp = json.loads(result.stdout)
    output = {
        "status": "ok",
        "direct_unsigned_rest_status": direct_status,
        "direct_signed_valid_context_rest_status": signed_valid_context_status,
        "mcp": mcp,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


def direct_unsigned_rest_status(url: str) -> int:
    request = urllib.request.Request(
        url,
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def direct_signed_valid_context_rest_status(url: str, audience: str) -> int:
    body = b"{}"
    headers = {
        "Content-Type": "application/json",
        "x-dnsid-sub": EXPECTED_DNSID_SUB,
        "x-dnsid-iss": DNSID_ISSUER,
        "x-dnsid-aud": audience,
        "x-dnsid-jti": "direct-signed-valid-context-probe",
        "x-dnsid-domain": EXPECTED_DNSID_SUB,
        "x-dnsid-auth-mode": "gateway-dnsid-lab",
        "x-dnsid-verified-at": "2026-05-28T00:00:00Z",
    }
    credentials = Session().get_credentials()
    if credentials is None:
        raise RuntimeError("AWS credentials are unavailable for signed direct-call check.")
    aws_request = AWSRequest(method="POST", url=url, data=body, headers=headers)
    SigV4Auth(credentials.get_frozen_credentials(), "execute-api", REGION).add_auth(aws_request)
    prepared = aws_request.prepare()
    request = urllib.request.Request(
        prepared.url,
        data=body,
        headers=dict(prepared.headers.items()),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"verify-gateway failed: {exc}", file=sys.stderr)
        raise
