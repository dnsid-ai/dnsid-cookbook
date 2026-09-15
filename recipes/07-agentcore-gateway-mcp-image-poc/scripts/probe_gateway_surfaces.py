#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import subprocess
import sys
import urllib.request
from typing import Any

from gateway_resources import (
    DNSID_CLI,
    DNSID_ISSUER,
    EXPECTED_DNSID_SUB,
    PROVISIONAL_AUDIENCE,
    account_id,
    client,
    require_dnsid_agent_domain,
)


def main() -> int:
    global EXPECTED_DNSID_SUB
    EXPECTED_DNSID_SUB = require_dnsid_agent_domain()
    status = dnsid_status()
    claims = mint_and_decode_claims(PROVISIONAL_AUDIENCE)
    output = {
        "account_id": account_id(),
        "agentcore_control_available": "bedrock-agentcore-control"
        in client("bedrock-agentcore-control").meta.service_model.service_name,
        "dnsid_oidc": dnsid_oidc_summary(),
        "dnsid_status": status,
        "token_claims": safe_claims(claims),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    if claims.get("sub") != EXPECTED_DNSID_SUB:
        print("Unexpected DNSid token subject.", file=sys.stderr)
        return 1
    return 0


def dnsid_oidc_summary() -> dict[str, Any]:
    with urllib.request.urlopen(
        f"{DNSID_ISSUER}/.well-known/openid-configuration",
        timeout=20,
    ) as response:
        data = json.loads(response.read().decode("utf-8"))
    return {
        "issuer": data.get("issuer"),
        "jwks_uri": data.get("jwks_uri"),
        "algorithms": data.get("id_token_signing_alg_values_supported", []),
    }


def dnsid_status() -> dict[str, Any]:
    result = subprocess.run(
        [
            DNSID_CLI,
            "--server",
            DNSID_ISSUER,
            "status",
            "--domain",
            EXPECTED_DNSID_SUB,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return parse_status_output(result.stdout)


def parse_status_output(output: str) -> dict[str, Any]:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip().lower()] = value.strip()
    return {
        "id": fields.get("agent"),
        "domain": fields.get("domain"),
        "status": fields.get("status"),
        "environment": fields.get("environment"),
    }


def mint_and_decode_claims(audience: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            DNSID_CLI,
            "--server",
            DNSID_ISSUER,
            "token",
            "--domain",
            EXPECTED_DNSID_SUB,
            "--audience",
            audience,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return decode_claims(result.stdout.strip())


def decode_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("DNSid CLI did not return a JWT.")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))


def safe_claims(claims: dict[str, Any]) -> dict[str, Any]:
    return {
        "iss": claims.get("iss"),
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
        "jti_present": bool(claims.get("jti")),
        "token_type": claims.get("token_type"),
    }


if __name__ == "__main__":
    raise SystemExit(main())
