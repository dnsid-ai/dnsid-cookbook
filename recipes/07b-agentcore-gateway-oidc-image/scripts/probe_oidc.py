#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import sys
import urllib.request
from typing import Any

from oidc_image.config import DnsidSettings, load_dnsid_settings
from oidc_image.identity import mint_dnsid_token


def main() -> int:
    dnsid = load_dnsid_settings(require_https=True)
    discovery = fetch_discovery(dnsid.server)
    claims = mint_and_decode_claims(dnsid, "dnsid-cookbook-probe")
    output = {
        "status": "ok",
        "dnsid_oidc": {
            "issuer": discovery.get("issuer"),
            "jwks_uri": discovery.get("jwks_uri"),
            "token_endpoint": discovery.get("token_endpoint"),
            "grant_types_supported": discovery.get("grant_types_supported", []),
        },
        "token_claims": {
            "iss": claims.get("iss"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
            "jti_present": bool(claims.get("jti")),
            "scope": claims.get("scope"),
        },
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    if claims.get("sub") != dnsid.agent_domain:
        print("Unexpected DNSid token subject.", file=sys.stderr)
        return 1
    return 0


def fetch_discovery(issuer: str) -> dict[str, Any]:
    with urllib.request.urlopen(
        f"{issuer}/.well-known/openid-configuration",
        timeout=20,
    ) as response:
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("OIDC discovery did not return an object.")
    return data


def mint_and_decode_claims(dnsid: DnsidSettings, audience: str) -> dict[str, Any]:
    parts = mint_dnsid_token(dnsid, audience).split(".")
    if len(parts) < 2:
        raise RuntimeError("DNSid SDK did not return a JWT.")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
