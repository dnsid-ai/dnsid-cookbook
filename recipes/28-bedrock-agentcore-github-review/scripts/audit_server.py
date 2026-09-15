#!/usr/bin/env python3
"""Minimal audit server for local recipe testing.

Accepts POST /audit with a DNSid Bearer token. Validates the token against
the issuer's JWKS, then logs and stores the audit record in memory.

Usage:
    python scripts/audit_server.py

Environment:
    AUDIT_PORT          Port to listen on (default: 9090)
    ALLOWED_ISSUERS     Comma-separated list of allowed DNSid domains.
                        If unset, any valid token is accepted (dev mode).

In the recipe, the bot's BOT_DOMAIN should appear in ALLOWED_ISSUERS so
only the known review bot can submit audit records.
"""

import json
import os
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import httpx
import jwt  # PyJWT

PORT = int(os.environ.get("AUDIT_PORT", "9090"))
ALLOWED_ISSUERS = [
    d.strip()
    for d in os.environ.get("ALLOWED_ISSUERS", "").split(",")
    if d.strip()
]

# In-memory audit log — good enough for a recipe demo
audit_log: list[dict] = []


def _validate_token(token: str) -> dict:
    """Validate a DNSid OIDC token and return its claims.

    Fetches the JWKS from the issuer's /.well-known/openid-configuration,
    verifies the signature, and checks the issuer against the allowlist.

    Raises ValueError with a reason string on any failure.
    """
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.DecodeError as e:
        raise ValueError(f"malformed token: {e}") from e

    issuer = unverified.get("iss", "")
    if not issuer:
        raise ValueError("token missing iss claim")

    if ALLOWED_ISSUERS and issuer not in ALLOWED_ISSUERS:
        raise ValueError(f"issuer not allowed: {issuer}")

    # Fetch OIDC discovery → JWKS URI
    discovery_url = f"https://{issuer}/.well-known/openid-configuration"
    try:
        discovery = httpx.get(discovery_url, timeout=5).json()
        jwks_uri = discovery["jwks_uri"]
        jwks = httpx.get(jwks_uri, timeout=5).json()
    except Exception as e:
        raise ValueError(f"could not fetch JWKS for {issuer}: {e}") from e

    # Verify signature
    try:
        jwks_client = jwt.PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["EdDSA", "ES256", "RS256"],
            audience=None,
            options={"verify_aud": False},
        )
    except jwt.PyJWTError as e:
        raise ValueError(f"signature verification failed: {e}") from e

    return claims


class AuditHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # suppress default access log
        pass

    def _respond(self, status: int, body: dict):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if urlparse(self.path).path != "/audit":
            self._respond(404, {"error": "not found"})
            return

        # Extract Bearer token
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._respond(401, {"error": "Authorization: Bearer <token> required"})
            return
        token = auth.removeprefix("Bearer ").strip()

        # Validate DNSid token
        try:
            claims = _validate_token(token)
        except ValueError as e:
            print(f"[audit] rejected: {e}")
            self._respond(401, {"error": str(e)})
            return

        # Read body
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        record = {
            "id": str(uuid.uuid4()),
            "ts": time.time(),
            "agent": claims.get("iss"),
            "pr_url": body.get("pr_url"),
            "summary": body.get("summary"),
        }
        audit_log.append(record)
        print(f"[audit] ✓ agent={record['agent']} pr={record['pr_url']}")
        self._respond(200, {"id": record["id"]})

    def do_GET(self):
        if urlparse(self.path).path != "/audit":
            self._respond(404, {"error": "not found"})
            return
        self._respond(200, {"records": audit_log})


if __name__ == "__main__":
    server = HTTPServer(("", PORT), AuditHandler)
    issuers = ", ".join(ALLOWED_ISSUERS) if ALLOWED_ISSUERS else "any (dev mode)"
    print(f"[audit] listening on :{PORT}  allowed issuers: {issuers}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[audit] stopped")
