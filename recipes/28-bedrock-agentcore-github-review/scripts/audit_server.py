#!/usr/bin/env python3
"""Minimal audit server for local recipe testing.

Accepts POST /audit with a DNSid OIDC Bearer token. Validates it against
a configured issuer's JWKS, then stores the audit record in memory.

Usage:
    python scripts/audit_server.py

Environment:
    AUDIT_PORT          Port to listen on (default: 9090)
    AUDIT_ISSUER      Trusted HTTPS OIDC issuer URL (e.g. https://oidc.dnsid.ai).
    AUDIT_SUBJECT     Allowed bot domain (the issued token's sub claim).
    AUDIT_AUDIENCE    Exact AUDIT_ENDPOINT used to mint the token.

All three are required. This demo binds to loopback only.
"""

import json
import os
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, urlsplit

import httpx
import jwt  # PyJWT

PORT = int(os.environ.get("AUDIT_PORT", "9090"))
ISSUER = os.environ.get("AUDIT_ISSUER", "").strip()
SUBJECT = os.environ.get("AUDIT_SUBJECT", "").strip()
AUDIENCE = os.environ.get("AUDIT_AUDIENCE", "").strip()

# In-memory audit log — good enough for a recipe demo
audit_log: list[dict] = []


def _issuer_origin() -> str:
    url = urlsplit(ISSUER)
    if (url.scheme != "https" or not url.hostname or url.username is not None
            or url.path or url.query or url.fragment):
        raise ValueError("AUDIT_ISSUER must be an HTTPS origin without credentials or a path")
    if not SUBJECT or not AUDIENCE:
        raise ValueError("AUDIT_SUBJECT and AUDIT_AUDIENCE are required")
    return f"https://{url.netloc}"


def _validate_token(token: str) -> dict:
    """Verify a token using only the configured issuer and its same-origin JWKS."""
    origin = _issuer_origin()
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        if unverified.get("iss") != ISSUER:
            raise ValueError("issuer not allowed")

        with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
            response = client.get(f"{origin}/.well-known/openid-configuration")
            response.raise_for_status()
            discovery = response.json()
            if discovery.get("issuer") != ISSUER:
                raise ValueError("discovery issuer mismatch")
            jwks_uri = discovery["jwks_uri"]
            jwks_url = urlsplit(jwks_uri)
            if (jwks_url.scheme != "https" or jwks_url.netloc != urlsplit(origin).netloc
                    or not jwks_url.path.startswith("/") or jwks_url.fragment):
                raise ValueError("JWKS URL must use the trusted issuer origin")
            response = client.get(jwks_uri)
            response.raise_for_status()
            jwks = response.json()

        header = jwt.get_unverified_header(token)
        if header.get("alg") not in ("EdDSA", "ES256", "RS256") or not header.get("kid"):
            raise ValueError("unsupported JWT key or algorithm")
        keys = [key for key in jwt.PyJWKSet.from_dict(jwks).keys if key.key_id == header["kid"]]
        if len(keys) != 1:
            raise ValueError("JWT key not found or ambiguous")
        claims = jwt.decode(
            token, keys[0].key, algorithms=[header["alg"]],
            issuer=ISSUER, audience=AUDIENCE,
            options={"require": ["iss", "sub", "aud", "exp", "iat"]},
        )
        if claims["sub"] != SUBJECT:
            raise ValueError("subject not allowed")
        return claims
    except (httpx.HTTPError, jwt.PyJWTError, KeyError, TypeError) as e:
        raise ValueError(f"invalid token or issuer response: {e}") from e


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
            "agent": claims["sub"],
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
    _issuer_origin()  # Fail closed before accepting requests.
    server = HTTPServer(("127.0.0.1", PORT), AuditHandler)
    print(f"[audit] listening on 127.0.0.1:{PORT}  issuer: {ISSUER}  bot: {SUBJECT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[audit] stopped")
