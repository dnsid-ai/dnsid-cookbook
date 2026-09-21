#!/usr/bin/env python3
"""Serve this identity's JWKS at /.well-known/jwks.json. Standard library only.

The `_dnsid` TXT record published for this identity points verifiers at
`ku=https://<domain>/.well-known/jwks.json` — this process is what answers
that URL. The local registry's TLS proxy terminates https://<domain> and forwards
to this server's local port.

Run under the local registry so the identity directory is injected:

    dnsid local run publish --upstream http://localhost:3201 -- \
        python3 -u src/serve.py

The public key comes from DNSID_CONFIG_DIR/public.jwk — the keypair the
`dnsid` CLI generated when the identity was provisioned. Serving anything
else here would break verification: the record's `sg=` signature and the
registry's challenge both bind the domain to exactly this key.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse


def load_jwks() -> dict:
    config_dir = os.environ.get("DNSID_CONFIG_DIR", "").strip()
    if not config_dir:
        raise SystemExit(
            "DNSID_CONFIG_DIR is not set. Run via `dnsid local run publish -- ...` "
            "so the provisioned identity directory is injected."
        )
    public_jwk = json.loads((Path(config_dir) / "public.jwk").read_text())
    return {"keys": [public_jwk]}


def port_from_env() -> int:
    upstream = os.environ.get("DNSID_AGENT_UPSTREAM", "")
    return urlparse(upstream).port or 3201


class JwksHandler(BaseHTTPRequestHandler):
    jwks: dict = {}

    def do_GET(self) -> None:
        if self.path != "/.well-known/jwks.json":
            self.send_error(404)
            return
        body = json.dumps(self.jwks).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[jwks] {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    JwksHandler.jwks = load_jwks()
    port = port_from_env()
    kid = JwksHandler.jwks["keys"][0].get("kid", "")
    print(f"serving JWKS (kid {kid}) on :{port}", flush=True)
    HTTPServer(("0.0.0.0", port), JwksHandler).serve_forever()


if __name__ == "__main__":
    main()
