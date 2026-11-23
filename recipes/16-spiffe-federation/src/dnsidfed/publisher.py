"""Rackloria binding publisher.

    python -m dnsidfed.publisher

Every few seconds reads Rackloria's CURRENT trust bundle from its own SPIRE server (admin API, the
authoritative source), and whenever the X.509 authority set changes - or the last statement is close to
expiry - signs a new binding statement with Rackloria's DNSid identity (agent operational key, via the
SDK's JOSE profile) and serves it at GET /binding.jws (plain HTTP is fine: the content is signed).

Includes every authority SPIRE publishes, including prepared-but-not-yet-active ones, so a CA rotation
is pre-announced before the new authority is used.

Environment: the DNSID_* variables of a single signer identity (never the registry API key), plus
SPIRE_ADMIN_SOCKET, BINDING_TRUST_DOMAIN, BINDING_ENDPOINT_URL, BINDING_ENDPOINT_SPIFFE_ID.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dnsid import JoseProfile, identity_manager_from_environment

from . import BINDING_TYPE
from .binding import statement_hash, x509_authorities
from .spire import SpireAdmin

log = logging.getLogger("dnsidfed.publisher")
LIFETIME_S = 900
RESIGN_BEFORE_S = 300


class Publisher:
    def __init__(self):
        self.spire = SpireAdmin(os.environ.get("SPIRE_ADMIN_SOCKET", "/run/spire/server/api.sock"))
        self.domain = os.environ["DNSID_DOMAIN"]
        self.td = os.environ["BINDING_TRUST_DOMAIN"]
        self.ep_url = os.environ["BINDING_ENDPOINT_URL"]
        self.ep_id = os.environ["BINDING_ENDPOINT_SPIFFE_ID"]
        self.lock = threading.Lock()
        self.jws: str | None = None
        self.stmt: dict | None = None
        self.error: str | None = None
        self.next_attempt = 0.0   # backoff after failed signing (each attempt is a full DNSid verification)
        self.backoff = 5.0

    def sign(self, spki: list[str]) -> None:
        now = int(time.time())
        stmt = {"typ": BINDING_TYPE, "iss": self.domain, "trust_domain": self.td,
                "bundle_endpoint": {"url": self.ep_url, "spiffe_id": self.ep_id},
                "x509_authorities_spki_sha256": spki, "seq": now, "iat": now, "exp": now + LIFETIME_S}
        with identity_manager_from_environment() as m:  # fresh per signature
            jws = JoseProfile.from_identity_manager(m).create_jws(json.dumps(stmt, sort_keys=True).encode())
        with self.lock:
            self.jws, self.stmt, self.error = jws, stmt, None
        log.info(json.dumps({"layer": "DNSid", "msg": "binding signed", "signer": self.domain,
                             "spki": spki, "seq": now, "hash": statement_hash(jws)}))

    def tick(self) -> None:
        if time.time() < self.next_attempt:
            return
        try:
            spki = sorted(x509_authorities(self.spire.own_bundle()))
            with self.lock:
                cur = self.stmt
            if cur is None or cur["x509_authorities_spki_sha256"] != spki or \
                    cur["exp"] - time.time() < RESIGN_BEFORE_S:
                self.sign(spki)
            self.backoff = 5.0
        except Exception as exc:  # noqa: BLE001 - keep serving last good statement; report error
            with self.lock:
                self.error = f"{type(exc).__name__}: {exc}"
            self.next_attempt = time.time() + self.backoff
            log.warning(json.dumps({"msg": "publish failed", "error": self.error[:300],
                                    "retry_in_s": self.backoff}))
            self.backoff = min(self.backoff * 2, 120.0)


def serve(pub: Publisher, port: int) -> None:
    class H(BaseHTTPRequestHandler):
        def _send(self, code, body: bytes, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            with pub.lock:
                jws, stmt, err = pub.jws, pub.stmt, pub.error
            if self.path == "/binding.jws":
                if not jws:
                    return self._send(503, b"no binding signed yet\n", "text/plain")
                return self._send(200, jws.encode(), "application/jose")
            if self.path == "/status":
                body = json.dumps({"signer": pub.domain, "statement": stmt, "error": err,
                                   "hash": statement_hash(jws) if jws else None}).encode()
                return self._send(200, body, "application/json")
            if self.path == "/healthz":
                return self._send(200 if jws else 503, b"ok\n" if jws else b"not yet\n", "text/plain")
            self._send(404, b"not found\n", "text/plain")

        def log_message(self, *a):
            pass

    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    pub = Publisher()
    threading.Thread(target=serve, args=(pub, 8080), daemon=True).start()
    while True:
        pub.tick()
        time.sleep(float(os.environ.get("PUBLISH_INTERVAL_S", "5")))


if __name__ == "__main__":
    sys.exit(main())
