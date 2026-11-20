"""Fetching the peer's SPIFFE bundle endpoint.

Bootstrap (Acme holds no bundle for the trust domain): the channel is NOT authenticated; authenticity
of the material comes solely from the DNSid-signed binding (every served X.509 authority must be in the
signed set). This replaces the manual, out-of-band bundle exchange that https_spiffe bootstrap needs.

Continuity (Acme already holds an authenticated bundle): the endpoint must present an X.509-SVID that
chains to an authority Acme ALREADY trusts and whose URI SAN is the policy's endpoint SPIFFE ID
(the https_spiffe profile). New authorities are therefore accepted only if BOTH the DNSid binding covers
them AND they are served by an endpoint authenticated with previously authenticated material, so a stolen
DNSid operational key alone cannot introduce an attacker's CA.
"""
from __future__ import annotations

import json
import ssl
import urllib.parse
from http.client import HTTPSConnection

from cryptography import x509


class BundleFetchError(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail = reason, detail


def pems_from_bundle(bundle: dict) -> list[str]:
    out = []
    for k in bundle.get("keys", []):
        if k.get("use") == "x509-svid" and k.get("x5c"):
            b64 = k["x5c"][0]
            body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
            out.append(f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
    return out


def _uri_sans(der: bytes) -> list[str]:
    cert = x509.load_der_x509_certificate(der)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return ext.value.get_values_for_type(x509.UniformResourceIdentifier)


def fetch_bundle(url: str, expected_spiffe_id: str, trusted_pems: list[str] | None,
                 timeout: float = 5.0) -> tuple[dict, str]:
    """Return (bundle_json, mode) where mode is 'bootstrap' or 'continuity'."""
    u = urllib.parse.urlsplit(url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # SPIFFE: identity is the URI SAN, checked below
    if trusted_pems:
        mode = "continuity"
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata="".join(trusted_pems))
    else:
        mode = "bootstrap"
        ctx.verify_mode = ssl.CERT_NONE
    conn = HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=timeout)
    try:
        conn.request("GET", u.path or "/")
        sock = conn.sock
        der = sock.getpeercert(binary_form=True) if sock else None
        resp = conn.getresponse()
        body = resp.read(1 << 20)
    except ssl.SSLCertVerificationError as exc:
        raise BundleFetchError("CONTINUITY_FAILED",
                               f"bundle endpoint not authenticated by currently trusted authorities: {exc}") from exc
    except (OSError, ssl.SSLError) as exc:
        raise BundleFetchError("BUNDLE_UNAVAILABLE", f"{type(exc).__name__}: {exc}") from exc
    finally:
        conn.close()
    if mode == "continuity":
        sans = _uri_sans(der) if der else []
        if expected_spiffe_id not in sans:
            raise BundleFetchError("CONTINUITY_FAILED",
                                   f"endpoint SPIFFE ID {sans} != expected {expected_spiffe_id}")
    if resp.status != 200:
        raise BundleFetchError("BUNDLE_UNAVAILABLE", f"HTTP {resp.status}")
    try:
        return json.loads(body), mode
    except ValueError as exc:
        raise BundleFetchError("BUNDLE_INVALID", f"not JSON: {exc}") from exc


def b64der_to_pem(b64: str) -> str:  # helper for tests
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(
        b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n-----END CERTIFICATE-----\n"


__all__ = ["BundleFetchError", "fetch_bundle", "pems_from_bundle", "b64der_to_pem"]
