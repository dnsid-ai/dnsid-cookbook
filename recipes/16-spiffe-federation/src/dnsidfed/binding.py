"""Binding statement and bundle-material rules. Pure functions: no network, no SDK calls.

Binding statement (JSON payload of a compact JWS signed by Rackloria's DNSid identity):

    {"typ": "dnsid-spiffe-federation+v0", "iss": "<signer fqdn>", "trust_domain": "rackloria.test",
     "bundle_endpoint": {"url": "...", "spiffe_id": "spiffe://rackloria.test/spire/server"},
     "x509_authorities_spki_sha256": ["<b64url>", ...], "seq": 7, "iat": 1793..., "exp": 1793...}

This statement format is specific to this recipe: the DNSid draft defines no binding for external key
material.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import BINDING_TYPE
from .policy import FederationPolicy


class BindingRejected(Exception):
    """A definitive, non-transient rejection of the binding or of the bundle material."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Statement:
    iss: str
    trust_domain: str
    endpoint_url: str
    endpoint_spiffe_id: str
    spki: frozenset[str]
    seq: int
    iat: int
    exp: int


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def spki_hash_of_der_cert(der: bytes) -> str:
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return b64u(hashlib.sha256(spki).digest())


def x509_authorities(bundle: dict) -> dict[str, dict]:
    """Map SPKI hash -> JWK for every X.509 authority in a SPIFFE bundle (JWKS). JWT keys ignored."""
    out: dict[str, dict] = {}
    for k in bundle.get("keys", []):
        if k.get("use") != "x509-svid":
            continue
        x5c = k.get("x5c") or []
        if len(x5c) != 1:
            raise BindingRejected("BUNDLE_INVALID", "x509-svid key must carry exactly one certificate")
        out[spki_hash_of_der_cert(base64.b64decode(x5c[0]))] = k
    return out


def parse_statement(payload: bytes) -> dict:
    try:
        doc = json.loads(payload)
    except ValueError as exc:
        raise BindingRejected("BINDING_MALFORMED", f"payload is not JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise BindingRejected("BINDING_MALFORMED", "payload is not a JSON object")
    return doc


def validate_statement(doc: dict, *, signer_fqdn: str, policy: FederationPolicy, now: float,
                       max_age_s: float, skew_s: float, last_seq: int | None) -> Statement:
    """Check the signed statement against Acme's policy. `signer_fqdn` is the DNSid identity that
    the SDK verified as the JWS signer (never taken from the payload)."""
    def need(key, typ):
        v = doc.get(key)
        if not isinstance(v, typ) or isinstance(v, bool):
            raise BindingRejected("BINDING_MALFORMED", f"missing or invalid '{key}'")
        return v

    if doc.get("typ") != BINDING_TYPE:
        raise BindingRejected("BINDING_MALFORMED", f"typ must be {BINDING_TYPE}")
    iss = need("iss", str).lower().rstrip(".")
    if iss != signer_fqdn.lower().rstrip("."):
        raise BindingRejected("BINDING_ISSUER_MISMATCH", f"iss {iss} != verified signer {signer_fqdn}")
    td = need("trust_domain", str)
    if td != policy.trust_domain:
        raise BindingRejected("TRUST_DOMAIN_NOT_BOUND",
                              f"statement binds '{td}', policy governs '{policy.trust_domain}'")
    ep = need("bundle_endpoint", dict)
    if ep.get("url") != policy.bundle_endpoint_url or ep.get("spiffe_id") != policy.bundle_endpoint_spiffe_id:
        raise BindingRejected("BUNDLE_ENDPOINT_MISMATCH", f"statement endpoint {ep} differs from policy")
    spki = need("x509_authorities_spki_sha256", list)
    if not spki or not all(isinstance(s, str) and s for s in spki):
        raise BindingRejected("BINDING_MALFORMED", "x509_authorities_spki_sha256 must be a non-empty list")
    seq, iat, exp = need("seq", int), need("iat", int), need("exp", int)
    if iat > now + skew_s:
        raise BindingRejected("BINDING_NOT_YET_VALID", f"iat {iat} is in the future")
    if exp <= now - skew_s:
        raise BindingRejected("BINDING_EXPIRED", f"exp {exp} has passed")
    if now - iat > max_age_s:
        raise BindingRejected("BINDING_EXPIRED", f"statement older than {max_age_s:.0f}s")
    if exp <= iat:
        raise BindingRejected("BINDING_MALFORMED", "exp must be after iat")
    if last_seq is not None and seq < last_seq:
        raise BindingRejected("BINDING_ROLLBACK", f"seq {seq} < last accepted {last_seq}")
    return Statement(iss=iss, trust_domain=td, endpoint_url=ep["url"], endpoint_spiffe_id=ep["spiffe_id"],
                     spki=frozenset(spki), seq=seq, iat=iat, exp=exp)


def select_authorities(fetched_bundle: dict, statement: Statement) -> dict:
    """Coverage rule: EVERY X.509 authority Rackloria serves must be covered by the signed set.
    Signed-but-not-yet-served authorities are allowed (pre-announced rotation). Returns the bundle to
    install: X.509 authorities only (JWT authorities are never installed; nothing verified them)."""
    fetched = x509_authorities(fetched_bundle)
    if not fetched:
        raise BindingRejected("BUNDLE_INVALID", "bundle endpoint served no X.509 authorities")
    uncovered = sorted(set(fetched) - statement.spki)
    if uncovered:
        raise BindingRejected("BUNDLE_NOT_COVERED",
                              f"served authorities not covered by the DNSid-signed binding: {uncovered}")
    out = {"keys": [fetched[h] for h in sorted(fetched)]}
    for k in ("spiffe_sequence", "spiffe_refresh_hint"):
        if k in fetched_bundle:
            out[k] = fetched_bundle[k]
    return out


def statement_hash(jws: str) -> str:
    return b64u(hashlib.sha256(jws.encode()).digest())
