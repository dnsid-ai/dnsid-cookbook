"""Shared fakes and crypto fixtures for the offline tests (real EC P-256 CA certs, in-memory SPIRE, fake verifier)."""
from __future__ import annotations

import base64
import copy
import datetime as dt
import json
import types

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from dnsidfed import BINDING_TYPE
from dnsidfed.binding import spki_hash_of_der_cert
from dnsidfed.policy import FederationPolicy, Policy, VerificationSettings
from dnsidfed.reconcile import Reconciler, State
from dnsidfed.verifier import DnsidDenied, VerifiedBinding

NOW = 1_800_000_000.0
TD = "rackloria.test"
GOV = "rackloria.test"
SIGNER = "spire-fed-abc.rackloria.test"
ENDPOINT_URL = "https://rackloria-spire.test:8443/bundle"
ENDPOINT_ID = "spiffe://rackloria.test/spire/server"
ENTRIES = ("spiffe://acme.test/purchasing",)


def make_policy(grace=30.0, **fed_over) -> Policy:
    kw = dict(trust_domain=TD, governance_id=GOV, entity_key_thumbprints=("thumb1",),
              signer_pattern="spire-fed-*." + GOV, binding_url="http://r/binding",
              bundle_endpoint_url=ENDPOINT_URL, bundle_endpoint_spiffe_id=ENDPOINT_ID,
              federated_entries=ENTRIES)
    kw.update(fed_over)
    return Policy(FederationPolicy(**kw),
                  VerificationSettings(unavailable_grace_s=grace, log_policy_file="/nonexistent/log.policy"))


# ------------------------------------------------------------------ crypto fixtures
class CA:
    def __init__(self, cn="ca", uri=None):
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
             .not_valid_after(dt.datetime(2036, 1, 1, tzinfo=dt.timezone.utc))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True))
        if uri:
            b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False)
        self.cert = b.sign(self.key, hashes.SHA256())
        self.der = self.cert.public_bytes(Encoding.DER)
        self.b64 = base64.b64encode(self.der).decode()
        self.spki = spki_hash_of_der_cert(self.der)

    def jwk(self):
        n = self.key.public_key().public_numbers()
        enc = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()  # noqa: E731
        return {"use": "x509-svid", "kty": "EC", "crv": "P-256", "x": enc(n.x), "y": enc(n.y), "x5c": [self.b64]}


def jwt_key(kid="jwt1"):
    k = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    enc = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()  # noqa: E731
    return {"use": "jwt-svid", "kty": "EC", "crv": "P-256", "kid": kid, "x": enc(k.x), "y": enc(k.y)}


def bundle_of(*cas, jwt=True, seq=1):
    keys = [c.jwk() for c in cas]
    if jwt:
        keys.append(jwt_key())
    return {"keys": keys, "spiffe_sequence": seq, "spiffe_refresh_hint": 60}


def good_doc(*cas, seq=5, now=NOW, **over):
    doc = {"typ": BINDING_TYPE, "iss": SIGNER, "trust_domain": TD,
           "bundle_endpoint": {"url": ENDPOINT_URL, "spiffe_id": ENDPOINT_ID},
           "x509_authorities_spki_sha256": [c.spki for c in cas] or ["abc"],
           "seq": seq, "iat": int(now) - 10, "exp": int(now) + 600}
    doc.update(over)
    return doc


# ------------------------------------------------------------------ fakes
class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class FakeSpire:
    def __init__(self):
        self.bundles: dict[str, dict] = {}
        self.calls: list[tuple] = []
        self.federated: dict[str, set] = {}

    def get_bundle(self, td):
        b = self.bundles.get(td)
        return copy.deepcopy(b) if b else None

    def set_bundle(self, td, bundle):
        self.calls.append(("set_bundle", td, copy.deepcopy(bundle)))
        self.bundles[td] = copy.deepcopy(bundle)

    def delete_bundle(self, td, mode="dissociate"):
        """Models SPIRE: "restrict" refuses while any entry federates with td; "dissociate" strips td from all."""
        self.calls.append(("delete_bundle", td, mode))
        if td not in self.bundles:
            return False
        users = sorted(sid for sid, tds in self.federated.items() if td in tds)
        if mode == "restrict" and users:
            from dnsidfed.spire import SpireError
            raise SpireError(f"bundle delete failed: entries still federate with {td}: {users}")
        for tds in self.federated.values():
            tds.discard(td)
        del self.bundles[td]
        return True

    def remove_federates(self, sid, td):
        self.calls.append(("remove_federates", sid, td))
        tds = self.federated.setdefault(sid, set())
        changed = td in tds
        tds.discard(td)
        return changed

    def ensure_federates(self, sid, td):
        self.calls.append(("ensure_federates", sid, td))
        s = self.federated.setdefault(sid, set())
        changed = td not in s
        s.add(td)
        return changed

    def names(self):
        return [c[0] for c in self.calls]


class FakeVerifier:
    """Stands in for DnsidVerifier: returns a VerifiedBinding for env's current statement, or raises."""

    def __init__(self, env):
        self.env, self.error, self.calls, self.signer = env, None, 0, SIGNER

    def verify(self, jws):
        self.calls += 1
        if self.error:
            raise self.error
        e = self.env
        return VerifiedBinding(
            payload=json.dumps(e.doc()).encode(), signer=self.signer, governance_id=GOV,
            entity_key_thumbprint="thumb1", logged_state="ACTIVE", log_reference="log#1",
            checkpoint_origin="origin", checkpoint_size=7, checkpoint_root="root",
            witness_time=dt.datetime.fromtimestamp(e.clock() - 5, dt.timezone.utc), dnssec="SECURE")


class Env:
    """A Reconciler wired to fakes. Mutate attributes between cycles to script Rackloria's behaviour."""

    def __init__(self, tmp_path, grace=30.0):
        self.clock = Clock()
        self.policy = make_policy(grace)
        self.A, self.B = CA("A"), CA("B")
        self.served = bundle_of(self.A)          # what the bundle endpoint serves
        self.signed = [self.A]                   # authorities covered by the signed statement
        self.seq = 5
        self.doc_over: dict = {}
        self.binding_error = None
        self.bundle_error = None
        self.bundle_calls: list[tuple] = []
        self.spire = FakeSpire()
        self.verifier = FakeVerifier(self)
        self.state_path = tmp_path / "state.json"
        self.state = State(str(self.state_path))
        self.audit: list = []
        self.rec = self.make_reconciler(self.state)

    def make_reconciler(self, state):
        return Reconciler(self.policy, self.verifier, self.spire, state, fetch_binding=self._fetch_binding,
                          fetch_bundle_fn=self._fetch_bundle, clock=self.clock, audit=self.audit.append)

    def doc(self):
        return good_doc(*self.signed, seq=self.seq, now=self.clock(), **self.doc_over)

    def _fetch_binding(self, url):
        if self.binding_error:
            raise self.binding_error
        return "fake.jws.sig"

    def _fetch_bundle(self, url, spiffe_id, trusted_pems):
        self.bundle_calls.append((url, spiffe_id, trusted_pems))
        if self.bundle_error:
            raise self.bundle_error
        return copy.deepcopy(self.served), ("continuity" if trusted_pems else "bootstrap")

    def cycle(self):
        return self.rec.cycle()

    def install(self):
        d = self.cycle()
        assert (d.decision, d.action) == ("ALLOW", "INSTALLED"), d
        return d


def sdk_error(code_name, msg="x", transient=False, **structured):
    """A real dnsid.VerificationError; `structured` may set category / agent_state like the SDK does."""
    from dnsid import VerificationError
    from dnsid.enums import VerificationCode
    return VerificationError(VerificationCode[code_name], msg, transient=transient, **structured)


def denied(reason, transient=False):
    return DnsidDenied(reason, "test", transient=transient)


def fake_domain(domain=SIGNER, gi=GOV):
    return types.SimpleNamespace(record=types.SimpleNamespace(gi=gi), domain=domain,
                                 signing_key_thumbprint="thumb1",
                                 dnssec_state=types.SimpleNamespace(name="SECURE"))
