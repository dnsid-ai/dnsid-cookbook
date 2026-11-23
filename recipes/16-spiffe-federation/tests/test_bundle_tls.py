"""The real fetch_bundle against a real TLS server on 127.0.0.1: continuity-mode authentication of the
bundle endpoint (chain to the already-trusted authorities AND the policy's endpoint SPIFFE ID as URI SAN).

No mocks of fetch_bundle, ssl or http.client: each test starts an HTTPS server in-process on loopback with
a freshly minted certificate chain and calls dnsidfed.bundle.fetch_bundle exactly as the reconciler does.
These checks are what let the docs say a stolen DNSid signer key alone cannot introduce a new CA.
"""
from __future__ import annotations

import datetime as dt
import json
import ssl
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import helpers as H
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from dnsidfed.bundle import BundleFetchError, b64der_to_pem, fetch_bundle

EXPECTED_ID = H.ENDPOINT_ID   # spiffe://rackloria.test/spire/server


def leaf(ca: H.CA, uris=(EXPECTED_ID,), cn="bundle-endpoint"):
    """An X.509-SVID-shaped server leaf signed by `ca`, with the given URI SANs. Returns (cert_pem, key_pem)."""
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(ca.cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.UTC))
         .not_valid_after(dt.datetime(2036, 1, 1, tzinfo=dt.UTC))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=True, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()), critical=False))
    if uris:
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(u) for u in uris]),
                            critical=False)
    cert = b.sign(ca.key, hashes.SHA256())
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


@contextmanager
def bundle_endpoint(tmp_path, cert_pem: bytes, key_pem: bytes, body: dict, only=None, seen=None):
    """An HTTPS server on 127.0.0.1 presenting `cert_pem` and serving `body` as JSON at any path.

    It accepts TLS 1.2 and later (pinned to one version with `only`), and appends each negotiated protocol
    version to `seen` when given."""
    (tmp_path / "cert.pem").write_bytes(cert_pem)
    (tmp_path / "key.pem").write_bytes(key_pem)
    payload = json.dumps(body).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if seen is not None:
                seen.append(self.request.version())
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if only is not None:
        sctx.minimum_version = sctx.maximum_version = only
    sctx.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"https://127.0.0.1:{srv.server_address[1]}/"
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(5)


@pytest.fixture
def cas():
    trusted, untrusted = H.CA("rackloria-current"), H.CA("attacker")
    return trusted, untrusted, [b64der_to_pem(trusted.b64)]


def test_continuity_trusted_ca_and_expected_uri_san_is_accepted(tmp_path, cas):
    trusted, _, anchors = cas
    served = H.bundle_of(trusted)
    with bundle_endpoint(tmp_path, *leaf(trusted), served) as url:
        got, mode = fetch_bundle(url, EXPECTED_ID, anchors)
    assert mode == "continuity"
    assert got == served


def test_continuity_untrusted_ca_is_rejected(tmp_path, cas):
    trusted, untrusted, anchors = cas
    # Correct SPIFFE ID, but chained to a CA Acme has never trusted (e.g. a CA added with a stolen signer key).
    with (bundle_endpoint(tmp_path, *leaf(untrusted), H.bundle_of(trusted, untrusted)) as url,
          pytest.raises(BundleFetchError) as ei):
        fetch_bundle(url, EXPECTED_ID, anchors)
    assert ei.value.reason == "CONTINUITY_FAILED"
    assert "not authenticated by currently trusted authorities" in ei.value.detail


@pytest.mark.parametrize("uris,cn", [
    (("spiffe://rackloria.test/attacker",), "bundle-endpoint"),        # another workload of the trust domain
    (("spiffe://evil.test/spire/server",), "bundle-endpoint"),         # same path, another trust domain
    ((), EXPECTED_ID),                                                 # expected ID only in the CN: not a SAN
])
def test_continuity_trusted_ca_wrong_uri_san_is_rejected(tmp_path, cas, uris, cn):
    trusted, _, anchors = cas
    with (bundle_endpoint(tmp_path, *leaf(trusted, uris=uris, cn=cn), H.bundle_of(trusted)) as url,
          pytest.raises(BundleFetchError) as ei):
        fetch_bundle(url, EXPECTED_ID, anchors)
    assert ei.value.reason == "CONTINUITY_FAILED"
    assert f"!= expected {EXPECTED_ID}" in ei.value.detail


def test_bootstrap_mode_does_not_authenticate_the_channel(tmp_path, cas):
    # Control: with no anchors the channel is deliberately unauthenticated (authenticity then comes only from
    # the DNSid binding's SPKI coverage). This shows the rejections above come from the continuity checks.
    trusted, untrusted, _ = cas
    with bundle_endpoint(tmp_path, *leaf(untrusted, uris=()), H.bundle_of(trusted)) as url:
        _, mode = fetch_bundle(url, EXPECTED_ID, None)
    assert mode == "bootstrap"


# ------------------------------------------------------------------ protocol versions
@pytest.mark.parametrize("continuity", [True, False])
def test_fetch_bundle_sets_an_explicit_tls_1_2_minimum(tmp_path, cas, monkeypatch, continuity):
    # Spies, not mocks: the real wrap_socket and minimum_version setter still run, so the handshake, verification
    # and SAN checks happen for real. The setter spy records the ASSIGNMENT, because on current Python/OpenSSL the
    # default minimum is already TLS 1.2 and the resulting value alone cannot tell explicit from default.
    trusted, _, anchors = cas
    clients, assigned = [], []
    real_wrap, real_min = ssl.SSLContext.wrap_socket, ssl.SSLContext.minimum_version

    def recording_wrap(self, *args, **kwargs):
        if not kwargs.get("server_side"):
            clients.append(self)
        return real_wrap(self, *args, **kwargs)

    def recording_set_min(self, value):
        assigned.append((id(self), value))
        real_min.fset(self, value)

    with bundle_endpoint(tmp_path, *leaf(trusted), H.bundle_of(trusted)) as url:
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", recording_wrap)
        monkeypatch.setattr(ssl.SSLContext, "minimum_version", property(real_min.fget, recording_set_min))
        _, mode = fetch_bundle(url, EXPECTED_ID, anchors if continuity else None)
    assert mode == ("continuity" if continuity else "bootstrap")
    assert len(clients) == 1
    ctx = clients[0]
    assert (id(ctx), ssl.TLSVersion.TLSv1_2) in assigned                    # set explicitly by fetch_bundle
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED           # TLS 1.3 not excluded
    assert ctx.verify_mode == (ssl.CERT_REQUIRED if continuity else ssl.CERT_NONE)


@pytest.mark.parametrize("version,name", [(ssl.TLSVersion.TLSv1_3, "TLSv1.3"), (ssl.TLSVersion.TLSv1_2, "TLSv1.2")])
def test_continuity_negotiates_tls_1_3_and_1_2(tmp_path, cas, version, name):
    if version == ssl.TLSVersion.TLSv1_3 and not ssl.HAS_TLSv1_3:
        pytest.skip("TLS 1.3 not supported by this OpenSSL")
    trusted, _, anchors = cas
    seen = []
    with bundle_endpoint(tmp_path, *leaf(trusted), H.bundle_of(trusted), only=version, seen=seen) as url:
        _, mode = fetch_bundle(url, EXPECTED_ID, anchors)
    assert (mode, seen) == ("continuity", [name])
