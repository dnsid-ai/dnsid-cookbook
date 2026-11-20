
from cryptography import x509

import helpers as H
from dnsidfed.bundle import _uri_sans, b64der_to_pem, pems_from_bundle


def test_pems_round_trip_to_loadable_certs_and_skip_jwt():
    a, b = H.CA("a"), H.CA("b")
    pems = pems_from_bundle(H.bundle_of(a, b, jwt=True))
    assert len(pems) == 2  # JWT key not included
    certs = [x509.load_pem_x509_certificate(p.encode()) for p in pems]
    assert [c.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)
            for c in certs] == [a.der, b.der]


def test_pems_empty_bundle():
    assert pems_from_bundle({"keys": []}) == []
    assert pems_from_bundle({}) == []
    assert pems_from_bundle({"keys": [H.jwt_key()]}) == []


def test_b64der_to_pem_helper():
    a = H.CA("a")
    assert x509.load_pem_x509_certificate(b64der_to_pem(a.b64).encode()).subject == a.cert.subject


def test_uri_sans():
    c = H.CA("srv", uri="spiffe://rackloria.test/spire/server")
    assert _uri_sans(c.der) == ["spiffe://rackloria.test/spire/server"]
    assert _uri_sans(H.CA("nosan").der) == []
