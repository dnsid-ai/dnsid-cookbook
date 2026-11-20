
import pytest

import helpers as H
from dnsidfed.binding import BindingRejected, Statement, select_authorities, validate_statement, x509_authorities

AGE, SKEW = 900.0, 60.0


def v(doc, policy, *, signer=H.SIGNER, last_seq=None, now=H.NOW):
    return validate_statement(doc, signer_fqdn=signer, policy=policy.federation, now=now,
                              max_age_s=AGE, skew_s=SKEW, last_seq=last_seq)


def rejects(reason, doc, policy, **kw):
    with pytest.raises(BindingRejected) as ei:
        v(doc, policy, **kw)
    assert ei.value.reason == reason
    return ei.value


def test_happy_path(policy):
    s = v(H.good_doc(H.CA("x"), seq=5), policy)
    assert isinstance(s, Statement)
    assert (s.trust_domain, s.seq, s.iss) == (H.TD, 5, H.SIGNER)


def test_wrong_typ(policy):
    rejects("BINDING_MALFORMED", H.good_doc(typ="other"), policy)


def test_issuer_mismatch(policy):
    rejects("BINDING_ISSUER_MISMATCH", H.good_doc(iss="spire-fed-evil.rackloria.test"), policy)


def test_issuer_compare_ignores_case_and_trailing_dot(policy):
    v(H.good_doc(iss=H.SIGNER.upper() + "."), policy)


def test_trust_domain_not_bound(policy):
    rejects("TRUST_DOMAIN_NOT_BOUND", H.good_doc(trust_domain="evil.test"), policy)


@pytest.mark.parametrize("ep", [
    {"url": "https://evil/bundle", "spiffe_id": H.ENDPOINT_ID},
    {"url": H.ENDPOINT_URL, "spiffe_id": "spiffe://rackloria.test/other"},
    {"url": H.ENDPOINT_URL},
])
def test_endpoint_mismatch(policy, ep):
    rejects("BUNDLE_ENDPOINT_MISMATCH", H.good_doc(bundle_endpoint=ep), policy)


@pytest.mark.parametrize("spki", [[], [""], [1], "abc", None, ["ok", ""]])
def test_empty_or_invalid_spki_list(policy, spki):
    rejects("BINDING_MALFORMED", H.good_doc(x509_authorities_spki_sha256=spki), policy)


def test_iat_in_future_beyond_skew(policy):
    n = int(H.NOW)
    rejects("BINDING_NOT_YET_VALID", H.good_doc(iat=n + 61, exp=n + 900), policy)
    v(H.good_doc(iat=n + 59, exp=n + 900), policy)  # within skew accepted


def test_expired_exp(policy):
    n = int(H.NOW)
    rejects("BINDING_EXPIRED", H.good_doc(iat=n - 200, exp=n - 61), policy)


def test_older_than_max_age(policy):
    n = int(H.NOW)
    rejects("BINDING_EXPIRED", H.good_doc(iat=n - 901, exp=n + 100), policy)
    v(H.good_doc(iat=n - 900, exp=n + 100), policy)


def test_exp_not_after_iat(policy):
    n = int(H.NOW)
    rejects("BINDING_MALFORMED", H.good_doc(iat=n, exp=n), policy)
    rejects("BINDING_MALFORMED", H.good_doc(iat=n, exp=n - 1), policy)


def test_seq_rollback_rejected_and_equal_accepted(policy):
    e = rejects("BINDING_ROLLBACK", H.good_doc(seq=4), policy, last_seq=5)
    assert "4" in e.detail
    assert v(H.good_doc(seq=5), policy, last_seq=5).seq == 5
    assert v(H.good_doc(seq=6), policy, last_seq=5).seq == 6


@pytest.mark.parametrize("key,val", [("seq", True), ("seq", "5"), ("seq", 5.0), ("iat", True), ("iat", "1"),
                                     ("exp", True), ("exp", "9"), ("trust_domain", 1), ("iss", None)])
def test_bool_and_str_types_rejected_for_ints(policy, key, val):
    rejects("BINDING_MALFORMED", H.good_doc(**{key: val}), policy)


# ---------------------------------------------------------------- select_authorities
def stmt(*cas):
    return v(H.good_doc(*cas), H.make_policy())


def test_all_served_covered_installs_x509_only_jwt_stripped():
    a, b = H.CA("a"), H.CA("b")
    fetched = H.bundle_of(a, b, jwt=True)
    assert any(k["use"] == "jwt-svid" for k in fetched["keys"])
    out = select_authorities(fetched, stmt(a, b))
    assert {k["use"] for k in out["keys"]} == {"x509-svid"}
    assert set(x509_authorities(out)) == {a.spki, b.spki}
    assert out["spiffe_sequence"] == 1


def test_served_not_in_signed_set_is_not_covered():
    a, b = H.CA("a"), H.CA("b")
    with pytest.raises(BindingRejected) as ei:
        select_authorities(H.bundle_of(a, b), stmt(a))
    assert ei.value.reason == "BUNDLE_NOT_COVERED"
    assert b.spki in ei.value.detail


def test_signed_but_not_served_extra_allowed_pre_announced_rotation():
    a, b = H.CA("a"), H.CA("b")
    out = select_authorities(H.bundle_of(a), stmt(a, b))
    assert set(x509_authorities(out)) == {a.spki}


def test_no_x509_authorities_is_bundle_invalid():
    a = H.CA("a")
    for fetched in ({"keys": []}, {"keys": [H.jwt_key()]}, {}):
        with pytest.raises(BindingRejected) as ei:
            select_authorities(fetched, stmt(a))
        assert ei.value.reason == "BUNDLE_INVALID"


def test_x5c_with_two_certs_is_bundle_invalid():
    a, b = H.CA("a"), H.CA("b")
    k = a.jwk()
    k["x5c"] = [a.b64, b.b64]
    with pytest.raises(BindingRejected) as ei:
        select_authorities({"keys": [k]}, stmt(a))
    assert ei.value.reason == "BUNDLE_INVALID"
