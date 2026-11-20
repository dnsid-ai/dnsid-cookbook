import datetime as dt

import pytest

import helpers as H
import dnsidfed.verifier as V
from dnsid.c2sp_tlog import C2spTlogError, InMemoryCheckpointStore
from dnsidfed.verifier import DnsidDenied, DnsidVerifier, _map_sdk_error, _parse_checkpoint


@pytest.mark.parametrize("code,msg,transient,reason,exp_transient", [
    ("COUNTERPARTY_NOT_ACCEPTED", "gi not trusted", False, "GOVERNANCE_NOT_APPROVED", False),
    ("SIGNATURE_INVALID", "bad sig", False, "BINDING_SIGNATURE_INVALID", False),
    ("KEY_NOT_FOUND", "kid", False, "BINDING_SIGNATURE_INVALID", False),
    ("RECORD_INVALID", "JOSE header bad", False, "BINDING_SIGNATURE_INVALID", False),
    ("RECORD_INVALID", "two TXT records", False, "VERIFICATION_FAILED", False),
    ("STATUS_NOT_ACTIVE", "REVOKED", False, "IDENTITY_NOT_ACTIVE", False),
    ("TLS_ERROR", "jwks fetch: HTTP 410", False, "IDENTITY_NOT_ACTIVE", False),
    ("TLS_ERROR", "cert expired", False, "VERIFICATION_FAILED", False),
    ("RECORD_NOT_FOUND", "nxdomain", False, "IDENTITY_NOT_FOUND", False),
    ("LOG_ERROR", "checkpoint too stale", True, "EVIDENCE_STALE", True),
    ("LOG_ERROR", "checkpoint too stale", False, "EVIDENCE_STALE", True),
    ("LOG_ERROR", "identity Revoked in log", False, "IDENTITY_NOT_ACTIVE", False),
    ("LOG_ERROR", "terminal state", False, "IDENTITY_NOT_ACTIVE", False),
    ("LOG_ERROR", "log unreachable", True, "EVIDENCE_UNAVAILABLE", True),
    ("LOG_ERROR", "proof failed", False, "LOG_VERIFICATION_FAILED", False),
    ("DNS_RESOLUTION", "timeout", True, "EVIDENCE_UNAVAILABLE", True),
    ("DNS_RESOLUTION", "timeout", False, "EVIDENCE_UNAVAILABLE", True),
    ("STATUS_UNAVAILABLE", "x", True, "EVIDENCE_UNAVAILABLE", True),
    ("DEADLINE_EXCEEDED", "x", True, "EVIDENCE_UNAVAILABLE", True),
    ("DNSSEC_FAILED", "x", False, "VERIFICATION_FAILED", False),
])
def test_map_sdk_error(code, msg, transient, reason, exp_transient):
    d = _map_sdk_error(H.sdk_error(code, msg, transient))
    assert d.reason == reason and d.transient is exp_transient and d.sdk_code == code
    # consistency with the reconciler's rule: non-transient reasons must be DEFINITIVE to withdraw immediately
    if not d.transient:
        assert d.reason in V.DEFINITIVE


def test_parse_checkpoint():
    assert _parse_checkpoint(b"origin\n12\nroot=\n") == ("origin", 12, "root=")
    assert _parse_checkpoint("o\n3\nr\n") == ("o", 3, "r")
    assert _parse_checkpoint(b"garbage") == ("", -1, "")


# ---------------------------------------------------------------- a new manager per verify() call
class FakeManager:
    def __init__(self, behavior):
        self.entered = self.exited = 0
        self.domain_calls = self.evidence_calls = 0
        self.b = behavior

    def __enter__(self):
        self.entered += 1
        return self

    def __exit__(self, *exc):
        self.exited += 1
        return False

    def verify_domain(self, domain):
        self.domain_calls += 1
        return self.b.get("domain_fn", lambda: H.fake_domain())()

    def verify_log_evidence(self, vd):
        self.evidence_calls += 1
        if "evidence_exc" in self.b:
            raise self.b["evidence_exc"]
        return self.b.get("evidence", evidence())


def evidence(state="ACTIVE", age=-5.0):
    return type("Ev", (), dict(
        logged_state=state, log_reference="log#1", checkpoint=b"origin\n9\nroot\n",
        freshness_time=dt.datetime.fromtimestamp(H.NOW + age, dt.timezone.utc)))()


class FakeJose:
    def __init__(self, resolver, **kw):
        self.r = resolver

    def verify_jws(self, jws):
        vd = self.r.verify_domain(H.SIGNER)  # exactly what dnsid.JoseProfile.verify_jws does with its resolver
        return b'{"payload": 1}', vd


@pytest.fixture
def mk(monkeypatch):
    monkeypatch.setattr(V, "JoseProfile", FakeJose)
    made = []

    def build(*behaviors):
        it = iter(behaviors)

        def factory():
            b = next(it)
            if isinstance(b, BaseException):
                raise b
            m = FakeManager(b)
            made.append(m)
            return m
        return DnsidVerifier(H.make_policy(), manager_factory=factory, clock=lambda: H.NOW), made
    return build


def test_new_manager_per_verify_call(mk):
    ver, made = mk({}, {}, {})
    for _ in range(3):
        vb = ver.verify("a.b.c")
        assert vb.signer == H.SIGNER and vb.logged_state == "ACTIVE" and vb.checkpoint_size == 9
    assert len(made) == 3 and len({id(m) for m in made}) == 3
    assert ver.managers_built == 3
    assert all(m.entered == 1 and m.exited == 1 and m.domain_calls == 1 and m.evidence_calls == 1 for m in made)


def test_manager_never_reused_after_exception(mk):
    ver, made = mk({"domain_fn": lambda: (_ for _ in ()).throw(RuntimeError("boom"))}, {})
    with pytest.raises(DnsidDenied):
        ver.verify("j")
    ver.verify("j")
    assert len(made) == 2 and made[0] is not made[1]
    assert made[0].exited == 1 and made[0].domain_calls == 1  # failed manager closed, not reused
    assert made[1].domain_calls == 1 and ver.managers_built == 2


def _policy_with_log_policy(tmp_path):
    import dataclasses
    lp = tmp_path / "lp"
    lp.write_bytes(b"policy")
    pol = H.make_policy()
    return dataclasses.replace(pol, verification=dataclasses.replace(pol.verification, log_policy_file=str(lp)))


@pytest.fixture
def capture_sdk(monkeypatch):
    """Record what the default factory hands to the SDK, without touching the network."""
    seen = {"options": [], "managers": [], "kwargs": []}

    def registry(opts):
        seen["options"].append(opts)
        return object()

    def for_verification(*a, **k):
        seen["kwargs"].append(k)
        seen["managers"].append(object())
        return seen["managers"][-1]

    monkeypatch.setattr(V, "create_c2sp_tlog_verification_registry", registry)
    monkeypatch.setattr(V.IdentityManager, "for_verification", staticmethod(for_verification))
    return seen


def test_default_factory_fresh_manager_shared_checkpoint_store(capture_sdk, tmp_path):
    pol = _policy_with_log_policy(tmp_path)
    store = InMemoryCheckpointStore()
    f = V.default_manager_factory(pol, store)
    m1, m2, m3 = f(), f(), f()
    # Fresh lifecycle state every call ...
    assert len({id(m1), id(m2), id(m3)}) == 3
    # ... but one trusted-checkpoint store for all of them (rollback/fork protection accumulates).
    assert all(o.trusted_checkpoint_store is store for o in capture_sdk["options"])
    o = capture_sdk["options"][0]
    assert o.policy_document == b"policy"
    assert o.checkpoint_freshness_ms == int(pol.verification.checkpoint_freshness_s * 1000)
    assert o.max_clock_skew_ms == int(pol.verification.clock_skew_s * 1000)
    vc = capture_sdk["kwargs"][0]["verification"]
    assert vc.status_check_interval == dt.timedelta(0)  # status endpoint asked on every verification


def test_governance_and_entity_key_pin_passed_to_sdk(capture_sdk, tmp_path):
    pol = _policy_with_log_policy(tmp_path)
    V.default_manager_factory(pol, InMemoryCheckpointStore())()
    (te,) = capture_sdk["kwargs"][0]["verification"].trusted_entities
    assert te.governance_id == H.GOV
    assert tuple(te.entity_key_thumbprints) == ("thumb1",)


def test_verifier_without_store_still_shares_one_store_across_cycles(capture_sdk, tmp_path):
    ver = DnsidVerifier(_policy_with_log_policy(tmp_path))
    assert isinstance(ver.checkpoint_store, InMemoryCheckpointStore)
    ver.manager_factory(), ver.manager_factory()
    assert [o.trusted_checkpoint_store for o in capture_sdk["options"]] == [ver.checkpoint_store] * 2


def test_verifier_uses_injected_store(capture_sdk, tmp_path):
    store = InMemoryCheckpointStore()
    ver = DnsidVerifier(_policy_with_log_policy(tmp_path), checkpoint_store=store)
    ver.manager_factory()
    assert ver.checkpoint_store is store and capture_sdk["options"][0].trusted_checkpoint_store is store


def test_factory_raising_tlog_error_is_transient_unavailable(mk):
    ver, made = mk(C2spTlogError("policy parse"))
    with pytest.raises(DnsidDenied) as ei:
        ver.verify("j")
    assert (ei.value.reason, ei.value.transient) == ("EVIDENCE_UNAVAILABLE", True)
    assert ver.managers_built == 0


def test_witness_time_in_future_is_stale(mk):
    ver, _ = mk({"evidence": evidence(age=+120)})
    with pytest.raises(DnsidDenied) as ei:
        ver.verify("j")
    assert (ei.value.reason, ei.value.transient) == ("EVIDENCE_STALE", True)


def test_witness_time_within_skew_ok(mk):
    ver, _ = mk({"evidence": evidence(age=+30)})
    assert ver.verify("j").witness_time.timestamp() == H.NOW + 30


@pytest.mark.parametrize("state", ["REVOKED", "RETIRED", "", "UNKNOWN"])
def test_logged_state_not_active_is_definitive(mk, state):
    ver, _ = mk({"evidence": evidence(state=state)})
    with pytest.raises(DnsidDenied) as ei:
        ver.verify("j")
    assert (ei.value.reason, ei.value.transient) == ("IDENTITY_NOT_ACTIVE", False)
    assert ei.value.reason in V.DEFINITIVE


def test_governance_mismatch_defence_in_depth(mk):
    ver, _ = mk({"domain_fn": lambda: H.fake_domain(gi="rackl0ria.test")})
    with pytest.raises(DnsidDenied) as ei:
        ver.verify("j")
    assert ei.value.reason == "GOVERNANCE_NOT_APPROVED" and not ei.value.transient


def test_sdk_verification_error_is_mapped(mk):
    ver, _ = mk({"evidence_exc": H.sdk_error("LOG_ERROR", "identity revoked")})
    with pytest.raises(DnsidDenied) as ei:
        ver.verify("j")
    assert ei.value.reason == "IDENTITY_NOT_ACTIVE"


def test_tlog_error_during_verification_is_transient(mk):
    ver, _ = mk({"evidence_exc": C2spTlogError("log down")})
    with pytest.raises(DnsidDenied) as ei:
        ver.verify("j")
    assert (ei.value.reason, ei.value.transient) == ("EVIDENCE_UNAVAILABLE", True)


def test_unexpected_exception_fails_closed(mk):
    ver, made = mk({"evidence_exc": ZeroDivisionError("bug")})
    with pytest.raises(DnsidDenied) as ei:
        ver.verify("j")
    assert (ei.value.reason, ei.value.transient) == ("EVIDENCE_UNAVAILABLE", True)
    assert made[0].exited == 1
