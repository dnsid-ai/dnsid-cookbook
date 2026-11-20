import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

import helpers as H
from dnsidfed.binding import x509_authorities
from dnsidfed.bundle import BundleFetchError
from dnsidfed.reconcile import State


def test_bootstrap_install(env):
    d = env.install()
    assert (d.reason, d.mode) == ("OK", "bootstrap")
    assert env.bundle_calls[0][2] is None  # unauthenticated bootstrap: no trusted PEMs
    (_, td, bundle), = [c for c in env.spire.calls if c[0] == "set_bundle"]
    assert td == H.TD and {k["use"] for k in bundle["keys"]} == {"x509-svid"}  # JWT stripped
    assert set(x509_authorities(bundle)) == {env.A.spki}
    ens = [c for c in env.spire.calls if c[0] == "ensure_federates"]
    assert [(c[1], c[2]) for c in ens] == [(e, H.TD) for e in H.ENTRIES]
    assert env.state.last_seq == 5 and env.state.last_verified_at == H.NOW
    assert d.statement["seq"] == 5 and d.evidence["signer"] == H.SIGNER and d.installed_spki == [env.A.spki]
    assert env.audit == [d]


def test_unchanged_second_cycle_does_not_rewrite(env):
    env.install()
    env.clock.advance(5)
    n = env.spire.names().count("set_bundle")
    d = env.cycle()
    assert (d.decision, d.action) == ("ALLOW", "UNCHANGED")
    assert env.spire.names().count("set_bundle") == n
    assert env.state.last_verified_at == H.NOW + 5


def test_continuity_passes_installed_pems(env):
    env.install()
    env.clock.advance(5)
    d = env.cycle()
    assert d.mode == "continuity"
    pems = env.bundle_calls[-1][2]
    assert pems and len(pems) == 1
    cert = x509.load_pem_x509_certificate(pems[0].encode())
    assert cert.public_bytes(Encoding.DER) == env.A.der


def test_rotation_adds_new_authority_updated(env):
    env.install()
    env.clock.advance(5)
    env.signed, env.served, env.seq = [env.A, env.B], H.bundle_of(env.A, env.B), 6
    d = env.cycle()
    assert (d.decision, d.action) == ("ALLOW", "UPDATED")
    assert set(x509_authorities(env.spire.bundles[H.TD])) == {env.A.spki, env.B.spki}
    assert env.state.last_seq == 6


def test_pre_announced_rotation_not_yet_served_is_unchanged(env):
    env.install()
    env.signed, env.seq = [env.A, env.B], 6
    assert env.cycle().action == "UNCHANGED"


def test_continuity_failed_holds_then_withdraws_after_grace(env):
    env.install()
    env.bundle_error = BundleFetchError("CONTINUITY_FAILED", "not authenticated")
    env.clock.advance(10)
    d = env.cycle()
    assert (d.decision, d.action, d.reason) == ("HOLD", "HELD", "CONTINUITY_FAILED")
    assert H.TD in env.spire.bundles and "delete_bundle" not in env.spire.names()
    env.clock.advance(25)  # 35s since last verification > grace 30
    d = env.cycle()
    assert (d.decision, d.action, d.reason) == ("DENY", "WITHDRAWN", "CONTINUITY_FAILED")
    assert H.TD not in env.spire.bundles
    assert env.state.last_verified_at is None


def test_grace_boundary_is_exclusive(env):
    env.install()
    env.bundle_error = BundleFetchError("BUNDLE_UNAVAILABLE", "down")
    env.clock.advance(30)
    assert env.cycle().decision == "HOLD"  # exactly grace: still held
    env.clock.advance(0.5)
    assert env.cycle().action == "WITHDRAWN"


@pytest.mark.parametrize("reason", ["IDENTITY_NOT_ACTIVE", "GOVERNANCE_NOT_APPROVED", "BINDING_SIGNATURE_INVALID",
                                    "IDENTITY_NOT_FOUND", "LOG_VERIFICATION_FAILED", "LOG_INCONSISTENT",
                                    "CHECKPOINT_STORE_FAILED"])
def test_definitive_dnsid_denial_withdraws_immediately(env, reason):
    env.install()
    env.clock.advance(1)
    env.verifier.error = H.denied(reason)
    d = env.cycle()
    assert (d.decision, d.action, d.reason) == ("DENY", "WITHDRAWN", reason)
    assert H.TD not in env.spire.bundles
    assert env.state.last_verified_at is None and d.seconds_since_last_verified is None


@pytest.mark.parametrize("reason", ["EVIDENCE_UNAVAILABLE", "EVIDENCE_STALE"])
def test_transient_evidence_holds_then_withdraws(env, reason):
    env.install()
    env.verifier.error = H.denied(reason, transient=True)
    env.clock.advance(10)
    d = env.cycle()
    assert (d.decision, d.action) == ("HOLD", "HELD")
    assert d.seconds_since_last_verified == 10.0
    env.clock.advance(21)
    d = env.cycle()
    assert (d.decision, d.action, d.reason) == ("DENY", "WITHDRAWN", reason)
    assert "fail closed" in d.detail


def test_indeterminate_never_becomes_allow_even_if_verifier_flaps(env):
    env.install()
    env.verifier.error = H.denied("EVIDENCE_UNAVAILABLE", transient=True)
    for _ in range(5):
        env.clock.advance(10)
        assert env.cycle().decision != "ALLOW"
    assert H.TD not in env.spire.bundles


def test_binding_unavailable_holds_then_withdraws(env):
    env.install()
    env.binding_error = OSError("connection refused")
    env.clock.advance(10)
    d = env.cycle()
    assert (d.decision, d.reason) == ("HOLD", "BINDING_UNAVAILABLE")
    assert env.verifier.calls == 1  # verifier not consulted without a statement
    env.clock.advance(25)
    assert env.cycle().action == "WITHDRAWN"


def test_bundle_not_covered_holds_never_installs_new_material_then_withdraws(env):
    env.install()
    sets = env.spire.names().count("set_bundle")
    env.served = H.bundle_of(env.A, env.B)  # B served but not signed
    env.clock.advance(10)
    d = env.cycle()
    assert (d.decision, d.action, d.reason) == ("HOLD", "HELD", "BUNDLE_NOT_COVERED")
    assert env.spire.names().count("set_bundle") == sets
    assert set(x509_authorities(env.spire.bundles[H.TD])) == {env.A.spki}
    env.clock.advance(25)
    d = env.cycle()
    assert (d.decision, d.action) == ("DENY", "WITHDRAWN")
    assert env.spire.names().count("set_bundle") == sets


def test_bundle_not_covered_on_bootstrap_installs_nothing(env):
    env.served = H.bundle_of(env.A, env.B)
    d = env.cycle()
    assert (d.decision, d.action, d.reason) == ("HOLD", "NONE", "BUNDLE_NOT_COVERED")
    assert "set_bundle" not in env.spire.names() and env.state.last_seq is None


def test_trust_domain_not_bound_withdraws_immediately(env):
    env.install()
    env.clock.advance(1)
    env.doc_over = {"trust_domain": "evil.test"}
    d = env.cycle()
    assert (d.decision, d.action, d.reason) == ("DENY", "WITHDRAWN", "TRUST_DOMAIN_NOT_BOUND")
    assert env.state.last_verified_at is None


@pytest.mark.parametrize("over,reason", [
    ({"iss": "spire-fed-x.rackloria.test"}, "BINDING_ISSUER_MISMATCH"),
    ({"bundle_endpoint": {"url": "https://evil", "spiffe_id": H.ENDPOINT_ID}}, "BUNDLE_ENDPOINT_MISMATCH"),
])
def test_other_definitive_binding_reasons_withdraw(env, over, reason):
    env.install()
    env.doc_over = over
    d = env.cycle()
    assert (d.decision, d.action, d.reason) == ("DENY", "WITHDRAWN", reason)


def test_signer_not_allowed_withdraws_immediately(env):
    env.install()
    env.verifier.signer = "intruder.rackloria.test"
    env.doc_over = {"iss": "intruder.rackloria.test"}
    d = env.cycle()
    assert (d.decision, d.action, d.reason) == ("DENY", "WITHDRAWN", "SIGNER_NOT_ALLOWED")


def test_signer_not_allowed_without_bundle_is_none(env):
    env.verifier.signer = "intruder.rackloria.test"
    d = env.cycle()
    assert (d.decision, d.action) == ("DENY", "NONE")
    assert "set_bundle" not in env.spire.names()


@pytest.mark.parametrize("err", [H.denied("IDENTITY_NOT_ACTIVE"), H.denied("EVIDENCE_UNAVAILABLE", True),
                                 OSError("x")])
def test_deny_or_hold_without_installed_bundle_is_action_none(env, err):
    env.verifier.error = err if isinstance(err, H.DnsidDenied) else None
    env.binding_error = None if isinstance(err, H.DnsidDenied) else err
    d = env.cycle()
    assert d.action == "NONE" and d.decision in ("DENY", "HOLD")
    assert env.spire.calls == [] and env.state.last_seq is None


def test_expired_statement_holds_then_withdraws(env):
    env.install()
    n = int(env.clock())
    env.clock.advance(10)
    env.doc_over = {"iat": n - 1000, "exp": n + 600}
    d = env.cycle()
    assert (d.decision, d.reason) == ("HOLD", "BINDING_EXPIRED")


def test_anti_rollback_across_cycles(env):
    env.install()
    env.clock.advance(5)
    env.seq = 4
    d = env.cycle()
    assert (d.decision, d.action, d.reason) == ("HOLD", "HELD", "BINDING_ROLLBACK")
    assert env.state.last_seq == 5
    env.seq = 5
    assert env.cycle().decision == "ALLOW"  # equal seq accepted
    env.seq = 9
    env.cycle()
    env.seq = 8
    assert env.cycle().reason == "BINDING_ROLLBACK" and env.state.last_seq == 9


def test_state_persistence_round_trip(env, tmp_path):
    env.install()
    on_disk = json.loads(env.state_path.read_text())
    assert {k: on_disk[k] for k in ("last_seq", "last_verified_at")} == {"last_seq": 5, "last_verified_at": H.NOW}
    assert on_disk["anchors"] and all("BEGIN CERTIFICATE" in a for a in on_disk["anchors"])
    s2 = State(str(env.state_path))
    assert (s2.last_seq, s2.last_verified_at) == (5, H.NOW)
    # a restarted controller still enforces anti-rollback
    env.rec = env.make_reconciler(s2)
    env.seq = 3
    assert env.cycle().reason == "BINDING_ROLLBACK"
    # a missing/None path state is in-memory only
    s3 = State(None)
    s3.last_seq = 1
    s3.save()
    assert State(str(tmp_path / "absent.json")).last_seq is None


def test_withdraw_clears_persisted_grace_clock(env):
    env.install()
    env.verifier.error = H.denied("IDENTITY_NOT_ACTIVE")
    env.cycle()
    assert State(str(env.state_path)).last_verified_at is None
    # after withdrawal a transient failure with a reinstalled bundle cannot ride a stale clock
    env.verifier.error = None
    env.clock.advance(1)
    env.install()
    assert State(str(env.state_path)).last_verified_at == env.clock()


def test_installed_bundle_with_no_prior_verification_fails_closed(env):
    """Bundle present but no recorded verification (e.g. state file lost): a hold must withdraw."""
    env.spire.bundles[H.TD] = H.bundle_of(env.A, jwt=False)
    env.binding_error = OSError("down")
    d = env.cycle()
    assert (d.decision, d.action) == ("DENY", "WITHDRAWN")


def test_reinstall_after_withdraw(env):
    env.install()
    env.verifier.error = H.denied("IDENTITY_NOT_ACTIVE")
    env.cycle()
    env.verifier.error = None
    env.clock.advance(5)
    d = env.cycle()
    # Security property: after a withdrawal the controller does NOT fall back to an unauthenticated
    # bootstrap; re-approval is authenticated by the persisted, previously DNSid-approved anchors.
    assert (d.decision, d.action, d.mode) == ("ALLOW", "INSTALLED", "continuity")


def test_allow_decision_carries_evidence_age(env):
    d = env.install()
    assert d.evidence["evidence_age_s"] == 5.0 and d.evidence["logged_state"] == "ACTIVE"


# ---------------------------------------------------------------------------------------------------------
# Continuity must not downgrade to an
# unauthenticated bootstrap after a withdrawal. Anchors persist in controller state; only an explicit admin
# re-bootstrap clears them.
def test_forced_withdrawal_keeps_continuity_anchors(env):
    env.install()
    anchors = list(env.state.anchors)
    assert anchors, "approval must persist the authenticated authority set"
    env.verifier.error = H.denied("IDENTITY_NOT_ACTIVE")      # e.g. attacker replays an old revoked JWS
    d = env.cycle()
    assert (d.decision, d.action) == ("DENY", "WITHDRAWN")
    assert env.state.anchors == anchors, "a DENY must not discard the trust anchors"
    env.verifier.error = None
    env.clock.advance(5)
    env.cycle()
    _, _, trusted = env.bundle_calls[-1]
    assert trusted == anchors, "re-approval fetch must be authenticated by the persisted anchors"


def test_grace_withdrawal_keeps_anchors(env):
    env.install()
    anchors = list(env.state.anchors)
    env.verifier.error = H.denied("EVIDENCE_UNAVAILABLE", transient=True)
    env.clock.advance(31)
    d = env.cycle()
    assert d.action == "WITHDRAWN" and env.state.anchors == anchors


def test_only_admin_rebootstrap_allows_unauthenticated_bootstrap(env):
    env.install()
    env.state.rebootstrap()
    assert env.state.anchors is None and env.state.last_seq is None
    env.spire.bundles.clear()
    env.clock.advance(5)
    d = env.cycle()
    _, _, trusted = env.bundle_calls[-1]
    assert trusted is None and d.mode == "bootstrap" and d.action == "INSTALLED"


def test_continuity_failure_holds_and_names_admin_action(env):
    env.install()
    from dnsidfed.bundle import BundleFetchError
    env.bundle_error = BundleFetchError("CONTINUITY_FAILED", "endpoint not authenticated")
    d = env.cycle()
    assert d.decision == "HOLD" and d.reason == "CONTINUITY_FAILED"
    assert "rebootstrap" in d.detail and d.layer == "controller-policy" and d.dnsid_result == "INDETERMINATE"


def test_dnsid_result_is_distinct_from_controller_decision(env):
    d = env.install()
    assert (d.decision, d.dnsid_result, d.layer) == ("ALLOW", "VERIFIED", "DNSid")
    env.verifier.error = H.denied("GOVERNANCE_NOT_APPROVED")
    d = env.cycle()
    assert (d.decision, d.dnsid_result, d.layer) == ("DENY", "NOT_VERIFIED", "DNSid")


# ---------------------------------------------------------------------------------------------------------
# Fail closed end to end: every SDK error shape the verifier can see, mapped by the real verifier code and
# fed through the real reconciler, ends in DENY or HOLD, never adds trust, and withdraws an installed bundle
# either immediately (definitive) or once the grace period has passed (indeterminate).
def _sdk_failures():
    import datetime as dt
    from dnsid.c2sp_tlog import (
        C2spCheckpointConsistencyError, C2spCheckpointStoreError, C2spLifecycleErrorCategory, C2spTlogError,
        TrustedCheckpoint,
    )
    from dnsid.enums import VerificationCode
    cp = lambda n, f: TrustedCheckpoint("o.test/log", n, bytes([f]) * 32, dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))  # noqa: E731
    out = [H.sdk_error(c.name, "x", t) for c in VerificationCode for t in (False, True)]
    out += [H.sdk_error("LOG_ERROR", "x", category=c) for c in
            ("LOG_ROLLBACK", "LOG_FORK", "LOG_INCONSISTENT", "CHECKPOINT_STORE_ERROR", "TERMINAL_STATE")]
    out += [H.sdk_error("STATUS_NOT_ACTIVE", "x", agent_state=s) for s in ("REVOKED", "RETIRED")]
    out += [C2spCheckpointConsistencyError("r", category=C2spLifecycleErrorCategory.LOG_ROLLBACK,
                                           trusted=cp(9, 1), observed=cp(7, 2)),
            C2spCheckpointStoreError("s"), C2spTlogError("t"), RuntimeError("bug")]
    return out


class _RaisingManager:
    def __init__(self, exc):
        self.exc = exc

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def verify_domain(self, domain):
        return H.fake_domain()

    def verify_log_evidence(self, vd):
        raise self.exc


class _Jose:
    def __init__(self, resolver, **kw):
        self.r = resolver

    def verify_jws(self, jws):
        return b"{}", self.r.verify_domain(H.SIGNER)


@pytest.mark.parametrize("exc", _sdk_failures(), ids=lambda e: f"{type(e).__name__}:{getattr(getattr(e, 'code', None), 'name', '')}:{getattr(e, 'category', '') or getattr(e, 'agent_state', '') or ''}:{getattr(e, 'transient', '')}")
def test_no_sdk_failure_reaches_allow(env, monkeypatch, exc):
    import dnsidfed.verifier as V
    env.install()
    monkeypatch.setattr(V, "JoseProfile", _Jose)
    env.rec.verifier = V.DnsidVerifier(env.policy, manager_factory=lambda: _RaisingManager(exc), clock=env.clock)
    sets_before = env.spire.names().count("set_bundle")
    env.clock.advance(1)
    d = env.cycle()
    assert d.decision in ("DENY", "HOLD")
    assert env.spire.names().count("set_bundle") == sets_before  # nothing added or changed
    if d.decision == "HOLD":
        env.clock.advance(env.policy.verification.unavailable_grace_s + 1)
        d = env.cycle()
    assert (d.decision, d.action) == ("DENY", "WITHDRAWN") and H.TD not in env.spire.bundles
