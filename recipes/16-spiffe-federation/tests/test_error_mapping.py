"""Structured SDK error mapping: categories and lifecycle state win over message text; every outcome is
DENY or HOLD (never ALLOW); message fallbacks only where the SDK has no structured signal."""
import datetime as dt

import pytest
from dnsid import VerificationError
from dnsid.c2sp_tlog import (
    C2spCheckpointConsistencyError, C2spCheckpointStoreError, C2spLifecycleErrorCategory, TrustedCheckpoint,
)
from dnsid.enums import LifecycleErrorCategory
from dnsid.exceptions import LifecycleVerificationError

import helpers as H
import dnsidfed.verifier as V
from dnsidfed.verifier import DnsidDenied, _map_sdk_error


def _cp(size, fill):
    return TrustedCheckpoint("log.test/origin", size, bytes([fill]) * 32,
                             dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))


def _check(d: DnsidDenied, reason: str, transient: bool):
    assert (d.reason, d.transient) == (reason, transient), (d.reason, d.transient, d.detail)
    if not transient:  # non-transient reasons must withdraw immediately in the reconciler
        assert d.reason in V.DEFINITIVE


# ------------------------------------------------------------------ structured: categories
@pytest.mark.parametrize("category", ["LOG_ROLLBACK", "LOG_FORK", "LOG_INCONSISTENT"])
@pytest.mark.parametrize("transient", [False, True])
def test_log_consistency_category_is_definitive(category, transient):
    # Category wins even if a (hypothetical) transient flag or misleading message is present.
    exc = H.sdk_error("LOG_ERROR", "checkpoint too stale", transient, category=category)
    _check(_map_sdk_error(exc), "LOG_INCONSISTENT", False)


def test_checkpoint_store_category_is_definitive():
    exc = H.sdk_error("LOG_ERROR", "store unavailable", category="CHECKPOINT_STORE_ERROR")
    _check(_map_sdk_error(exc), "CHECKPOINT_STORE_FAILED", False)


def test_terminal_state_category_without_keyword_in_message():
    exc = H.sdk_error("LOG_ERROR", "lifecycle reducer rejected event", category="TERMINAL_STATE")
    _check(_map_sdk_error(exc), "IDENTITY_NOT_ACTIVE", False)


def test_real_lifecycle_verification_error_subclass():
    exc = LifecycleVerificationError(LifecycleErrorCategory.TERMINAL_STATE, "event after terminal state")
    _check(_map_sdk_error(exc), "IDENTITY_NOT_ACTIVE", False)


def test_real_c2sp_enum_category_value_is_matched():
    # The SDK stores the StrEnum value as the category string at the LogReader boundary.
    exc = H.sdk_error("LOG_ERROR", "x", category=C2spLifecycleErrorCategory.LOG_ROLLBACK.value)
    _check(_map_sdk_error(exc), "LOG_INCONSISTENT", False)


# ------------------------------------------------------------------ structured: lifecycle state
@pytest.mark.parametrize("state", ["REVOKED", "RETIRED", "revoked"])
def test_agent_state_terminal(state):
    exc = H.sdk_error("STATUS_NOT_ACTIVE", "identity is not ACTIVE", agent_state=state)
    _check(_map_sdk_error(exc), "IDENTITY_NOT_ACTIVE", False)


@pytest.mark.parametrize("state", ["PENDING", "VERIFYING"])
def test_agent_state_non_terminal_status_still_denied(state):
    exc = H.sdk_error("STATUS_NOT_ACTIVE", "identity is not ACTIVE", agent_state=state)
    _check(_map_sdk_error(exc), "IDENTITY_NOT_ACTIVE", False)


# ------------------------------------------------------------------ structured: codes
@pytest.mark.parametrize("code,reason", [
    ("COUNTERPARTY_NOT_ACCEPTED", "GOVERNANCE_NOT_APPROVED"),
    ("SIGNATURE_INVALID", "BINDING_SIGNATURE_INVALID"),
    ("KEY_NOT_FOUND", "BINDING_SIGNATURE_INVALID"),
    ("STATUS_NOT_ACTIVE", "IDENTITY_NOT_ACTIVE"),
    ("RECORD_NOT_FOUND", "IDENTITY_NOT_FOUND"),
    ("DNSSEC_FAILED", "VERIFICATION_FAILED"),
    ("KEY_AGE_EXCEEDED", "VERIFICATION_FAILED"),
])
def test_codes_independent_of_message(code, reason):
    _check(_map_sdk_error(H.sdk_error(code, "no recognisable words here")), reason, False)


@pytest.mark.parametrize("code", ["DNS_RESOLUTION", "STATUS_UNAVAILABLE", "DEADLINE_EXCEEDED"])
def test_transient_codes_hold(code):
    _check(_map_sdk_error(H.sdk_error(code, "x", transient=True)), "EVIDENCE_UNAVAILABLE", True)


# ------------------------------------------------------------------ message fallbacks (no structured signal)
def test_fallback_jose_label():
    _check(_map_sdk_error(H.sdk_error("RECORD_INVALID", "JOSE header invalid")), "BINDING_SIGNATURE_INVALID", False)


def test_fallback_jwks_410():
    _check(_map_sdk_error(H.sdk_error("TLS_ERROR", "JWKS fetch returned HTTP 410 for 'x'")), "IDENTITY_NOT_ACTIVE", False)


def test_fallback_stale_checkpoint_is_hold():
    # Real SDK wording (reader: "C2SP checkpoint is too stale for non-revocation verification"), no category.
    exc = H.sdk_error("LOG_ERROR", "C2SP checkpoint is too stale for non-revocation verification")
    _check(_map_sdk_error(exc), "EVIDENCE_STALE", True)


@pytest.mark.parametrize("code,msg,reason,transient", [
    # If the SDK ever rewords these messages, the result degrades to another DENY/HOLD, never ALLOW.
    ("RECORD_INVALID", "header invalid", "VERIFICATION_FAILED", False),
    ("TLS_ERROR", "JWKS gone", "VERIFICATION_FAILED", False),
    ("LOG_ERROR", "checkpoint is old", "LOG_VERIFICATION_FAILED", False),
])
def test_reworded_fallbacks_still_fail_closed(code, msg, reason, transient):
    _check(_map_sdk_error(H.sdk_error(code, msg)), reason, transient)


# ------------------------------------------------------------------ verify(): unwrapped C2SP errors
class _Mgr:
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


@pytest.mark.parametrize("exc,reason,transient", [
    (C2spCheckpointConsistencyError("rollback", category=C2spLifecycleErrorCategory.LOG_ROLLBACK,
                                    trusted=_cp(9, 1), observed=_cp(7, 2)), "LOG_INCONSISTENT", False),
    (C2spCheckpointStoreError("store corrupt"), "CHECKPOINT_STORE_FAILED", False),
    (VerificationError(__import__("dnsid.enums", fromlist=["VerificationCode"]).VerificationCode.LOG_ERROR,
                       "C2SP checkpoint tree size regressed", category="LOG_ROLLBACK"), "LOG_INCONSISTENT", False),
])
def test_verify_maps_unwrapped_and_wrapped_consistency_errors(monkeypatch, exc, reason, transient):
    monkeypatch.setattr(V, "JoseProfile", _Jose)
    ver = V.DnsidVerifier(H.make_policy(), manager_factory=lambda: _Mgr(exc), clock=lambda: H.NOW)
    with pytest.raises(DnsidDenied) as ei:
        ver.verify("j")
    _check(ei.value, reason, transient)
