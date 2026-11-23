"""[DNSid] verification of the signed binding statement.

Two kinds of SDK state are handled differently on purpose:

* Lifecycle state is never reused. The SDK caches verified C2SP history per log reader for the whole
  freshness window, so a long-lived `IdentityManager` could keep answering ACTIVE after a revocation
  the log already shows. `DnsidVerifier.verify()` therefore builds a brand-new `IdentityManager` and
  log registry on every call, with `status_check_interval=0` so the status endpoint is asked on every
  call too.
* Trusted checkpoints are always reused. One `CheckpointStore` (see `checkpoints.py`) is injected into
  every fresh registry, so a log that rolls back or forks between cycles is detected instead of being
  trusted again on first contact.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta

from dnsid import (
    IdentityManager, IdentityManagerDependencies, JoseProfile, TransportConfig, TrustedEntity,
    VerificationConfig, VerificationError,
)
from dnsid.c2sp_tlog import (
    C2spCheckpointConsistencyError, C2spCheckpointStoreError, C2spTlogError, C2spTlogVerificationOptions,
    CheckpointStore, InMemoryCheckpointStore, create_c2sp_tlog_verification_registry,
)

from .policy import Policy

# Reasons. DEFINITIVE reasons withdraw trust immediately; INDETERMINATE ones hold the current state
# (never adding material) and withdraw once `unavailable_grace_s` passes without a full verification.
DEFINITIVE = {
    "IDENTITY_NOT_ACTIVE", "IDENTITY_NOT_FOUND", "GOVERNANCE_NOT_APPROVED", "BINDING_SIGNATURE_INVALID",
    "SIGNER_NOT_ALLOWED", "TRUST_DOMAIN_NOT_BOUND", "BINDING_ISSUER_MISMATCH", "BUNDLE_ENDPOINT_MISMATCH",
    "LOG_VERIFICATION_FAILED", "VERIFICATION_FAILED",
    # The log served a checkpoint that does not extend the one already trusted (rollback or fork).
    "LOG_INCONSISTENT",
    # Trusted checkpoint storage is unavailable or corrupt. The SDK says never to substitute empty
    # trust or retry automatically, so this withdraws until an operator restores the store.
    "CHECKPOINT_STORE_FAILED",
}

# Stable categories (dnsid.enums.LifecycleErrorCategory / dnsid.c2sp_tlog.C2spLifecycleErrorCategory)
# carried on VerificationError.category.
_LOG_CONSISTENCY_CATEGORIES = {"LOG_ROLLBACK", "LOG_FORK", "LOG_INCONSISTENT"}
_STORE_CATEGORY = "CHECKPOINT_STORE_ERROR"
_TERMINAL_CATEGORY = "TERMINAL_STATE"
_TERMINAL_AGENT_STATES = {"REVOKED", "RETIRED"}
_TRANSIENT_CODES = {"DNS_RESOLUTION", "STATUS_UNAVAILABLE", "DEADLINE_EXCEEDED"}


class DnsidDenied(Exception):
    def __init__(self, reason: str, detail: str, *, transient: bool, sdk_code: str = ""):
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail, self.transient, self.sdk_code = reason, detail, transient, sdk_code


@dataclass(frozen=True)
class VerifiedBinding:
    payload: bytes
    signer: str
    governance_id: str
    entity_key_thumbprint: str
    logged_state: str
    log_reference: str
    checkpoint_origin: str
    checkpoint_size: int
    checkpoint_root: str
    witness_time: dt.datetime
    dnssec: str
    status_state: str = ""
    status_transition_at: str = ""
    status_url: str = ""
    extra: dict = field(default_factory=dict)


def transport_from(policy: Policy) -> TransportConfig:
    v = policy.verification
    return TransportConfig(dns_server=v.dns_server or None, ca_bundle_path=v.ca_bundle_path or None,
                           private_address_hosts=list(v.private_address_hosts))


def default_manager_factory(policy: Policy, checkpoint_store: CheckpointStore) -> Callable[[], IdentityManager]:
    """Return a factory that builds a brand-new IdentityManager (and log registry) per call.

    Every registry it builds shares `checkpoint_store`, so rollback/fork protection accumulates across
    calls while lifecycle history and status are always fetched and verified fresh.
    """
    v = policy.verification
    # The C2SP log trust policy is configured once, independently of any log or identity data, and is
    # never refetched per cycle.
    log_policy = open(v.log_policy_file, "rb").read()
    pin = TrustedEntity(policy.federation.governance_id, list(policy.federation.entity_key_thumbprints))

    def make() -> IdentityManager:
        transport = transport_from(policy)
        registry = create_c2sp_tlog_verification_registry(C2spTlogVerificationOptions(
            policy_document=log_policy,
            transport_config=transport,
            trusted_checkpoint_store=checkpoint_store,
            checkpoint_freshness_ms=int(v.checkpoint_freshness_s * 1000),
            max_clock_skew_ms=int(v.clock_skew_s * 1000),
        ))
        return IdentityManager.for_verification(
            IdentityManagerDependencies(log_registry=registry),
            verification=VerificationConfig(status_check_interval=timedelta(0), trusted_entities=[pin]),
            transport=transport,
        )
    return make


def _map_sdk_error(exc: VerificationError) -> DnsidDenied:
    """Map an SDK VerificationError to a controller reason. Structured fields first; message text only
    where the SDK exposes no structured signal. Every path is DENY or HOLD; none can lead to ALLOW."""
    code = getattr(exc.code, "name", str(exc.code))
    msg = str(exc)
    transient = bool(getattr(exc, "transient", False))
    category = str(getattr(exc, "category", None) or "")
    agent_state = str(getattr(exc, "agent_state", None) or "").upper()

    def deny(reason: str) -> DnsidDenied:
        return DnsidDenied(reason, msg, transient=False, sdk_code=code)

    def hold(reason: str) -> DnsidDenied:
        return DnsidDenied(reason, msg, transient=True, sdk_code=code)

    # 1. Structured: stable categories and lifecycle state.
    if category in _LOG_CONSISTENCY_CATEGORIES:
        return deny("LOG_INCONSISTENT")
    if category == _STORE_CATEGORY:
        return deny("CHECKPOINT_STORE_FAILED")
    if category == _TERMINAL_CATEGORY or agent_state in _TERMINAL_AGENT_STATES:
        return deny("IDENTITY_NOT_ACTIVE")

    # 2. Structured: verification codes.
    if code == "COUNTERPARTY_NOT_ACCEPTED":
        return deny("GOVERNANCE_NOT_APPROVED")
    if code in ("SIGNATURE_INVALID", "KEY_NOT_FOUND"):
        return deny("BINDING_SIGNATURE_INVALID")
    if code == "STATUS_NOT_ACTIVE":
        return deny("IDENTITY_NOT_ACTIVE")
    if code == "RECORD_NOT_FOUND":
        return deny("IDENTITY_NOT_FOUND")

    # 3. Message fallbacks, used only where the SDK (0.36.0) has no structured equivalent. They refine
    #    the reason label or DENY-vs-HOLD; if the wording ever changes, the result is still DENY or HOLD.
    if code == "RECORD_INVALID" and "JOSE" in msg:
        return deny("BINDING_SIGNATURE_INVALID")
    if code == "TLS_ERROR" and "HTTP 410" in msg:  # a revoked identity's JWKS answers 410 Gone
        return deny("IDENTITY_NOT_ACTIVE")
    if code == "LOG_ERROR":
        low = msg.lower()
        if "too stale" in low:  # stale checkpoint: no category is set; fresher evidence may follow
            return hold("EVIDENCE_STALE")
        if "revoked" in low or "retired" in low or "terminal" in low:
            return deny("IDENTITY_NOT_ACTIVE")
        return hold("EVIDENCE_UNAVAILABLE") if transient else deny("LOG_VERIFICATION_FAILED")

    if code in _TRANSIENT_CODES or transient:
        return hold("EVIDENCE_UNAVAILABLE")
    return deny("VERIFICATION_FAILED")


def _parse_checkpoint(cp) -> tuple[str, int, str]:
    raw = cp if isinstance(cp, (bytes, bytearray)) else str(cp).encode()
    lines = bytes(raw).split(b"\n")
    try:
        return lines[0].decode(), int(lines[1]), lines[2].decode()
    except (IndexError, ValueError):
        return "", -1, ""


class DnsidVerifier:
    def __init__(self, policy: Policy, manager_factory: Callable[[], IdentityManager] | None = None,
                 clock: Callable[[], float] | None = None, checkpoint_store: CheckpointStore | None = None):
        self.policy = policy
        # Process-lifetime protection at minimum; the controller passes a durable FileCheckpointStore.
        self.checkpoint_store = checkpoint_store if checkpoint_store is not None else InMemoryCheckpointStore()
        self.manager_factory = manager_factory or default_manager_factory(policy, self.checkpoint_store)
        self.log_policy_sha256 = ""
        if policy.verification.log_policy_file:
            try:
                self.log_policy_sha256 = hashlib.sha256(open(policy.verification.log_policy_file, "rb").read()).hexdigest()
            except OSError:
                pass
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc).timestamp())
        self.managers_built = 0

    def verify(self, jws: str) -> VerifiedBinding:
        """Verify signer identity (+ governance pin) and fresh C2SP non-revocation. Fresh SDK state."""
        try:
            manager = self.manager_factory()
            self.managers_built += 1
        except C2spTlogError as exc:
            raise DnsidDenied("EVIDENCE_UNAVAILABLE", f"log trust setup failed: {exc}", transient=True) from exc
        try:
            with manager:
                payload, vd = JoseProfile(resolver=manager).verify_jws(jws)
                gi = (vd.record.gi or "").lower().rstrip(".")
                if gi != self.policy.federation.governance_id:  # defence in depth; TrustedEntity enforces too
                    raise DnsidDenied("GOVERNANCE_NOT_APPROVED", f"gi {gi} not approved", transient=False)
                ev = manager.verify_log_evidence(vd)
                if ev.logged_state != "ACTIVE":
                    raise DnsidDenied("IDENTITY_NOT_ACTIVE", f"logged state {ev.logged_state}", transient=False)
                wt = ev.freshness_time
                now = self.clock()
                # Defence in depth: the SDK already excludes future-dated cosignatures from the quorum
                # (bounded by max_clock_skew_ms); re-check the accepted freshness time here.
                if wt.timestamp() > now + self.policy.verification.clock_skew_s:
                    raise DnsidDenied("EVIDENCE_STALE", f"witness time {wt.isoformat()} is in the future",
                                      transient=True)
                origin, size, root = _parse_checkpoint(ev.checkpoint)
                return VerifiedBinding(
                    payload=payload, signer=vd.domain, governance_id=gi,
                    entity_key_thumbprint=vd.signing_key_thumbprint, logged_state=ev.logged_state,
                    log_reference=ev.log_reference, checkpoint_origin=origin, checkpoint_size=size,
                    checkpoint_root=root, witness_time=wt, dnssec=str(getattr(vd.dnssec_state, "name", "")),
                    status_state=str(getattr(getattr(vd, "registry_status", None), "state", "")),
                    status_transition_at=str(getattr(getattr(vd, "registry_status", None), "last_transition_at", "")),
                    status_url=str(getattr(getattr(vd, "record", None), "su", "")),
                )
        except DnsidDenied:
            raise
        except VerificationError as exc:
            raise _map_sdk_error(exc) from exc
        except C2spCheckpointConsistencyError as exc:  # if raised unwrapped: rollback/fork is definitive
            raise DnsidDenied("LOG_INCONSISTENT", f"{type(exc).__name__}: {exc}", transient=False) from exc
        except C2spCheckpointStoreError as exc:  # never substitute empty trust
            raise DnsidDenied("CHECKPOINT_STORE_FAILED", f"{type(exc).__name__}: {exc}", transient=False) from exc
        except C2spTlogError as exc:
            raise DnsidDenied("EVIDENCE_UNAVAILABLE", f"{type(exc).__name__}: {exc}", transient=True) from exc
        except Exception as exc:  # fail closed: anything unexpected is indeterminate, never ALLOW
            raise DnsidDenied("EVIDENCE_UNAVAILABLE", f"{type(exc).__name__}: {exc}", transient=True) from exc
