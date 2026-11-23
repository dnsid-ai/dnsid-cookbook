"""One reconcile cycle of the Acme DNSid federation controller.

Order (all must pass before anything is written to Acme's SPIRE):
  1. fetch the binding statement (JWS)                         -> BINDING_UNAVAILABLE   (indeterminate)
  2. [DNSid] verify signer identity, governance pin, signature  -> fresh SDK manager per cycle
  3. [DNSid] verify fresh C2SP non-revocation evidence          -> IDENTITY_NOT_ACTIVE / EVIDENCE_STALE ...
  4. policy: signer pattern, statement fields, trust-domain mapping, freshness, anti-rollback
  5. fetch the bundle endpoint: bootstrap (unauthenticated; ONLY before the first approval or after an
     explicit admin re-bootstrap) or continuity (authenticated by the last DNSid-approved authority set,
     persisted in controller state - NOT by whatever SPIRE currently holds, so a forced withdrawal can't
     push the controller back into an unauthenticated bootstrap) -> CONTINUITY_FAILED / BUNDLE_UNAVAILABLE
  6. coverage: every served X.509 authority is in the signed set -> BUNDLE_NOT_COVERED
  7. apply: bundle set (X.509 authorities only) + federatesWith on approved Acme entries

Outcomes:
  ALLOW  install/update (or unchanged).
  DENY   definitive reason (revoked identity, unapproved governance, bad signature, wrong trust domain,
         ...): WITHDRAW immediately.
  HOLD   indeterminate reason (evidence/binding/bundle unavailable or stale, expired statement, uncovered
         or discontinuous material): keep what is installed, add nothing, and WITHDRAW once
         `unavailable_grace_s` has passed since the last fully verified cycle (fail closed).
"""
from __future__ import annotations

import json
import time
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .binding import (
    BindingRejected, parse_statement, select_authorities, statement_hash, validate_statement,
    x509_authorities,
)
from .bundle import BundleFetchError, fetch_bundle, pems_from_bundle
from .policy import Policy
from .spire import SpireAdmin
from .verifier import DEFINITIVE, DnsidDenied, DnsidVerifier

DEFINITIVE_BINDING = {"TRUST_DOMAIN_NOT_BOUND", "BINDING_ISSUER_MISMATCH", "BUNDLE_ENDPOINT_MISMATCH"}


@dataclass
class Decision:
    at: float
    decision: str                 # ALLOW | DENY | HOLD
    action: str                   # INSTALLED | UPDATED | UNCHANGED | WITHDRAWN | HELD | NONE
    reason: str                   # OK or a reason code
    detail: str = ""
    layer: str = "DNSid"
    dnsid_result: str = ""        # VERIFIED | NOT_VERIFIED | INDETERMINATE (the DNSid result itself, kept
                                  # distinct from the controller-policy decision, e.g. HOLD within grace)
    mode: str = ""                # bootstrap | continuity
    evidence: dict = field(default_factory=dict)
    statement: dict = field(default_factory=dict)
    installed_spki: list = field(default_factory=list)
    seconds_since_last_verified: float | None = None
    cycle_ms: int = 0


class State:
    """Persisted controller state (anti-rollback and the fail-closed grace clock)."""

    def __init__(self, path: str | None):
        self.path = Path(path) if path else None
        self.last_seq: int | None = None
        self.last_verified_at: float | None = None
        # Trust anchors: PEMs of the last authority set that passed full DNSid + coverage checks. Once set,
        # bundle fetches MUST be authenticated by them (continuity) until an admin explicitly re-bootstraps.
        self.anchors: list[str] | None = None
        # Ownership record: the X.509 authority set (SPKI hashes) THIS controller last installed into the
        # SPIRE server, or None when it has nothing installed. Set on apply, cleared on every withdrawal. An
        # orderly shutdown withdraws only a bundle that still matches this record exactly.
        self.managed_spki: list[str] | None = None
        if self.path and self.path.exists():
            d = json.loads(self.path.read_text())
            self.last_seq, self.last_verified_at = d.get("last_seq"), d.get("last_verified_at")
            self.anchors = d.get("anchors")
            self.managed_spki = d.get("managed_spki")

    def save(self):
        if self.path:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"last_seq": self.last_seq, "last_verified_at": self.last_verified_at,
                                       "anchors": self.anchors, "managed_spki": self.managed_spki}))
            tmp.replace(self.path)

    def rebootstrap(self):
        """Explicit admin action: forget trust anchors and anti-rollback state."""
        self.anchors, self.last_seq, self.last_verified_at = None, None, None
        self.managed_spki = None
        self.save()


def http_get_text(url: str, timeout: float = 5.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 - fixed policy URL
        if r.status != 200:
            raise OSError(f"HTTP {r.status}")
        return r.read(64 * 1024).decode().strip()


class Reconciler:
    def __init__(self, policy: Policy, verifier: DnsidVerifier, spire: SpireAdmin, state: State, *,
                 fetch_binding: Callable[[str], str] = http_get_text,
                 fetch_bundle_fn: Callable = fetch_bundle,
                 clock: Callable[[], float] = time.time,
                 audit: Callable[[Decision], None] | None = None):
        self.p, self.verifier, self.spire, self.state = policy, verifier, spire, state
        self.fetch_binding, self.fetch_bundle = fetch_binding, fetch_bundle_fn
        self.clock, self.audit = clock, audit or (lambda d: None)

    # ------------------------------------------------------------------ helpers
    def _since_verified(self, now: float) -> float | None:
        lv = self.state.last_verified_at
        return None if lv is None else round(now - lv, 1)

    def _withdraw(self, installed: dict | None) -> str:
        if installed is None:
            self.state.managed_spki = None
            return "NONE"
        self.spire.delete_bundle(self.p.federation.trust_domain)
        self.state.managed_spki = None
        return "WITHDRAWN"

    def _finish(self, d: Decision, t0: float) -> Decision:
        d.cycle_ms = int((time.monotonic() - t0) * 1000)
        self.audit(d)
        return d

    def _deny(self, reason, detail, installed, now, t0, **kw) -> Decision:
        action = self._withdraw(installed)
        # A definitive denial also invalidates the grace clock: re-approval needs full verification.
        self.state.last_verified_at = None
        self.state.save()
        return self._finish(Decision(now, "DENY", action, reason, detail, dnsid_result="NOT_VERIFIED",
                                     seconds_since_last_verified=None, **kw), t0)

    def _hold(self, reason, detail, installed, now, t0, **kw) -> Decision:
        since = self._since_verified(now)
        grace = self.p.verification.unavailable_grace_s
        if installed is not None and (since is None or since > grace):
            action = self._withdraw(installed)
            detail = f"{detail} | no full verification for {since}s > grace {grace:.0f}s: fail closed"
            self.state.last_verified_at = None
            self.state.save()
            return self._finish(Decision(now, "DENY", action, reason, detail, layer="controller-policy",
                                         dnsid_result="INDETERMINATE", seconds_since_last_verified=since, **kw), t0)
        action = "HELD" if installed is not None else "NONE"
        return self._finish(Decision(now, "HOLD", action, reason, detail, layer="controller-policy",
                                     dnsid_result="INDETERMINATE",
                                     seconds_since_last_verified=since, **kw), t0)

    # ------------------------------------------------------------------ cycle
    def cycle(self) -> Decision:
        t0 = time.monotonic()
        now = self.clock()
        fed = self.p.federation
        installed = self.spire.get_bundle(fed.trust_domain)
        installed_spki = sorted(x509_authorities(installed)) if installed else []
        ctx: dict = {"installed_spki": installed_spki}

        # 1. binding statement
        try:
            jws = self.fetch_binding(fed.binding_url)
        except Exception as exc:  # noqa: BLE001 - any failure is indeterminate
            return self._hold("BINDING_UNAVAILABLE", f"{type(exc).__name__}: {exc}", installed, now, t0, **ctx)

        # 2-3. DNSid identity, governance pin, signature, fresh non-revocation (fresh SDK state)
        try:
            vb = self.verifier.verify(jws)
        except DnsidDenied as e:
            fn = self._hold if e.transient or e.reason not in DEFINITIVE else self._deny
            return fn(e.reason, e.detail, installed, now, t0, **ctx)
        ctx["evidence"] = {
            "signer": vb.signer, "governance_id": vb.governance_id,
            "entity_key_thumbprint": vb.entity_key_thumbprint, "logged_state": vb.logged_state,
            "log_reference": vb.log_reference, "checkpoint": {"origin": vb.checkpoint_origin,
                                                                "size": vb.checkpoint_size,
                                                                "root": vb.checkpoint_root},
            "witness_time": vb.witness_time.isoformat(), "evidence_age_s": round(now - vb.witness_time.timestamp(), 1),
            "dnssec": vb.dnssec,
            # su is served by the registry, outside gi: delegated operational status (draft SU section)
            "status_service": {"state": vb.status_state, "last_transition_at": vb.status_transition_at,
                               "url": vb.status_url, "note": "delegated operational status (su outside gi)"},
            "log_policy_sha256": getattr(self.verifier, "log_policy_sha256", ""),
        }

        # 4. policy checks on the verified statement
        if not fed.signer_allowed(vb.signer):
            return self._deny("SIGNER_NOT_ALLOWED", f"{vb.signer} does not match {fed.signer_pattern}",
                              installed, now, t0, **ctx)
        try:
            stmt = validate_statement(parse_statement(vb.payload), signer_fqdn=vb.signer, policy=fed, now=now,
                                      max_age_s=self.p.verification.max_statement_age_s,
                                      skew_s=self.p.verification.clock_skew_s, last_seq=self.state.last_seq)
        except BindingRejected as e:
            fn = self._deny if e.reason in DEFINITIVE_BINDING else self._hold
            return fn(e.reason, e.detail, installed, now, t0, **ctx)
        ctx["statement"] = {"hash": statement_hash(jws), "seq": stmt.seq, "iat": stmt.iat, "exp": stmt.exp,
                            "spki": sorted(stmt.spki)}

        # 5. bundle endpoint (bootstrap vs continuity). Anchors come from persisted controller state; the
        #    installed bundle is used only if state was lost while a bundle is still installed.
        anchors = self.state.anchors or (pems_from_bundle(installed) if installed else None)
        try:
            fetched, mode = self.fetch_bundle(fed.bundle_endpoint_url, fed.bundle_endpoint_spiffe_id, anchors)
        except BundleFetchError as e:
            if e.reason == "CONTINUITY_FAILED":
                e.detail += " | requires an explicit admin re-bootstrap (POST /rebootstrap)"
            return self._hold(e.reason, e.detail, installed, now, t0, **ctx)
        ctx["mode"] = mode

        # 6. coverage
        try:
            desired = select_authorities(fetched, stmt)
        except BindingRejected as e:
            return self._hold(e.reason, e.detail, installed, now, t0, **ctx)

        # 7. apply
        desired_spki = sorted(x509_authorities(desired))
        if installed is None:
            action = "INSTALLED"
        elif desired_spki != installed_spki:
            action = "UPDATED"
        else:
            action = "UNCHANGED"
        if action != "UNCHANGED":
            self.spire.set_bundle(fed.trust_domain, desired)
        for sid in fed.federated_entries:
            self.spire.ensure_federates(sid, fed.trust_domain)
        self.state.last_seq = stmt.seq
        self.state.last_verified_at = now
        self.state.anchors = pems_from_bundle(desired)
        self.state.managed_spki = desired_spki
        self.state.save()
        ctx["installed_spki"] = desired_spki
        return self._finish(Decision(now, "ALLOW", action, "OK", "", dnsid_result="VERIFIED",
                                     seconds_since_last_verified=0.0, **ctx), t0)


def decision_dict(d: Decision) -> dict:
    return asdict(d)
