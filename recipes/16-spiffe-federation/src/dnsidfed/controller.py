"""Acme DNSid federation controller service.

    python -m dnsidfed.controller --policy /etc/dnsidfed/policy.toml [--once]

Runs a reconcile cycle every poll_interval_s. Serves (plain HTTP, bound to localhost on the host):
  GET  /status     last decision + history (JSON)
  GET  /healthz
  POST /reconcile  run one cycle now and return its decision (admin token required)
  POST /rebootstrap  admin: forget persisted trust anchors (next approval is an unauthenticated bootstrap)
Appends every decision to the audit log (JSON Lines).

Orderly shutdown (SIGTERM / SIGINT, e.g. `docker stop`, `make stop`): the cycle in progress finishes, then,
under the reconciliation lock, the controller withdraws ONLY the federation trust it can prove it installed
(see `Controller.shutdown`), writes a CONTROLLER_SHUTDOWN audit event and exits. Trust anchors, the
anti-rollback sequence and the trusted checkpoint history are kept. A crash, SIGKILL, OOM kill or host failure
runs none of this: whatever bundle was installed stays installed until the controller runs again (its first
cycle then re-verifies and, if anything is wrong, withdraws).

State directory (protect it like the policy and pinned keys):
  state.json                 anti-rollback sequence, grace clock, approved trust anchors
  trusted-checkpoints.json   C2SP trusted checkpoints shared by every cycle (see checkpoints.py);
                             created only by `python -m dnsidfed.checkpoints init`, never by the controller
  trusted-checkpoints.journal  append-only record of store initialization and resets
  audit.jsonl                decision log
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .checkpoints import FileCheckpointStore, store_path
from .policy import load_policy
from .binding import x509_authorities
from .reconcile import Decision, Reconciler, State, decision_dict
from .spire import SpireAdmin, SpireError
from .verifier import DnsidVerifier

log = logging.getLogger("dnsidfed.controller")


class Controller:
    def __init__(self, policy_path: str, state_dir: str, spire_socket: str):
        self.policy = load_policy(policy_path)
        os.makedirs(state_dir, exist_ok=True)
        self.audit_path = os.path.join(state_dir, "audit.jsonl")
        # One durable trusted-checkpoint store for the life of the controller, shared by the fresh SDK
        # registry built on every cycle. It must have been initialized explicitly (see checkpoints.py);
        # if it is missing or cannot be loaded, it fails closed and every cycle DENYs.
        self.checkpoints = FileCheckpointStore(store_path(state_dir))
        self.verifier = DnsidVerifier(self.policy, checkpoint_store=self.checkpoints)
        self.rec = Reconciler(self.policy, self.verifier, SpireAdmin(spire_socket),
                              State(os.path.join(state_dir, "state.json")), audit=self._audit)
        self.lock = threading.Lock()
        self.last: Decision | None = None
        self.history: list[dict] = []
        self.started_at = time.time()
        self.last_cycle_end: float | None = None
        self.shutdown_ok: bool | None = None
        self.stopping = False   # set under the lock by shutdown(): no cycle may re-install trust afterwards

    def _audit(self, d: Decision) -> None:
        rec = decision_dict(d)
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        self.history = (self.history + [{k: rec[k] for k in ("at", "decision", "action", "reason")}])[-50:]
        log.info(json.dumps({"layer": "DNSid", "decision": d.decision, "action": d.action, "reason": d.reason,
                             "detail": d.detail[:300], "signer": d.evidence.get("signer"),
                             "mode": d.mode, "cycle_ms": d.cycle_ms}))

    def run_cycle(self) -> Decision:
        with self.lock:
            if self.stopping:
                return Decision(time.time(), "HOLD", "NONE", "CONTROLLER_STOPPING",
                                "shutdown in progress: no further reconciliation", layer="controller-policy")
            try:
                d = self.rec.cycle()
            except Exception as exc:  # noqa: BLE001 - never crash into an ALLOW; fail closed after grace
                log.exception("reconcile cycle failed")
                d = self._controller_error(exc)
            self.last = d
            self.last_cycle_end = time.time()
            return d

    def stale_after_s(self) -> float:
        """Enforcement is considered INACTIVE if no cycle completed for this long (healthz -> 503)."""
        return max(60.0, 6 * self.policy.verification.poll_interval_s)

    def enforcing(self) -> bool:
        ref = self.last_cycle_end or self.started_at
        return time.time() - ref <= self.stale_after_s()

    def _controller_error(self, exc: Exception) -> Decision:
        """A cycle that raises is indeterminate: hold within the grace window, then withdraw (fail closed)."""
        now = time.time()
        detail = f"{type(exc).__name__}: {exc}"
        st, grace = self.rec.state, self.rec.p.verification.unavailable_grace_s
        since = None if st.last_verified_at is None else round(now - st.last_verified_at, 1)
        if since is not None and since <= grace:
            d = Decision(now, "HOLD", "HELD", "CONTROLLER_ERROR", detail, seconds_since_last_verified=since)
        else:
            try:
                removed = self.rec.spire.delete_bundle(self.rec.p.federation.trust_domain)
                action = "WITHDRAWN" if removed else "NONE"
            except Exception as exc2:  # noqa: BLE001
                action, detail = "NONE", f"{detail} | withdraw also failed: {exc2}"
            st.last_verified_at = None
            if action == "WITHDRAWN":
                st.managed_spki = None
            st.save()
            d = Decision(now, "DENY", action, "CONTROLLER_ERROR",
                         f"{detail} | no full verification for {since}s > grace {grace:.0f}s: fail closed",
                         seconds_since_last_verified=since)
        self._audit(d)
        return d

    def shutdown(self) -> Decision:
        """Orderly shutdown: withdraw only federation trust this controller provably installed.

        Ownership is established, under the reconciliation lock, only when all of these hold:
          * the persisted ownership record (state.managed_spki) says this controller installed a bundle, and
          * the bundle SPIRE holds for the policy's trust domain right now has exactly that X.509 authority set.
        Then, and only then:
          1. the policy's own federated entries stop federating with that trust domain (other federations
             on those entries are kept), which withdraws the trust this controller granted;
          2. the bundle is deleted in SPIRE's "restrict" mode, which refuses while any OTHER entry still
             federates with it, so relationships this controller does not manage are never cut.
        If ownership cannot be established, nothing is changed and the event says why (exit status 3).
        Trust anchors, the anti-rollback sequence and the checkpoint history are always kept.
        """
        fed = self.policy.federation
        with self.lock:
            self.stopping = True
            now = time.time()
            st = self.rec.state
            try:
                installed = self.rec.spire.get_bundle(fed.trust_domain)
            except Exception as exc:  # noqa: BLE001 - cannot inspect: never delete blind
                return self._shutdown_event(now, "NONE", "CONTROLLER_SHUTDOWN_OWNERSHIP_UNCERTAIN",
                                            f"could not read SPIRE's {fed.trust_domain} bundle: {exc}", ok=False)
            current = sorted(x509_authorities(installed)) if installed else None
            managed = sorted(st.managed_spki) if st.managed_spki else None
            if current is None:
                st.managed_spki, st.last_verified_at = None, None
                st.save()
                return self._shutdown_event(now, "NONE", "CONTROLLER_SHUTDOWN",
                                            f"no {fed.trust_domain} bundle installed; nothing to withdraw")
            if managed is None:
                return self._shutdown_event(now, "NONE", "CONTROLLER_SHUTDOWN_OWNERSHIP_UNCERTAIN",
                                            f"a {fed.trust_domain} bundle is installed but this controller has no "
                                            "record of installing it: left untouched", ok=False)
            if current != managed:
                return self._shutdown_event(now, "NONE", "CONTROLLER_SHUTDOWN_OWNERSHIP_UNCERTAIN",
                                            f"the installed {fed.trust_domain} bundle {current} differs from the one "
                                            f"this controller installed {managed}: left untouched", ok=False)
            try:
                for sid in fed.federated_entries:
                    self.rec.spire.remove_federates(sid, fed.trust_domain)
            except Exception as exc:  # noqa: BLE001
                return self._shutdown_event(now, "NONE", "CONTROLLER_SHUTDOWN_OWNERSHIP_UNCERTAIN",
                                            f"could not dissociate managed entries: {exc}", ok=False)
            # Managed entries no longer federate: the trust this controller granted is withdrawn.
            st.managed_spki, st.last_verified_at = None, None
            st.save()
            try:
                self.rec.spire.delete_bundle(fed.trust_domain, mode="restrict")
            except SpireError as exc:
                return self._shutdown_event(now, "DISSOCIATED", "CONTROLLER_SHUTDOWN",
                                            f"managed entries no longer federate with {fed.trust_domain}; the bundle "
                                            f"is kept because other entries still reference it: {exc}")
            return self._shutdown_event(now, "WITHDRAWN", "CONTROLLER_SHUTDOWN",
                                        f"withdrew the {fed.trust_domain} bundle this controller installed; "
                                        "anchors and checkpoint history kept")

    def _shutdown_event(self, now: float, action: str, reason: str, detail: str, ok: bool = True) -> Decision:
        # HOLD = left exactly as it was (ownership not established); DENY = trust withdrawn or nothing installed.
        d = Decision(now, "DENY" if ok else "HOLD", action, reason, detail, layer="controller-policy")
        self._audit(d)
        self.last, self.shutdown_ok = d, ok
        (log.info if ok else log.error)(json.dumps({"msg": "controller shutdown", "action": action,
                                                    "reason": reason, "detail": detail[:300]}))
        return d

    def status(self) -> dict:
        p = self.policy
        return {
            "policy": {"trust_domain": p.federation.trust_domain, "governance_id": p.federation.governance_id,
                       "entity_key_thumbprints": list(p.federation.entity_key_thumbprints),
                       "signer_pattern": p.federation.signer_pattern,
                       "poll_interval_s": p.verification.poll_interval_s,
                       "checkpoint_freshness_s": p.verification.checkpoint_freshness_s,
                       "unavailable_grace_s": p.verification.unavailable_grace_s},
            "managers_built": self.verifier.managers_built,
            "checkpoint_store": {"path": str(self.checkpoints.path), "healthy": self.checkpoints.failure is None,
                                 "failure": self.checkpoints.failure},
            "enforcing": self.enforcing(),
            "last_cycle_age_s": None if self.last_cycle_end is None else round(time.time() - self.last_cycle_end, 1),
            "last": decision_dict(self.last) if self.last else None,
            "history": self.history,
        }


def serve(ctrl: Controller, port: int, admin_token: str | None = None) -> None:
    import hmac

    class H(BaseHTTPRequestHandler):
        def _json(self, code, obj):
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path == "/status":
                return self._json(200, ctrl.status())
            if self.path == "/healthz":
                # Unhealthy when the reconcile loop has stalled: a running container is not the same as
                # active enforcement.
                ok = ctrl.enforcing()
                return self._json(200 if ok else 503, {"ok": ok, "enforcing": ok})
            self._json(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            # The controller also sits on the DNSid Local network: state-changing endpoints need the
            # admin token. GET /status stays readable.
            if admin_token and not hmac.compare_digest(self.headers.get("X-Admin-Token", ""), admin_token):
                return self._json(403, {"error": "admin token required"})
            if self.path == "/reconcile":
                return self._json(200, decision_dict(ctrl.run_cycle()))
            if self.path == "/rebootstrap":
                # Explicit admin action: withdraw the installed bundle AND forget the trust anchors, so the
                # next approval is a genuine (unauthenticated-channel, DNSid-signed) bootstrap.
                with ctrl.lock:
                    withdrawn = ctrl.rec.spire.delete_bundle(ctrl.policy.federation.trust_domain)
                    ctrl.rec.state.rebootstrap()
                log.info(json.dumps({"layer": "controller-policy", "msg": "admin re-bootstrap",
                                     "withdrawn": withdrawn}))
                return self._json(200, {"rebootstrap": True, "withdrawn": withdrawn})
            self._json(404, {"error": "not found"})

        def log_message(self, *a):
            pass

    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default=os.environ.get("DNSIDFED_POLICY", "/etc/dnsidfed/policy.toml"))
    ap.add_argument("--state-dir", default=os.environ.get("DNSIDFED_STATE", "/var/lib/dnsidfed"))
    ap.add_argument("--spire-socket", default=os.environ.get("SPIRE_ADMIN_SOCKET", "/run/spire/server/api.sock"))
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--admin-token-file", default=os.environ.get("DNSIDFED_ADMIN_TOKEN_FILE", ""))
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    ctrl = Controller(a.policy, a.state_dir, a.spire_socket)
    if a.once:
        print(json.dumps(decision_dict(ctrl.run_cycle()), indent=2, default=str))
        return 0
    token = open(a.admin_token_file).read().strip() if a.admin_token_file else None
    stop = threading.Event()
    install_signal_handlers(stop)
    threading.Thread(target=serve, args=(ctrl, a.port, token), daemon=True).start()
    log.info(json.dumps({"layer": "DNSid", "msg": "controller started", "policy": ctrl.status()["policy"]}))
    return run_until_stopped(ctrl, stop)


def install_signal_handlers(stop: threading.Event) -> None:
    """SIGTERM/SIGINT only set `stop`; the loop finishes the cycle in progress, then shuts down. (Without a
    handler, a PID 1 process ignores SIGTERM and Docker eventually SIGKILLs it, so nothing is withdrawn.)"""
    def handler(signum, _frame):
        log.info(json.dumps({"msg": "stop requested", "signal": signal.Signals(signum).name}))
        stop.set()
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


def run_until_stopped(ctrl: Controller, stop: threading.Event) -> int:
    while not stop.is_set():
        ctrl.run_cycle()  # always completes; a stop request is honoured between cycles
        stop.wait(ctrl.policy.verification.poll_interval_s)
    ctrl.shutdown()
    ctrl.checkpoints.close()
    return 0 if ctrl.shutdown_ok else 3


if __name__ == "__main__":
    sys.exit(main())
