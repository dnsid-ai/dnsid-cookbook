"""Orderly controller shutdown: withdraws only the federation trust this controller provably installed,
keeps unrelated SPIFFE federation relationships, preserves anchors and checkpoint history, and the
restarted controller resumes from preserved state (authenticated continuity)."""
import json
import os
import signal
import threading
import time
import types

import pytest

import helpers as H
from dnsidfed.controller import Controller, install_signal_handlers, run_until_stopped
from dnsidfed.reconcile import State

PURCHASING = H.ENTRIES[0]


def make_ctrl(env, tmp_path):
    c = object.__new__(Controller)
    c.policy, c.rec, c.verifier = env.policy, env.rec, env.verifier
    c.lock, c.last, c.history = threading.Lock(), None, []
    c.audit_path = str(tmp_path / "audit.jsonl")
    c.started_at, c.last_cycle_end = time.time(), None
    c.shutdown_ok, c.stopping = None, False
    c.checkpoints = types.SimpleNamespace(close=lambda: None, failure=None, path="unused")
    return c


def audit(tmp_path):
    return [json.loads(ln) for ln in (tmp_path / "audit.jsonl").read_text().splitlines()]


# ------------------------------------------------------------------ ownership record
def test_install_records_ownership_and_withdrawal_clears_it(env):
    env.install()
    assert env.state.managed_spki == [env.A.spki]
    assert State(str(env.state_path)).managed_spki == [env.A.spki]  # persisted
    env.verifier.error = H.denied("IDENTITY_NOT_ACTIVE")
    env.clock.advance(1)
    assert env.cycle().action == "WITHDRAWN"
    assert env.state.managed_spki is None and State(str(env.state_path)).managed_spki is None


def test_rebootstrap_clears_ownership(env):
    env.install()
    env.state.rebootstrap()
    assert State(str(env.state_path)).managed_spki is None


def test_older_state_file_without_ownership_field_loads(tmp_path):
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"last_seq": 3, "last_verified_at": 1.0, "anchors": ["pem"]}))
    st = State(str(p))
    assert st.managed_spki is None and st.anchors == ["pem"]


# ------------------------------------------------------------------ shutdown withdrawal
def test_shutdown_withdraws_owned_trust_and_keeps_anchors(env, tmp_path):
    env.install()
    anchors, seq = list(env.state.anchors), env.state.last_seq
    c = make_ctrl(env, tmp_path)
    d = c.shutdown()
    assert (d.decision, d.action, d.reason) == ("DENY", "WITHDRAWN", "CONTROLLER_SHUTDOWN") and c.shutdown_ok
    assert H.TD not in env.spire.bundles
    assert H.TD not in env.spire.federated[PURCHASING]
    assert ("delete_bundle", H.TD, "restrict") in env.spire.calls  # never "dissociate" on shutdown
    st = State(str(env.state_path))
    assert st.anchors == anchors and st.last_seq == seq             # continuity + anti-rollback kept
    assert st.managed_spki is None and st.last_verified_at is None
    (ev,) = audit(tmp_path)
    assert ev["reason"] == "CONTROLLER_SHUTDOWN" and ev["action"] == "WITHDRAWN"


def test_shutdown_preserves_unrelated_federation_relationships(env, tmp_path):
    env.install()
    other_td, other_entry = "partner.test", "spiffe://acme.test/reporting"
    env.spire.bundles[other_td] = H.bundle_of(env.B)                 # an unrelated federated bundle
    env.spire.federated[PURCHASING].add(other_td)                   # managed entry also federates elsewhere
    env.spire.federated[other_entry] = {H.TD, other_td}             # an entry this controller does not manage
    c = make_ctrl(env, tmp_path)
    d = c.shutdown()
    assert d.action == "DISSOCIATED" and c.shutdown_ok
    assert env.spire.federated[PURCHASING] == {other_td}            # only the managed relationship removed
    assert env.spire.federated[other_entry] == {H.TD, other_td}     # unmanaged entry untouched
    assert H.TD in env.spire.bundles                                # restrict refused: still referenced
    assert other_td in env.spire.bundles
    assert "other entries still reference it" in d.detail


def test_bundle_not_recorded_as_ours_is_left_untouched(env, tmp_path):
    env.spire.set_bundle(H.TD, H.bundle_of(env.A))                  # installed by someone else
    env.spire.federated[PURCHASING] = {H.TD}
    before = (json.dumps(env.spire.bundles, sort_keys=True), {k: set(v) for k, v in env.spire.federated.items()})
    c = make_ctrl(env, tmp_path)
    d = c.shutdown()
    assert (d.decision, d.action, d.reason) == ("HOLD", "NONE", "CONTROLLER_SHUTDOWN_OWNERSHIP_UNCERTAIN")
    assert c.shutdown_ok is False
    assert (json.dumps(env.spire.bundles, sort_keys=True), env.spire.federated) == before


def test_bundle_changed_since_we_installed_it_is_left_untouched(env, tmp_path):
    env.install()
    env.spire.bundles[H.TD] = H.bundle_of(env.B)                    # replaced behind the controller's back
    c = make_ctrl(env, tmp_path)
    d = c.shutdown()
    assert d.reason == "CONTROLLER_SHUTDOWN_OWNERSHIP_UNCERTAIN" and c.shutdown_ok is False
    assert H.TD in env.spire.bundles and H.TD in env.spire.federated[PURCHASING]
    assert not any(x[0] == "remove_federates" for x in env.spire.calls)
    assert ("delete_bundle", H.TD, "restrict") not in env.spire.calls


def test_nothing_installed_is_a_clean_shutdown(env, tmp_path):
    c = make_ctrl(env, tmp_path)
    d = c.shutdown()
    assert (d.decision, d.action, d.reason) == ("DENY", "NONE", "CONTROLLER_SHUTDOWN") and c.shutdown_ok


def test_unreadable_spire_state_never_deletes_blind(env, tmp_path):
    env.install()

    def boom(td):
        raise RuntimeError("admin socket gone")
    env.spire.get_bundle = boom
    c = make_ctrl(env, tmp_path)
    d = c.shutdown()
    assert d.reason == "CONTROLLER_SHUTDOWN_OWNERSHIP_UNCERTAIN" and c.shutdown_ok is False
    assert H.TD in env.spire.bundles


def test_no_cycle_can_reinstall_after_shutdown(env, tmp_path):
    env.install()
    c = make_ctrl(env, tmp_path)
    c.shutdown()
    n = len(env.spire.calls)
    d = c.run_cycle()                                               # e.g. a late POST /reconcile
    assert (d.decision, d.reason) == ("HOLD", "CONTROLLER_STOPPING")
    assert len(env.spire.calls) == n and H.TD not in env.spire.bundles


# ------------------------------------------------------------------ restart after shutdown
def test_restart_resumes_preserved_state_in_authenticated_continuity(env, tmp_path):
    env.install()
    make_ctrl(env, tmp_path).shutdown()
    restarted = State(str(env.state_path))                          # a new process loads the same file
    env.rec = env.make_reconciler(restarted)
    env.state = restarted
    env.clock.advance(60)
    d = env.cycle()
    assert (d.decision, d.action, d.mode) == ("ALLOW", "INSTALLED", "continuity")
    assert env.bundle_calls[-1][2]                                  # authenticated by the preserved anchors
    assert restarted.managed_spki == [env.A.spki]


def test_restart_after_abrupt_stop_rechecks_on_first_cycle(env, tmp_path):
    """No shutdown ran (crash / SIGKILL): the bundle is still installed. The first cycle after restart
    re-verifies; a revoked signer is withdrawn immediately."""
    env.install()
    env.rec = env.make_reconciler(State(str(env.state_path)))
    env.verifier.error = H.denied("IDENTITY_NOT_ACTIVE")
    env.clock.advance(600)
    d = env.cycle()
    assert (d.decision, d.action) == ("DENY", "WITHDRAWN") and H.TD not in env.spire.bundles


# ------------------------------------------------------------------ signals and the main loop
def test_sigterm_and_sigint_only_request_a_stop():
    old = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            stop = threading.Event()
            install_signal_handlers(stop)
            os.kill(os.getpid(), sig)
            assert stop.wait(2)
    finally:
        for s, h in old.items():
            signal.signal(s, h)


class LoopCtrl:
    def __init__(self, stop, ok=True):
        self.stop, self.ok, self.events = stop, ok, []
        self.policy = types.SimpleNamespace(verification=types.SimpleNamespace(poll_interval_s=0.01))
        self.checkpoints = types.SimpleNamespace(close=lambda: self.events.append("close"))
        self.shutdown_ok = None

    def run_cycle(self):
        self.events.append("cycle-start")
        self.stop.set()                    # stop requested in the middle of a cycle
        self.events.append("cycle-end")

    def shutdown(self):
        self.events.append("shutdown")
        self.shutdown_ok = self.ok


@pytest.mark.parametrize("ok,rc", [(True, 0), (False, 3)])
def test_loop_finishes_cycle_then_shuts_down_once(ok, rc):
    stop = threading.Event()
    c = LoopCtrl(stop, ok)
    assert run_until_stopped(c, stop) == rc
    assert c.events == ["cycle-start", "cycle-end", "shutdown", "close"]
