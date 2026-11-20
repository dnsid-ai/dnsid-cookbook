import threading
import types


import helpers as H
from dnsidfed.controller import Controller
from dnsidfed.reconcile import Decision


def bare(rec, tmp_path=None):
    import tempfile
    c = object.__new__(Controller)
    c.rec, c.lock, c.last, c.history = rec, threading.Lock(), None, []
    c.stopping, c.shutdown_ok = False, None
    c.audit_path = str((tmp_path or __import__("pathlib").Path(tempfile.mkdtemp())) / "audit.jsonl")
    if not hasattr(rec, "p"):
        rec.p = H.make_policy(grace=30.0)
    if not hasattr(rec, "spire"):
        rec.spire = H.FakeSpire()
    if not hasattr(rec, "state"):
        rec.state = types.SimpleNamespace(last_verified_at=None, last_seq=None, save=lambda: None)
    return c


class Boom:
    def __init__(self, exc):
        self.exc = exc

    def cycle(self):
        raise self.exc


class Fixed:
    def __init__(self, d):
        self.d = d

    def cycle(self):
        return self.d


def test_cycle_exception_is_hold_controller_error_never_allow():
    for exc in (RuntimeError("spire socket gone"), KeyError("k"), ValueError("v")):
        c = bare(Boom(exc))
        d = c.run_cycle()
        # nothing verified yet and nothing installed: DENY with no action; never ALLOW
        assert d.decision != "ALLOW" and d.reason == "CONTROLLER_ERROR"
        assert d.action in ("NONE", "HELD")
        assert type(exc).__name__ in d.detail
        assert c.last is d


def test_lock_released_after_error():
    c = bare(Boom(RuntimeError("x")))
    c.run_cycle()
    assert c.lock.acquire(blocking=False)


def test_normal_decision_passed_through():
    want = Decision(1.0, "ALLOW", "UNCHANGED", "OK")
    c = bare(Fixed(want))
    assert c.run_cycle() is want and c.last is want


def test_persistent_controller_error_eventually_withdraws_bundle():
    """Was a strict xfail (fail-open product gap found by test-engineer); fixed in Controller._controller_error."""
    import time
    spire = H.FakeSpire()
    spire.bundles[H.TD] = {"keys": []}
    state = types.SimpleNamespace(last_verified_at=time.time() - 10_000, last_seq=5, save=lambda: None)

    class BoomRec(Boom):
        p = H.make_policy(grace=30.0)

    rec = BoomRec(RuntimeError("persistent"))
    rec.spire, rec.state = spire, state
    c = bare(rec)
    c.run_cycle()
    assert H.TD not in spire.bundles


def test_controller_error_within_grace_holds_bundle():
    import time
    spire = H.FakeSpire()
    spire.bundles[H.TD] = {"keys": []}
    rec = Boom(RuntimeError("transient"))
    rec.p = H.make_policy(grace=30.0)
    rec.spire = spire
    rec.state = types.SimpleNamespace(last_verified_at=time.time() - 5, last_seq=5, save=lambda: None)
    d = bare(rec).run_cycle()
    assert (d.decision, d.action) == ("HOLD", "HELD") and H.TD in spire.bundles


# ------------------------------------------------------------------ enforcement liveness
def _live(c, poll=5.0):
    c.policy = types.SimpleNamespace(verification=types.SimpleNamespace(poll_interval_s=poll))
    c.started_at, c.last_cycle_end = __import__("time").time(), None
    return c


def test_enforcing_true_after_recent_cycle_and_false_when_loop_stalls():
    import time
    c = _live(bare(Fixed(Decision(1.0, "HOLD", "NONE", "BINDING_UNAVAILABLE"))))
    c.run_cycle()
    assert c.enforcing() and c.last_cycle_end is not None
    c.last_cycle_end = time.time() - c.stale_after_s() - 1   # loop stalled
    assert not c.enforcing()


def test_enforcing_grace_at_startup_then_inactive_if_no_cycle_ever_completes():
    import time
    c = _live(bare(Fixed(Decision(1.0, "ALLOW", "UNCHANGED", "OK"))))
    assert c.enforcing()                                      # just started
    c.started_at = time.time() - c.stale_after_s() - 1
    assert not c.enforcing()                                  # never completed a cycle


def test_stale_threshold_scales_with_poll_interval():
    c = _live(bare(Fixed(None)), poll=30.0)
    assert c.stale_after_s() == 180.0
    assert _live(bare(Fixed(None)), poll=5.0).stale_after_s() == 60.0


# ------------------------------------------------------------------ durable checkpoint store wiring
def _real_controller(tmp_path):
    from test_policy import GOOD
    lp = tmp_path / "log.policy"
    lp.write_bytes(b"log policy")
    pol = tmp_path / "policy.toml"
    pol.write_text(GOOD.replace("/x/log.policy", str(lp)))
    return Controller(str(pol), str(tmp_path / "state"), str(tmp_path / "no-spire.sock"))


def test_controller_injects_one_durable_store(tmp_path):
    from dnsidfed.checkpoints import FileCheckpointStore, init_store
    init_store(tmp_path / "state")  # explicit operator action (make bootstrap does this once)
    c = _real_controller(tmp_path)
    try:
        assert isinstance(c.checkpoints, FileCheckpointStore)
        assert c.verifier.checkpoint_store is c.checkpoints
        assert c.checkpoints.path == tmp_path / "state" / "trusted-checkpoints.json"
        st = c.status()["checkpoint_store"]
        assert st["healthy"] is True and st["failure"] is None
    finally:
        c.checkpoints.close()


def test_controller_starts_and_reports_unhealthy_store_instead_of_crashing(tmp_path):
    # Starting is important: a controller that refuses to run would leave installed trust in place.
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "trusted-checkpoints.json").write_text("corrupt")
    c = _real_controller(tmp_path)
    try:
        st = c.status()["checkpoint_store"]
        assert st["healthy"] is False and "malformed" in st["failure"]
    finally:
        c.checkpoints.close()


def test_controller_never_initializes_its_own_store(tmp_path):
    c = _real_controller(tmp_path)
    try:
        st = c.status()["checkpoint_store"]
        assert st["healthy"] is False and "not initialized" in st["failure"]
        assert not (tmp_path / "state" / "trusted-checkpoints.json").exists()
    finally:
        c.checkpoints.close()
