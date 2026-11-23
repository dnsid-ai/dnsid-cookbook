"""POST /rebootstrap (Controller.admin_rebootstrap): an administrative trust reset is audited, runs under the
reconciliation lock, and changes nothing when the bundle cannot be withdrawn. Offline: FakeSpire, no HTTP."""
import json
import threading
import time

import helpers as H
from dnsidfed.reconcile import Decision, State
from dnsidfed.spire import SpireError
from test_shutdown import make_ctrl


def audit(tmp_path):
    p = tmp_path / "audit.jsonl"
    return [json.loads(ln) for ln in p.read_text().splitlines()] if p.exists() else []


def test_rebootstrap_withdraws_resets_state_and_is_audited_last(env, tmp_path):
    env.install()
    c = make_ctrl(env, tmp_path)
    c._audit(Decision(time.time(), "ALLOW", "UNCHANGED", "OK"))                       # an earlier decision
    before = audit(tmp_path)
    d = c.admin_rebootstrap()
    assert (d.decision, d.action, d.reason, d.layer) == ("DENY", "WITHDRAWN", "ADMIN_REBOOTSTRAP", "controller-policy")
    assert H.TD not in env.spire.bundles
    st = State(str(env.state_path))
    assert (st.anchors, st.last_seq, st.last_verified_at, st.managed_spki) == (None, None, None, None)
    rows = audit(tmp_path)
    assert rows[:len(before)] == before and len(rows) == len(before) + 1       # appended, nothing rewritten
    assert (rows[-1]["reason"], rows[-1]["action"]) == ("ADMIN_REBOOTSTRAP", "WITHDRAWN")
    assert "cleared" in rows[-1]["detail"]


def test_rebootstrap_with_nothing_installed_is_audited_as_none(env, tmp_path):
    c = make_ctrl(env, tmp_path)
    d = c.admin_rebootstrap()
    assert (d.decision, d.action, d.reason) == ("DENY", "NONE", "ADMIN_REBOOTSTRAP")
    (row,) = audit(tmp_path)
    assert row["reason"] == "ADMIN_REBOOTSTRAP" and "no bundle installed" in row["detail"]


def test_rebootstrap_failure_resets_nothing_and_is_audited(env, tmp_path):
    env.install()
    anchors, seq, managed = list(env.state.anchors), env.state.last_seq, list(env.state.managed_spki)
    c = make_ctrl(env, tmp_path)

    def refuse(_td, mode="dissociate"):
        raise SpireError("bundle delete failed: permission denied")
    env.spire.delete_bundle = refuse
    d = c.admin_rebootstrap()
    assert (d.decision, d.action, d.reason) == ("HOLD", "NONE", "ADMIN_REBOOTSTRAP_FAILED")
    assert H.TD in env.spire.bundles
    st = State(str(env.state_path))
    assert (st.anchors, st.last_seq, st.managed_spki) == (anchors, seq, managed)   # trust state untouched
    (row,) = audit(tmp_path)
    assert row["reason"] == "ADMIN_REBOOTSTRAP_FAILED" and "SpireError" in row["detail"]


def test_rebootstrap_waits_for_the_reconciliation_lock(env, tmp_path):
    env.install()
    c = make_ctrl(env, tmp_path)
    done = threading.Event()
    c.lock.acquire()                                       # a cycle (or shutdown) is in progress
    try:
        t = threading.Thread(target=lambda: (c.admin_rebootstrap(), done.set()), daemon=True)
        t.start()
        time.sleep(0.2)
        assert not done.is_set() and H.TD in env.spire.bundles and audit(tmp_path) == []
    finally:
        c.lock.release()
    t.join(5)
    assert done.is_set() and audit(tmp_path)[-1]["reason"] == "ADMIN_REBOOTSTRAP"
