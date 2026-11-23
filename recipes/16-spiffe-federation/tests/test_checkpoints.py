"""FileCheckpointStore: explicit initialization, persistence across cycles and restarts, fail-closed loss
and tampering detection, and audited reset.

The consistency rules themselves (equal-size fork detection, never moving backwards) are the SDK's own
InMemoryCheckpointStore; these tests exercise them through the durable wrapper. The Merkle prefix check
for rollback/fork lives in the SDK's log reader, which passes a `verify` callback; here the callback is
driven directly. Live validation against real signed checkpoints is separate (see the recipe README).
"""
import datetime as dt
import json
import os
import stat

import pytest
from dnsid.c2sp_tlog import (
    C2spCheckpointConsistencyError, C2spCheckpointStoreError, C2spLifecycleErrorCategory, TrustedCheckpoint,
)

import helpers as H
import dnsidfed.checkpoints as C
import dnsidfed.verifier as V
from dnsidfed.checkpoints import FileCheckpointStore, init_store, reset_store, store_path
from dnsidfed.verifier import DnsidDenied

ORIGIN = "registry.test/log"
WT = dt.datetime(2027, 1, 1, 12, 0, tzinfo=dt.timezone.utc)


def cp(size, fill=1, origin=ORIGIN, wt=WT):
    return TrustedCheckpoint(origin, size, bytes([fill]) * 32, wt)


def noop(stored):
    return None


@pytest.fixture
def sdir(tmp_path):
    return tmp_path / "state"


@pytest.fixture
def path(sdir):
    return store_path(sdir)


@pytest.fixture
def stores():
    opened = []
    yield opened
    for s in opened:
        s.close()


def open_store(path, stores):
    s = FileCheckpointStore(path)
    stores.append(s)
    return s


def restart(store, path, stores):
    store.close()
    return open_store(path, stores)


@pytest.fixture
def ready(sdir, path, stores):
    """An initialized store, opened."""
    init_store(sdir)
    return open_store(path, stores)


# ------------------------------------------------------------------ initialization
def test_uninitialized_store_fails_closed_and_is_never_created(path, stores):
    s = open_store(path, stores)
    assert s.failure and "not initialized" in s.failure
    for call in (lambda: s.get(ORIGIN), lambda: s.verify_and_advance(cp(5), noop)):
        with pytest.raises(C2spCheckpointStoreError):
            call()
    assert not path.exists()  # the controller never creates its own baseline


def test_init_creates_empty_store_and_journal(sdir, path, stores):
    sid = init_store(sdir)
    s = open_store(path, stores)
    assert s.failure is None and s.store_id == sid and s.get(ORIGIN) is None
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640  # group-readable for archiving, never world
    (ev,) = C.read_journal(path)
    assert ev["event"] == "initialized" and ev["store_id"] == sid


def test_init_refuses_existing_store(sdir):
    init_store(sdir)
    with pytest.raises(C2spCheckpointStoreError, match="already exists"):
        init_store(sdir)


def test_missing_after_initialization_is_loss_not_first_start(sdir, path, stores):
    init_store(sdir)
    path.unlink()
    s = open_store(path, stores)
    assert s.failure and "missing, but the journal records initialized" in s.failure
    s.close()  # controller stopped; the operator now tries a plain init
    with pytest.raises(C2spCheckpointStoreError, match="not a first start"):
        init_store(sdir)  # no silent re-initialization
    assert not path.exists()


def test_init_refuses_while_controller_holds_lock(sdir, path, stores):
    open_store(path, stores)  # holds the lock even though uninitialized
    with pytest.raises(C2spCheckpointStoreError, match="in use"):
        init_store(sdir)


# ------------------------------------------------------------------ persistence
def test_accepted_checkpoint_survives_restart(ready, path, stores):
    ready.verify_and_advance(cp(5), noop)
    s2 = restart(ready, path, stores)
    got = s2.get(ORIGIN)
    assert (got.origin, got.tree_size, got.root_hash, got.witness_time) == (ORIGIN, 5, bytes([1]) * 32, WT)
    assert s2.store_id == ready.store_id


def test_multiple_origins_persist_independently(ready, path, stores):
    ready.verify_and_advance(cp(5, origin="a.test/log"), noop)
    ready.verify_and_advance(cp(9, origin="b.test/log"), noop)
    s2 = restart(ready, path, stores)
    assert s2.get("a.test/log").tree_size == 5 and s2.get("b.test/log").tree_size == 9


def test_never_moves_backwards(ready, path, stores):
    ready.verify_and_advance(cp(5), noop)
    ready.verify_and_advance(cp(9, fill=2), noop)
    ready.verify_and_advance(cp(7, fill=3), noop)  # callback did not object: SDK store keeps 9
    assert ready.get(ORIGIN).tree_size == 9
    assert restart(ready, path, stores).get(ORIGIN).tree_size == 9


# ------------------------------------------------------------------ rollback / fork across cycles and restarts
def test_callback_sees_checkpoint_trusted_before_restart(ready, path, stores):
    ready.verify_and_advance(cp(9, fill=4), noop)
    s2 = restart(ready, path, stores)
    seen = []
    s2.verify_and_advance(cp(12, fill=5), seen.append)  # the SDK reader compares against this
    assert [(c.tree_size, c.root_hash) for c in seen] == [(9, bytes([4]) * 32)]


def test_rollback_rejected_by_callback_leaves_memory_and_disk_unchanged(ready, path, stores):
    ready.verify_and_advance(cp(9, fill=4), noop)
    before = path.read_bytes()

    def sdk_like_reader_check(stored):  # what the SDK reader raises for a smaller tree
        if stored is not None and stored.tree_size > 7:
            raise C2spCheckpointConsistencyError("tree size regressed", category=C2spLifecycleErrorCategory.LOG_ROLLBACK,
                                                 trusted=stored, observed=cp(7, fill=6))

    s2 = restart(ready, path, stores)
    with pytest.raises(C2spCheckpointConsistencyError) as ei:
        s2.verify_and_advance(cp(7, fill=6), sdk_like_reader_check)
    assert ei.value.category == C2spLifecycleErrorCategory.LOG_ROLLBACK
    assert s2.get(ORIGIN).tree_size == 9 and path.read_bytes() == before


def test_equal_size_fork_rejected_by_sdk_store_after_restart(ready, path, stores):
    ready.verify_and_advance(cp(9, fill=4), noop)
    s2 = restart(ready, path, stores)
    before = path.read_bytes()
    with pytest.raises(C2spCheckpointConsistencyError) as ei:
        s2.verify_and_advance(cp(9, fill=7), noop)
    assert ei.value.category == C2spLifecycleErrorCategory.LOG_FORK
    assert s2.get(ORIGIN).root_hash == bytes([4]) * 32 and path.read_bytes() == before


def _verifier_with(store, monkeypatch, on_evidence):
    class Mgr:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def verify_domain(self, domain):
            return H.fake_domain()

        def verify_log_evidence(self, vd):
            on_evidence()
            return type("Ev", (), dict(logged_state="ACTIVE", log_reference="l", checkpoint=b"o\n9\nr\n",
                                       freshness_time=dt.datetime.fromtimestamp(H.NOW - 5, dt.timezone.utc)))()

    class Jose:
        def __init__(self, resolver, **kw):
            self.r = resolver

        def verify_jws(self, jws):
            return b"{}", self.r.verify_domain(H.SIGNER)

    monkeypatch.setattr(V, "JoseProfile", Jose)
    return V.DnsidVerifier(H.make_policy(), manager_factory=Mgr, clock=lambda: H.NOW, checkpoint_store=store)


def test_store_shared_by_verifier_detects_fork_on_a_later_cycle(monkeypatch, ready):
    candidates = iter([cp(9, fill=4), cp(9, fill=7)])
    ver = _verifier_with(ready, monkeypatch, lambda: ready.verify_and_advance(next(candidates), noop))
    assert ver.verify("j").logged_state == "ACTIVE"  # cycle 1
    with pytest.raises(DnsidDenied) as ei:  # cycle 2: forked checkpoint
        ver.verify("j")
    assert (ei.value.reason, ei.value.transient) == ("LOG_INCONSISTENT", False)


# ------------------------------------------------------------------ fail closed: corruption, loss, tampering
@pytest.mark.parametrize("content", [
    b"not json",
    b"[]",
    b'{"version": 2, "store_id": "x", "checkpoints": {}}',
    b'{"version": 1, "checkpoints": {}}',
    b'{"version": 1, "store_id": "x", "checkpoints": []}',
    b'{"version": 1, "store_id": "x", "checkpoints": {"registry.test/log": {"tree_size": 5}}}',
    b'{"version": 1, "store_id": "x", "checkpoints": {"registry.test/log": {"tree_size": -1, "root_hash": "AQ==", "witness_time": "2027-01-01T00:00:00+00:00"}}}',
    b'{"version": 1, "store_id": "x", "checkpoints": {"registry.test/log": {"tree_size": 5, "root_hash": "AQ==", "witness_time": "2027-01-01T00:00:00+00:00"}}}',
    b'{"version": 1, "store_id": "x", "checkpoints": {"registry.test/log": {"tree_size": 5, "root_hash": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "witness_time": "2027-01-01T00:00:00"}}}',
    b'{"version": 1, "store_id": "x", "checkpoints": {"registry.test/log": {"tree_size": "5", "root_hash": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "witness_time": "2027-01-01T00:00:00+00:00"}}}',
])
def test_malformed_file_fails_closed_and_is_not_overwritten(path, stores, content):
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    s = open_store(path, stores)
    assert s.failure and "malformed" in s.failure
    for call in (lambda: s.get(ORIGIN), lambda: s.put(cp(5)), lambda: s.verify_and_advance(cp(5), noop)):
        with pytest.raises(C2spCheckpointStoreError):
            call()
    assert path.read_bytes() == content


def test_deleted_while_running_fails_closed_and_is_not_recreated(ready, path):
    ready.verify_and_advance(cp(5), noop)
    path.unlink()
    with pytest.raises(C2spCheckpointStoreError, match="disappeared"):
        ready.verify_and_advance(cp(9, fill=2), noop)
    assert not path.exists()  # the in-memory state is NOT written back as a new baseline
    with pytest.raises(C2spCheckpointStoreError):
        ready.get(ORIGIN)


def test_replaced_with_older_copy_while_running_fails_closed(ready, path):
    ready.verify_and_advance(cp(5), noop)
    older = path.read_bytes()
    ready.verify_and_advance(cp(9, fill=2), noop)
    path.write_bytes(older)  # roll the file back behind the controller's back
    with pytest.raises(C2spCheckpointStoreError, match="changed outside"):
        ready.get(ORIGIN)


def test_second_writer_is_refused(ready, path, stores):
    second = open_store(path, stores)
    assert ready.failure is None
    assert second.failure and "in use" in second.failure


def test_write_failure_poisons_store(ready, path):
    ready.verify_and_advance(cp(5), noop)
    os.chmod(path.parent, 0o500)  # directory no longer writable: the atomic rename fails
    try:
        with pytest.raises(C2spCheckpointStoreError):
            ready.verify_and_advance(cp(9, fill=2), noop)
        assert ready.failure and "persist" in ready.failure
        with pytest.raises(C2spCheckpointStoreError):
            ready.get(ORIGIN)
    finally:
        os.chmod(path.parent, 0o700)
    assert json.loads(path.read_text())["checkpoints"][ORIGIN]["tree_size"] == 5


def test_store_failure_through_verifier_is_definitive_deny(monkeypatch, path, stores):
    s = open_store(path, stores)  # uninitialized: fails closed
    ver = _verifier_with(s, monkeypatch, lambda: s.get(ORIGIN))
    with pytest.raises(DnsidDenied) as ei:
        ver.verify("j")
    assert (ei.value.reason, ei.value.transient) == ("CHECKPOINT_STORE_FAILED", False)
    assert ei.value.reason in V.DEFINITIVE


# ------------------------------------------------------------------ explicit, audited reset
def test_reset_requires_confirmation_and_reason(sdir):
    init_store(sdir)
    with pytest.raises(C2spCheckpointStoreError, match="confirm-new-baseline"):
        reset_store(sdir, confirm_new_baseline=False, reason="x")
    with pytest.raises(C2spCheckpointStoreError, match="reason"):
        reset_store(sdir, confirm_new_baseline=True, reason="  ")


def test_reset_refused_while_controller_running(ready, sdir):
    with pytest.raises(C2spCheckpointStoreError, match="in use"):
        reset_store(sdir, confirm_new_baseline=True, reason="test")


def test_reset_archives_old_file_and_journals(ready, sdir, path, stores):
    ready.verify_and_advance(cp(9, fill=4), noop)
    old = path.read_bytes()
    ready.close()
    sid = reset_store(sdir, confirm_new_baseline=True, reason="log operator confirmed re-key")
    s2 = open_store(path, stores)
    assert s2.failure is None and s2.store_id == sid and s2.get(ORIGIN) is None
    archived = [p for p in path.parent.iterdir() if p.name.startswith(path.name + ".replaced-")]
    assert len(archived) == 1 and archived[0].read_bytes() == old
    ev = C.read_journal(path)[-1]
    assert ev["event"] == "reset" and ev["reason"] == "log operator confirmed re-key"
    assert ev["previous_file"] == archived[0].name and len(ev["previous_sha256"]) == 64


def test_reset_recovers_lost_store(sdir, path, stores):
    init_store(sdir)
    path.unlink()
    assert open_store(path, stores).failure  # lost: fail closed
    stores.pop().close()
    reset_store(sdir, confirm_new_baseline=True, reason="restored after disk loss")
    assert open_store(path, stores).failure is None
    assert C.read_journal(path)[-1]["previous_sha256"] is None


def test_malformed_journal_fails_closed_when_store_missing(sdir, path, stores):
    sdir.mkdir()
    C.journal_path(path).write_text("{not json\n")
    s = open_store(path, stores)
    assert s.failure and "malformed journal" in s.failure
    with pytest.raises(C2spCheckpointStoreError):
        init_store(sdir)


# ------------------------------------------------------------------ CLI
def test_cli_init_status_reset(sdir, capsys):
    assert C.main(["init", "--state-dir", str(sdir)]) == 0
    assert C.main(["init", "--state-dir", str(sdir)]) == 2  # refuses
    assert C.main(["status", "--state-dir", str(sdir)]) == 0
    out = capsys.readouterr().out
    assert '"exists": true' in out and '"event": "initialized"' in out
    assert C.main(["reset", "--state-dir", str(sdir)]) == 2  # no confirmation
    assert C.main(["reset", "--state-dir", str(sdir), "--confirm-new-baseline", "--reason", "drill"]) == 0


# ------------------------------------------------------------------ bootstrap: ensure-initialized
def test_ensure_initialized_first_install_then_preserved(sdir, path):
    first = C.ensure_initialized(sdir)
    assert "initialized" in first
    before = path.read_bytes()
    assert C.ensure_initialized(sdir) == {"present": True}   # restart: nothing rewritten
    assert path.read_bytes() == before
    assert [e["event"] for e in C.read_journal(path)] == ["initialized"]


def test_ensure_initialized_refuses_lost_store(sdir, path):
    C.ensure_initialized(sdir)
    path.unlink()
    with pytest.raises(C2spCheckpointStoreError, match="not a first start"):
        C.ensure_initialized(sdir)
    assert not path.exists()


def test_cli_ensure_initialized(sdir, capsys):
    assert C.main(["ensure-initialized", "--state-dir", str(sdir)]) == 0
    assert '"initialized"' in capsys.readouterr().out
    assert C.main(["ensure-initialized", "--state-dir", str(sdir)]) == 0
    assert '"present": true' in capsys.readouterr().out
