"""Durable trusted-checkpoint storage for C2SP log verification.

    python -m dnsidfed.checkpoints init   --state-dir DIR
    python -m dnsidfed.checkpoints ensure-initialized --state-dir DIR   (bootstrap: init on first install only)
    python -m dnsidfed.checkpoints status --state-dir DIR
    python -m dnsidfed.checkpoints reset  --state-dir DIR --confirm-new-baseline --reason TEXT

Why this exists
---------------
The controller builds a brand-new `IdentityManager` and C2SP log registry on every reconcile cycle, so
lifecycle status and log history are always verified fresh (see `verifier.py`). A fresh registry would
also start with an empty *trusted-checkpoint* store. A log that has been rolled back or forked could
then serve an older, validly signed checkpoint that leaves out a revocation, and it would be trusted
on first contact.

The SDK keeps rollback and fork protection in a `CheckpointStore`. The store remembers the highest
checkpoint it has accepted for each log origin, and every later checkpoint must extend it. This module
provides one store that the controller creates once and passes to every fresh registry
(`C2spTlogVerificationOptions.trusted_checkpoint_store`), and it keeps that store on disk.

Guarantees
----------
1. Initialization is an explicit operator action (`init`). The controller never creates the store. A
   missing file is never read as "start fresh".
2. First start and loss are told apart. `init` appends an `initialized` event to an append-only
   journal next to the store. A store file that is missing while the journal records an
   initialization is reported as lost, not as new, and `init` refuses to run.
3. Fail closed. A missing, unreadable, malformed or foreign store file, a second writer, a failed write,
   or a file changed or removed while the controller runs all make the store *unavailable*. Every call
   then raises `C2spCheckpointStoreError`. The SDK reports that as a non-transient `LOG_ERROR`, and the
   controller turns it into a definitive DENY and withdraws federation trust.
4. A restart is not a reset. The controller loads the same file. Checkpoints are written atomically
   (temp file, fsync, rename, directory fsync) before the verification that used them completes.
5. Recovery is explicit and audited. Only `reset --confirm-new-baseline --reason ...` creates a new,
   empty baseline. It needs the controller stopped (it takes the store lock), keeps the previous file
   (renamed, never deleted), and appends a `reset` event with the old file's digest and the reason to
   the journal.

`FileCheckpointStore` wraps the SDK's `InMemoryCheckpointStore`, which provides the locking, input
validation, budget checks and equal-size fork detection the `CheckpointStore` contract requires. This
module adds only persistence and the checks above, and uses public SDK APIs only.

Threat model and limits
-----------------------
* Protected against: a log or network path that rolls back or forks after a checkpoint was trusted,
  including across controller restarts; accidental loss or corruption of the store, which fails closed
  instead of silently re-trusting; a second controller writing the same store.
* Not protected against: anyone who can write the controller's state directory. Such a party can
  delete both the store and its journal, which looks exactly like a fresh install, or replace the store
  with an older copy of itself. Local files cannot defend against their own administrator. Treat the
  state directory like the policy and the pinned keys. Where that matters, keep the journal on
  append-only or off-host storage, alert on `reset` events and on store failures in the audit log, or
  seed a new store from an independently obtained checkpoint (for example a witness).
* First contact: after `init` or `reset` the store is empty, so the first checkpoint seen for each log
  origin is trusted on first use, exactly as with the SDK default.
* Single writer: one controller process per state directory, enforced with an exclusive `flock`.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
import secrets
import sys
import threading
from collections.abc import Callable
from pathlib import Path

from dnsid.c2sp_tlog import (
    C2spCheckpointStoreError,
    CheckpointStore,
    InMemoryCheckpointStore,
    TrustedCheckpoint,
)

FORMAT_VERSION = 1
# Group-readable, never world-readable: the files hold public log data (integrity matters, not secrecy), and
# the host operator's group must be able to archive them (`make clean`) when the controller runs as another uid.
FILE_MODE = 0o640
STORE_FILE = "trusted-checkpoints.json"
JOURNAL_FILE = "trusted-checkpoints.journal"


def store_path(state_dir: str | os.PathLike[str]) -> Path:
    return Path(state_dir) / STORE_FILE


def journal_path(store: Path) -> Path:
    return store.with_name(JOURNAL_FILE)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _encode(cp: TrustedCheckpoint) -> dict:
    return {
        "tree_size": cp.tree_size,
        "root_hash": base64.b64encode(cp.root_hash).decode(),
        "witness_time": cp.witness_time.astimezone(dt.timezone.utc).isoformat(),
    }


def _decode(origin: str, rec: dict) -> TrustedCheckpoint:
    if not isinstance(rec, dict):
        raise ValueError("checkpoint record must be an object")
    return TrustedCheckpoint(
        origin=origin,
        tree_size=rec["tree_size"],
        root_hash=base64.b64decode(rec["root_hash"], validate=True),
        witness_time=dt.datetime.fromisoformat(rec["witness_time"]),
    )


def _fsync_dir(d: Path) -> None:
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, body: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE), "wb") as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def read_journal(store: Path) -> list[dict]:
    """Journal events, oldest first. A malformed line raises ValueError (callers fail closed)."""
    try:
        lines = journal_path(store).read_text().splitlines()
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in lines if line.strip()]


def _append_journal(store: Path, event: dict) -> None:
    line = (json.dumps(event, sort_keys=True) + "\n").encode()
    fd = os.open(journal_path(store), os.O_WRONLY | os.O_CREAT | os.O_APPEND, FILE_MODE)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(store.parent)


def _empty_document(store_id: str) -> bytes:
    return json.dumps({"version": FORMAT_VERSION, "store_id": store_id, "created_at": _now(),
                       "checkpoints": {}}, sort_keys=True, indent=2).encode()


class _Lock:
    """Exclusive, non-blocking flock on `<store>.lock`: one writer per store."""

    def __init__(self, store: Path):
        self.path = store.with_name(store.name + ".lock")
        self.fd: int | None = None

    def acquire(self) -> None:
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise C2spCheckpointStoreError(f"cannot open lock file {self.path}: {exc}") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise C2spCheckpointStoreError(
                f"{self.path.with_suffix('')} is in use by another process (single writer required)") from exc
        self.fd = fd

    def release(self) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None


class FileCheckpointStore(CheckpointStore):
    """The SDK's in-memory checkpoint store plus explicit-initialization, fail-closed persistence."""

    def __init__(self, path: str | os.PathLike[str]):
        self._path = Path(path)
        self._inner = InMemoryCheckpointStore()
        self._write_lock = threading.Lock()
        self._origins: set[str] = set()
        self._failure: str | None = None
        self._store_id: str | None = None
        self._digest: str | None = None  # sha256 of the file as this process last read or wrote it
        self._lock = _Lock(self._path)
        try:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)  # the directory only, never the store
            except OSError as exc:
                raise C2spCheckpointStoreError(f"cannot create {self._path.parent}: {exc}") from exc
            self._lock.acquire()
            self._load()
        except C2spCheckpointStoreError as exc:
            self._failure = str(exc)

    # ------------------------------------------------------------------ status
    @property
    def path(self) -> Path:
        return self._path

    @property
    def store_id(self) -> str | None:
        return self._store_id

    @property
    def failure(self) -> str | None:
        """None while healthy; otherwise why the store refuses to answer (fail closed)."""
        return self._failure

    def _fail(self, reason: str) -> C2spCheckpointStoreError:
        self._failure = reason
        return C2spCheckpointStoreError(reason)

    def _check(self) -> None:
        if self._failure is not None:
            raise C2spCheckpointStoreError(f"trusted checkpoint store unavailable: {self._failure}")
        # The file must still be exactly what this process last read or wrote. Removal or replacement
        # behind the controller's back fails closed. Serialized with writes so a concurrent persist is
        # never mistaken for tampering.
        with self._write_lock:
            try:
                current = hashlib.sha256(self._path.read_bytes()).hexdigest()
            except FileNotFoundError:
                raise self._fail(f"{self._path} disappeared while in use") from None
            except OSError as exc:
                raise self._fail(f"cannot read {self._path}: {exc}") from exc
            if current != self._digest:
                raise self._fail(f"{self._path} was changed outside this controller")

    # ------------------------------------------------------------------ CheckpointStore
    def get(self, origin: str) -> TrustedCheckpoint | None:
        self._check()
        return self._inner.get(origin)

    def put(self, checkpoint: TrustedCheckpoint) -> None:
        self._check()
        self._inner.put(checkpoint)
        self._persist(checkpoint.origin)

    def verify_and_advance(
        self,
        candidate: TrustedCheckpoint,
        verify: Callable[[TrustedCheckpoint | None], None],
    ) -> None:
        self._check()
        # The SDK store runs `verify` and the advance under its per-origin lock; exceptions from
        # `verify` (rollback, fork) propagate unchanged and leave both memory and disk untouched.
        self._inner.verify_and_advance(candidate, verify)
        self._persist(candidate.origin)

    # ------------------------------------------------------------------ persistence
    def _load(self) -> None:
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            try:
                initialized = [e for e in read_journal(self._path) if e.get("event") in ("initialized", "reset")]
            except ValueError as exc:
                raise C2spCheckpointStoreError(f"malformed journal {journal_path(self._path)}: {exc}") from exc
            if initialized:
                last = initialized[-1]
                raise C2spCheckpointStoreError(
                    f"{self._path} is missing, but the journal records {last.get('event')} of store "
                    f"{last.get('store_id')} at {last.get('at')}: trusted checkpoint history was lost or "
                    "removed. Investigate, then restore the file or run an explicit reset.") from None
            raise C2spCheckpointStoreError(
                f"{self._path} is not initialized: run `python -m dnsidfed.checkpoints init` once "
                "before starting the controller") from None
        except OSError as exc:
            raise C2spCheckpointStoreError(f"cannot read {self._path}: {exc}") from exc
        try:
            doc = json.loads(raw)
            if not isinstance(doc, dict) or doc.get("version") != FORMAT_VERSION:
                raise ValueError(f"unsupported format (expected version {FORMAT_VERSION})")
            store_id = doc.get("store_id")
            if not isinstance(store_id, str) or not store_id:
                raise ValueError("missing store_id")
            records = doc.get("checkpoints")
            if not isinstance(records, dict):
                raise ValueError("'checkpoints' must be an object keyed by log origin")
            for origin, rec in records.items():
                self._inner.put(_decode(origin, rec))  # SDK validation of every stored value
                self._origins.add(origin)
        except (ValueError, TypeError, KeyError) as exc:
            raise C2spCheckpointStoreError(f"malformed trusted checkpoint file {self._path}: {exc}") from exc
        self._store_id = store_id
        self._digest = hashlib.sha256(raw).hexdigest()

    def _persist(self, origin: str) -> None:
        with self._write_lock:
            try:
                self._origins.add(origin)
                snapshot = {}
                for o in sorted(self._origins):
                    cp = self._inner.get(o)
                    if cp is not None:
                        snapshot[o] = _encode(cp)
                body = json.dumps({"version": FORMAT_VERSION, "store_id": self._store_id,
                                   "updated_at": _now(), "checkpoints": snapshot},
                                  sort_keys=True, indent=2).encode()
                _atomic_write(self._path, body)
                self._digest = hashlib.sha256(body).hexdigest()
            except OSError as exc:
                # Memory may now be ahead of disk. Refuse all further use rather than risk a restart
                # that silently trusts an older checkpoint.
                raise self._fail(f"failed to persist trusted checkpoints to {self._path}: {exc}") from exc

    def close(self) -> None:
        self._lock.release()


# ---------------------------------------------------------------------- operator actions
def init_store(state_dir: str | os.PathLike[str]) -> str:
    """First-time initialization. Refuses if the store exists or the journal shows an earlier one."""
    path = store_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = _Lock(path)
    lock.acquire()
    try:
        if path.exists():
            raise C2spCheckpointStoreError(f"{path} already exists: refusing to re-initialize")
        try:
            prior = [e for e in read_journal(path) if e.get("event") in ("initialized", "reset")]
        except ValueError as exc:
            raise C2spCheckpointStoreError(f"malformed journal: {exc}") from exc
        if prior:
            raise C2spCheckpointStoreError(
                f"the journal shows store {prior[-1].get('store_id')} was initialized before; its file is "
                "missing. That is not a first start: investigate, then use `reset --confirm-new-baseline`.")
        store_id = secrets.token_hex(8)
        _atomic_write(path, _empty_document(store_id))
        _append_journal(path, {"event": "initialized", "store_id": store_id, "at": _now()})
        return store_id
    finally:
        lock.release()


def ensure_initialized(state_dir: str | os.PathLike[str]) -> dict:
    """Bootstrap helper: initialize on a first install only.

    * store present            -> {"present": true}   (history preserved; nothing written)
    * no store, no journal     -> {"initialized": id} (first install)
    * no store, journal shows an earlier initialization -> C2spCheckpointStoreError (loss, not first start)
    """
    if store_path(state_dir).exists():
        return {"present": True}
    return {"initialized": init_store(state_dir)}


def reset_store(state_dir: str | os.PathLike[str], *, confirm_new_baseline: bool, reason: str) -> str:
    """Explicit recovery: archive the current file (if any) and start an empty, audited baseline."""
    if not confirm_new_baseline:
        raise C2spCheckpointStoreError("reset accepts a NEW trust baseline: pass --confirm-new-baseline")
    if not reason or not reason.strip():
        raise C2spCheckpointStoreError("reset requires --reason (recorded in the journal)")
    path = store_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = _Lock(path)
    lock.acquire()  # fails while a controller holds the store: stop it first
    try:
        old_digest, archived = None, None
        if path.exists():
            raw = path.read_bytes()
            old_digest = hashlib.sha256(raw).hexdigest()
            archived = path.with_name(f"{path.name}.replaced-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}")
            os.replace(path, archived)
        store_id = secrets.token_hex(8)
        _atomic_write(path, _empty_document(store_id))
        _append_journal(path, {"event": "reset", "store_id": store_id, "at": _now(), "reason": reason.strip(),
                               "previous_sha256": old_digest,
                               "previous_file": archived.name if archived else None})
        return store_id
    finally:
        lock.release()


def store_status(state_dir: str | os.PathLike[str]) -> dict:
    """Read-only summary (does not take the lock, so it works next to a running controller)."""
    path = store_path(state_dir)
    try:
        events = read_journal(path)
        journal_ok = True
    except ValueError:
        events, journal_ok = [], False
    out: dict = {"path": str(path), "exists": path.exists(), "journal_ok": journal_ok,
                 "journal_events": [{k: e.get(k) for k in ("event", "store_id", "at", "reason")} for e in events]}
    if path.exists():
        try:
            doc = json.loads(path.read_bytes())
            out.update(store_id=doc.get("store_id"),
                       origins={o: r.get("tree_size") for o, r in (doc.get("checkpoints") or {}).items()})
        except (ValueError, AttributeError) as exc:
            out["error"] = f"malformed: {exc}"
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m dnsidfed.checkpoints", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "ensure-initialized", "status", "reset"):
        p = sub.add_parser(name)
        p.add_argument("--state-dir", required=True)
        if name == "reset":
            p.add_argument("--confirm-new-baseline", action="store_true")
            p.add_argument("--reason", default="")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "init":
            print(json.dumps({"initialized": init_store(a.state_dir)}))
        elif a.cmd == "ensure-initialized":
            print(json.dumps(ensure_initialized(a.state_dir)))
        elif a.cmd == "reset":
            sid = reset_store(a.state_dir, confirm_new_baseline=a.confirm_new_baseline, reason=a.reason)
            print(json.dumps({"reset": sid, "warning": "new trust baseline: the next checkpoint per log origin "
                                                       "is trusted on first use"}))
        else:
            print(json.dumps(store_status(a.state_dir), indent=2))
    except C2spCheckpointStoreError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
