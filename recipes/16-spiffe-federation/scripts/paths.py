"""Path guards: every destructive or state-writing operation in this recipe is confined to the recipe's own
directories.

    python3 -I scripts/paths.py check-state STATE    exit 0 only for this recipe's dedicated .dnsid-local

Rules for the DNSid local registry state directory (STATE / DNSID_LOCAL_STATE):
  * exactly <recipe>/.dnsid-local, spelled canonically (absolute, no `.`/`..`, no doubled or trailing slash):
    the dnsid CLI derives its Docker labels and Compose project from the literal path, so two spellings of
    one directory could select different instances
  * the recipe directory itself must not be reached through a symlink
  * if it exists, it is a real directory, not a symlink
Anything else (another instance such as ~/.dnsid-local, path traversal, a symlink) is refused.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

RECIPE_ROOT = Path(__file__).resolve().parents[1]
LOCAL_STATE_NAME = ".dnsid-local"
RECIPE_STATE_NAME = ".state"


class UnsafePath(ValueError):
    pass


def _canonical_spelling(raw: str) -> bool:
    return os.path.isabs(raw) and os.path.normpath(raw) == raw and not raw.startswith("//")


def _no_symlink_components(path: Path) -> bool:
    """True if no existing component of `path` is a symlink."""
    p = Path("/")
    for part in path.parts[1:]:
        p = p / part
        if p.is_symlink():
            return False
        if not p.exists():
            break
    return True


def check_recipe_root(root: Path = RECIPE_ROOT) -> Path:
    raw = str(root)
    if not _canonical_spelling(raw) or not _no_symlink_components(root) or Path(os.path.realpath(raw)) != root:
        raise UnsafePath(f"recipe directory {raw} must be reached by its canonical path, without symlinks")
    return root


def check_local_state(raw: str, root: Path = RECIPE_ROOT) -> Path:
    """Return the validated DNSid local registry state directory, or raise UnsafePath."""
    root = check_recipe_root(root)
    expected = root / LOCAL_STATE_NAME
    if not raw:
        raise UnsafePath("DNSid local registry state directory is not set")
    if not _canonical_spelling(raw):
        raise UnsafePath(f"refusing non-canonical state path {raw!r} (expected {expected})")
    if Path(raw) != expected:
        raise UnsafePath(f"refusing state directory {raw}: this recipe only uses its own {expected}")
    if expected.is_symlink() or (expected.exists() and not expected.is_dir()):
        raise UnsafePath(f"{expected} must be a real directory, not a symlink or file")
    return expected


def check_recipe_state(raw: str, root: Path = RECIPE_ROOT) -> Path:
    """Return the validated recipe working-state directory (<recipe>/.state), or raise UnsafePath."""
    root = check_recipe_root(root)
    expected = root / RECIPE_STATE_NAME
    if not _canonical_spelling(raw or "") or Path(raw) != expected:
        raise UnsafePath(f"refusing recipe state directory {raw!r}: expected {expected}")
    if expected.is_symlink() or (expected.exists() and not expected.is_dir()):
        raise UnsafePath(f"{expected} must be a real directory, not a symlink or file")
    return expected


def require_under(path: str | os.PathLike[str], base: Path) -> Path:
    """Return `path` if it lies strictly inside `base` with no symlink anywhere below `base`; else raise."""
    raw = str(path)
    if ".." in Path(raw).parts:
        raise UnsafePath(f"refusing path with '..': {raw!r}")
    p = Path(os.path.abspath(raw))
    if base not in p.parents:
        raise UnsafePath(f"refusing {p}: outside {base}")
    cur = base
    for part in p.relative_to(base).parts:
        cur = cur / part
        if cur.is_symlink():
            raise UnsafePath(f"refusing {p}: {cur} is a symlink")
    return p


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "check-state":
        try:
            check_local_state(argv[1])
        except UnsafePath as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
