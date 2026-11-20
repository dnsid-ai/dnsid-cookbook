"""Path guards: every destructive or state-writing operation in this recipe is confined to the recipe's own
directories.

    python3 -I scripts/paths.py check-state STATE    exit 0 only for this recipe's dedicated .dnsid-local
    python3 -I scripts/paths.py project [OVERRIDE [OPT_IN]]  print this checkout's Compose project name
    python3 -I scripts/paths.py check-owner PROJECT  refuse unless PROJECT's resources belong to this checkout
    python3 -I scripts/paths.py check-ports          validate the RECIPE16_*_PORT host-port overrides

Rules for the DNSid local registry state directory (STATE / DNSID_LOCAL_STATE):
  * exactly <recipe>/.dnsid-local, spelled canonically (absolute, no `.`/`..`, no doubled or trailing slash):
    the dnsid CLI derives its Docker labels and Compose project from the literal path, so two spellings of
    one directory could select different instances
  * the recipe directory itself must not be reached through a symlink
  * if it exists, it is a real directory, not a symlink
Anything else (another instance such as ~/.dnsid-local, path traversal, a symlink) is refused.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
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


# ------------------------------------------------------------------ Compose project and host ports
# Every checkout gets its own Compose project (containers, named volumes, networks, image tags), derived from
# its canonical path, so two checkouts never share or clean up each other's resources. Releases before this
# change used one fixed name for every checkout; that LEGACY project is reachable only by naming it explicitly.
LEGACY_PROJECT = "dnsid-recipe16"
PROJECT_ENV = "RECIPE16_COMPOSE_PROJECT"
# Lowercase letters, digits and inner hyphens: valid as a Compose project name AND as an image-name component.
_PROJECT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")

PORT_DEFAULTS = {  # env var -> default host port (127.0.0.1 only)
    "RECIPE16_PURCHASING_PORT": 18080, "RECIPE16_INVENTORY_PORT": 18081, "RECIPE16_SUPPLIER_PORT": 18082,
    "RECIPE16_CONTROLLER_PORT": 18085, "RECIPE16_PUBLISHER_PORT": 18090, "RECIPE16_BUNDLE_ENDPOINT_PORT": 18443,
}


def derived_project(root: Path = RECIPE_ROOT) -> str:
    """Stable per-checkout project name: the legacy prefix plus a hash of the canonical recipe path."""
    root = check_recipe_root(root)
    return f"{LEGACY_PROJECT}-{hashlib.sha256(str(root).encode()).hexdigest()[:10]}"


def check_project_name(name: str) -> str:
    if not _PROJECT_RE.match(name or ""):
        raise UnsafePath(f"invalid Compose project name {name!r}: use 1-40 lowercase letters, digits and inner "
                         "hyphens")
    return name


_DERIVED_RE = re.compile(rf"^{re.escape(LEGACY_PROJECT)}-[0-9a-f]{{10}}$")
CUSTOM_OPT_IN_ENV = "RECIPE16_ALLOW_CUSTOM_PROJECT"


def compose_project(override: str | None = None, root: Path = RECIPE_ROOT, opt_in: str | None = None) -> str:
    """The Compose project for this checkout.

    No override: the derived name. Overrides: this checkout's own derived name; the legacy name; or any other
    valid name only with an explicit opt-in that repeats it (RECIPE16_ALLOW_CUSTOM_PROJECT=<name>). The derived
    pattern is reserved: another checkout's derived name is always refused.
    """
    own = derived_project(root)
    if not override or override == own:
        return own
    check_project_name(override)
    if _DERIVED_RE.match(override):
        raise UnsafePath(f"{override} is another checkout's project (this checkout's is {own}); refusing")
    if override == LEGACY_PROJECT:
        return override
    if opt_in != override:
        raise UnsafePath(f"custom Compose project {override!r} needs an explicit opt-in: "
                         f"{CUSTOM_OPT_IN_ENV}={override}")
    return override


def _docker_lines(cmd: list[str], run) -> list[str]:
    cp = run(cmd)
    if cp.returncode != 0:
        raise UnsafePath(f"could not inspect Docker ({' '.join(cmd[:3])}): ownership unknown, refusing")
    return [ln.strip() for ln in (cp.stdout or "").splitlines() if ln.strip()]


def check_ownership(project: str, root: Path = RECIPE_ROOT, run=None) -> str:
    """Refuse unless every existing resource of `project` provably belongs to this checkout. Read-only.

    Containers (running AND stopped) carry Compose's working-dir label: all must name this recipe directory.
    A missing label is ambiguous. Volumes and networks carry no such label, so if they exist with no
    container left, ownership is established only for this checkout's own derived name (it is bound to this
    path); for the legacy or a custom name it cannot be, and the operation is refused. Returns a summary.
    """
    run = run or (lambda c: subprocess.run(c, capture_output=True, text=True, timeout=30))
    root = check_recipe_root(root)
    flt = f"label=com.docker.compose.project={project}"
    dirs = _docker_lines(["docker", "ps", "-a", "--filter", flt, "--format",
                          '{{.Names}}\t{{.Label "com.docker.compose.project.working_dir"}}'], run)
    foreign, unlabeled = [], []
    for ln in dirs:
        name, _, wd = ln.partition("\t")
        if not wd.strip():
            unlabeled.append(name)
        elif Path(wd.strip()) != root:
            foreign.append(f"{name} ({wd.strip()})")
    if foreign:
        raise UnsafePath(f"Compose project {project} belongs to another checkout: {', '.join(foreign[:3])}")
    if unlabeled:
        raise UnsafePath(f"Compose project {project} has containers without a working-dir label "
                         f"({', '.join(unlabeled[:3])}): ownership is ambiguous, refusing")
    if not dirs:
        orphans = (_docker_lines(["docker", "volume", "ls", "--filter", flt, "--format", "{{.Name}}"], run)
                   + _docker_lines(["docker", "network", "ls", "--filter", flt, "--format", "{{.Name}}"], run))
        if orphans and project != derived_project(root):
            raise UnsafePath(f"Compose project {project} has volumes/networks but no containers "
                             f"({', '.join(orphans[:3])}): ownership cannot be established, refusing")
        return f"{project}: no containers" + (f"; {len(orphans)} orphaned volume(s)/network(s) of this checkout"
                                              if orphans else "")
    return f"{project}: {len(dirs)} container(s), all from this checkout"


def check_ports(env: dict[str, str], reserved: tuple[int, ...] = ()) -> dict[str, int]:
    """Validate the host-port overrides: numeric, 1024-65535, pairwise distinct, none of `reserved`."""
    ports = {}
    for key, default in PORT_DEFAULTS.items():
        raw = env.get(key) or str(default)
        if not raw.isdigit() or not 1024 <= int(raw) <= 65535:
            raise UnsafePath(f"{key}={raw!r} must be a port number from 1024 to 65535")
        ports[key] = int(raw)
    clash = [p for p in ports.values() if list(ports.values()).count(p) > 1 or p in reserved]
    if clash:
        raise UnsafePath(f"host ports must be distinct and must not reuse {sorted(set(reserved))}: {sorted(set(clash))}")
    return ports


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 2 and argv[0] == "check-state":
            check_local_state(argv[1])
            return 0
        if len(argv) in (1, 2, 3) and argv[0] == "project":
            override = argv[1] if len(argv) >= 2 else None
            opt_in = argv[2] if len(argv) == 3 else os.environ.get(CUSTOM_OPT_IN_ENV)
            print(compose_project(override, opt_in=opt_in or None))
            return 0
        if len(argv) == 2 and argv[0] == "check-owner":
            print(check_ownership(check_project_name(argv[1])))
            return 0
        if len(argv) == 1 and argv[0] == "check-ports":
            reserved = tuple(int(os.environ[k]) for k in ("DNSID_LOCAL_PROXY_PORT", "DNSID_LOCAL_REGISTRY_PORT",
                                                          "DNSID_LOCAL_DNS_PORT") if os.environ.get(k, "").isdigit())
            check_ports(dict(os.environ), reserved)
            return 0
    except UnsafePath as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
