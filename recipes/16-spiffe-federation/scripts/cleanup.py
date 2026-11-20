"""`make clean`: remove this recipe's containers, volumes, local registry and working state, deliberately.

    python3 -I scripts/cleanup.py --state STATE [--dry-run]       (CONFIRM is read from the environment)

1. Validates STATE (only <recipe>/.dnsid-local, canonical, no symlinks; see paths.py).
2. Prints exactly what will be removed: this recipe's Compose project (containers, volumes, networks), the
   containers of THIS local registry instance, and the two state directories.
3. If the controller's trusted checkpoint history exists, refuses unless CONFIRM=delete-checkpoint-history.
4. Archives the checkpoint store, its journal, any reset archives and the decision audit log to
   <recipe>/.archive/checkpoints-<utc>/ (outside everything that is deleted), verified by SHA-256, with a
   manifest. If archiving fails, nothing is deleted.
5. Removes: `docker compose -p <this checkout's project> down -v --remove-orphans`, `dnsid local reset --hard
   --state STATE`, and <recipe>/.state. Nothing else: no other Compose project, local registry instance or
   directory. The project is this checkout's own (scripts/paths.py). The LEGACY project `dnsid-recipe16`
   (shared by every checkout before per-checkout names) is refused unless it was selected explicitly with
   RECIPE16_COMPOSE_PROJECT=dnsid-recipe16 AND CONFIRM_LEGACY_PROJECT=dnsid-recipe16 is set.

A local registry reset starts a NEW transparency log, so the old checkpoint history cannot be kept in place:
it would make the controller deny the new log as a rollback. Archiving keeps it for inspection.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from paths import (  # noqa: E402
    CUSTOM_OPT_IN_ENV, LEGACY_PROJECT, PROJECT_ENV, RECIPE_ROOT, UnsafePath, check_local_state, check_ownership,
    check_recipe_state, compose_project, require_under,
)

CONFIRM_WORD = "delete-checkpoint-history"
HISTORY_GLOBS = ("trusted-checkpoints.json", "trusted-checkpoints.journal", "trusted-checkpoints.json.replaced-*",
                 "audit.jsonl")

Runner = Callable[[list[str]], subprocess.CompletedProcess]


def default_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300)


def history_files(recipe_state: Path) -> list[Path]:
    data = recipe_state / "controller" / "data"
    out: list[Path] = []
    for pattern in HISTORY_GLOBS:
        out += sorted(p for p in data.glob(pattern) if p.is_file() and not p.is_symlink())
    return out


def has_checkpoint_history(files: list[Path]) -> bool:
    return any(p.name.startswith("trusted-checkpoints") for p in files)


def lines(cp: subprocess.CompletedProcess) -> list[str]:
    return [ln for ln in (cp.stdout or "").splitlines() if ln.strip()] if cp.returncode == 0 else []


def plan(state: Path, recipe_state: Path, run: Runner, project: str) -> dict:
    proj = f"label=com.docker.compose.project={project}"
    inst = f"label=com.docker.compose.project.working_dir={state}"
    return {
        "compose_project": project,
        "compose_containers": lines(run(["docker", "ps", "-a", "--filter", proj, "--format", "{{.Names}}"])),
        "compose_volumes": lines(run(["docker", "volume", "ls", "--filter", proj, "--format", "{{.Name}}"])),
        "compose_networks": lines(run(["docker", "network", "ls", "--filter", proj, "--format", "{{.Name}}"])),
        "local_registry_containers": lines(run(["docker", "ps", "-a", "--filter", inst, "--format", "{{.Names}}"])),
        "directories": [str(state), str(recipe_state)],
    }


def print_plan(p: dict, files: list[Path]) -> None:
    print("make clean will remove ONLY this recipe's resources:")
    print(f"  Compose project {p['compose_project']} (docker compose down -v --remove-orphans):")
    for k in ("compose_containers", "compose_volumes", "compose_networks"):
        print(f"    {k.split('_')[1]}: {', '.join(p[k]) or '(none)'}")
    print(f"  Local registry instance (dnsid local reset --hard): {', '.join(p['local_registry_containers']) or '(no containers)'}")
    for d in p["directories"]:
        print(f"  directory: {d}")
    if has_checkpoint_history(files):
        print("  CHECKPOINT HISTORY (archived first, then deleted with the directory above):")
        for f in files:
            print(f"    {f}")


def archive(files: list[Path], recipe_root: Path, now: dt.datetime) -> Path:
    """Copy `files` to <recipe>/.archive/checkpoints-<utc>/ and verify every copy. Raises on any failure."""
    base = recipe_root / ".archive"
    dest = base / f"checkpoints-{now:%Y%m%dT%H%M%SZ}"
    if base.is_symlink() or dest.exists():
        raise UnsafePath(f"refusing archive destination {dest}")
    dest.mkdir(parents=True, mode=0o700)
    manifest = {"created_at": now.isoformat(), "files": []}
    for src in files:
        digest = hashlib.sha256(src.read_bytes()).hexdigest()
        target = dest / src.name
        shutil.copy2(src, target)
        if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise OSError(f"archive copy of {src} does not match the original")
        manifest["files"].append({"source": str(src), "name": src.name, "sha256": digest})
    (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return dest


def clean(state_raw: str, confirm: str, *, dry_run: bool = False, run: Runner = default_runner,
          root: Path = RECIPE_ROOT, now: dt.datetime | None = None, project_override: str | None = None,
          confirm_legacy: str = "", opt_in: str | None = None) -> int:
    try:
        state = check_local_state(state_raw, root)
        recipe_state = check_recipe_state(str(root / ".state"), root)
        project = compose_project(project_override, root, opt_in=opt_in)
    except UnsafePath as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if project == LEGACY_PROJECT and confirm_legacy != LEGACY_PROJECT:
        print(f"ERROR: refusing to clean the legacy Compose project {LEGACY_PROJECT}: older checkouts of this recipe "
              f"share it. If you mean it, re-run with RECIPE16_COMPOSE_PROJECT={LEGACY_PROJECT} and "
              f"CONFIRM_LEGACY_PROJECT={LEGACY_PROJECT}. Nothing was changed.", file=sys.stderr)
        return 2
    if project != LEGACY_PROJECT:
        # This checkout's .dnsid-local and .state may still back a LEGACY stack started from the same checkout
        # before per-checkout names. Deleting them under it would break it, so refuse while any exists.
        legacy = run(["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={LEGACY_PROJECT}",
                      "--filter", f"label=com.docker.compose.project.working_dir={root}", "--format", "{{.Names}}"])
        if legacy.returncode != 0:
            print("ERROR: could not check for legacy containers of this checkout; nothing was changed.", file=sys.stderr)
            return 2
        if lines(legacy):
            print(f"ERROR: refusing: {len(lines(legacy))} container(s) of the legacy Compose project {LEGACY_PROJECT} "
                  f"from this checkout still use its local registry and state ({', '.join(lines(legacy)[:3])}...). "
                  f"Stop and remove that stack explicitly first (RECIPE16_COMPOSE_PROJECT={LEGACY_PROJECT}). "
                  "Nothing was changed.", file=sys.stderr)
            return 2
    try:  # every existing resource of the project must provably belong to THIS checkout (read-only check)
        print(f"ownership: {check_ownership(project, root, run)}")
    except UnsafePath as exc:
        print(f"ERROR: {exc}. Nothing was changed.", file=sys.stderr)
        return 2
    files = history_files(recipe_state)
    p = plan(state, recipe_state, run, project)
    print_plan(p, files)
    if dry_run:
        print("dry run: nothing removed")
        return 0
    if has_checkpoint_history(files) and confirm != CONFIRM_WORD:
        print(f"\nRefusing: this deletes the controller's trusted checkpoint history and its journal.\n"
              f"Re-run with: make clean CONFIRM={CONFIRM_WORD}   (an archive copy is kept under .archive/)",
              file=sys.stderr)
        return 2
    if files:
        try:
            dest = archive(files, root, now or dt.datetime.now(dt.timezone.utc))
        except (OSError, UnsafePath) as exc:
            print(f"ERROR: archiving failed, nothing was removed: {exc}", file=sys.stderr)
            return 1
        print(f"archived {len(files)} file(s) to {dest}")
    steps = [
        ["docker", "compose", "-p", project, "--project-directory", str(root), "-f", str(root / "compose.yaml"),
         "down", "-v", "--remove-orphans"],
        ["dnsid", "local", "reset", "--hard", "--state", str(state)],
    ]
    rc = 0
    for cmd in steps:
        cp = run(cmd)
        if cp.returncode != 0:
            print(f"WARN: {' '.join(cmd[:4])} exited {cp.returncode}: {(cp.stderr or '').strip()[:300]}", file=sys.stderr)
            rc = 1
    target = require_under(recipe_state, root)
    if target == root / ".state" and target.exists():
        shutil.rmtree(target)
    print("clean complete" if rc == 0 else "clean finished with warnings (see above)")
    return rc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scripts/cleanup.py")
    ap.add_argument("--state", required=True)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    return clean(a.state, os.environ.get("CONFIRM", ""), dry_run=a.dry_run,
                 project_override=os.environ.get(PROJECT_ENV) or None,
                 confirm_legacy=os.environ.get("CONFIRM_LEGACY_PROJECT", ""),
                 opt_in=os.environ.get(CUSTOM_OPT_IN_ENV) or None)


if __name__ == "__main__":
    sys.exit(main())
