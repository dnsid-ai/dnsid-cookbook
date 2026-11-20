"""Operational safety: path guards (paths.py, identity.py), the Makefile's non-destructive `stop` and its
refusal of unsafe STATE overrides, and `make clean`'s confirmation and archive (cleanup.py)."""
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import types
from pathlib import Path

import pytest

import cleanup
import paths
from paths import UnsafePath, check_local_state, check_recipe_state, require_under

RECIPE = paths.RECIPE_ROOT


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "recipe"
    (r / "scripts").mkdir(parents=True)
    return Path(os.path.realpath(r))


# ------------------------------------------------------------------ paths.py
def test_only_the_recipes_own_state_is_accepted(root):
    assert check_local_state(str(root / ".dnsid-local"), root) == root / ".dnsid-local"


@pytest.mark.parametrize("bad", [
    "",
    ".dnsid-local",                                  # relative
    "{root}/./.dnsid-local",                         # non-canonical spelling
    "{root}/.dnsid-local/",                          # trailing slash
    "{root}//.dnsid-local",                          # doubled slash
    "{root}/x/../.dnsid-local",                      # traversal
    "{root}/../.dnsid-local",                        # escapes the recipe
    "{root}/.dnsid-local/../../elsewhere",
    "{home}/.dnsid-local",                           # the CLI default instance
    "{home}/another-demo/.dnsid-local",              # another demo's instance
    "{root}/.dnsid-local-other",
])
def test_unsafe_state_paths_are_refused(root, bad):
    raw = bad.format(root=root, home=os.path.expanduser("~"))
    with pytest.raises(UnsafePath):
        check_local_state(raw, root)


def test_symlinked_state_directory_is_refused(root, tmp_path):
    elsewhere = tmp_path / "other-instance"
    elsewhere.mkdir()
    (root / ".dnsid-local").symlink_to(elsewhere)
    with pytest.raises(UnsafePath, match="symlink"):
        check_local_state(str(root / ".dnsid-local"), root)


def test_state_path_that_is_a_file_is_refused(root):
    (root / ".dnsid-local").write_text("x")
    with pytest.raises(UnsafePath):
        check_local_state(str(root / ".dnsid-local"), root)


def test_recipe_reached_through_a_symlink_is_refused(root, tmp_path):
    link = tmp_path / "link-to-recipe"
    link.symlink_to(root)
    with pytest.raises(UnsafePath, match="canonical"):
        check_local_state(str(link / ".dnsid-local"), link)


def test_recipe_state_must_be_exactly_dot_state(root):
    assert check_recipe_state(str(root / ".state"), root) == root / ".state"
    for bad in (str(root / "state"), f"{root}/.state/", f"{root}/./.state", "/tmp/.state", ""):
        with pytest.raises(UnsafePath):
            check_recipe_state(bad, root)


def test_require_under(root):
    base = root / ".state" / "dnsid"
    base.mkdir(parents=True)
    assert require_under(base / "publisher.env", base) == base / "publisher.env"
    for bad in (base, root / ".state" / "x", base / ".." / "x", "/etc/passwd", root.parent / "dnsid" / "x"):
        with pytest.raises(UnsafePath):
            require_under(bad, base)
    (base / "link").symlink_to(root)
    with pytest.raises(UnsafePath, match="symlink"):
        require_under(base / "link" / "x", base)


def test_check_state_cli():
    assert paths.main(["check-state", str(RECIPE / ".dnsid-local")]) == 0
    assert paths.main(["check-state", os.path.expanduser("~/.dnsid-local")]) == 2


# ------------------------------------------------------------------ identity.py
@pytest.fixture
def identity(monkeypatch):
    import identity as I
    return I


def good_env():
    return {"DNSID_LOCAL_STATE": str(RECIPE / ".dnsid-local"), "RECIPE_STATE": str(RECIPE / ".state"),
            "DNSID_LOCAL_REGISTRY_PORT": "7965", "DNSID_LOCAL_DNS_PORT": "7963"}


def test_identity_accepts_only_this_recipes_instance(identity):
    identity.configure(good_env())
    assert identity.LOCAL == RECIPE / ".dnsid-local" and identity.DNSID_DIR == RECIPE / ".state" / "dnsid"
    assert identity.DNS_PORT == 7963
    for key, bad in (("DNSID_LOCAL_STATE", os.path.expanduser("~/.dnsid-local")),
                     ("DNSID_LOCAL_STATE", str(RECIPE / ".dnsid-local" / ".." / ".dnsid-local")),
                     ("RECIPE_STATE", "/tmp/.state"),
                     ("DNSID_LOCAL_REGISTRY_PORT", ""),
                     ("DNSID_LOCAL_DNS_PORT", ""),
                     ("DNSID_LOCAL_DNS_PORT", "0"),
                     ("DNSID_LOCAL_DNS_PORT", "70000")):
        env = dict(good_env(), **{key: bad})
        with pytest.raises(SystemExit) as ei:
            identity.configure(env)
        assert ei.value.code == 2


def test_identity_outputs_confined_to_state_dnsid(identity):
    identity.configure(good_env())
    d = RECIPE / ".state" / "dnsid"
    assert identity.output_path(str(d / "publisher.env")) == d / "publisher.env"
    for bad in (str(RECIPE / ".state" / "controller" / "x"), str(d / ".." / "x"), "/tmp/publisher.env",
                str(RECIPE / ".dnsid-local" / "x"), str(d)):
        with pytest.raises(SystemExit):
            identity.output_path(bad)


# ------------------------------------------------------------------ Makefile (dry runs only: make -n)
def make_n(*args, env=None, cwd=RECIPE):
    if not shutil.which("make"):
        pytest.skip("make not available")
    e = dict(os.environ)
    e.pop("STATE", None)
    e.update(env or {})
    return subprocess.run(["make", "-n", *args], cwd=cwd, env=e, capture_output=True, text=True, timeout=30)


def test_make_stop_is_non_destructive():
    cp = make_n("stop")
    assert cp.returncode == 0, cp.stderr
    cmds = [ln for ln in cp.stdout.splitlines() if ln.strip()]
    assert any("stop rackloria-publisher" in c for c in cmds)
    assert any("stop acme-dnsid-controller" in c for c in cmds)
    assert any(c.startswith("dnsid local down --state ") and c.endswith("/.dnsid-local") for c in cmds)
    order = [i for i, c in enumerate(cmds) if "stop rackloria-publisher" in c or "stop acme-dnsid-controller" in c]
    assert order == sorted(order) and "publisher" in cmds[order[0]]   # publisher first, then controller
    for c in cmds:
        for forbidden in (" down", "reset", "rm ", "volume", "rmi", "prune", "cleanup.py"):
            if forbidden == " down" and c.startswith("dnsid local down "):
                continue  # stops the local registry containers and keeps its state (non-destructive)
            assert forbidden not in f" {c} ", f"stop must not run {forbidden!r}: {c}"


def test_make_clean_delegates_to_the_guarded_cleanup():
    cp = make_n("clean")
    assert cp.returncode == 0, cp.stderr
    cmds = [ln.strip() for ln in cp.stdout.splitlines() if ln.strip()]
    assert cmds[-1].startswith("python3 -I scripts/cleanup.py --state ")
    assert not any(c.startswith(("rm ", "docker ", "dnsid ")) for c in cmds)


@pytest.mark.parametrize("target", ["stop", "clean", "bootstrap", "verify", "checkpoints-reset"])
@pytest.mark.parametrize("how", ["cmdline", "environment"])
def test_make_refuses_state_overrides(target, how):
    other = os.path.expanduser("~/.dnsid-local")
    cp = make_n(f"STATE={other}", target) if how == "cmdline" else make_n(target, env={"STATE": other})
    assert cp.returncode != 0 and "refusing STATE" in cp.stderr
    assert "dnsid" not in cp.stdout and "docker" not in cp.stdout


def test_make_refuses_traversal_spelling_of_its_own_state():
    cp = make_n(f"STATE={RECIPE}/x/../.dnsid-local", "stop")
    assert cp.returncode != 0 and "refusing STATE" in cp.stderr


def test_make_refuses_to_run_from_another_directory():
    cp = make_n("-f", str(RECIPE / "Makefile"), "stop", cwd=RECIPE.parent)
    assert cp.returncode != 0 and "run this Makefile from its own directory" in cp.stderr


# ------------------------------------------------------------------ cleanup.py
class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd):
        self.calls.append(cmd)
        out = ""
        if cmd[:2] == ["docker", "ps"]:
            out = "dnsid-recipe16-acme-server-1\n"
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")

    def destructive(self):
        return [c for c in self.calls if "down" in c or "reset" in c]


NOW = dt.datetime(2026, 11, 19, 12, 0, tzinfo=dt.timezone.utc)


def seed_history(root):
    data = root / ".state" / "controller" / "data"
    data.mkdir(parents=True)
    files = {"trusted-checkpoints.json": b'{"version": 1}', "trusted-checkpoints.journal": b'{"event": "initialized"}\n',
             "trusted-checkpoints.json.replaced-20261101T000000Z": b"old", "audit.jsonl": b"{}\n"}
    for name, body in files.items():
        (data / name).write_bytes(body)
    (data / "state.json").write_text("{}")
    return files


def test_clean_refuses_without_confirmation_and_changes_nothing(root, capsys):
    files = seed_history(root)
    run = Runner()
    rc = cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW)
    assert rc == 2 and run.destructive() == []
    assert not (root / ".archive").exists()
    assert all((root / ".state/controller/data" / n).read_bytes() == b for n, b in files.items())
    out = capsys.readouterr()
    assert "CHECKPOINT HISTORY" in out.out and "CONFIRM=delete-checkpoint-history" in out.err
    assert "dnsid-recipe16-acme-server-1" in out.out and str(root / ".state") in out.out


def test_clean_rejects_wrong_confirmation_word(root):
    seed_history(root)
    run = Runner()
    assert cleanup.clean(str(root / ".dnsid-local"), "yes", run=run, root=root, now=NOW) == 2
    assert run.destructive() == []


def test_clean_with_confirmation_archives_then_removes_only_recipe_resources(root):
    files = seed_history(root)
    run = Runner()
    rc = cleanup.clean(str(root / ".dnsid-local"), "delete-checkpoint-history", run=run, root=root, now=NOW)
    assert rc == 0
    arch = root / ".archive" / "checkpoints-20261119T120000Z"
    for name, body in files.items():
        assert (arch / name).read_bytes() == body
    manifest = json.loads((arch / "MANIFEST.json").read_text())
    assert {f["name"]: f["sha256"] for f in manifest["files"]} == {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}
    down, reset = run.destructive()
    assert down[:4] == ["docker", "compose", "-p", "dnsid-recipe16"] and down[-3:] == ["down", "-v", "--remove-orphans"]
    assert reset == ["dnsid", "local", "reset", "--hard", "--state", str(root / ".dnsid-local")]
    assert not (root / ".state").exists() and arch.exists()            # archive survives the cleanup


def test_clean_without_history_needs_no_confirmation(root):
    (root / ".state").mkdir()
    run = Runner()
    assert cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW) == 0
    assert len(run.destructive()) == 2 and not (root / ".state").exists()


def test_archive_failure_aborts_before_anything_is_removed(root, tmp_path):
    seed_history(root)
    (tmp_path / "elsewhere").mkdir()
    (root / ".archive").symlink_to(tmp_path / "elsewhere")             # unsafe archive destination
    run = Runner()
    rc = cleanup.clean(str(root / ".dnsid-local"), "delete-checkpoint-history", run=run, root=root, now=NOW)
    assert rc == 1 and run.destructive() == [] and (root / ".state").exists()


def test_clean_refuses_unsafe_state_before_any_command(root):
    run = Runner()
    for bad in (os.path.expanduser("~/.dnsid-local"), f"{root}/.dnsid-local/../x", f"{root}/.dnsid-local/"):
        assert cleanup.clean(bad, "delete-checkpoint-history", run=run, root=root, now=NOW) == 2
    assert run.calls == []


def test_dry_run_removes_nothing(root):
    seed_history(root)
    run = Runner()
    assert cleanup.clean(str(root / ".dnsid-local"), "", dry_run=True, run=run, root=root, now=NOW) == 0
    assert run.destructive() == [] and (root / ".state").exists()
