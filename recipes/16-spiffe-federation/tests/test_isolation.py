"""Per-checkout Compose isolation, the explicit legacy-project transition, and configurable host ports.

Offline: no Docker daemon, no containers. Shell paths run in bash against a stubbed `docker`; Make paths use
`make -n` (dry run), which prints commands without running them.
"""
import datetime as dt
import os
import re
import shutil
import subprocess
import types
from pathlib import Path

import pytest

import cleanup
import paths
from paths import LEGACY_PROJECT, PORT_DEFAULTS, UnsafePath, check_ports, compose_project, derived_project

RECIPE = paths.RECIPE_ROOT
LIB = (RECIPE / "scripts" / "lib.sh").read_text()
COMPOSE = (RECIPE / "compose.yaml").read_text()
COMPOSE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")       # Docker Compose's own project-name rule
IMAGE_COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")  # image path component rule


def checkout(tmp_path, name):
    d = tmp_path / name / "16-spiffe-federation"
    (d / "scripts").mkdir(parents=True)
    return Path(os.path.realpath(d))


# ------------------------------------------------------------------ project names
def test_different_checkouts_get_different_projects(tmp_path):
    a, b = checkout(tmp_path, "one"), checkout(tmp_path, "two")
    assert derived_project(a) != derived_project(b)


def test_same_checkout_is_stable(tmp_path):
    a = checkout(tmp_path, "one")
    assert derived_project(a) == derived_project(a) == compose_project(None, a) == compose_project("", a)


def test_this_checkout_is_stable_and_not_legacy():
    name = derived_project()
    assert name == derived_project() and name != LEGACY_PROJECT and name.startswith(LEGACY_PROJECT + "-")


@pytest.mark.parametrize("root_name", ["one", "two", "x" * 60])
def test_derived_names_meet_compose_and_image_constraints(tmp_path, root_name):
    name = derived_project(checkout(tmp_path, root_name))
    assert COMPOSE_NAME_RE.match(name) and IMAGE_COMPONENT_RE.match(name) and len(name) <= 40


@pytest.mark.parametrize("good", [LEGACY_PROJECT, "r16-test", "a", "a1", "x" * 40])
def test_valid_overrides(good):
    assert compose_project(good, opt_in=good) == good
    assert COMPOSE_NAME_RE.match(good) and IMAGE_COMPONENT_RE.match(good)


@pytest.mark.parametrize("bad", ["Upper", "under_score", "-lead", "trail-", "x" * 41, "a/b", "a.b", "a b",
                                 "x'; touch pwn", "dnsid recipe16"])
def test_invalid_overrides_rejected(bad):
    with pytest.raises(UnsafePath):
        compose_project(bad)


def test_cli_prints_project_and_rejects_bad_override():
    cp = subprocess.run(["python3", "-I", str(RECIPE / "scripts" / "paths.py"), "project"], capture_output=True, text=True)
    assert cp.returncode == 0 and cp.stdout.strip() == derived_project()
    cp = subprocess.run(["python3", "-I", str(RECIPE / "scripts" / "paths.py"), "project", "Bad_Name"],
                        capture_output=True, text=True)
    assert cp.returncode == 2 and "invalid Compose project name" in cp.stderr


# ------------------------------------------------------------------ every command targets the right project
def make_n(*args, env=None):
    if not shutil.which("make"):
        pytest.skip("make not available")
    e = {k: v for k, v in os.environ.items() if not k.startswith(("RECIPE16_", "STATE", "CONFIRM"))}
    for k in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL"):   # inherited from an invoking make (see test_safety.make_n)
        e.pop(k, None)
    e.update(env or {})
    return subprocess.run(["make", "--no-print-directory", "-n", *args], cwd=RECIPE, env=e, capture_output=True,
                          text=True, timeout=30)


def projects_in(text):
    return set(re.findall(r"compose -p (\S+)", text))


@pytest.mark.parametrize("target", ["stop", "checkpoints-status", "checkpoints-reset"])
def test_make_targets_use_the_derived_project(target):
    cp = make_n(target, "REASON=x") if target == "checkpoints-reset" else make_n(target)
    assert cp.returncode == 0, cp.stderr
    assert projects_in(cp.stdout) == {derived_project()}


@pytest.mark.parametrize("how", ["environment", "cmdline"])
def test_explicit_override_reaches_every_compose_command(how):
    cp = make_n("stop", env={"RECIPE16_COMPOSE_PROJECT": LEGACY_PROJECT}) if how == "environment" \
        else make_n("stop", f"RECIPE16_COMPOSE_PROJECT={LEGACY_PROJECT}")
    assert cp.returncode == 0 and projects_in(cp.stdout) == {LEGACY_PROJECT}


def test_invalid_override_stops_make_before_any_command():
    cp = make_n("stop", "RECIPE16_COMPOSE_PROJECT=x'; touch pwned")
    assert cp.returncode != 0 and "valid Compose project name" in cp.stderr
    assert "docker" not in cp.stdout and not (RECIPE / "pwned").exists()


def test_compose_file_names_project_and_images_after_the_variable():
    assert re.search(r"^name: \$\{RECIPE16_COMPOSE_PROJECT:\?", COMPOSE, re.M)
    images = re.findall(r"image: (\S+)", COMPOSE)
    assert images and all(i.startswith("${RECIPE16_COMPOSE_PROJECT:?") for i in images)
    assert "dnsid-recipe16/" not in COMPOSE and not re.search(r"^name: dnsid-recipe16\s*$", COMPOSE, re.M)


def lib_eval(expr, env=None):
    """Source lib.sh (it needs make's environment) and print EXPR."""
    e = {"PATH": os.environ["PATH"], "DNSID_LOCAL_STATE": str(RECIPE / ".dnsid-local"),
         "DNSID_LOCAL_REGISTRY_PORT": "7965", "DNSID_LOCAL_DNS_PORT": "7963"}
    e.update(env or {})
    return subprocess.run(["bash", "-c", f'. "{RECIPE}/scripts/lib.sh" && {expr}'], env=e, capture_output=True,
                          text=True, timeout=30)


def test_lib_sh_uses_derived_project_and_exports_it():
    cp = lib_eval('echo "$PROJECT $RECIPE16_COMPOSE_PROJECT"')
    assert cp.returncode == 0 and cp.stdout.split() == [derived_project()] * 2


def test_lib_sh_honours_and_validates_the_override():
    assert lib_eval('echo "$PROJECT"', {"RECIPE16_COMPOSE_PROJECT": "r16-test",
                                       "RECIPE16_ALLOW_CUSTOM_PROJECT": "r16-test"}).stdout.strip() == "r16-test"
    assert lib_eval('echo reached', {"RECIPE16_COMPOSE_PROJECT": "r16-test"}).returncode != 0   # no opt-in
    cp = lib_eval('echo reached', {"RECIPE16_COMPOSE_PROJECT": "Bad_Name"})
    assert cp.returncode != 0 and "reached" not in cp.stdout


# ------------------------------------------------------------------ legacy project: never touched by accident
def legacy_check(running, project_env=None, docker_rc=0):
    fn = re.search(r"^legacy_stack_check\(\) \{.*?^\}", LIB, re.S | re.M).group(0)
    script = "\n".join([
        f'PROJECT={project_env or derived_project()}; LEGACY_PROJECT={LEGACY_PROJECT}',
        f'docker() {{ echo "$*" >> "$CALLS"; [ {docker_rc} = 0 ] || return {docker_rc}; printf "%s" "$RUNNING"; }}',
        fn, "legacy_stack_check"])
    calls = Path(os.environ.get("TMPDIR", "/tmp")) / f"lc-{os.getpid()}-{id(script)}"
    calls.write_text("")
    cp = subprocess.run(["/bin/bash", "-c", script], env={"PATH": "/usr/bin:/bin", "RUNNING": running,
                                                           "CALLS": str(calls)}, capture_output=True, text=True)
    logged = calls.read_text().splitlines()
    calls.unlink()
    return cp, logged


def test_bootstrap_refuses_while_legacy_stack_runs_and_only_reads():
    cp, calls = legacy_check("abc\ndef\n")
    assert cp.returncode != 0 and "2 container(s)" in cp.stderr and "RECIPE16_COMPOSE_PROJECT=dnsid-recipe16 make stop" in cp.stderr
    assert calls and all(c.startswith("ps ") for c in calls)                 # read-only: never stop/rm/down


def test_bootstrap_proceeds_without_a_legacy_stack_or_when_legacy_is_explicit():
    assert legacy_check("")[0].returncode == 0
    cp, calls = legacy_check("abc\n", project_env=LEGACY_PROJECT)
    assert cp.returncode == 0 and calls == []


def test_bootstrap_fails_closed_if_docker_cannot_be_queried():
    assert legacy_check("", docker_rc=1)[0].returncode != 0


def test_bootstrap_calls_the_legacy_check_first():
    boot = (RECIPE / "scripts" / "bootstrap.sh").read_text()
    assert boot.index("legacy_stack_check") < boot.index("dnsid local up")


class FakeDocker:
    """Fake `docker`. `legacy`: legacy containers from this checkout (cleanup's same-checkout guard).
    `owned`: {project: [(container, working_dir or "")]} answered to the ownership query (running AND stopped,
    so `docker ps -a`). `orphans`: {project: [volume or network names]}. `fail`: subcommands that error."""

    def __init__(self, legacy=(), owned=None, orphans=None, fail=()):
        self.calls, self.legacy = [], list(legacy)
        self.owned, self.orphans, self.fail = owned or {}, orphans or {}, set(fail)

    def __call__(self, cmd):
        self.calls.append(cmd)
        proj = next((c.split("project=", 1)[1] for c in cmd if c.startswith("label=com.docker.compose.project=")), None)
        if cmd[1] in self.fail:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="daemon unavailable")
        out = ""
        if cmd[:2] == ["docker", "ps"] and any("working_dir" in c for c in cmd if c.startswith("label=")):
            out = "".join(f"{n}\n" for n in self.legacy)
        elif cmd[:2] == ["docker", "ps"] and any(c.startswith("{{") and "working_dir" in c for c in cmd):
            assert "-a" in cmd, "ownership must include stopped containers"
            out = "".join(f"{n}\t{wd}\n" for n, wd in self.owned.get(proj, []))
        elif cmd[:2] in (["docker", "volume"], ["docker", "network"]):
            out = "".join(f"{n}\n" for n in self.orphans.get(proj, []))
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")

    def destructive(self):
        return [c for c in self.calls if "down" in c or "reset" in c]


NOW = dt.datetime(2026, 11, 20, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def root(tmp_path):
    return checkout(tmp_path, "clone")


def test_cleanup_targets_only_the_derived_project(root):
    (root / ".state").mkdir()
    run = FakeDocker()
    assert cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW) == 0
    down = run.destructive()[0]
    assert down[:4] == ["docker", "compose", "-p", derived_project(root)]
    queried = {c.split("project=", 1)[1] for cmd in run.calls for c in cmd if c.startswith("label=com.docker.compose.project=")}
    assert queried == {derived_project(root), LEGACY_PROJECT}               # legacy is only ever READ (the guard)
    assert not any(LEGACY_PROJECT == c for cmd in run.destructive() for c in cmd)


def test_cleanup_refuses_legacy_project_without_explicit_confirmation(root):
    (root / ".state").mkdir()
    run = FakeDocker()
    assert cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW,
                         project_override=LEGACY_PROJECT) == 2
    assert run.calls == [] and (root / ".state").exists()


def test_cleanup_of_legacy_needs_both_explicit_name_and_confirmation(root):
    (root / ".state").mkdir()
    run = FakeDocker()
    assert cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW,
                         project_override=LEGACY_PROJECT, confirm_legacy=LEGACY_PROJECT) == 0
    assert run.destructive()[0][:4] == ["docker", "compose", "-p", LEGACY_PROJECT]


def test_cleanup_refuses_while_a_legacy_stack_uses_this_checkouts_state(root):
    (root / ".state").mkdir()
    run = FakeDocker(legacy=["dnsid-recipe16-acme-server-1"])
    assert cleanup.clean(str(root / ".dnsid-local"), "delete-checkpoint-history", run=run, root=root, now=NOW) == 2
    assert run.destructive() == [] and (root / ".state").exists()
    legacy_query = run.calls[0]
    assert f"label=com.docker.compose.project.working_dir={root}" in legacy_query      # only THIS checkout's


def test_cleanup_rejects_invalid_override(root):
    run = FakeDocker()
    assert cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW, project_override="Bad") == 2
    assert run.calls == []


# ------------------------------------------------------------------ host ports
def test_port_defaults_are_unchanged():
    assert check_ports({}) == PORT_DEFAULTS == {
        "RECIPE16_PURCHASING_PORT": 18080, "RECIPE16_INVENTORY_PORT": 18081, "RECIPE16_SUPPLIER_PORT": 18082,
        "RECIPE16_CONTROLLER_PORT": 18085, "RECIPE16_PUBLISHER_PORT": 18090, "RECIPE16_BUNDLE_ENDPOINT_PORT": 18443}


def test_port_overrides_are_applied():
    assert check_ports({"RECIPE16_PURCHASING_PORT": "28080"})["RECIPE16_PURCHASING_PORT"] == 28080


@pytest.mark.parametrize("env", [
    {"RECIPE16_PURCHASING_PORT": "abc"}, {"RECIPE16_PURCHASING_PORT": "80"}, {"RECIPE16_PURCHASING_PORT": "70000"},
    {"RECIPE16_PURCHASING_PORT": "18081"},                                   # collides with inventory
])
def test_bad_ports_rejected(env):
    with pytest.raises(UnsafePath):
        check_ports(env)


def test_ports_may_not_reuse_registry_dns_or_proxy():
    with pytest.raises(UnsafePath):
        check_ports({"RECIPE16_CONTROLLER_PORT": "7965"}, reserved=(443, 7965, 7963))


def test_compose_ports_use_the_variables_with_the_old_defaults():
    mapped = dict(re.findall(r'"127\.0\.0\.1:\$\{(RECIPE16_[A-Z_]+_PORT):-(\d+)\}:\d+"', COMPOSE))
    assert {k: int(v) for k, v in mapped.items()} == PORT_DEFAULTS
    assert not re.search(r'"127\.0\.0\.1:\d+:\d+"', COMPOSE)                 # no hard-coded host port left


def test_status_urls_follow_the_port_overrides():
    cp = lib_eval("url purchasing; url controller", {"RECIPE16_PURCHASING_PORT": "28080"})
    assert cp.stdout.split() == ["http://127.0.0.1:28080", "http://127.0.0.1:18085"]


def test_make_exports_port_overrides_and_validates_them():
    cp = make_n("stop", "PURCHASING_PORT=28080")
    assert cp.returncode == 0 and "paths.py check-ports" in cp.stdout


def test_proxy_port_stays_fixed_at_443():
    mk = (RECIPE / "Makefile").read_text()
    assert re.search(r"^PROXY_PORT \?= 443$", mk, re.M)


# ------------------------------------------------------------------ cross-checkout ownership
def test_another_checkouts_derived_name_is_rejected(tmp_path):
    mine, other = checkout(tmp_path, "mine"), checkout(tmp_path, "other")
    with pytest.raises(UnsafePath, match="another checkout"):
        compose_project(derived_project(other), mine)
    with pytest.raises(UnsafePath, match="another checkout"):          # even with the custom opt-in
        compose_project(derived_project(other), mine, opt_in=derived_project(other))


def test_this_checkouts_own_derived_name_is_accepted_as_override(tmp_path):
    mine = checkout(tmp_path, "mine")
    assert compose_project(derived_project(mine), mine) == derived_project(mine)


def test_custom_name_needs_matching_opt_in():
    with pytest.raises(UnsafePath, match="opt-in"):
        compose_project("r16-test")
    with pytest.raises(UnsafePath, match="opt-in"):
        compose_project("r16-test", opt_in="something-else")
    assert compose_project("r16-test", opt_in="r16-test") == "r16-test"


def test_make_refuses_custom_name_without_opt_in_and_other_checkouts_name():
    cp = make_n("stop", "RECIPE16_COMPOSE_PROJECT=r16-test")
    assert cp.returncode != 0 and "opt-in" in cp.stderr and "docker" not in cp.stdout
    assert projects_in(make_n("stop", "RECIPE16_COMPOSE_PROJECT=r16-test",
                              "RECIPE16_ALLOW_CUSTOM_PROJECT=r16-test").stdout) == {"r16-test"}
    cp = make_n("stop", "RECIPE16_COMPOSE_PROJECT=dnsid-recipe16-0123456789")
    assert cp.returncode != 0 and "another checkout" in cp.stderr


def test_make_guard_checks_ownership_before_every_resource_target():
    for target in ("stop", "checkpoints-status", "clean", "bootstrap"):
        cp = make_n(target, "REASON=x")
        assert cp.returncode == 0, cp.stderr
        out = cp.stdout
        assert f'paths.py check-owner "{derived_project()}"' in out
        first_docker = min((out.find(k) for k in ("docker ", "bash scripts", "cleanup.py") if k in out), default=-1)
        assert out.find("check-owner") < first_docker


def own(root, n=1):
    return [(f"c{i}", str(root)) for i in range(n)]


@pytest.mark.parametrize("state", ["running", "stopped"])
def test_foreign_containers_are_refused(root, tmp_path, state):
    other = str(checkout(tmp_path, "other"))
    run = FakeDocker(owned={derived_project(root): [("mine", str(root)), (f"theirs-{state}", other)]})
    with pytest.raises(UnsafePath, match="another checkout"):
        paths.check_ownership(derived_project(root), root, run)


def test_foreign_legacy_containers_are_refused(root, tmp_path):
    other = str(checkout(tmp_path, "old-checkout"))
    run = FakeDocker(owned={LEGACY_PROJECT: [("dnsid-recipe16-acme-server-1", other)]})
    with pytest.raises(UnsafePath, match="another checkout"):
        paths.check_ownership(LEGACY_PROJECT, root, run)


def test_own_legacy_containers_are_accepted(root):
    run = FakeDocker(owned={LEGACY_PROJECT: own(root, 3)})
    assert "3 container(s), all from this checkout" in paths.check_ownership(LEGACY_PROJECT, root, run)


@pytest.mark.parametrize("wd", ["", "   "])
def test_unlabeled_containers_are_ambiguous(root, wd):
    run = FakeDocker(owned={derived_project(root): [("mine", str(root)), ("mystery", wd)]})
    with pytest.raises(UnsafePath, match="ambiguous"):
        paths.check_ownership(derived_project(root), root, run)


@pytest.mark.parametrize("sub", ["ps", "volume", "network"])
def test_docker_query_failure_fails_closed(root, sub):
    run = FakeDocker(fail=[sub])
    with pytest.raises(UnsafePath, match="could not inspect Docker"):
        paths.check_ownership("r16-test", root, run)


def test_orphaned_volumes_of_own_derived_project_are_ours(root):
    run = FakeDocker(orphans={derived_project(root): [f"{derived_project(root)}_acme-server-data"]})
    assert "orphaned" in paths.check_ownership(derived_project(root), root, run)


@pytest.mark.parametrize("project", [LEGACY_PROJECT, "r16-test"])
def test_orphaned_volumes_of_shared_or_custom_names_are_refused(root, project):
    run = FakeDocker(orphans={project: [f"{project}_acme-server-data"]})
    with pytest.raises(UnsafePath, match="ownership cannot be established"):
        paths.check_ownership(project, root, run)


def test_cleanup_refuses_foreign_project_and_changes_nothing(root, tmp_path):
    (root / ".state").mkdir()
    other = str(checkout(tmp_path, "other"))
    run = FakeDocker(owned={"r16-test": [("theirs", other)]})
    assert cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW,
                         project_override="r16-test", opt_in="r16-test") == 2
    assert run.destructive() == [] and (root / ".state").exists()


def test_cleanup_refuses_orphaned_custom_volumes(root):
    (root / ".state").mkdir()
    run = FakeDocker(orphans={"r16-test": ["r16-test_acme-server-data"]})
    assert cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW,
                         project_override="r16-test", opt_in="r16-test") == 2
    assert run.destructive() == [] and (root / ".state").exists()


def test_cleanup_custom_name_without_opt_in_is_refused(root):
    (root / ".state").mkdir()
    run = FakeDocker()
    assert cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW, project_override="r16-test") == 2
    assert run.calls == []


def test_cleanup_of_own_project_with_own_containers_and_orphans_proceeds(root):
    (root / ".state").mkdir()
    run = FakeDocker(owned={derived_project(root): own(root, 2)})
    assert cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW) == 0
    assert run.destructive()[0][:4] == ["docker", "compose", "-p", derived_project(root)]


def test_cleanup_of_own_legacy_needs_confirmation_and_ownership(root, tmp_path):
    (root / ".state").mkdir()
    other = str(checkout(tmp_path, "old-checkout"))
    run = FakeDocker(owned={LEGACY_PROJECT: [("x", other)]})      # legacy stack belongs to ANOTHER checkout
    assert cleanup.clean(str(root / ".dnsid-local"), "", run=run, root=root, now=NOW,
                         project_override=LEGACY_PROJECT, confirm_legacy=LEGACY_PROJECT) == 2
    assert run.destructive() == []
