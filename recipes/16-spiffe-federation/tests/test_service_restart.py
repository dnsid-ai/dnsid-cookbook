"""Resuming after DNSid Local recreated its Docker network (scripts/dnsid_service.py and start_controller in
scripts/lib.sh). Offline: the shell path runs in bash against stubbed `docker` and `dc`."""
import json
import re
import subprocess
from pathlib import Path

import pytest

import dnsid_service as DS

ROOT = Path(__file__).resolve().parents[1]
LIB = (ROOT / "scripts" / "lib.sh").read_text()
WD = str(ROOT)   # the label and mount paths must name the real recipe directory (scripts run from it)
PROJ = "dnsid-recipe16"
NET = "dnsid-dnsid-local-bb802a_local"
LPROJ = "dnsid-dnsid-local-bb802a"
NEW_ID = "df363db3c997" + "1" * 52
OLD_ID = "d693b8b24cc3" + "2" * 52
CA = WD + "/.dnsid-local/certs/root-ca.pem"
SERVICES = ["acme-dnsid-controller", "rackloria-publisher"]


def network(**over):
    n = {"Name": NET, "Id": NEW_ID, "Driver": "bridge",
         "Labels": {"com.docker.compose.project": LPROJ, "com.docker.compose.network": "local"}}
    n.update(over)
    return [n]


def mounts(**drop_or_change):
    m = [
        {"Type": "bind", "Source": WD + "/.state/controller/data", "Destination": "/var/lib/dnsidfed", "RW": True},
        {"Type": "bind", "Source": "/host_mnt" + WD + "/.state/controller/policy.toml",
         "Destination": "/etc/dnsidfed/policy.toml", "RW": False},
        {"Type": "bind", "Source": "/host_mnt" + WD + "/.state/dnsid/log-policy.txt",
         "Destination": "/etc/dnsidfed/log-policy.txt", "RW": False},
        {"Type": "bind", "Source": WD + "/.state/controller/admin-token", "Destination": "/etc/dnsidfed/admin-token",
         "RW": False},
        {"Type": "bind", "Source": CA, "Destination": "/dnsid/root-ca.pem", "RW": False},
        {"Type": "volume", "Name": PROJ + "_acme-server-admin", "Source": "/var/lib/docker/volumes/x/_data",
         "Destination": "/run/spire/server", "RW": True},
    ]
    return m


def container(service="acme-dnsid-controller", status="exited", health="unhealthy", attached=NEW_ID, **lab_over):
    labels = {"com.docker.compose.project": PROJ, "com.docker.compose.service": service,
              "com.docker.compose.project.working_dir": WD, "com.docker.compose.oneoff": "False"}
    labels.update(lab_over)
    return {"Name": f"/{PROJ}-{service}-1",
            "State": {"Status": status, "Health": {"Status": health}},
            "Config": {"Labels": labels, "User": "1000:1000",
                       "Env": ["PATH=/usr/local/bin:/usr/bin", "LANG=C.UTF-8", "PYTHONUNBUFFERED=1"]},
            "NetworkSettings": {"Networks": {NET: {"NetworkID": attached},
                                             f"{PROJ}_default": {"NetworkID": "9" * 64}}},
            "Mounts": mounts()}


def plan(net, ctrs, service="acme-dnsid-controller"):
    return DS.plan(net, ctrs, service=service, project=PROJ, working_dir=WD, network=NET, local_project=LPROJ)


def uncertain(fn, *a, **kw):
    with pytest.raises(DS.Uncertain) as ei:
        fn(*a, **kw)
    return str(ei.value)


# ------------------------------------------------------------------ plan (both DNSid-layer services)
@pytest.mark.parametrize("svc", SERVICES)
def test_no_existing_container_starts_normally(svc):
    assert plan(network(), [], svc)[0] == DS.START


@pytest.mark.parametrize("svc", SERVICES)
@pytest.mark.parametrize("status", ["exited", "created"])
def test_stopped_on_current_network_starts_normally(svc, status):
    assert plan(network(), [container(svc, status=status)], svc)[0] == DS.START


@pytest.mark.parametrize("svc", SERVICES)
@pytest.mark.parametrize("status", ["exited", "created"])
def test_stopped_with_stale_network_is_recreated(svc, status):
    action, why = plan(network(), [container(svc, status=status, attached=OLD_ID)], svc)
    assert action == DS.RECREATE and OLD_ID[:12] in why and NEW_ID[:12] in why


@pytest.mark.parametrize("svc", SERVICES)
def test_running_healthy_is_kept(svc):
    assert plan(network(), [container(svc, status="running", health="healthy")], svc)[0] == DS.KEEP


@pytest.mark.parametrize("svc", SERVICES)
@pytest.mark.parametrize("ctr", [
    dict(status="running", health="unhealthy"),
    dict(status="running", health="starting"),
    dict(status="running", health="healthy", attached=OLD_ID),
    dict(status="paused"), dict(status="restarting"), dict(status="dead"), dict(status="removing"),
])
def test_running_but_not_healthy_or_odd_state_is_never_touched(svc, ctr):
    uncertain(plan, network(), [container(svc, **ctr)], svc)


@pytest.mark.parametrize("net", [
    network(Labels={"com.docker.compose.project": "dnsid-state-130253", "com.docker.compose.network": "local"}),
    network(Labels={"com.docker.compose.project": LPROJ, "com.docker.compose.network": "other"}),
    network(Labels={}),
    network(Labels=None) + [],
    network(Name="dnsid-state-130253_local"),
    network(Id=""), network(Id="not-hex"),
    network() + network(),                          # two networks by that name
    [], "garbage", None,
])
def test_unknown_or_incorrect_network_ownership_fails_closed(net):
    uncertain(plan, net, [container(attached=OLD_ID)])


@pytest.mark.parametrize("over", [
    {"com.docker.compose.project": "dnsid-spire-demo"},
    {"com.docker.compose.service": "acme-server"},
    {"com.docker.compose.project.working_dir": "/elsewhere"},
    {"com.docker.compose.oneoff": "True"},
])
def test_container_not_owned_by_this_recipe_fails_closed(over):
    uncertain(plan, network(), [container(attached=OLD_ID, **over)])


def test_two_containers_fail_closed():
    uncertain(plan, network(), [container(attached=OLD_ID), container(attached=OLD_ID)])


def test_container_not_on_the_local_network_fails_closed():
    c = container(attached=OLD_ID)
    del c["NetworkSettings"]["Networks"][NET]
    uncertain(plan, network(), [c])


@pytest.mark.parametrize("ctrs", ["garbage", None, ["x"]])
def test_unreadable_container_inspection_fails_closed(ctrs):
    uncertain(plan, network(), ctrs)


# ------------------------------------------------------------------ verify-controller (state preservation)
def verify(c, net=None):
    return DS.verify_controller(c, net or network(), project=PROJ, working_dir=WD, network=NET,
                                local_project=LPROJ, root_ca=CA)


def healthy():
    return container(status="running", health="healthy")


def test_verified_controller_summary_has_names_only():
    c = healthy()
    c["Config"]["Env"].append("SOME_SETTING=value-that-must-not-print")
    s = verify([c])
    assert "SOME_SETTING" in s                     # names are reported ...
    assert "value-that-must-not-print" not in s    # ... values never are


def mutate(fn):
    c = healthy()
    fn(c)
    return c


@pytest.mark.parametrize("bad", [
    mutate(lambda c: c["Mounts"].pop(0)),                                            # checkpoint dir not mounted
    mutate(lambda c: c["Mounts"][0].update(Type="volume", Name="anon")),              # state in a volume: lost on recreate
    mutate(lambda c: c["Mounts"][0].update(Source="/tmp/other")),                     # state elsewhere
    mutate(lambda c: c["Mounts"][1].update(RW=True)),                                  # policy writable
    mutate(lambda c: c["Mounts"].append({"Type": "bind", "Source": "/", "Destination": "/host", "RW": True})),
    mutate(lambda c: c["Mounts"][5].update(Name="other_acme-server-admin")),
    mutate(lambda c: c["NetworkSettings"]["Networks"][NET].update(NetworkID=OLD_ID)),
    mutate(lambda c: c["NetworkSettings"]["Networks"].update({"host": {"NetworkID": "3" * 64}})),
    mutate(lambda c: c["Config"].update(User="0:0")),
    mutate(lambda c: c["Config"]["Env"].append("DNSID_API_KEY=FAKE-CREDENTIAL-MUST-NOT-PRINT")),
    mutate(lambda c: c["State"].update(Status="exited")),
    mutate(lambda c: c["State"].update(Health={"Status": "unhealthy"})),
])
def test_unexpected_controller_configuration_fails(bad):
    msg = uncertain(verify, [bad])
    assert "FAKE-CREDENTIAL-MUST-NOT-PRINT" not in msg


def test_persistent_state_is_bind_mounted_from_the_recipe_state_dir():
    m = DS.controller_mounts(WD, CA, PROJ)
    assert m["/var/lib/dnsidfed"] == ("bind", WD + "/.state/controller/data", True)
    assert all(t == "bind" and src.startswith(WD + "/.state/") for d, (t, src, _) in m.items()
               if d.startswith(("/var/lib", "/etc/dnsidfed")))


def test_compose_controller_state_is_bind_mounted():
    """Recreating the controller container cannot lose checkpoints, journal, audit log or pins: compose binds
    them from .state/ (the only named volume is SPIRE's admin socket)."""
    text = (ROOT / "compose.yaml").read_text()
    block = re.search(r"^  acme-dnsid-controller:\n(.*?)(?=^\S|^  [a-z][\w-]*:\n)", text, re.S | re.M).group(1)
    vols = re.findall(r"^\s+- \"?([^\"\n#]+?)\"?\s*(?:#.*)?$", block.split("volumes:")[1].split("networks:")[0], re.M)
    assert "./.state/controller/data:/var/lib/dnsidfed" in vols
    named = [v for v in vols if not v.startswith(("./", "${"))]
    assert named == ["acme-server-admin:/run/spire/server"]


# ------------------------------------------------------------------ start_controller in bash (stubbed docker)
def shell_fn(name):
    return re.search(rf"^{name}\(\) \{{.*?^\}}", LIB, re.S | re.M).group(0)


HARNESS = "\n".join([
    "set -euo pipefail",
    'ROOT=$1; STATE=$2; FIX=$3; PROJECT=' + PROJ + '; DNSID_LOCAL_STATE=$1/.dnsid-local',
    "ok()  { printf 'OK %s\\n' \"$*\"; }",
    "say() { printf '%s\\n' \"$*\"; }",
    "die() { printf 'DIE %s\\n' \"$*\"; exit 1; }",
    "dnsid_local_network() { [ -f \"$FIX/no-local\" ] && return 1; echo \"" + NET + " 10.77.198.3\"; }",
    "dc() { printf '%s\\n' \"$*\" >> \"$FIX/dc.calls\"; return \"$(cat \"$FIX/dc.rc\" 2>/dev/null || echo 0)\"; }",
    "docker() {",
    "  printf '%s\\n' \"$*\" >> \"$FIX/docker.calls\"",
    "  case \"$1 $2\" in",
    "    'ps -q') echo dnsc ;;",
    "    'inspect -f') echo \"$(cat \"$FIX/lproj\")\" ;;",
    "    'network inspect') [ -f \"$FIX/net.rc\" ] && return \"$(cat \"$FIX/net.rc\")\"; cat \"$FIX/net.json\" ;;",
    "    'ps -aq') cat \"$FIX/ids\" ;;",
    "    inspect\\ *) n=$(( $(cat \"$FIX/n\" 2>/dev/null || echo 0) + 1 )); echo $n > \"$FIX/n\"",
    "                 [ -f \"$FIX/ctr.$n.json\" ] && cat \"$FIX/ctr.$n.json\" || cat \"$FIX/ctr.last.json\" ;;",
    "    *) echo \"unexpected docker $*\" >&2; return 99 ;;",
    "  esac",
    "}",
    shell_fn("dnsid_local_project"),
    shell_fn("service_inspection"),
    shell_fn("service_plan"),
    shell_fn("start_controller"),
    "start_controller",
])


def run_start(tmp_path, before, after=None, net=None, dc_rc=0, lproj=LPROJ, net_rc=None, no_local=False):
    fix = tmp_path / "fix"
    fix.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    (state / "compose.env").write_text(f"HOST_GID=20\nDNSID_ROOT_CA={CA}\n")
    (fix / "lproj").write_text(lproj)
    (fix / "net.json").write_text(json.dumps(net if net is not None else network()))
    if net_rc is not None:
        (fix / "net.rc").write_text(str(net_rc))
    if no_local:
        (fix / "no-local").write_text("")
    (fix / "ids").write_text("abc123\n" if before else "")
    (fix / "ctr.1.json").write_text(json.dumps([before] if before else []))
    (fix / "ctr.last.json").write_text(json.dumps([after] if after else []))
    (fix / "dc.rc").write_text(str(dc_rc))
    if not before:  # first listing empty, the post-start listing finds the new container
        (fix / "ids").write_text("")
        harness = HARNESS.replace("'ps -aq') cat \"$FIX/ids\" ;;",
                                  "'ps -aq') [ -f \"$FIX/n\" ] && echo abc123 || cat \"$FIX/ids\"; echo 0 > \"$FIX/n\" ;;")
        (fix / "ctr.1.json").write_text(json.dumps([after] if after else []))
    else:
        harness = HARNESS
    p = subprocess.run(["/bin/bash", "-c", harness, "h", WD, str(state), str(fix)], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})
    calls = (fix / "dc.calls").read_text().splitlines() if (fix / "dc.calls").exists() else []
    return p, calls


NEVER = re.compile(r"\b(rm|down|kill|volume|prune)\b|-v\b|--volumes")


def check_no_destructive(calls):
    assert not any(NEVER.search(c) for c in calls), calls


def test_bash_no_existing_controller(tmp_path):
    p, calls = run_start(tmp_path, None, after=healthy())
    assert p.returncode == 0, p.stdout + p.stderr
    assert calls == ["up -d --wait acme-dnsid-controller"] and "controller container verified" in p.stdout


def test_bash_existing_controller_with_matching_network(tmp_path):
    p, calls = run_start(tmp_path, container(), after=healthy())
    assert p.returncode == 0, p.stdout + p.stderr
    assert calls == ["up -d --wait acme-dnsid-controller"]


def test_bash_stopped_controller_with_stale_network_is_recreated_alone(tmp_path):
    p, calls = run_start(tmp_path, container(attached=OLD_ID), after=healthy())
    assert p.returncode == 0, p.stdout + p.stderr
    assert calls == ["up -d --wait --force-recreate --no-deps acme-dnsid-controller"]
    assert "NOTE recreating the stopped controller" in p.stdout and "State is bind-mounted" in p.stdout
    check_no_destructive(calls)


def test_bash_running_healthy_controller_is_not_restarted(tmp_path):
    p, calls = run_start(tmp_path, healthy(), after=healthy())
    assert p.returncode == 0 and calls == [] and "not restarted" in p.stdout


@pytest.mark.parametrize("kw", [
    dict(lproj="dnsid-state-130253"),                     # network not owned by this recipe's DNSid Local
    dict(net=network(Labels={"com.docker.compose.project": "dnsid-state-130253",
                             "com.docker.compose.network": "local"})),
    dict(net_rc=1),                                        # failed network inspection
    dict(no_local=True),                                   # this recipe's DNSid Local not identifiable
    dict(net="garbage"),
])
def test_bash_uncertain_network_changes_nothing(tmp_path, kw):
    p, calls = run_start(tmp_path, container(attached=OLD_ID), after=healthy(), **kw)
    assert p.returncode != 0 and "DIE CONTROLLER CONTAINER" in p.stdout and "nothing was changed" in p.stdout
    assert calls == []


@pytest.mark.parametrize("before", [
    container(attached=OLD_ID, **{"com.docker.compose.project": "dnsid-spire-demo"}),
    container(status="running", health="unhealthy"),
    container(status="running", health="healthy", attached=OLD_ID),
])
def test_bash_foreign_or_unhealthy_running_controller_changes_nothing(tmp_path, before):
    p, calls = run_start(tmp_path, before, after=healthy())
    assert p.returncode != 0 and calls == []


def test_bash_failed_recreation_is_reported_and_not_retried(tmp_path):
    p, calls = run_start(tmp_path, container(attached=OLD_ID), after=None, dc_rc=1)
    assert p.returncode != 0 and "recreation failed" in p.stdout and "untouched" in p.stdout
    assert calls == ["up -d --wait --force-recreate --no-deps acme-dnsid-controller"]
    check_no_destructive(calls)


def test_bash_recreated_controller_with_wrong_mounts_fails(tmp_path):
    bad = healthy()
    bad["Mounts"].pop(0)
    p, calls = run_start(tmp_path, container(attached=OLD_ID), after=bad)
    assert p.returncode != 0 and "does not match the expected configuration" in p.stdout


# ------------------------------------------------------------------ publisher restart behavior
def test_publisher_is_removed_before_each_act_2_start():
    """verify.sh removes any existing publisher container before Act 2 creates it, so a publisher stopped by
    `make stop` can never be restarted onto a deleted DNSid Local network."""
    v = (ROOT / "verify" / "verify.sh").read_text()
    rm = v.index("dc rm -sf rackloria-publisher")
    up = v.index("dc up -d --wait rackloria-publisher")
    assert rm < up


def test_bootstrap_never_starts_the_publisher_and_uses_start_controller():
    b = (ROOT / "scripts" / "bootstrap.sh").read_text()
    code = "\n".join(ln for ln in b.splitlines() if not ln.lstrip().startswith("#"))
    assert "rackloria-publisher" not in code
    assert "start_controller" in code and "dc up -d --wait acme-dnsid-controller" not in code
