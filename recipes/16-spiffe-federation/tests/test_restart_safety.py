"""Restart safety: resolver isolation, signer preservation, and failure classification (scripts/identity.py).

Offline: Docker, dig, curl, the registry and the dnsid CLI are all stubbed through identity.py's `_run`,
`_urlopen`, `_sleep` and `base_env` indirections.
"""
import io
import json
import re
import subprocess
import urllib.error
from pathlib import Path

import pytest

import identity as I

SIGNER = "spire-fed-20261119235048-df43.rackloria.test"
OTHER_SIGNER = "spire-fed-20261101000000-beef.rackloria.test"
OURS = 7963
CLI_DEFAULT = 7753
CONFIG = f'zone: test\ndefaults:\n    registryUrl: http://127.0.0.1:7965\n    dnsPort: "{OURS}"\nagents: {{}}\n'
OWNED_PORTS = f"127.0.0.1:{OURS}->53/tcp, 127.0.0.1:{OURS}->53/udp\n"
RECORD = ('"v=dnsid-draft-01;ek=https://dnsid.rackloria.test/.well-known/dnsid-ek.json;gi=rackloria.test;'
          'ku=https://x.rackloria.test/.well-known/jwks.json"\n')
LEAK_MARKER = "leak-marker-must-not-print"  # stands in for the registry credential


def cp(rc=0, out=""):
    return subprocess.CompletedProcess([], rc, out, "")


@pytest.fixture
def world(monkeypatch, tmp_path):
    """A recipe layout under tmp_path, with every external effect stubbed. Mutate `w` to change the world."""
    recipe = tmp_path / "recipe"
    local, state = recipe / ".dnsid-local", recipe / ".state"
    (state / "dnsid").mkdir(parents=True)
    local.mkdir(parents=True)
    (local / "config.yml").write_text(CONFIG)
    monkeypatch.setattr(I, "LOCAL", local, raising=False)
    monkeypatch.setattr(I, "RECIPE_STATE", state, raising=False)
    monkeypatch.setattr(I, "DNSID_DIR", state / "dnsid", raising=False)
    monkeypatch.setattr(I, "CURRENT", state / "dnsid" / "current-signer", raising=False)
    monkeypatch.setattr(I, "REGISTRY", "http://127.0.0.1:7965", raising=False)
    monkeypatch.setattr(I, "DNS_PORT", OURS, raising=False)
    monkeypatch.setattr(I, "_RESOLVER", None)
    monkeypatch.setattr(I, "_sleep", lambda s: None)

    w = {
        "docker": cp(0, OWNED_PORTS),            # what `docker ps` (filtered to OUR instance) reports
        "soa": {OURS: cp(0, "ns.test. hostmaster.test. 1 60 60 60 60\n")},  # port -> dig SOA result
        "txt": {OURS: cp(0, RECORD)},            # port -> dig TXT result (or an exception to raise)
        "cli_env": {"DNSID_DNS_SERVER": f"127.0.0.1:{CLI_DEFAULT}", "DNSID_API_KEY": LEAK_MARKER,
                    "DNSID_CA_BUNDLE": "/x/root-ca.pem"},
        "calls": [],
        "status": [],                            # queued responses for _urlopen; last one repeats
        "created": [],
    }

    def fake_run(argv, **kw):
        w["calls"].append(list(argv))
        if argv[0] == "docker":
            if isinstance(w["docker"], BaseException):
                raise w["docker"]
            return w["docker"]
        if argv[0] == "dig":
            port = int(argv[argv.index("-p") + 1])
            table = w["soa"] if "SOA" in argv else w["txt"]
            res = table.get(port, cp(9, ""))    # nothing listening: dig exits 9 (no reply)
            if isinstance(res, BaseException):
                raise res
            return res
        if argv[0] == "curl":
            res = w.get("curl", cp(0, b""))
            if isinstance(res, BaseException):
                raise res
            return res
        raise AssertionError(f"unexpected command {argv}")

    def fake_urlopen(url, timeout=None):
        w["calls"].append(["urlopen", url])
        item = w["status"].pop(0) if len(w["status"]) > 1 else w["status"][0]
        if isinstance(item, BaseException):
            raise item
        return io.BytesIO(item if isinstance(item, bytes) else json.dumps(item).encode())

    def fake_create():
        w["created"].append(True)
        return OTHER_SIGNER

    monkeypatch.setattr(I, "_run", fake_run)
    monkeypatch.setattr(I, "_urlopen", fake_urlopen)
    monkeypatch.setattr(I, "base_env", lambda: dict(w["cli_env"]))
    monkeypatch.setattr(I, "create", fake_create)
    w["recipe"], w["local"], w["state"] = recipe, local, state
    return w


def exit_code(fn, *a, **kw):
    with pytest.raises(SystemExit) as ei:
        fn(*a, **kw)
    return ei.value.code


def http_error(code):
    return urllib.error.HTTPError("http://127.0.0.1:7965/v1/status/x", code, "err", {}, io.BytesIO(b"{}"))


def dig_ports(w):
    return [int(c[c.index("-p") + 1]) for c in w["calls"] if c[0] == "dig"]


# ------------------------------------------------------------------ resolver isolation
def test_configured_port_is_authoritative():
    assert I.configured_dns_port(CONFIG, OURS) == OURS


@pytest.mark.parametrize("text", [
    "zone: test\n",                                                   # no dnsPort
    CONFIG + '    dnsPort: "7753"\n',                                 # ambiguous: two values
])
def test_config_without_exactly_one_dns_port_fails_closed(text):
    assert exit_code(I.configured_dns_port, text, OURS) == I.EXIT_RESOLVER


def test_config_disagreeing_with_recipe_port_fails_closed():
    assert exit_code(I.configured_dns_port, CONFIG, CLI_DEFAULT) == I.EXIT_RESOLVER


@pytest.mark.parametrize("ports,expected", [
    (OWNED_PORTS, [OURS]),
    (f"127.0.0.1:{OURS}->53/udp", [OURS]),
    (f"127.0.0.1:{OURS}->53/tcp", []),                 # TCP only is not the resolver dig uses
    (f"0.0.0.0:{OURS}->53/udp", []),                   # not loopback-only
    (f"127.0.0.1:{OURS}->5353/udp", []),               # not DNS
    ("", []),                                          # no running container of ours
    (OWNED_PORTS + OWNED_PORTS, []),                   # two containers: ambiguous ownership
])
def test_owned_dns_ports_parsing(ports, expected):
    assert I.owned_dns_ports(ports) == expected


def test_cli_mismatch_is_reported_and_own_resolver_used(world, capsys):
    assert I.local_resolver() == f"127.0.0.1:{OURS}"
    err = capsys.readouterr().err
    assert f"DNSID_DNS_SERVER=127.0.0.1:{CLI_DEFAULT}" in err and f"127.0.0.1:{OURS}" in err
    assert LEAK_MARKER not in err                           # never echoes other environment values
    assert CLI_DEFAULT not in dig_ports(world)         # the CLI's resolver is never queried


def test_matching_cli_value_prints_no_note(world, capsys):
    world["cli_env"]["DNSID_DNS_SERVER"] = f"127.0.0.1:{OURS}"
    I.local_resolver()
    assert "NOTE" not in capsys.readouterr().err


def test_ownership_is_checked_against_this_instance_label(world):
    I.local_resolver()
    docker = next(c for c in world["calls"] if c[0] == "docker")
    assert f"label=com.docker.compose.project.working_dir={world['local']}" in docker
    assert "label=com.docker.compose.service=dns-host" in docker


@pytest.mark.parametrize("docker", [
    cp(0, ""),                                                       # our instance is not running
    cp(0, f"127.0.0.1:{CLI_DEFAULT}->53/udp\n"),                     # ours publishes some other port
    cp(1, ""),                                                       # docker error
    FileNotFoundError("docker"),                                     # no docker CLI
    subprocess.TimeoutExpired("docker", 20),
])
def test_wrong_or_unverifiable_instance_fails_closed(world, docker):
    world["docker"] = docker
    # Even a perfectly healthy resolver on the CLI's port (another instance) must not be used.
    world["soa"][CLI_DEFAULT] = cp(0, "ns.test. x 1 60 60 60 60\n")
    world["txt"][CLI_DEFAULT] = cp(0, RECORD)
    assert exit_code(I.local_resolver) == I.EXIT_RESOLVER
    assert dig_ports(world) == []


@pytest.mark.parametrize("soa", [cp(9, ""), cp(0, ""), subprocess.TimeoutExpired("dig", 10)])
def test_unhealthy_own_resolver_fails_closed(world, soa):
    world["soa"][OURS] = soa
    assert exit_code(I.local_resolver) == I.EXIT_RESOLVER


def test_missing_config_fails_closed(world):
    (world["local"] / "config.yml").unlink()
    assert exit_code(I.local_resolver) == I.EXIT_RESOLVER


def test_published_record_reads_only_from_own_resolver(world):
    rec = I.published_record(SIGNER)
    assert rec["gi"] == "rackloria.test"
    assert set(dig_ports(world)) == {OURS}


@pytest.mark.parametrize("txt", [cp(9, ""), subprocess.TimeoutExpired("dig", 10)])
def test_resolver_going_away_mid_lookup_is_a_resolver_error(world, txt):
    I.local_resolver()                       # healthy at first
    world["txt"][OURS] = txt
    assert exit_code(I.published_record, SIGNER) == I.EXIT_RESOLVER


def test_absent_record_is_a_record_error(world):
    world["txt"][OURS] = cp(0, "")
    assert exit_code(I.published_record, SIGNER) == I.EXIT_RECORD


def test_malformed_record_is_a_record_error(world):
    world["txt"][OURS] = cp(0, '"gi=rackloria.test;ek=https://a/x;gi=rackloria.test"')
    assert exit_code(I.published_record, SIGNER) == I.EXIT_RECORD


# ------------------------------------------------------------------ registry status
@pytest.mark.parametrize("resp,expected", [
    ({"state": "ACTIVE"}, (I.DEFINITE, "ACTIVE")),
    ({"state": "REVOKED"}, (I.DEFINITE, "REVOKED")),
    ({"state": "RETIRED"}, (I.DEFINITE, "RETIRED")),
    (http_error(404), (I.MISSING, "NOT_FOUND")),
    (http_error(500), (I.UNCERTAIN, "HTTP 500")),
    (http_error(503), (I.UNCERTAIN, "HTTP 503")),
    (urllib.error.URLError("refused"), (I.UNCERTAIN, "URLError")),
    (TimeoutError(), (I.UNCERTAIN, "TimeoutError")),
    (ConnectionResetError(), (I.UNCERTAIN, "ConnectionResetError")),
    (b"not json", (I.UNCERTAIN, "unparseable status response")),
    ({}, (I.UNCERTAIN, "status response has no recognizable state")),
    ({"state": None}, (I.UNCERTAIN, "status response has no recognizable state")),
    ({"state": "active"}, (I.UNCERTAIN, "status response has no recognizable state")),
    ({"state": "ACTIVE; or not"}, (I.UNCERTAIN, "status response has no recognizable state")),
    ([], (I.UNCERTAIN, "status response has no recognizable state")),
])
def test_signer_status_classification(world, resp, expected):
    world["status"] = [resp]
    assert I.signer_status(SIGNER) == expected


def test_uncertainty_is_retried_until_definite(world):
    world["status"] = [TimeoutError(), http_error(503), {"state": "ACTIVE"}]
    assert I.verified_status(SIGNER) == (I.DEFINITE, "ACTIVE")


def test_definite_answer_is_not_retried(world):
    world["status"] = [{"state": "REVOKED"}, {"state": "ACTIVE"}]
    assert I.verified_status(SIGNER) == (I.DEFINITE, "REVOKED")


def test_registry_state_display(world):
    world["status"] = [TimeoutError()]
    assert I.registry_state(SIGNER) == "UNKNOWN (TimeoutError)"


# ------------------------------------------------------------------ signer preservation
def with_signer(w, name=SIGNER):
    I.CURRENT.write_text(name + "\n")


def test_active_signer_is_reused(world, capsys):
    with_signer(world)
    world["status"] = [{"state": "ACTIVE"}]
    I.cmd_ensure_active(first_enrollment=True)
    assert capsys.readouterr().out.strip() == SIGNER
    assert world["created"] == []


def test_active_after_slow_start_is_reused(world, capsys):
    with_signer(world)
    world["status"] = [urllib.error.URLError("starting"), TimeoutError(), {"state": "ACTIVE"}]
    I.cmd_ensure_active(first_enrollment=True)
    assert capsys.readouterr().out.strip() == SIGNER and world["created"] == []


@pytest.mark.parametrize("first", [False, True])
@pytest.mark.parametrize("resp", [TimeoutError(), urllib.error.URLError("refused"), http_error(500),
                                  b"garbage", {"state": None}])
def test_uncertain_status_never_creates_a_replacement(world, resp, first):
    with_signer(world)
    world["status"] = [resp]
    assert exit_code(I.cmd_ensure_active, first_enrollment=first) == I.EXIT_REGISTRY_UNCERTAIN
    assert world["created"] == []
    assert I.CURRENT.read_text().strip() == SIGNER          # the record of the signer is untouched


@pytest.mark.parametrize("first", [False, True])
@pytest.mark.parametrize("resp", [{"state": "REVOKED"}, {"state": "RETIRED"}, {"state": "PENDING"},
                                  http_error(404)])
def test_unusable_signer_stops_without_replacement(world, resp, first, capsys):
    with_signer(world)
    world["status"] = [resp]
    assert exit_code(I.cmd_ensure_active, first_enrollment=first) == I.EXIT_SIGNER_UNUSABLE
    assert world["created"] == []
    assert I.CURRENT.read_text().strip() == SIGNER
    assert "never reissued or replaced automatically" in capsys.readouterr().err


@pytest.mark.parametrize("evidence", [
    "dnsid/pins.json",
    "dnsid/signer",
    "controller/data/trusted-checkpoints.json",
    "controller/data/trusted-checkpoints.journal",
])
def test_prior_enrollment_evidence_blocks_first_issue(world, evidence):
    p = world["state"] / evidence
    p.parent.mkdir(parents=True, exist_ok=True)
    p.mkdir() if evidence.endswith("signer") else p.write_text("x")
    assert exit_code(I.cmd_ensure_active, first_enrollment=True) == I.EXIT_SIGNER_UNUSABLE
    assert world["created"] == []


def test_signer_in_local_registry_blocks_first_issue(world):
    (world["local"] / "state.json").write_text(json.dumps({"agents": {SIGNER: {}}}))
    assert exit_code(I.cmd_ensure_active, first_enrollment=True) == I.EXIT_SIGNER_UNUSABLE
    assert world["created"] == []


def test_unreadable_local_registry_state_blocks_first_issue(world):
    (world["local"] / "state.json").write_text("{not json")
    assert exit_code(I.cmd_ensure_active, first_enrollment=True) == I.EXIT_SIGNER_UNUSABLE
    assert world["created"] == []


def test_unrelated_agents_are_not_evidence(world):
    (world["local"] / "state.json").write_text(json.dumps({"agents": {"alice.test": {}}}))
    assert I.enrollment_evidence() == []


def test_first_issue_requires_explicit_authorization(world):
    assert exit_code(I.cmd_ensure_active) == I.EXIT_SIGNER_UNUSABLE
    assert world["created"] == []


def test_authorized_first_enrollment_issues_exactly_one(world, capsys):
    I.cmd_ensure_active(first_enrollment=True)
    assert world["created"] == [True]
    assert capsys.readouterr().out.strip() == OTHER_SIGNER


# ------------------------------------------------------------------ classification of the entity-key path
EK_OK = "https://dnsid.rackloria.test/.well-known/dnsid-ek.json"


@pytest.fixture
def ek_world(world, monkeypatch):
    monkeypatch.setattr(I, "agent_env", lambda name: {})
    with_signer(world)
    return world


def test_governance_mismatch_is_classified(ek_world):
    ek_world["txt"][OURS] = cp(0, f'"v=dnsid-draft-01;gi=other.test;ek={EK_OK}"')
    assert exit_code(I.entity_key_url, SIGNER) == I.EXIT_GOVERNANCE


def test_malformed_entity_key_url_is_a_record_error(ek_world):
    ek_world["txt"][OURS] = cp(0, '"v=dnsid-draft-01;gi=rackloria.test;ek=http://dnsid.rackloria.test/x"')
    assert exit_code(I.entity_key_url, SIGNER) == I.EXIT_RECORD


@pytest.mark.parametrize("doc", [b"not json", b"[]", b'{"keys": "x"}', b'{"keys": [{"kty": "nope"}]}',
                                 b'{"keys": []}'])
def test_malformed_entity_key_document_is_a_record_error(doc):
    assert exit_code(I.entity_thumbprints, doc) == I.EXIT_RECORD


@pytest.mark.parametrize("curl", [cp(7, b""), cp(60, b""), subprocess.TimeoutExpired("curl", 20)])
def test_unreachable_entity_key_document_is_uncertain(world, curl):
    world["curl"] = curl
    assert exit_code(I.fetch_local_https, EK_OK, "/x/root-ca.pem") == I.EXIT_REGISTRY_UNCERTAIN


def test_missing_pin_file_is_not_reported_as_key_mismatch(world):
    assert exit_code(I.cmd_pin_check, str(world["state"] / "dnsid" / "pins.json")) == I.EXIT_USAGE


# ------------------------------------------------------------------ bootstrap.sh names every category
LIB = Path(I.__file__).resolve().parent / "lib.sh"
EXIT_CODES = {n: v for n, v in vars(I).items() if n.startswith("EXIT_")}


def reason(code: int) -> str:
    src = LIB.read_text()
    fn = re.search(r"^identity_reason\(\) \{.*?^\}", src, re.S | re.M).group(0)
    return subprocess.run(["bash", "-c", f"{fn}\nidentity_reason {code}"], capture_output=True, text=True,
                          check=True).stdout.strip()


def test_exit_codes_are_distinct():
    assert len(set(EXIT_CODES.values())) == len(EXIT_CODES)


@pytest.mark.parametrize("name,label", [
    ("EXIT_RESOLVER", "RESOLVER"),
    ("EXIT_REGISTRY_UNCERTAIN", "REGISTRY UNCERTAIN"),
    ("EXIT_SIGNER_UNUSABLE", "SIGNER UNUSABLE"),
    ("EXIT_RECORD", "MALFORMED RECORD"),
    ("EXIT_GOVERNANCE", "GOVERNANCE MISMATCH"),
    ("EXIT_ENTITY_KEY", "ENTITY-KEY MISMATCH"),
    ("EXIT_USAGE", "CONFIGURATION"),
    ("EXIT_REFUSED", "REFUSED"),
])
def test_bootstrap_names_each_category(name, label):
    assert reason(EXIT_CODES[name]).startswith(label + ":")


def test_unknown_code_is_not_misreported():
    assert reason(1).startswith("unexpected failure")


def test_bootstrap_passes_first_enrollment_and_verify_does_not():
    root = LIB.parent.parent
    boot = (root / "scripts" / "bootstrap.sh").read_text()
    ver = (root / "verify" / "verify.sh").read_text()
    assert "ensure-active --first-enrollment" in boot
    assert "ensure-active" in ver and "--first-enrollment" not in ver
    assert "CHECKPOINT STORE:" in boot
