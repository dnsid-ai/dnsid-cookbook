"""The real SpireAdmin adapter (dnsidfed.spire) against a stand-in `spire-server` executable that records its
argv and answers like SPIRE. Pins the exact CLI calls the orderly shutdown makes: dissociating a managed entry
(entry show + entry update) and the restrict-mode bundle delete. No Docker, no network."""
import json
import stat
import subprocess
import sys
import textwrap

import pytest

from dnsidfed.spire import SpireAdmin, SpireError

SOCK = "/run/spire/server/api.sock"
PURCHASING = "spiffe://acme.test/purchasing"


def entry(feds):
    return {"id": "entry-1", "spiffe_id": {"trust_domain": "acme.test", "path": "/purchasing"},
            "parent_id": {"trust_domain": "acme.test", "path": "/node/agent"},
            "selectors": [{"type": "unix", "value": "uid:10001"}], "federates_with": list(feds)}


@pytest.fixture
def fake_spire(tmp_path):
    """Returns (binary_path, calls_reader, configure). configure(responses) maps "verb noun" -> (rc, stdout, stderr,
    sleep_s)."""
    log, responses = tmp_path / "argv.jsonl", tmp_path / "responses.json"
    binary = tmp_path / "spire-server"
    binary.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import json, sys, time
        argv = sys.argv[1:]
        with open({str(log)!r}, "a") as f:
            f.write(json.dumps(argv) + "\\n")
        r = json.load(open({str(responses)!r})).get(" ".join(argv[:2]), [0, "", "", 0])
        time.sleep(r[3])
        sys.stdout.write(r[1]); sys.stderr.write(r[2])
        sys.exit(r[0])
        """))
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)

    def calls():
        return [json.loads(ln) for ln in log.read_text().splitlines()] if log.exists() else []

    def configure(mapping):
        responses.write_text(json.dumps(mapping))
    configure({})
    return str(binary), calls, configure


def test_remove_federates_drops_only_the_managed_domain(fake_spire):
    binary, calls, configure = fake_spire
    configure({"entry show": [0, json.dumps({"entries": [entry(["rackloria.test", "partner.test"])]}), "", 0]})
    assert SpireAdmin(SOCK, binary).remove_federates(PURCHASING, "rackloria.test") is True
    show, update = calls()
    assert show == ["entry", "show", "-spiffeID", PURCHASING, "-output", "json", "-socketPath", SOCK]
    assert update == ["entry", "update", "-entryID", "entry-1", "-parentID", "spiffe://acme.test/node/agent",
                      "-spiffeID", PURCHASING, "-selector", "unix:uid:10001",
                      "-federatesWith", "spiffe://partner.test", "-socketPath", SOCK]


def test_remove_last_federation_sends_no_federates_with(fake_spire):
    binary, calls, configure = fake_spire
    configure({"entry show": [0, json.dumps({"entries": [entry(["rackloria.test"])]}), "", 0]})
    assert SpireAdmin(SOCK, binary).remove_federates(PURCHASING, "rackloria.test") is True
    update = calls()[1]
    assert update[:2] == ["entry", "update"] and "-federatesWith" not in update


def test_remove_federates_is_a_no_op_when_not_federated(fake_spire):
    binary, calls, configure = fake_spire
    configure({"entry show": [0, json.dumps({"entries": [entry(["partner.test"])]}), "", 0]})
    assert SpireAdmin(SOCK, binary).remove_federates(PURCHASING, "rackloria.test") is False
    assert [c[:2] for c in calls()] == [["entry", "show"]]                 # no update issued


def test_remove_federates_refuses_an_ambiguous_entry(fake_spire):
    binary, calls, configure = fake_spire
    two = {"entries": [entry(["rackloria.test"]), dict(entry(["rackloria.test"]), id="entry-2")]}
    configure({"entry show": [0, json.dumps(two), "", 0]})
    with pytest.raises(SpireError, match="exactly one entry"):
        SpireAdmin(SOCK, binary).remove_federates(PURCHASING, "rackloria.test")
    assert [c[:2] for c in calls()] == [["entry", "show"]]


def test_restrict_delete_argv_and_outcomes(fake_spire):
    binary, calls, configure = fake_spire
    admin = SpireAdmin(SOCK, binary)
    assert admin.delete_bundle("rackloria.test", mode="restrict") is True
    assert calls()[-1] == ["bundle", "delete", "-id", "spiffe://rackloria.test", "-mode", "restrict",
                           "-socketPath", SOCK]
    configure({"bundle delete": [1, "", "rpc error: code = NotFound desc = no such bundle", 0]})
    assert admin.delete_bundle("rackloria.test", mode="restrict") is False
    configure({"bundle delete": [1, "", "rpc error: code = FailedPrecondition desc = bundle in use", 0]})
    with pytest.raises(SpireError, match="bundle in use"):
        admin.delete_bundle("rackloria.test", mode="restrict")


def test_unknown_delete_mode_is_rejected_before_any_call(fake_spire):
    binary, calls, _ = fake_spire
    with pytest.raises(ValueError):
        SpireAdmin(SOCK, binary).delete_bundle("rackloria.test", mode="delete")
    assert calls() == []


def test_a_hung_cli_surfaces_as_timeout_expired(fake_spire):
    # The adapter does not convert timeouts into SpireError; Controller.shutdown handles both (see
    # test_shutdown.py: a restrict-delete timeout is audited as CONTROLLER_SHUTDOWN_INCOMPLETE).
    binary, _, configure = fake_spire
    configure({"bundle delete": [0, "", "", 5]})
    with pytest.raises(subprocess.TimeoutExpired):
        SpireAdmin(SOCK, binary, timeout=0.5).delete_bundle("rackloria.test", mode="restrict")

