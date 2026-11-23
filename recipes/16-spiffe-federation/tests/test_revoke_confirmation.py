"""identity.py revoke: the local registry's state decides the outcome, not the dnsid CLI's exit status.
The real cmd_revoke -> ensure -> dnsid path runs; only the process call, the registry lookup and sleep are stubbed."""
import json
import subprocess

import pytest

import identity as I

SIGNER = "spire-fed-20261123000000-abcd.rackloria.test"


@pytest.fixture
def world(monkeypatch, tmp_path, capsys):
    w = {"cli": subprocess.CompletedProcess([], 0, "", ""), "states": ["ACTIVE", "REVOKED"], "argv": []}
    monkeypatch.setattr(I, "LOCAL", tmp_path / ".dnsid-local", raising=False)
    monkeypatch.setattr(I, "REGISTRY", "http://127.0.0.1:7965", raising=False)
    monkeypatch.setattr(I, "_sleep", lambda s: None)
    monkeypatch.setattr(I, "current", lambda: SIGNER)

    def state(_name):
        return w["states"].pop(0) if len(w["states"]) > 1 else w["states"][0]
    monkeypatch.setattr(I, "registry_state", state)

    def run(argv, **kw):
        w["argv"].append(argv)
        if isinstance(w["cli"], BaseException):
            raise w["cli"]
        return w["cli"]
    monkeypatch.setattr(I.subprocess, "run", run)
    return w


def revoke(capsys):
    I.cmd_revoke(True)
    return json.loads(capsys.readouterr().out)


def test_cli_success_and_registry_revoked(world, capsys):
    out = revoke(capsys)
    assert out["revoked"] == SIGNER and out["registry_state"] == "REVOKED" and "cli_exit" not in out
    (argv,) = world["argv"]
    assert argv[0] == "dnsid" and argv[-6:] == ["revoke", "--domain", SIGNER, "--reason", "owner_request", "--yes"]


def test_cli_failure_but_registry_revoked_is_success(world, capsys):
    world["cli"] = subprocess.CompletedProcess([], 1, "", "witness timeout")
    world["states"] = ["ACTIVE", "ACTIVE", "ACTIVE", "REVOKED"]      # lands a few polls later
    out = revoke(capsys)
    assert out["registry_state"] == "REVOKED" and out["cli_exit"] == 1


def test_cli_failure_and_registry_still_active_fails_clearly(world, capsys):
    world["cli"] = subprocess.CompletedProcess([], 1, "", "witness timeout")
    world["states"] = ["ACTIVE"]
    with pytest.raises(SystemExit) as ei:
        I.cmd_revoke(True)
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "not confirmed by the local registry" in err and f"within {I.REVOKE_CONFIRM_S} s" in err
    assert "CLI exit 1" in err and "witness timeout" in err


def test_cli_timeout_but_registry_revoked_is_success(world, capsys):
    world["cli"] = subprocess.TimeoutExpired(["dnsid"], 180)
    out = revoke(capsys)
    assert out["registry_state"] == "REVOKED" and out["cli_exit"] == "timeout"


def test_cli_timeout_and_registry_still_active_fails_clearly(world, capsys):
    world["cli"] = subprocess.TimeoutExpired(["dnsid"], 180)
    world["states"] = ["ACTIVE"]
    with pytest.raises(SystemExit):
        I.cmd_revoke(True)
    assert "CLI exit timeout" in capsys.readouterr().err


def test_wait_is_bounded(world, capsys, monkeypatch):
    polls = []
    world["cli"] = subprocess.CompletedProcess([], 1, "", "")
    monkeypatch.setattr(I, "registry_state", lambda _n: polls.append(1) or "ACTIVE")
    with pytest.raises(SystemExit):
        I.cmd_revoke(True)
    assert len(polls) == 1 + I.REVOKE_CONFIRM_S                      # the pre-check, then the bounded wait


def test_already_revoked_issues_no_cli_call(world, capsys):
    world["states"] = ["REVOKED"]
    out = revoke(capsys)
    assert out.get("note") == "already revoked" and world["argv"] == []


def test_revocation_still_requires_yes(world):
    with pytest.raises(SystemExit) as ei:
        I.cmd_revoke(False)
    assert ei.value.code == 2 and world["argv"] == []
