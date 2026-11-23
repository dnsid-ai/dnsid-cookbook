"""Entity-key discovery from the signer's published _dnsid record, and the bootstrap pinning model.

Discovery only locates the governance entity-key document. Trust comes from the pin captured during trusted
setup (and the controller's SDK verification against that pin every cycle); a restart never re-pins.
"""
import json

import pytest

import identity as I
from identity import RecordError, parse_dnsid_record, validate_entity_key_url

GOV = "rackloria.test"
# Deliberately hostile hostnames are assembled at runtime (the repository's identity scanner convention for
# negative fixtures), so they never appear as literal identities in the source.
EVIL_SUB = "keys." + "evil.test"
SUFFIX_TRICK = "rackloria.test." + "evil.test"
LOOKALIKE_SUB = "dnsid." + "rackl0ria.test"
OTHER_ORG_EK = "dnsid." + "evil.test"
EK = "https://dnsid.rackloria.test/.well-known/dnsid-ek.json"


def rec(**over):
    r = {"v": "dnsid-draft-01", "gi": GOV, "ek": EK, "ku": "https://x/jwks.json"}
    r.update(over)
    return {k: v for k, v in r.items() if v is not None}


# ------------------------------------------------------------------ parsing
def test_parse_dig_output_with_chunked_txt_strings():
    dig = ('"v=dnsid-draft-01;ek=https://dnsid.rackloria.test/.well-known/dnsid-ek.json;gi=rackloria.test;" '
           '"lr=c2sp-tlog:testnet:https://registry.test#ag-1234" "abcd;sg=xyz"\n')
    r = parse_dnsid_record(dig)
    assert r["ek"] == EK and r["gi"] == GOV and r["lr"] == "c2sp-tlog:testnet:https://registry.test#ag-1234abcd"


def test_parse_rejects_duplicate_fields():
    with pytest.raises(RecordError, match="duplicate"):
        parse_dnsid_record('"gi=rackloria.test;ek=https://a/x;gi=evil.test"')


# ------------------------------------------------------------------ valid
@pytest.mark.parametrize("ek", [
    EK,
    "https://rackloria.test/.well-known/dnsid-ek.json",             # the governance domain itself
    "https://dnsid.rackloria.test:443/.well-known/dnsid-ek.json",   # explicit default port
    "https://a.b.rackloria.test/ek.json",                           # deeper genuine subdomain
])
def test_valid_entity_key_urls(ek):
    assert validate_entity_key_url(rec(ek=ek), GOV) == ek


def test_governance_comparison_tolerates_trailing_dot_only():
    assert validate_entity_key_url(rec(gi="rackloria.test."), "rackloria.test.") == EK


# ------------------------------------------------------------------ rejected
@pytest.mark.parametrize("record,match", [
    (rec(gi=None), "no gi="),
    (rec(gi=""), "no gi="),
    (rec(ek=None), "no ek="),
    (rec(ek=""), "no ek="),
    (rec(gi="rackl0ria.test"), "expected governance"),                # lookalike governance
    (rec(gi="evil.test"), "expected governance"),
    (rec(gi="dnsid.rackloria.test"), "expected governance"),          # a subdomain is not the governance ID
    (rec(gi="Rackloria.Test"), "expected governance"),                # case games
    (rec(ek="http://dnsid.rackloria.test/.well-known/dnsid-ek.json"), "https"),
    (rec(ek="dnsid.rackloria.test/.well-known/dnsid-ek.json"), "https"),
    (rec(ek="ftp://dnsid.rackloria.test/x"), "https"),
    (rec(ek=f"https://{EVIL_SUB}/.well-known/dnsid-ek.json"), "not rackloria.test"),
    (rec(ek="https://evilrackloria.test/x"), "not rackloria.test"),    # misleading suffix, no dot boundary
    (rec(ek=f"https://{SUFFIX_TRICK}/x"), "not rackloria.test"),
    (rec(ek=f"https://{LOOKALIKE_SUB}/x"), "not rackloria.test"),   # lookalike
    (rec(ek="https://dnsid.rackloria.test:8443/x"), "unexpected port"),
    (rec(ek="https://dnsid.rackloria.test:0/x"), "unexpected port"),
    (rec(ek="https://dnsid.rackloria.test:99999/x"), "malformed"),
    (rec(ek="https://attacker@dnsid.rackloria.test/x"), "userinfo"),
    (rec(ek="https://dnsid.rackloria.test:pw@evil.test/x"), "userinfo"),
    (rec(ek="https://DNSID.rackloria.test/x"), "lowercase"),
    (rec(ek="https://dnsid.rackloria.test./x"), "lowercase|DNS name|not rackloria"),
    (rec(ek="https://dnsid.rackloria.test/x?y=1"), "query or fragment"),
    (rec(ek="https://dnsid.rackloria.test/x#frag"), "query or fragment"),
    (rec(ek="https://dnsid.rackloria.test"), "no path"),
    (rec(ek="https://dnsid_x.rackloria.test/x"), "DNS name"),
    (rec(ek="https://dnsid.rackloria.test/ x"), "malformed"),
    (rec(ek="https://dnsid.rаckloria.test/x"), "malformed"),           # Cyrillic 'а' homoglyph
    (rec(ek="https://[::1]/x"), "lowercase|DNS name|not rackloria"),
    (rec(ek="https://127.0.0.1/x"), "not rackloria"),
])
def test_rejected_records(record, match):
    with pytest.raises(RecordError, match=match):
        validate_entity_key_url(record, GOV)


def test_cli_provided_url_must_match_published():
    assert validate_entity_key_url(rec(), GOV, cli_ek=EK) == EK
    with pytest.raises(RecordError, match="differs"):
        validate_entity_key_url(rec(), GOV, cli_ek="https://dnsid.rackloria.test/other.json")


def test_governance_is_the_configured_value_not_the_records():
    # Even a self-consistent record for another organization is rejected.
    with pytest.raises(RecordError):
        validate_entity_key_url(rec(gi="evil.test", ek=f"https://{OTHER_ORG_EK}/x"), GOV)


# ------------------------------------------------------------------ pinning model (no network: thumbprints stubbed)
@pytest.fixture
def pin_env(monkeypatch, tmp_path):
    d = tmp_path / "dnsid"
    d.mkdir()
    monkeypatch.setattr(I, "DNSID_DIR", d, raising=False)
    served = {"thumbs": ["key-A"]}
    monkeypatch.setattr(I, "current_entity_thumbprints", lambda: list(served["thumbs"]))
    return d, served


def test_first_pin_is_written_at_trusted_setup(pin_env):
    d, _ = pin_env
    I.cmd_pin(str(d / "pins.json"))
    assert json.loads((d / "pins.json").read_text()) == ["key-A"]


def test_no_silent_repinning(pin_env):
    d, served = pin_env
    I.cmd_pin(str(d / "pins.json"))
    served["thumbs"] = ["key-B"]
    with pytest.raises(SystemExit) as ei:
        I.cmd_pin(str(d / "pins.json"))                    # a second capture is refused outright
    assert ei.value.code == 3
    assert json.loads((d / "pins.json").read_text()) == ["key-A"]


def test_restart_with_unchanged_key_passes(pin_env, capsys):
    d, _ = pin_env
    I.cmd_pin(str(d / "pins.json"))
    I.cmd_pin_check(str(d / "pins.json"))
    assert "still served" in capsys.readouterr().out


def test_restart_with_changed_entity_key_fails_and_keeps_pin(pin_env):
    d, served = pin_env
    I.cmd_pin(str(d / "pins.json"))
    served["thumbs"] = ["key-B"]                            # registry state replaced / key changed
    with pytest.raises(SystemExit) as ei:
        I.cmd_pin_check(str(d / "pins.json"))
    assert ei.value.code == I.EXIT_ENTITY_KEY
    assert json.loads((d / "pins.json").read_text()) == ["key-A"]


def test_restart_with_tampered_pin_file_fails(pin_env):
    d, _ = pin_env
    I.cmd_pin(str(d / "pins.json"))
    (d / "pins.json").write_text(json.dumps(["key-Z"]) + "\n")
    with pytest.raises(SystemExit):
        I.cmd_pin_check(str(d / "pins.json"))


def test_pin_outputs_confined(pin_env, tmp_path):
    with pytest.raises(SystemExit):
        I.cmd_pin(str(tmp_path / "elsewhere.json"))
