import pytest

from dnsidfed.policy import PolicyError, load_policy

GOOD = """
[federation]
trust_domain = "rackloria.test"
governance_id = "Rackloria.Test."
entity_key_thumbprints = ["abc"]
signer_pattern = "spire-fed-*.rackloria.test"
binding_url = "http://r/b"
bundle_endpoint_url = "https://r/bundle"
bundle_endpoint_spiffe_id = "spiffe://rackloria.test/spire/server"
federated_entries = ["spiffe://acme.test/purchasing"]

[verification]
poll_interval_s = 2
checkpoint_freshness_s = 120
log_policy_file = "/x/log.policy"
private_address_hosts = [".test", ".local"]
"""


def load(tmp_path, text):
    p = tmp_path / "policy.toml"
    p.write_text(text)
    return load_policy(p)


def test_valid_policy(tmp_path):
    p = load(tmp_path, GOOD)
    assert p.federation.governance_id == "rackloria.test"  # normalised
    assert p.federation.entity_key_thumbprints == ("abc",)
    assert p.verification.poll_interval_s == 2
    assert p.verification.private_address_hosts == (".test", ".local")
    assert p.verification.unavailable_grace_s == 30.0  # default


def test_missing_federation_table(tmp_path):
    with pytest.raises(PolicyError):
        load(tmp_path, '[verification]\nlog_policy_file="x"\n')


@pytest.mark.parametrize("line", ['entity_key_thumbprints = ["abc"]\n', 'governance_id = "Rackloria.Test."\n',
                                  'federated_entries = ["spiffe://acme.test/purchasing"]\n'])
def test_missing_required_field_rejected(tmp_path, line):
    with pytest.raises(PolicyError):
        load(tmp_path, GOOD.replace(line, ""))


def test_empty_pins_rejected(tmp_path):
    with pytest.raises(PolicyError):
        load(tmp_path, GOOD.replace('["abc"]', "[]"))


def test_signer_pattern_not_under_governance_rejected(tmp_path):
    for pat in ("spire-fed-*.rackl0ria.test", "*", "spire-fed-*.evil.test", "*rackloria.test"):
        with pytest.raises(PolicyError, match="signer_pattern"):
            load(tmp_path, GOOD.replace("spire-fed-*.rackloria.test", pat))


def test_missing_log_policy_file_rejected(tmp_path):
    with pytest.raises(PolicyError, match="log_policy_file"):
        load(tmp_path, GOOD.replace('log_policy_file = "/x/log.policy"\n', ""))
    with pytest.raises(PolicyError, match="log_policy_file"):
        load(tmp_path, GOOD.replace('"/x/log.policy"', '""'))


def test_nonpositive_intervals_rejected(tmp_path):
    with pytest.raises(PolicyError):
        load(tmp_path, GOOD.replace("poll_interval_s = 2", "poll_interval_s = 0"))
    with pytest.raises(PolicyError):
        load(tmp_path, GOOD.replace("checkpoint_freshness_s = 120", "checkpoint_freshness_s = -1"))


def test_signer_allowed_fnmatch_case_and_trailing_dot(tmp_path):
    f = load(tmp_path, GOOD).federation
    assert f.signer_allowed("spire-fed-abc.rackloria.test")
    assert f.signer_allowed("SPIRE-FED-ABC.Rackloria.Test")
    assert f.signer_allowed("spire-fed-abc.rackloria.test.")
    assert not f.signer_allowed("spire-fed-abc.rackl0ria.test")
    assert not f.signer_allowed("other.rackloria.test")
    assert not f.signer_allowed("spire-fed-abc.rackloria.test.evil.com")
