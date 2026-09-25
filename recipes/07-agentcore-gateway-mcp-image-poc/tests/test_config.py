import pytest

from image_poc.config import load_dnsid_settings, load_mode


def test_dnsid_settings_requires_agent_domain_for_gateway_paths():
    with pytest.raises(ValueError, match="DNSID_AGENT_DOMAIN"):
        load_dnsid_settings(environ={}, require_https=True)


def test_dnsid_settings_allows_missing_agent_domain_when_not_required():
    settings = load_dnsid_settings(
        environ={},
        require_https=False,
        require_agent_domain=False,
    )

    assert settings.cli == "dnsid"
    assert settings.server == "https://api.dev.dnsid.ai"
    assert settings.agent_domain == ""


def test_dnsid_settings_reads_env_overrides():
    settings = load_dnsid_settings(
        environ={
            "DNSID_CLI": "/opt/dnsid/bin/dnsid",
            "DNSID_SERVER": "https://dnsid.example.test/",
            "DNSID_AGENT_DOMAIN": "agent.example.test",
        },
        require_https=True,
    )

    assert settings.cli == "/opt/dnsid/bin/dnsid"
    assert settings.server == "https://dnsid.example.test"
    assert settings.agent_domain == "agent.example.test"


def test_gateway_dnsid_server_must_be_https():
    with pytest.raises(ValueError, match="DNSID_SERVER"):
        load_dnsid_settings(
            environ={
                "DNSID_SERVER": "http://dnsid.example.test",
                "DNSID_AGENT_DOMAIN": "agent.example.com",
            },
            require_https=True,
        )


def test_mode_must_be_gateway_or_local_test():
    assert load_mode({}) == "gateway"
    assert load_mode({"IMAGE_POC_MODE": "local-test"}) == "local-test"

    with pytest.raises(ValueError, match="IMAGE_POC_MODE"):
        load_mode({"IMAGE_POC_MODE": "test"})
