import pytest

from oidc_image.config import DEFAULT_DNSID_SERVER, load_dnsid_settings


def test_load_dnsid_settings_requires_agent_domain_by_default():
    with pytest.raises(ValueError, match="DNSID_AGENT_DOMAIN"):
        load_dnsid_settings(environ={})


def test_load_dnsid_settings_uses_defaults_when_agent_domain_not_required():
    settings = load_dnsid_settings(environ={}, require_agent_domain=False)

    assert settings.server == DEFAULT_DNSID_SERVER
    assert settings.agent_domain == ""


def test_load_dnsid_settings_trims_server_and_env_values():
    settings = load_dnsid_settings(
        environ={
            "DNSID_SERVER": " https://issuer.example.test/ ",
            "DNSID_AGENT_DOMAIN": " agent.example.test ",
        }
    )

    assert settings.server == "https://issuer.example.test"
    assert settings.agent_domain == "agent.example.test"


def test_load_dnsid_settings_requires_https_by_default():
    with pytest.raises(ValueError):
        load_dnsid_settings(
            environ={
                "DNSID_SERVER": "http://issuer.example.test",
                "DNSID_AGENT_DOMAIN": "agent.example.com",
            }
        )


def test_load_dnsid_settings_can_skip_https_requirement():
    settings = load_dnsid_settings(
        environ={
            "DNSID_SERVER": "http://issuer.example.test",
            "DNSID_AGENT_DOMAIN": "agent.example.com",
        },
        require_https=False,
    )

    assert settings.server == "http://issuer.example.test"
