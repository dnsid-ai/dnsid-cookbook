from types import SimpleNamespace

import pytest

from oidc_image import identity
from oidc_image.config import DnsidSettings


def settings():
    return DnsidSettings("https://issuer.example.test", "agent.example.test")


def test_mint_dnsid_token_uses_loaded_identity(monkeypatch):
    manager = SimpleNamespace(local_domain="agent.example.test")
    profile = SimpleNamespace(
        mint_oidc_token=lambda options: SimpleNamespace(access_token="header.payload.sig")
    )
    monkeypatch.setattr(identity, "identity_manager_from_cli_directory", lambda: manager)
    monkeypatch.setattr(
        identity.OIDCProfile,
        "from_identity_manager",
        lambda loaded, config: profile,
    )

    assert identity.mint_dnsid_token(settings(), "audience") == "header.payload.sig"


def test_mint_dnsid_token_rejects_wrong_identity(monkeypatch):
    manager = SimpleNamespace(local_domain="other.example.test")
    monkeypatch.setattr(identity, "identity_manager_from_cli_directory", lambda: manager)

    with pytest.raises(ValueError, match="does not match"):
        identity.mint_dnsid_token(settings(), "audience")
