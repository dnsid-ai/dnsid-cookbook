from __future__ import annotations

from dnsid import (
    OIDCConfig,
    OIDCProfile,
    OIDCTokenExchangeOptions,
    identity_manager_from_cli_directory,
)

from oidc_image.config import DnsidSettings


def mint_dnsid_token(dnsid: DnsidSettings, audience: str) -> str:
    manager = identity_manager_from_cli_directory()
    if manager.local_domain.rstrip(".").casefold() != dnsid.agent_domain.rstrip(
        "."
    ).casefold():
        raise ValueError("DNSID_AGENT_DOMAIN does not match the loaded identity")
    return OIDCProfile.from_identity_manager(
        manager,
        OIDCConfig(default_server_url=dnsid.server, timeout=30.0),
    ).mint_oidc_token(
        OIDCTokenExchangeOptions(audience=audience, scope=["openid", "dnsid"])
    ).access_token
