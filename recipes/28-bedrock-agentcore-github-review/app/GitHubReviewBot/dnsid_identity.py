from __future__ import annotations

from dnsid import (
    OIDCConfig,
    OIDCProfile,
    OIDCTokenExchangeOptions,
    identity_manager_from_cli_directory,
)


def mint_dnsid_token(
    audience: str,
    expected_domain: str,
    server_url: str,
    config_dir: str = "",
) -> str:
    manager = identity_manager_from_cli_directory(config_dir or None)
    if manager.local_domain.rstrip(".").casefold() != expected_domain.rstrip(
        "."
    ).casefold():
        raise ValueError("BOT_DOMAIN does not match the loaded DNSid identity")
    return OIDCProfile.from_identity_manager(
        manager,
        OIDCConfig(default_server_url=server_url, timeout=30.0),
    ).mint_oidc_token(
        OIDCTokenExchangeOptions(
            audience=audience,
            scope=["openid", "dnsid", "dnsid:review"],
        )
    ).access_token
