from __future__ import annotations

from dnsid import (
    JoseProfile,
    OIDCConfig,
    OIDCProfile,
    OIDCTokenExchangeOptions,
    identity_manager_from_cli_directory,
)

from orders_common.config import Settings


class CallerIdentity:
    def __init__(self, settings: Settings) -> None:
        self.manager = identity_manager_from_cli_directory(settings.dnsid_config_dir or None)
        self.domain = self.manager.local_domain
        self.jose = JoseProfile.from_identity_manager(self.manager)
        self.oidc = OIDCProfile.from_identity_manager(
            self.manager,
            OIDCConfig(default_server_url=settings.dnsid_server, timeout=30.0),
        )

    def mint_token(self, audience: str) -> str:
        return self.oidc.mint_oidc_token(
            OIDCTokenExchangeOptions(
                audience=audience,
                scope=["openid", "dnsid"],
            )
        ).access_token
