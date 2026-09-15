from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from dnsid import JWKS, JoseProfile, LocalKeyProvider, VerifiedDomain


@pytest.fixture
def jose_profiles():
    def build(state: str = "ACTIVE", domain: str = "agent.bank-a.example") -> tuple[JoseProfile, JoseProfile]:
        provider = LocalKeyProvider.generate()
        verified = MagicMock(spec=VerifiedDomain)
        verified.domain = domain
        verified.jwks = JWKS(keys=[provider.signing_key()])
        verified.cached_state.return_value = state
        verified.record = SimpleNamespace(gi="bank-a.example")
        resolver = MagicMock()
        resolver.verify_domain.return_value = verified
        return (
            JoseProfile(resolver, provider, domain),
            JoseProfile(resolver, None, "gateway.example"),
        )

    return build
