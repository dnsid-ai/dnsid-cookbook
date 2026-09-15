from __future__ import annotations

from dataclasses import dataclass
from typing import Any


TRUSTED_HEADER_NAMES = {
    "sub": "x-dnsid-sub",
    "issuer": "x-dnsid-iss",
    "audience": "x-dnsid-aud",
    "jti": "x-dnsid-jti",
    "dnsid_domain": "x-dnsid-domain",
    "scope": "x-dnsid-scope",
    "auth_mode": "x-dnsid-auth-mode",
    "verified_at": "x-dnsid-verified-at",
    "gateway_request_id": "x-gateway-request-id",
    "correlation_id": "x-correlation-id",
}

REQUIRED_HEADER_FIELDS = ("sub", "issuer", "audience", "jti", "dnsid_domain")
IDENTITY_LIKE_KEYS = {
    "identity",
    "dnsid",
    "sub",
    "x_dnsid_sub",
    "x-dnsid-sub",
    "jwt_sub",
    "accountable_entity",
}


class TrustedContextError(Exception):
    pass


@dataclass(frozen=True)
class TrustedContext:
    sub: str
    issuer: str
    audience: str
    jti: str
    dnsid_domain: str
    scope: str
    auth_mode: str
    verified_at: str
    gateway_request_id: str
    correlation_id: str

    def to_public_dict(self) -> dict[str, str]:
        return {
            "sub": self.sub,
            "dnsid": self.dnsid_domain,
            "accountable_entity": self.dnsid_domain,
            "iss": self.issuer,
            "aud": self.audience,
            "jti": self.jti,
            "scope": self.scope,
            "auth_mode": self.auth_mode,
            "verified_at": self.verified_at,
            "gateway_request_id": self.gateway_request_id,
            "correlation_id": self.correlation_id,
            "dnsid_status": "not_checked_phase3",
        }


def normalize_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if value is None:
            continue
        normalized[str(key).lower()] = str(value)
    return normalized


def parse_trusted_context(
    headers: dict[str, Any] | None,
    expected_sub: str | None = None,
) -> TrustedContext:
    normalized = normalize_headers(headers)
    values: dict[str, str] = {}
    for field, header_name in TRUSTED_HEADER_NAMES.items():
        value = normalized.get(header_name, "")
        if value and not _is_safe_header_value(value):
            raise TrustedContextError(f"{header_name} must contain printable ASCII.")
        values[field] = value.strip()

    for field in REQUIRED_HEADER_FIELDS:
        if not values[field]:
            raise TrustedContextError(f"Missing trusted header {TRUSTED_HEADER_NAMES[field]}.")

    if expected_sub and values["sub"] != expected_sub:
        raise TrustedContextError("Unexpected DNSid subject.")

    if not values["auth_mode"]:
        values["auth_mode"] = "gateway-dnsid-lab"

    return TrustedContext(**values)


def find_identity_like_keys(value: Any, prefix: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            if key_text.lower() in IDENTITY_LIKE_KEYS:
                found.append(path)
            found.extend(find_identity_like_keys(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            found.extend(find_identity_like_keys(child, path))
    return found


def _is_safe_header_value(value: str) -> bool:
    return all(32 <= ord(char) <= 126 for char in value)
