"""Acme's explicit federation trust policy (TOML). Loaded once at controller start."""
from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class FederationPolicy:
    trust_domain: str                      # SPIFFE trust domain this policy governs, e.g. rackloria.test
    governance_id: str                     # the ONLY DNSid governance ID (gi) allowed to speak for it
    entity_key_thumbprints: tuple[str, ...]  # pinned RFC 7638 thumbprints of that org's DNSid entity key
    signer_pattern: str                    # fnmatch pattern for the DNSid identity that signs bindings
    binding_url: str
    bundle_endpoint_url: str
    bundle_endpoint_spiffe_id: str
    federated_entries: tuple[str, ...]     # Acme SPIFFE IDs that may federate with this trust domain

    def signer_allowed(self, fqdn: str) -> bool:
        return fnmatch.fnmatchcase(fqdn.lower().rstrip("."), self.signer_pattern.lower())


@dataclass(frozen=True)
class VerificationSettings:
    poll_interval_s: float = 10.0
    checkpoint_freshness_s: float = 300.0  # max witness-cosigned checkpoint age (C2SP)
    max_statement_age_s: float = 900.0     # binding statement iat must be newer than this
    clock_skew_s: float = 60.0
    unavailable_grace_s: float = 30.0      # indeterminate results tolerated this long, then WITHDRAW
    log_policy_file: str = ""              # C2SP log trust policy, captured out of band (never fetched per cycle)
    dns_server: str = ""
    ca_bundle_path: str = ""
    private_address_hosts: tuple[str, ...] = (".test",)


@dataclass(frozen=True)
class Policy:
    federation: FederationPolicy
    verification: VerificationSettings = field(default_factory=VerificationSettings)


def _req(d: dict, key: str, ctx: str):
    if key not in d or d[key] in ("", None, []):
        raise PolicyError(f"{ctx}.{key} is required")
    return d[key]


def load_policy(path: str | Path) -> Policy:
    data = tomllib.loads(Path(path).read_text())
    fed = _req(data, "federation", "policy")
    pins = tuple(_req(fed, "entity_key_thumbprints", "federation"))
    if not pins:
        raise PolicyError("federation.entity_key_thumbprints must pin at least one entity key")
    fp = FederationPolicy(
        trust_domain=_req(fed, "trust_domain", "federation"),
        governance_id=_req(fed, "governance_id", "federation").lower().rstrip("."),
        entity_key_thumbprints=pins,
        signer_pattern=_req(fed, "signer_pattern", "federation"),
        binding_url=_req(fed, "binding_url", "federation"),
        bundle_endpoint_url=_req(fed, "bundle_endpoint_url", "federation"),
        bundle_endpoint_spiffe_id=_req(fed, "bundle_endpoint_spiffe_id", "federation"),
        federated_entries=tuple(_req(fed, "federated_entries", "federation")),
    )
    if not fp.signer_pattern.endswith("." + fp.governance_id):
        raise PolicyError("federation.signer_pattern must be under the approved governance_id")
    v = data.get("verification", {})
    known = set(VerificationSettings.__dataclass_fields__)
    unknown = set(v) - known
    if unknown:
        raise PolicyError(f"unknown [verification] keys: {sorted(unknown)}")
    vs = VerificationSettings(**{k: (tuple(x) if isinstance(x, list) else x) for k, x in v.items()})
    if vs.unavailable_grace_s < 0 or vs.clock_skew_s < 0 or vs.max_statement_age_s <= 0:
        raise PolicyError("verification grace/skew must be >= 0 and max_statement_age_s > 0")
    if vs.checkpoint_freshness_s <= 0 or vs.poll_interval_s <= 0:
        raise PolicyError("verification freshness and poll interval must be positive")
    if not vs.log_policy_file:
        raise PolicyError("verification.log_policy_file is required (pinned C2SP log trust policy)")
    return Policy(fp, vs)
