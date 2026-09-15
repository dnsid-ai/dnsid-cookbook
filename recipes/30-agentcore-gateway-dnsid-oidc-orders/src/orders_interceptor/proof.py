from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dnsid import DNSidError, IdentityManager, IdentityManagerDependencies, JoseProfile, VerifiedDomain
from dnsid.c2sp_tlog import C2spTlogVerificationOptions, create_c2sp_tlog_verification_registry

from orders_common.proof import ActionPayload, decode_payload
from orders_interceptor.replay import ReplayError


class ProofError(RuntimeError):
    def __init__(self, message: str, *, state: str = "") -> None:
        super().__init__(message)
        self.state = state


@dataclass(frozen=True)
class VerifiedAction:
    payload: ActionPayload
    identity: VerifiedDomain


class ProofVerifier:
    def __init__(self, profile: JoseProfile, replay_store: Any, max_age: int = 300) -> None:
        self.profile = profile
        self.replay_store = replay_store
        self.max_age = max_age

    def verify(self, jws: str, expected: dict[str, str], now: int) -> VerifiedAction:
        try:
            signed, identity = self.profile.verify_jws(jws)
            payload = decode_payload(signed)
        except (DNSidError, TypeError, ValueError) as exc:
            raise ProofError(
                "DNSid action proof verification failed",
                state=str(getattr(exc, "agent_state", "") or ""),
            ) from exc
        if identity.domain != payload.subject:
            raise ProofError("action proof subject does not match signer identity")
        for field, value in expected.items():
            if getattr(payload, field) != value:
                raise ProofError(f"action proof does not match {field}")
        if abs(now - payload.timestamp) > self.max_age:
            raise ProofError("action proof is stale")
        if identity.cached_state().upper() != "ACTIVE":
            raise ProofError(f"DNSid identity is {identity.cached_state().lower()}", state=identity.cached_state())
        try:
            self.replay_store.reserve(
                payload.nonce,
                max(1, payload.timestamp + self.max_age - now + 1),
                now,
            )
        except ReplayError as exc:
            raise ProofError(str(exc)) from exc
        return VerifiedAction(payload, identity)


def build_profile(subject: str, policy_url: str) -> JoseProfile:
    registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            policy_url=policy_url,
            checkpoint_freshness_ms=300_000,
            max_clock_skew_ms=30_000,
        )
    )
    manager = IdentityManager.for_verification(
        deps=IdentityManagerDependencies(log_registry=registry),
    )
    return JoseProfile(resolver=manager, key_provider=None, domain=subject)
