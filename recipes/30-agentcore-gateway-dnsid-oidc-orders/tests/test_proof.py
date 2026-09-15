from __future__ import annotations

import time

import pytest

from orders_common.proof import ActionPayload, encode_payload
from orders_interceptor.proof import ProofError, ProofVerifier
from orders_interceptor.replay import MemoryReplayStore


def payload(now: int) -> ActionPayload:
    return ActionPayload(
        subject="agent.bank-a.example",
        audience="https://gateway.example/mcp",
        token_jti_hash="jti-hash",
        tool_name="place_order",
        arguments_hash="arguments-hash",
        session_hash="session-hash",
        timestamp=now,
        nonce="one-use-nonce",
    )


def expected(value: ActionPayload) -> dict[str, str]:
    return {
        field: getattr(value, field)
        for field in (
            "subject",
            "audience",
            "token_jti_hash",
            "tool_name",
            "arguments_hash",
            "session_hash",
        )
    }


def test_dnsid_jws_is_bound_fresh_and_one_use(jose_profiles) -> None:
    signer, verifier_profile = jose_profiles()
    now = int(time.time())
    value = payload(now)
    proof = signer.create_jws(encode_payload(value))
    verifier = ProofVerifier(verifier_profile, MemoryReplayStore())

    assert verifier.verify(proof, expected(value), now).payload == value
    with pytest.raises(ProofError, match="replayed"):
        verifier.verify(proof, expected(value), now)

    future = payload(now + verifier.max_age)
    future_proof = signer.create_jws(encode_payload(future))
    future_verifier = ProofVerifier(verifier_profile, MemoryReplayStore())
    future_verifier.verify(future_proof, expected(future), now)
    with pytest.raises(ProofError, match="replayed"):
        future_verifier.verify(future_proof, expected(future), now + verifier.max_age + 1)


def test_modified_action_and_revoked_identity_are_denied(jose_profiles) -> None:
    now = int(time.time())
    signer, verifier_profile = jose_profiles()
    value = payload(now)
    proof = signer.create_jws(encode_payload(value))
    verifier = ProofVerifier(verifier_profile, MemoryReplayStore())

    with pytest.raises(ProofError, match="arguments_hash"):
        verifier.verify(proof, {**expected(value), "arguments_hash": "modified"}, now)

    revoked_signer, revoked_profile = jose_profiles("REVOKED")
    revoked_proof = revoked_signer.create_jws(encode_payload(value))
    with pytest.raises(ProofError, match="revoked"):
        ProofVerifier(revoked_profile, MemoryReplayStore()).verify(revoked_proof, expected(value), now)

    attacker, attacker_profile = jose_profiles(domain="attacker.example")
    attacker_proof = attacker.create_jws(encode_payload(value))
    with pytest.raises(ProofError, match="signer identity"):
        ProofVerifier(attacker_profile, MemoryReplayStore()).verify(attacker_proof, expected(value), now)
