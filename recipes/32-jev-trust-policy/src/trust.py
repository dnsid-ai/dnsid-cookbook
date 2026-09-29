"""Counterparty trust: operator-written clauses, answered by a Jev-compatible
decision model over a code-built fact sheet, combined by code.

The model answers one narrow yes/no question per clause. It never sees
signatures or raw records, never computes a fact, and never chooses the tier:
`decide` does, and the only thing a model answer can do is apply the clause's
own effect.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import math
import os
import re
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from facts import FactSettings, Interaction, facts_from_verified, read_history

if TYPE_CHECKING:
    import httpx

log = logging.getLogger("counterparty-trust")
DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policy.toml"


class Tier(enum.IntEnum):
    UNTRUSTED = 0
    LIMITED = 1
    TRUSTED = 2


EFFECTS = {"deny": Tier.UNTRUSTED, "limit": Tier.LIMITED}


@dataclass(frozen=True)
class Clause:
    name: str
    effect: Tier
    threshold: float
    text: str


@dataclass(frozen=True)
class Policy:
    version: str
    clauses: tuple[Clause, ...]
    settings: FactSettings

    @classmethod
    def load(cls, path: str | Path = DEFAULT_POLICY) -> Policy:
        data = tomllib.loads(Path(path).read_text("utf-8"))
        clauses = []
        for name, c in data.get("clauses", {}).items():
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
                raise ValueError(f"clause name {name!r}: use lowercase letters, digits and _")
            if c.get("effect") not in EFFECTS:
                raise ValueError(f"clause {name}: effect must be one of {sorted(EFFECTS)}")
            threshold = float(c.get("threshold", 0.5))
            if not 0 < threshold <= 1:
                raise ValueError(f"clause {name}: threshold must be in (0, 1]")
            text = " ".join(str(c.get("text", "")).split())
            if not 20 <= len(text) <= 1000:
                raise ValueError(f"clause {name}: text must be 20-1000 characters")
            clauses.append(Clause(name, EFFECTS[c["effect"]], threshold, text))
        if not clauses:
            raise ValueError("policy has no clauses")
        return cls(str(data["version"]), tuple(clauses), FactSettings(**data.get("facts", {})))


@dataclass(frozen=True)
class Decision:
    tier: Tier
    reasons: tuple[str, ...]  # clauses that fired, plus "history_unavailable"
    probabilities: dict[str, float]
    policy_version: str


@dataclass(frozen=True)
class Operation:
    """An operation in our own table and the tier it requires."""

    interaction: Interaction
    requires: Tier

    def permits(self, decision: Decision) -> bool:
        return decision.tier >= self.requires


def questions(policy: Policy) -> dict[str, Any]:
    return {
        c.name: {
            "type": "noul",
            "instructions": "Do the facts show that the counterparty violates this "
            f"trust-policy clause? {c.text}",
            "criteria": {
                "true": "Yes: the facts show this clause applies to the counterparty.",
                "false": "No: the facts do not show that this clause applies.",
            },
        }
        for c in policy.clauses
    }


def decide(policy: Policy, probabilities: dict[str, float], *, history_available: bool) -> Decision:
    """Combine clause answers. Starts at TRUSTED and can only go down."""
    tier, reasons = Tier.TRUSTED, []
    if not history_available:  # hard rule: no verified history, no full trust
        tier = Tier.LIMITED
        reasons.append("history_unavailable")
    for c in policy.clauses:
        if probabilities[c.name] >= c.threshold:
            tier = min(tier, c.effect)
            reasons.append(c.name)
    return Decision(Tier(tier), tuple(reasons), dict(probabilities), policy.version)


class DecisionClient:
    """Minimal client for the /v1/systemone wire API (Jev, OpenJev, Codiv, ...)."""

    def __init__(self, http: httpx.AsyncClient, endpoint: str, model: str, api_key: str | None):
        self.http, self.endpoint, self.model = http, endpoint, model
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    async def ask(self, facts: dict[str, Any], policy: Policy) -> dict[str, float]:
        body = {"model": self.model, "state": facts, "questions": questions(policy)}
        response = await self.http.post(self.endpoint, json=body, headers=self.headers)
        response.raise_for_status()
        answers = response.json()["answers"]
        out = {}
        for c in policy.clauses:
            answer = answers[c.name]
            if answer["type"] != "noul":
                raise ValueError(f"wrong decision type for {c.name}")
            p = answer["noul"]
            if isinstance(p, bool) or not isinstance(p, (int, float)) or not math.isfinite(p) or not 0 <= p <= 1:
                raise ValueError(f"malformed answer for {c.name}: {p!r}")
            out[c.name] = float(p)
        return out


class TrustEvaluator:
    def __init__(self, policy: Policy, client: DecisionClient, cache_seconds: float = 300):
        self.policy, self.client, self.cache_seconds = policy, client, cache_seconds
        self._cache: dict[tuple[Any, ...], tuple[float, Decision]] = {}

    async def evaluate(self, verified: Any, interaction: Interaction) -> Decision:
        """Decide how far to trust an already verified counterparty for one interaction.

        Raises httpx.HTTPError / ValueError / KeyError / TypeError when the
        decision model is unavailable or answers malformed; callers fail closed.
        """
        history = await asyncio.to_thread(read_history, verified)
        # A key rotation or any other lifecycle event changes the fingerprint,
        # so it always forces a fresh decision.
        key = (verified.domain, verified.record.gi, self.policy.version, interaction,
               history.fingerprint if history else None)
        now = time.monotonic()
        if (hit := self._cache.get(key)) and hit[0] > now:
            return hit[1]

        facts = facts_from_verified(verified, history, interaction, self.policy.settings)
        probabilities = await self.client.ask(facts, self.policy)
        decision = decide(self.policy, probabilities, history_available=history is not None)
        log.info("trust counterparty=%s direction=%s tier=%s reasons=%s p=%s policy=%s",
                 verified.domain, interaction.direction, decision.tier.name.lower(),
                 ",".join(decision.reasons) or "-", probabilities, self.policy.version)
        if self.cache_seconds > 0:
            if len(self._cache) > 10_000:
                self._cache.clear()
            self._cache[key] = (now + self.cache_seconds, decision)
        return decision


def evaluator_from_environment(http: httpx.AsyncClient) -> TrustEvaluator:
    policy = Policy.load(os.getenv("TRUST_POLICY") or DEFAULT_POLICY)
    client = DecisionClient(
        http,
        os.getenv("JEV_ENDPOINT", "http://127.0.0.1:8791/v1/systemone"),
        os.getenv("JEV_MODEL", "jev-latest"),
        os.getenv("JEV_API_KEY"),
    )
    return TrustEvaluator(policy, client, float(os.getenv("TRUST_CACHE_SECONDS", "300")))
