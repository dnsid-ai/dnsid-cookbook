"""Counterparty trust: operator-written clauses, answered by a Jev-compatible
decision model over a code-built fact sheet, combined by code.

The model answers three short naming questions. Code evaluates mechanical
clauses and combines the naming answers; `decide` alone chooses the tier.
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
QUESTION_NAMES = {"names_org", "same_org", "acts_for"}
EVALUATORS = {"impersonation": "model", "unproven": "code", "takeover_risk": "code"}


@dataclass(frozen=True)
class Clause:
    name: str
    effect: Tier
    threshold: float
    text: str
    evaluated_by: str


@dataclass(frozen=True)
class Policy:
    version: str
    clauses: tuple[Clause, ...]
    settings: FactSettings
    naming_questions: dict[str, str]

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
            evaluator = c.get("evaluated_by")
            if name not in EVALUATORS or evaluator != EVALUATORS[name]:
                raise ValueError(f"clause {name}: unsupported evaluator {evaluator!r}")
            clauses.append(Clause(name, EFFECTS[c["effect"]], threshold, text, evaluator))
        if not clauses:
            raise ValueError("policy has no clauses")
        naming_questions = data.get("questions", {})
        if set(naming_questions) != QUESTION_NAMES or any(
            not isinstance(t, str) or not 20 <= len(t) <= 250 for t in naming_questions.values()
        ):
            raise ValueError("policy needs three short naming questions: " + ", ".join(sorted(QUESTION_NAMES)))
        return cls(str(data["version"]), tuple(clauses), FactSettings(**data.get("facts", {})), naming_questions)


@dataclass(frozen=True)
class Decision:
    tier: Tier
    reasons: tuple[str, ...]  # clauses that fired, plus "history_unavailable"
    scores: dict[str, float]  # model intersection score or deterministic 0/1
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
        name: {"type": "noul", "instructions": text}
        for name, text in policy.naming_questions.items()
    }


def clause_scores(policy: Policy, facts: dict[str, Any], answers: dict[str, float]) -> dict[str, float]:
    """Deterministic rules and an intersection of naming signals, not a joint probability."""
    history, entity = facts["agent_history"], facts["accountable_entity_history"]
    established_entity = isinstance(entity, dict) and entity["first_issuance_days_ago"] >= policy.settings.new_agent_days
    unproven = (not isinstance(history, dict) or history["is_new"]) and not established_entity
    sensitive = {"moves money", "exposes credentials", "shares personal data"}
    impact = facts["interaction"]["impact"]
    if impact not in sensitive | {"none", "low"}:
        raise ValueError(f"unknown operation impact: {impact!r}")
    takeover = isinstance(history, dict) and history["recent_key_rotation"] and impact in sensitive
    # Minimum is a thresholded AND, without pretending independent judgments
    # can be multiplied into a calibrated probability of impersonation.
    impersonation = min(answers["names_org"], answers["acts_for"], 1 - answers["same_org"])
    scores = {"impersonation": impersonation, "unproven": float(unproven), "takeover_risk": float(takeover)}
    return {c.name: scores[c.name] for c in policy.clauses}


def decide(policy: Policy, scores: dict[str, float], *, history_available: bool) -> Decision:
    """Combine clause answers. Starts at TRUSTED and can only go down."""
    tier, reasons = Tier.TRUSTED, []
    if not history_available:  # hard rule: no verified history, no full trust
        tier = Tier.LIMITED
        reasons.append("history_unavailable")
    for c in policy.clauses:
        if scores[c.name] >= c.threshold:
            tier = min(tier, c.effect)
            reasons.append(c.name)
    return Decision(Tier(tier), tuple(reasons), dict(scores), policy.version)


class DecisionClient:
    """Minimal client for the /v1/systemone wire API (Jev, OpenJev, Codiv, ...)."""

    def __init__(self, http: httpx.AsyncClient, endpoint: str, model: str, api_key: str | None):
        self.http, self.endpoint, self.model = http, endpoint, model
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    async def ask(self, facts: dict[str, Any], policy: Policy) -> dict[str, float]:
        # No history, interaction, payload or policy paragraph goes to the model.
        body = {"model": self.model, "state": facts["counterparty"],
                "questions": questions(policy), "independent": True}
        response = await self.http.post(self.endpoint, json=body, headers=self.headers)
        response.raise_for_status()
        answers = response.json()["answers"]
        out = {}
        for name in policy.naming_questions:
            answer = answers[name]
            if answer["type"] != "noul":
                raise ValueError(f"wrong decision type for {name}")
            p = answer["noul"]
            if isinstance(p, bool) or not isinstance(p, (int, float)) or not math.isfinite(p) or not 0 <= p <= 1:
                raise ValueError(f"malformed answer for {name}: {p!r}")
            out[name] = float(p)
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
        answers = await self.client.ask(facts, self.policy)
        scores = clause_scores(self.policy, facts, answers)
        decision = decide(self.policy, scores, history_available=history is not None)
        log.info("trust counterparty=%s direction=%s tier=%s reasons=%s scores=%s naming=%s policy=%s",
                 verified.domain, interaction.direction, decision.tier.name.lower(),
                 ",".join(decision.reasons) or "-", scores, answers, self.policy.version)
        if self.cache_seconds > 0:
            if len(self._cache) > 10_000:
                self._cache.clear()
            self._cache[key] = (now + self.cache_seconds, decision)
        return decision


def evaluator_from_environment(http: httpx.AsyncClient) -> TrustEvaluator:
    policy = Policy.load(os.getenv("TRUST_POLICY") or DEFAULT_POLICY)
    client = DecisionClient(
        http,
        os.getenv("JEV_ENDPOINT", "http://127.0.0.1:8792/v1/systemone"),
        os.getenv("JEV_MODEL", "decider-12b"),
        os.getenv("JEV_API_KEY"),
    )
    return TrustEvaluator(policy, client, float(os.getenv("TRUST_CACHE_SECONDS", "300")))
