"""Verified identity -> facts -> configured rules -> operation permission."""

import asyncio
import enum
import logging
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

import httpx

from facts import facts_from_verified

log = logging.getLogger("counterparty-trust")
DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policy.toml"
# Application-owned descriptions of what operations actually do, never caller input.
IMPACTS = {"catalog": "none", "refund": "moves money",
           "order-lookup": "low", "customer-pii": "shares personal data"}
QUESTION_NAMES = {"names_org", "same_org", "acts_for"}


class Tier(enum.IntEnum):
    UNTRUSTED = 0
    LIMITED = 1
    TRUSTED = 2


EFFECTS = {"deny": Tier.UNTRUSTED, "limit": Tier.LIMITED}


def load_policy(path: str | Path | None = None) -> dict:
    policy = tomllib.loads(Path(path or os.getenv("TRUST_POLICY") or DEFAULT_POLICY).read_text("utf-8"))
    rules = policy["rules"]
    if not isinstance(policy["version"], str) or not policy["version"]:
        raise ValueError("policy needs a version")
    fields = {"impersonation": {"effect", "threshold"}, "unproven": {"effect", "new_agent_days"},
              "takeover_risk": {"effect", "recent_rotation_days"}}
    if set(policy) != {"version", "rules", "questions", "requires"} or set(rules) != set(fields) or any(
        set(rule) != fields[name] for name, rule in rules.items()
    ):
        raise ValueError("policy must configure exactly the supported rules and settings")
    if any(rule["effect"] not in EFFECTS for rule in rules.values()):
        raise ValueError("rule effects must be limit or deny")
    for days in (rules["unproven"]["new_agent_days"], rules["takeover_risk"]["recent_rotation_days"]):
        if type(days) is not int or days <= 0:
            raise ValueError("age windows must be positive integer days")
    threshold = rules["impersonation"]["threshold"]
    if type(threshold) not in (int, float) or not 0 < threshold <= 1:
        raise ValueError("impersonation threshold must be in (0, 1]")
    if set(policy["questions"]) != QUESTION_NAMES or any(
        not isinstance(q, str) or not q.strip() for q in policy["questions"].values()
    ):
        raise ValueError("policy needs the three naming questions")
    if set(policy["requires"]) != set(IMPACTS) or any(
        tier not in {"untrusted", "limited", "trusted"} for tier in policy["requires"].values()
    ):
        raise ValueError("policy must set a valid minimum tier for every operation")
    return policy


@dataclass(frozen=True)
class Decision:
    tier: Tier
    reasons: tuple[str, ...]


def decide(policy: dict, facts: dict, answers: dict, operation: str) -> Decision:
    rules = policy["rules"]
    history, entity = facts["agent_history"], facts["accountable_entity_history"]
    days = rules["unproven"]["new_agent_days"]
    established_entity = entity is not None and entity["first_issuance_days_ago"] >= days
    # Minimum is a thresholded AND, not a calibrated joint probability.
    impersonation = min(answers["names_org"], answers["acts_for"], 1 - answers["same_org"])
    matched = {
        "impersonation": impersonation >= rules["impersonation"]["threshold"],
        "unproven": (history is None or history["identity_age_days"] < days) and not established_entity,
        "takeover_risk": IMPACTS[operation] in {"moves money", "exposes credentials", "shares personal data"}
            and history is not None and history["key_event"] == "key rotation"
            and history["key_age_days"] < rules["takeover_risk"]["recent_rotation_days"],
    }
    tier = Tier.TRUSTED if history is not None else Tier.LIMITED
    reasons = [] if history is not None else ["history_unavailable"]
    for name, applies in matched.items():
        if applies:
            tier = min(tier, EFFECTS[rules[name]["effect"]])
            reasons.append(name)
    return Decision(tier, tuple(reasons))


async def ask_model(http: httpx.AsyncClient, policy: dict, counterparty: dict) -> dict:
    """Jev's 'noul' field is a yes/no probability. Send only verified naming facts."""
    body = {"model": os.getenv("JEV_MODEL", "clef-flash"), "state": counterparty, "independent": True,
            "questions": {name: {"type": "noul", "instructions": text}
                          for name, text in policy["questions"].items()}}
    key = os.getenv("JEV_API_KEY")
    response = await http.post(os.getenv("JEV_ENDPOINT", "http://127.0.0.1:8080/v1/systemone"),
                               json=body, headers={"Authorization": f"Bearer {key}"} if key else {})
    response.raise_for_status()
    answers = response.json()["answers"]
    out = {}
    for name in policy["questions"]:
        answer = answers[name]
        p = answer["noul"]
        if answer["type"] != "noul" or type(p) not in (int, float) or not 0 <= p <= 1:
            raise ValueError(f"malformed answer for {name}: {answer!r}")
        out[name] = p
    return out


class TrustEvaluator:
    def __init__(self, http: httpx.AsyncClient):
        self.http, self.policy = http, load_policy()

    async def evaluate(self, verified, operation: str) -> Decision:
        facts = await asyncio.to_thread(facts_from_verified, verified)
        answers = await ask_model(self.http, self.policy, facts["counterparty"])
        decision = decide(self.policy, facts, answers, operation)
        log.info("trust counterparty=%s operation=%s tier=%s reasons=%s naming=%s policy=%s",
                 verified.domain, operation, decision.tier.name.lower(),
                 ",".join(decision.reasons) or "-", answers, self.policy["version"])
        return decision

    def permits(self, decision: Decision, operation: str) -> bool:
        return decision.tier >= Tier[self.policy["requires"][operation].upper()]
