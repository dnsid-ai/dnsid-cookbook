"""Safety and policy checks without a registry or a real model."""

import asyncio
import copy
import datetime as dt
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from dnsid.models import IssuanceEvent, KeyRotationEvent, MigrationEvent

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from facts import counterparty, facts_from_verified, history_facts, name_signals
from trust import TrustEvaluator, ask_model, decide, load_policy, Tier

ROOT = Path(__file__).resolve().parent.parent
POLICY = load_policy()
CALM = {"names_org": 0.01, "same_org": 0.99, "acts_for": 0.01}
SUSPICIOUS = {"names_org": 0.99, "same_org": 0.01, "acts_for": 0.99}
T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def case(name):
    return json.loads((ROOT / "cases" / f"{name}.json").read_text())


def model_reply(body, seen):
    def handle(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=body)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
            return await ask_model(http, POLICY, counterparty("alice.test", "bob.test", "VALID"))
    return asyncio.run(run())


class TrustTests(unittest.TestCase):
    def test_all_labelled_mechanical_rules(self):
        for path in (ROOT / "cases").rglob("*.json"):
            c = json.loads(path.read_text())
            decision = decide(POLICY, c["facts"], CALM | {"unproven": 0, "takeover_risk": 0}, c["operation"])
            for name in ("unproven", "takeover_risk"):
                with self.subTest(case=path.stem, rule=name):
                    self.assertEqual(name in decision.reasons, c["expected"]["clauses"][name])

    def test_age_windows_use_raw_facts(self):
        for name, rule, knob, days in (
            ("delegated_contractor", "unproven", "new_agent_days", 365),
            ("old_rotation_money", "takeover_risk", "recent_rotation_days", 100),
        ):
            c, policy = case(name), copy.deepcopy(POLICY)
            self.assertNotIn(rule, decide(policy, c["facts"], CALM, c["operation"]).reasons)
            policy["rules"][rule][knob] = days
            self.assertIn(rule, decide(policy, c["facts"], CALM, c["operation"]).reasons)

    def test_exact_age_boundaries_and_event_types(self):
        for event in (IssuanceEvent, KeyRotationEvent, MigrationEvent):
            for age in (6.9999, 7):
                events = [IssuanceEvent(timestamp=T0)]
                if event is not IssuanceEvent:
                    events.append(event(timestamp=T0 + dt.timedelta(days=30 - age)))
                facts = case("recent_rotation_money")["facts"]
                facts["agent_history"] = history_facts(events, T0 + dt.timedelta(days=30))
                d = decide(POLICY, facts, CALM, "refund")
                self.assertNotIn("unproven", d.reasons)
                self.assertEqual("takeover_risk" in d.reasons, event is KeyRotationEvent and age < 7)
        facts["agent_history"] = history_facts([IssuanceEvent(timestamp=T0)], T0 + dt.timedelta(days=29.9999))
        self.assertIn("unproven", decide(POLICY, facts, CALM, "catalog").reasons)

    def test_sensitive_operations_only(self):
        facts = case("recent_rotation_money")["facts"]
        for operation in POLICY["requires"]:
            self.assertEqual("takeover_risk" in decide(POLICY, facts, CALM, operation).reasons,
                             operation in ("refund", "customer-pii"))
        with self.assertRaises(KeyError):
            decide(POLICY, facts, CALM, "unknown")

    def test_impersonation_is_thresholded_and(self):
        facts = case("brand_own_domain")["facts"]
        self.assertIn("impersonation", decide(POLICY, facts, SUSPICIOUS, "catalog").reasons)
        for override in ({"names_org": 0.01}, {"acts_for": 0.01}, {"same_org": 0.99}):
            self.assertNotIn("impersonation", decide(POLICY, facts, SUSPICIOUS | override, "catalog").reasons)
        self.assertIn("impersonation", decide(POLICY, facts, SUSPICIOUS | {"names_org": 0.3}, "catalog").reasons)

    def test_effects_and_most_restrictive_wins(self):
        c, policy = case("new_agent_new_entity"), copy.deepcopy(POLICY)
        self.assertEqual(decide(policy, c["facts"], CALM, "catalog").tier, Tier.LIMITED)
        policy["rules"]["unproven"]["effect"] = "deny"
        self.assertEqual(decide(policy, c["facts"], CALM, "catalog").tier, Tier.UNTRUSTED)
        policy["rules"]["impersonation"]["effect"] = "limit"
        self.assertEqual(decide(policy, c["facts"], SUSPICIOUS, "catalog").tier, Tier.UNTRUSTED)

    def test_missing_history_never_gets_full_trust(self):
        facts = case("new_agent_established_entity")["facts"]
        self.assertEqual(decide(POLICY, facts, CALM, "catalog").tier, Tier.TRUSTED)
        facts["agent_history"] = None
        self.assertEqual(decide(POLICY, facts, CALM, "catalog").tier, Tier.LIMITED)

    def test_minimum_tiers_come_from_policy(self):
        evaluator = TrustEvaluator(None)
        decision = decide(POLICY, case("new_agent_new_entity")["facts"], CALM, "catalog")
        self.assertTrue(evaluator.permits(decision, "catalog"))
        self.assertFalse(evaluator.permits(decision, "refund"))
        evaluator.policy["requires"]["catalog"] = "trusted"
        self.assertFalse(evaluator.permits(decision, "catalog"))

    def test_invalid_config_is_rejected(self):
        text = (ROOT / "policy.toml").read_text()
        for old, new in (("new_agent_days = 30", "new_agent_days = 0"),
                         ("recent_rotation_days = 7", "recent_rotation_days = true"),
                         ("threshold = 0.3", "threshold = nan"),
                         ('effect = "limit"', 'effect = "allow"'),
                         ('catalog = "limited"', 'catalog = "admin"'),
                         ("names_org =", "unknown ="),
                         ("new_agent_days = 30", "new_agent_days = 30\nthreshold = 0.5")):
            with self.subTest(new=new), tempfile.NamedTemporaryFile("w") as f:
                f.write(text.replace(old, new)); f.flush()
                with self.assertRaises(ValueError):
                    load_policy(f.name)

    def test_model_payload_and_answer_validation(self):
        answers = {k: {"type": "noul", "noul": v} for k, v in CALM.items()}
        seen = []
        self.assertEqual(model_reply({"answers": answers}, seen), CALM)
        self.assertEqual(set(seen[0]["questions"]), set(CALM))
        self.assertTrue(seen[0]["independent"])
        self.assertEqual(seen[0]["state"], counterparty("alice.test", "bob.test", "VALID"))
        for bad in (math.nan, math.inf, 10**1000, 1.5, -0.1, True, "0.2", None):
            with self.subTest(bad=bad), self.assertRaises((ValueError, TypeError)):
                model_reply({"answers": answers | {"names_org": {"type": "noul", "noul": bad}}}, [])
        with self.assertRaises(ValueError):
            model_reply({"answers": answers | {"names_org": {"type": "choice", "noul": 0.2}}}, [])
        with self.assertRaises(KeyError):
            model_reply({"answers": {}}, [])

    def test_local_model_defaults_and_endpoint_overrides(self):
        async def check(env, endpoint, model, authorization):
            def handle(request):
                self.assertEqual(str(request.url), endpoint)
                self.assertEqual(json.loads(request.content)["model"], model)
                self.assertEqual(request.headers.get("authorization"), authorization)
                return httpx.Response(200, json={"answers": {
                    k: {"type": "noul", "noul": v} for k, v in CALM.items()}})
            with patch.dict("os.environ", env, clear=True):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
                    self.assertEqual(await ask_model(http, POLICY, {}), CALM)
        asyncio.run(check({}, "http://127.0.0.1:8080/v1/systemone", "clef-flash", None))
        asyncio.run(check({"JEV_ENDPOINT": "https://classifier.example/v1/systemone",
                          "JEV_MODEL": "jev-latest", "JEV_API_KEY": "test-key"},
                         "https://classifier.example/v1/systemone", "jev-latest", "Bearer test-key"))

    def test_unicode_and_domain_relationships(self):
        signals = name_signals("xn--pypal-billing-w1k.com")
        self.assertEqual(signals["name_skeleton"], "paypal-billing.com")
        self.assertTrue(signals["mixed_script"])
        self.assertIn("漢", name_signals("漢.test")["name_skeleton"])
        for domain, label in (("alice.test", "self-accounted"), ("dnsid.alice.test", "hosted"), ("bob.test", "delegated")):
            self.assertTrue(counterparty(domain, "alice.test", "VALID")["relationship"].startswith(label))

    def test_unreadable_lifecycle_is_missing_history(self):
        verified = SimpleNamespace(domain="alice.test", record=SimpleNamespace(gi="bob.test"),
                                   dnssec_state=SimpleNamespace(name="VALID"), log_reader=None)
        self.assertIsNone(facts_from_verified(verified)["agent_history"])
        with self.assertRaises(ValueError):
            history_facts([KeyRotationEvent(timestamp=T0)], T0)


if __name__ == "__main__":
    unittest.main()
