"""Invariants of the trust layer. No local registry, SDK or model needed."""

import asyncio
import datetime as dt
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from facts import FactSettings, Interaction, build_facts, name_signals, read_history, relationship, summarise  # noqa: E402
from trust import DecisionClient, Policy, Tier, TrustEvaluator, clause_scores, decide, questions  # noqa: E402

POLICY = Policy.load()
READ = Interaction("inbound", "read the public product catalog", "none")
T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


class IssuanceEvent(SimpleNamespace):
    pass


class KeyRotationEvent(SimpleNamespace):
    pass


def calm(**overrides):
    return {c.name: 0.01 for c in POLICY.clauses} | overrides


def naming(**overrides):
    return {"names_org": 0.01, "acts_for": 0.01, "same_org": 0.99} | overrides


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self.body


class FakeHttp:
    def __init__(self, answers):
        self.answers, self.calls = answers, 0
        self.requests = []

    async def post(self, url, json, headers):
        self.calls += 1
        self.requests.append(json)
        return FakeResponse({"answers": {k: {"type": "noul", "noul": v} for k, v in self.answers.items()}})


def verified(events=None):
    reader = SimpleNamespace(rebuild_history=lambda domain: events) if events is not None else None
    return SimpleNamespace(domain="acme-billing.test", record=SimpleNamespace(gi="dnsid.test"),
                           dnssec_state=SimpleNamespace(name="UNSIGNED"), log_reader=reader)


class DecideTests(unittest.TestCase):
    def test_nothing_fired_is_trusted(self):
        self.assertEqual(decide(POLICY, calm(), history_available=True).tier, Tier.TRUSTED)

    def test_each_clause_applies_its_own_effect(self):
        for c in POLICY.clauses:
            d = decide(POLICY, calm(**{c.name: 0.99}), history_available=True)
            self.assertEqual(d.tier, c.effect)
            self.assertIn(c.name, d.reasons)

    def test_most_restrictive_wins(self):
        d = decide(POLICY, calm(unproven=0.99, impersonation=0.99), history_available=True)
        self.assertEqual(d.tier, Tier.UNTRUSTED)

    def test_missing_history_caps_at_limited_whatever_the_model_says(self):
        d = decide(POLICY, calm(), history_available=False)
        self.assertEqual(d.tier, Tier.LIMITED)
        self.assertIn("history_unavailable", d.reasons)

    def test_threshold_is_inclusive(self):
        c = POLICY.clauses[0]
        self.assertIn(c.name, decide(POLICY, calm(**{c.name: c.threshold}), history_available=True).reasons)


class PolicyTests(unittest.TestCase):
    def load(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".toml") as f:
            f.write(text)
            f.flush()
            return Policy.load(f.name)

    def test_rejects_unknown_effect(self):
        with self.assertRaises(ValueError):
            self.load('version="v"\n[clauses.x]\neffect="allow"\ntext="' + "a" * 30 + '"\n')

    def test_rejects_empty_policy(self):
        with self.assertRaises(ValueError):
            self.load('version="v"\n')

    def test_rejects_invalid_age_thresholds(self):
        for bad in (0, -1, True, 1.5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                FactSettings(new_agent_days=bad)

    def test_rejects_unknown_evaluator(self):
        text = Path(__file__).resolve().parent.parent.joinpath("policy.toml").read_text()
        with self.assertRaises(ValueError):
            self.load(text.replace('evaluated_by = "code"', 'evaluated_by = "model"'))


class DecisionClientTests(unittest.TestCase):
    def test_rejects_malformed_answers(self):
        for bad in (math.nan, 1.5, -0.1, True, "0.2", None):
            client = DecisionClient(FakeHttp(naming(names_org=bad)), "http://x", "m", None)
            with self.subTest(bad=bad), self.assertRaises((ValueError, TypeError)):
                asyncio.run(client.ask({"counterparty": {}}, POLICY))

    def test_rejects_wrong_answer_type(self):
        class WrongHttp(FakeHttp):
            async def post(self, url, json, headers):
                return FakeResponse({"answers": {k: {"type": "other", "noul": v}
                                                 for k, v in self.answers.items()}})

        with self.assertRaises(ValueError):
            asyncio.run(DecisionClient(WrongHttp(naming()), "http://x", "m", None).ask({"counterparty": {}}, POLICY))

    def test_rejects_missing_answer(self):
        answers = naming()
        answers.pop("names_org")
        with self.assertRaises(KeyError):
            asyncio.run(DecisionClient(FakeHttp(answers), "http://x", "m", None).ask({"counterparty": {}}, POLICY))


    def test_sends_only_naming_facts_and_three_short_questions(self):
        http = FakeHttp(naming())
        facts = {"counterparty": name_signals("paypal.test"), "agent_history": "private", "interaction": "private"}
        asyncio.run(DecisionClient(http, "http://x", "m", None).ask(facts, POLICY))
        body = http.requests[0]
        self.assertEqual(body["state"], facts["counterparty"])
        self.assertEqual(set(body["questions"]), {"names_org", "same_org", "acts_for"})
        self.assertTrue(body["independent"])
        self.assertNotIn("unproven", questions(POLICY))


class MechanicalTests(unittest.TestCase):
    def test_all_labelled_mechanical_rules(self):
        for path in Path(__file__).resolve().parent.parent.joinpath("cases").glob("*.json"):
            case = json.loads(path.read_text())
            # Model cannot override either deterministic rule, even if it returns extras.
            scores = clause_scores(POLICY, case["facts"], naming(unproven=0.99, takeover_risk=0.99))
            for name in ("unproven", "takeover_risk"):
                if name in case["expected"]["clauses"]:
                    with self.subTest(case=path.stem, clause=name):
                        self.assertEqual(bool(scores[name]), case["expected"]["clauses"][name])

    def test_sensitive_impacts_and_unknown_impact(self):
        facts = json.loads(Path(__file__).resolve().parent.parent.joinpath("cases/recent_rotation_money.json").read_text())["facts"]
        for impact in ("moves money", "exposes credentials", "shares personal data", "none", "low"):
            facts["interaction"]["impact"] = impact
            self.assertEqual(bool(clause_scores(POLICY, facts, naming())["takeover_risk"]),
                             impact not in ("none", "low"))
        facts["interaction"]["impact"] = "unknown"
        with self.assertRaises(ValueError):
            clause_scores(POLICY, facts, naming())

    def test_impersonation_requires_all_three_signals(self):
        facts = json.loads(Path(__file__).resolve().parent.parent.joinpath("cases/brand_own_domain.json").read_text())["facts"]
        suspicious = naming(names_org=0.99, acts_for=0.99, same_org=0.01)
        self.assertGreaterEqual(clause_scores(POLICY, facts, suspicious)["impersonation"], 0.3)
        for override in ({"names_org": 0.01}, {"acts_for": 0.01}, {"same_org": 0.99}):
            self.assertLess(clause_scores(POLICY, facts, suspicious | override)["impersonation"], 0.3)

    def test_homoglyph_signal_preserves_unknown_characters(self):
        signals = name_signals("xn--pypal-billing-w1k.com")
        self.assertEqual(signals["name_skeleton"], "paypal-billing.com")
        self.assertTrue(signals["mixed_script"])
        self.assertFalse(name_signals("paypal.com")["mixed_script"])
        self.assertIn("漢", name_signals("漢.test")["name_skeleton"])

    def test_age_and_rotation_boundaries_and_migration(self):
        for kind in ("key rotation", "migration", "issuance"):
            for age, recent in ((6.9999, True), (7, False)):
                h = summarise([IssuanceEvent(timestamp=T0)])
                h = SimpleNamespace(**(vars(h) | {"key_introduced_by": kind,
                    "key_introduced_at": T0 + dt.timedelta(days=30 - age)}))
                facts = build_facts(domain="alice.test", gi="bob.test", dnssec="VALID", history=h,
                                    interaction=READ, settings=FactSettings(), now=T0 + dt.timedelta(days=30))
                self.assertFalse(facts["agent_history"]["is_new"])
                self.assertEqual(facts["agent_history"]["recent_key_rotation"], recent and kind == "key rotation")
        facts = build_facts(domain="alice.test", gi="bob.test", dnssec="VALID", history=h,
                            interaction=READ, settings=FactSettings(), now=T0 + dt.timedelta(days=29.9999))
        self.assertTrue(facts["agent_history"]["is_new"])
        self.assertTrue(facts["agent_history"]["identity_age"].startswith("new:"))


class HistoryTests(unittest.TestCase):
    def test_summarises_rotation(self):
        h = summarise([IssuanceEvent(timestamp=T0), KeyRotationEvent(timestamp=T0 + dt.timedelta(days=3))])
        self.assertEqual((h.rotations, h.key_introduced_by, h.issued_at), (1, "key rotation", T0))

    def test_millisecond_timestamps(self):
        h = summarise([IssuanceEvent(timestamp=int(T0.timestamp() * 1000))])
        self.assertEqual(h.issued_at, T0)

    def test_unreadable_history_is_none(self):
        self.assertIsNone(read_history(verified()))
        self.assertIsNone(read_history(verified([KeyRotationEvent(timestamp=T0)])))

    def test_relationship(self):
        self.assertTrue(relationship("a.example", "a.example").startswith("self-accounted"))
        self.assertTrue(relationship("dnsid.alice.test", "alice.test").startswith("hosted"))
        self.assertTrue(relationship("bob.test", "alice.test").startswith("delegated"))


class EvaluatorTests(unittest.TestCase):
    def test_cache_is_busted_by_new_lifecycle_event(self):
        http = FakeHttp(naming())
        ev = TrustEvaluator(POLICY, DecisionClient(http, "http://x", "m", None), cache_seconds=60)
        events = [IssuanceEvent(timestamp=T0)]
        asyncio.run(ev.evaluate(verified(events), READ))
        asyncio.run(ev.evaluate(verified(events), READ))
        self.assertEqual(http.calls, 1)
        events.append(KeyRotationEvent(timestamp=T0 + dt.timedelta(days=1)))
        asyncio.run(ev.evaluate(verified(events), READ))
        self.assertEqual(http.calls, 2)

    def test_cases_match_the_fact_builder_shape(self):
        paths = list((Path(__file__).resolve().parent.parent / "cases").glob("*.json"))
        self.assertTrue(paths, "eval needs labelled cases")
        for path in paths:
            case = json.loads(path.read_text("utf-8"))
            self.assertEqual(set(case["facts"]),
                             {"counterparty", "agent_history", "accountable_entity_history", "interaction"})
            self.assertIn(case["expected"]["tier"], {"trusted", "limited", "untrusted"})


if __name__ == "__main__":
    unittest.main()
