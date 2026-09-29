"""Invariants of the trust layer. Stdlib only; no local registry, SDK or model needed."""

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

from facts import Interaction, read_history, relationship, summarise  # noqa: E402
from trust import DecisionClient, Policy, Tier, TrustEvaluator, decide  # noqa: E402

POLICY = Policy.load()
READ = Interaction("inbound", "read the public product catalog", "none")
T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


class IssuanceEvent(SimpleNamespace):
    pass


class KeyRotationEvent(SimpleNamespace):
    pass


def calm(**overrides):
    return {c.name: 0.01 for c in POLICY.clauses} | overrides


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

    async def post(self, url, json, headers):
        self.calls += 1
        return FakeResponse({"answers": {k: {"type": "noul", "noul": v} for k, v in self.answers.items()}})


def verified(events=None):
    reader = SimpleNamespace(rebuild_history=lambda domain: events) if events is not None else None
    return SimpleNamespace(domain="acme-billing.dev.dnsid.test", record=SimpleNamespace(gi="dnsid.test"),
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
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(text)
        return Policy.load(f.name)

    def test_rejects_unknown_effect(self):
        with self.assertRaises(ValueError):
            self.load('version="v"\n[clauses.x]\neffect="allow"\ntext="' + "a" * 30 + '"\n')

    def test_rejects_empty_policy(self):
        with self.assertRaises(ValueError):
            self.load('version="v"\n')


class DecisionClientTests(unittest.TestCase):
    def test_rejects_malformed_answers(self):
        for bad in (math.nan, 1.5, -0.1, True, "0.2", None):
            client = DecisionClient(FakeHttp(calm(impersonation=bad)), "http://x", "m", None)
            with self.subTest(bad=bad), self.assertRaises((ValueError, TypeError)):
                asyncio.run(client.ask({}, POLICY))

    def test_rejects_wrong_answer_type(self):
        class WrongHttp(FakeHttp):
            async def post(self, url, json, headers):
                return FakeResponse({"answers": {k: {"type": "other", "noul": v}
                                                 for k, v in self.answers.items()}})

        with self.assertRaises(ValueError):
            asyncio.run(DecisionClient(WrongHttp(calm()), "http://x", "m", None).ask({}, POLICY))

    def test_rejects_missing_answer(self):
        answers = calm()
        answers.pop("impersonation")
        with self.assertRaises(KeyError):
            asyncio.run(DecisionClient(FakeHttp(answers), "http://x", "m", None).ask({}, POLICY))


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
        self.assertTrue(relationship("x.a.example", "a.example").startswith("hosted"))
        self.assertTrue(relationship("x.b.example", "a.example").startswith("delegated"))


class EvaluatorTests(unittest.TestCase):
    def test_cache_is_busted_by_new_lifecycle_event(self):
        http = FakeHttp(calm())
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
