"""Measure a real decision model against the labelled fact sheets in cases/.

  JEV_ENDPOINT=http://127.0.0.1:8080/v1/systemone uv run python src/eval.py [cases/] [--strict]

Each case is a fact sheet exactly as src/facts.py builds it, plus the clauses
a careful human reviewer says apply and the resulting tier. No local registry
is needed. Use it to pick a model and tune thresholds before trusting either.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import httpx

from facts import name_signals
from trust import DecisionClient, Policy, clause_scores, decide


async def main(argv: list[str]) -> int:
    strict = "--strict" in argv
    folder = Path(next((a for a in argv if not a.startswith("--")), "cases"))
    policy = Policy.load(os.getenv("TRUST_POLICY") or Path(__file__).resolve().parent.parent / "policy.toml")
    fixture = False
    served_models = set()
    started = time.monotonic()

    async def spot_fixture(response: httpx.Response) -> None:
        nonlocal fixture
        fixture |= response.headers.get("x-recipe-fixture") == "1"
        await response.aread()
        if response.is_success and (model := response.json().get("model")):
            served_models.add(model)

    async with httpx.AsyncClient(timeout=60, event_hooks={"response": [spot_fixture]}) as http:
        client = DecisionClient(http, os.getenv("JEV_ENDPOINT", "http://127.0.0.1:8792/v1/systemone"),
                                os.getenv("JEV_MODEL", "decider-12b"), os.getenv("JEV_API_KEY"))
        clause_hits = clause_total = tier_hits = 0
        cases = sorted(folder.glob("*.json"))
        if not cases:
            raise ValueError(f"no labelled cases in {folder}")
        for path in cases:
            case = json.loads(path.read_text("utf-8"))
            facts, expected = case["facts"], case["expected"]
            # Rebuild Unicode signals from the DNS wire name, just as live code does.
            facts["counterparty"].update(name_signals(facts["counterparty"]["agent_name"]))
            answers = await client.ask(facts, policy)
            scores = clause_scores(policy, facts, answers)
            decision = decide(policy, scores,
                              history_available=isinstance(facts["agent_history"], dict))
            marks = []
            for c in policy.clauses:
                if c.name not in expected["clauses"]:
                    continue
                fired, want = scores[c.name] >= c.threshold, expected["clauses"][c.name]
                clause_total += 1
                clause_hits += fired == want
                marks.append(f"{c.name}={scores[c.name]:.2f}{'' if fired == want else '(!)'}")
            tier_ok = decision.tier.name.lower() == expected["tier"]
            tier_hits += tier_ok
            print(f"{'ok  ' if tier_ok else 'MISS'} {path.stem:32} tier={decision.tier.name.lower():9} "
                  f"want={expected['tier']:9} {' '.join(marks)} "
                  + " ".join(f"{k}={v:.2f}" for k, v in answers.items()), flush=True)

    print(f"\nmodel {', '.join(sorted(served_models)) or client.model}   "
          f"clauses {clause_hits}/{clause_total}   tiers {tier_hits}/{len(cases)}   "
          f"policy {policy.version}   seconds {time.monotonic() - started:.1f}")
    if fixture:
        print("warning: these answers came from the fixture server, not a model")
    return 1 if strict and (fixture or tier_hits != len(cases) or clause_hits != clause_total) else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
