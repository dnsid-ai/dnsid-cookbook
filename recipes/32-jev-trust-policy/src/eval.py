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
from pathlib import Path

import httpx

from trust import DecisionClient, Policy, decide


async def main(argv: list[str]) -> int:
    strict = "--strict" in argv
    folder = Path(next((a for a in argv if not a.startswith("--")), "cases"))
    policy = Policy.load(os.getenv("TRUST_POLICY") or Path(__file__).resolve().parent.parent / "policy.toml")
    fixture = False

    async def spot_fixture(response: httpx.Response) -> None:
        nonlocal fixture
        fixture |= response.headers.get("x-recipe-fixture") == "1"

    async with httpx.AsyncClient(timeout=60, event_hooks={"response": [spot_fixture]}) as http:
        client = DecisionClient(http, os.getenv("JEV_ENDPOINT", "http://127.0.0.1:8791/v1/systemone"),
                                os.getenv("JEV_MODEL", "jev-latest"), os.getenv("JEV_API_KEY"))
        clause_hits = clause_total = tier_hits = 0
        cases = sorted(folder.glob("*.json"))
        if not cases:
            raise ValueError(f"no labelled cases in {folder}")
        for path in cases:
            case = json.loads(path.read_text("utf-8"))
            facts, expected = case["facts"], case["expected"]
            probabilities = await client.ask(facts, policy)
            decision = decide(policy, probabilities,
                              history_available=isinstance(facts["agent_history"], dict))
            marks = []
            for c in policy.clauses:
                if c.name not in expected["clauses"]:
                    continue
                fired, want = probabilities[c.name] >= c.threshold, expected["clauses"][c.name]
                clause_total += 1
                clause_hits += fired == want
                marks.append(f"{c.name}={probabilities[c.name]:.2f}{'' if fired == want else '(!)'}")
            tier_ok = decision.tier.name.lower() == expected["tier"]
            tier_hits += tier_ok
            print(f"{'ok  ' if tier_ok else 'MISS'} {path.stem:32} tier={decision.tier.name.lower():9} "
                  f"want={expected['tier']:9} {' '.join(marks)}")

    print(f"\nclauses {clause_hits}/{clause_total}   tiers {tier_hits}/{len(cases)}   policy {policy.version}")
    if fixture:
        print("warning: these answers came from the fixture server, not a model")
    return 1 if strict and tier_hits != len(cases) else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
