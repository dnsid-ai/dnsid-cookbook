"""Measure a real decision model against the labelled fact sheets in cases/.

  JEV_ENDPOINT=http://127.0.0.1:8080/v1/systemone uv run python src/eval.py [cases/] [--strict]

Cases contain raw domains, ages and an operation, plus expected rule matches
and tiers for the default policy. The same code applies policy windows live
and offline. No registry is needed; these cases are not a calibration set.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import httpx

from facts import counterparty
from trust import ask_model, decide, load_policy


async def main(argv: list[str]) -> int:
    strict = "--strict" in argv
    folder = Path(next((a for a in argv if not a.startswith("--")), "cases"))
    policy = load_policy()
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
        clause_hits = clause_total = tier_hits = 0
        cases = sorted(folder.glob("*.json"))
        if not cases:
            raise ValueError(f"no labelled cases in {folder}")
        for path in cases:
            case = json.loads(path.read_text("utf-8"))
            facts, expected = case["facts"], case["expected"]
            cp = facts["counterparty"]
            facts["counterparty"] = counterparty(cp["agent_name"], cp["accountable_entity"], cp["dnssec"])
            answers = await ask_model(http, policy, facts["counterparty"])
            decision = decide(policy, facts, answers, case["operation"])
            marks = []
            for name, want in expected["clauses"].items():
                fired = name in decision.reasons
                clause_total += 1
                clause_hits += fired == want
                marks.append(f"{name}={fired}{'' if fired == want else '(!)'}")
            tier_ok = decision.tier.name.lower() == expected["tier"]
            tier_hits += tier_ok
            print(f"{'ok  ' if tier_ok else 'MISS'} {path.stem:32} tier={decision.tier.name.lower():9} "
                  f"want={expected['tier']:9} {' '.join(marks)} "
                  + " ".join(f"{k}={v:.2f}" for k, v in answers.items()), flush=True)

    print(f"\nmodel {', '.join(sorted(served_models)) or os.getenv('JEV_MODEL', 'decider-12b')}   "
          f"clauses {clause_hits}/{clause_total}   tiers {tier_hits}/{len(cases)}   "
          f"policy {policy['version']}   seconds {time.monotonic() - started:.1f}")
    if fixture:
        print("warning: these answers came from the fixture server, not a model")
    return 1 if strict and (fixture or tier_hits != len(cases) or clause_hits != clause_total) else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
