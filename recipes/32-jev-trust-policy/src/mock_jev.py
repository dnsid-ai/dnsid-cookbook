"""Fixture /v1/systemone server for `make verify`. NOT a trust model.

It answers the policy's clauses with hard-coded rules over the fact sheet, so
the wiring and fail-closed checks are deterministic. It understands nothing:
measure a real model with `make eval`.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

BRANDS = ("paypal", "stripe", "irs", "google", "microsoft", "amazon", "apple")
LOG = os.getenv("MOCK_JEV_LOG")


def impersonation(facts):
    cp = facts["counterparty"]
    entity = cp["accountable_entity"]
    name = cp.get("agent_name_unicode", cp["agent_name"]).removesuffix("." + entity)
    claims = any(b in name for b in BRANDS)
    return 0.97 if claims and not any(b in entity for b in BRANDS) else 0.03


def unproven(facts):
    history = facts["agent_history"]
    if isinstance(history, str):
        return 0.9
    new = history["identity_age"].startswith("new")
    return 0.9 if new and isinstance(facts["accountable_entity_history"], str) else 0.1


def takeover_risk(facts):
    history = facts["agent_history"]
    recent = isinstance(history, dict) and "(recent" in history["current_key"]
    return 0.9 if recent and facts["interaction"]["impact"] not in ("none", "low") else 0.05


RULES = {"impersonation": impersonation, "unproven": unproven, "takeover_risk": takeover_risk}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        facts, questions = request["state"], request["questions"]
        assert set(facts) >= {"counterparty", "agent_history", "interaction"}, facts
        assert all(q["type"] == "noul" and q["instructions"] for q in questions.values())
        answers = {name: {"type": "noul", "noul": RULES.get(name, lambda _: 0.01)(facts)} for name in questions}
        if LOG:
            with open(LOG, "a") as f:
                f.write(json.dumps({"agent": facts["counterparty"]["agent_name"], "answers": answers}) + "\n")
        data = json.dumps({"model": request.get("model"), "answers": answers}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Recipe-Fixture", "1")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("fixture decision server on 127.0.0.1:8791; NOT a trust model", flush=True)
    HTTPServer(("127.0.0.1", 8791), Handler).serve_forever()
