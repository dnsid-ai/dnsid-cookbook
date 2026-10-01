"""Fixture /v1/systemone server for make verify. NOT a trust model.

Hard-coded naming signals exercise wiring and fail-closed checks only.
Mechanical rules live in trust.py, shared by live evaluation and make eval.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

# Scripted responses for the demo identities, not a naming classifier.
ANSWERS = {"api.test": (0.03, 0.03, 0.03), "acme-billing.test": (0.03, 0.03, 0.03),
           "paypal-refunds.test": (0.97, 0.03, 0.97)}
LOG = os.getenv("FIXTURE_LOG")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        cp, questions = request["state"], request["questions"]
        assert "agent_name" in cp and "agent_history" not in cp, cp
        assert set(questions) == {"names_org", "same_org", "acts_for"}
        assert all(q["type"] == "noul" and q["instructions"] for q in questions.values())
        answers = {name: {"type": "noul", "noul": p} for name, p in
                   zip(("names_org", "same_org", "acts_for"), ANSWERS[cp["agent_name"]])}
        if LOG:
            with open(LOG, "a") as f:
                f.write(json.dumps({"agent": cp["agent_name"], "answers": answers}) + "\n")
        data = json.dumps({"model": "recipe-fixture", "answers": answers}).encode()
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
