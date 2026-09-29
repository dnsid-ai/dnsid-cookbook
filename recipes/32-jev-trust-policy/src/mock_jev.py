"""Protocol smoke-test stub, NOT a trust model. Never use for real decisions."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        state = json.loads(self.rfile.read(int(self.headers["Content-Length"])))['state']
        evidence, request = state["evidence"], state["context"]["body"]
        # ponytail: fixture-only string matches; use a calibrated model for semantic trust.
        is_peer = evidence["domain"] == "peer.dev.dnsid.test"
        routine = request.get("purpose") == "check service health"
        injection = "SYSTEM:" in request.get("details", "")
        assert evidence["request_signature_verified"] is True
        assert evidence["log_freshness"] and state["policy"]
        data = json.dumps({"answers": {
            "permit": {"type": "noul", "noul": 0.95 if is_peer and routine and not injection else 0.1},
            "injection": {"type": "noul", "noul": 0.99 if injection else 0.01},
        }}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print("fixture decision server listening on 127.0.0.1:8791; NOT a trust model", flush=True)
    HTTPServer(("127.0.0.1", 8791), Handler).serve_forever()
