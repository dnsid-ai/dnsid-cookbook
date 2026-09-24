"""Run from recipe root: .venv/bin/python -m unittest discover -s verify"""

import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from middleware import DnsidSignatureMiddleware, TOOLS_VERIFY_OPTS


class SignedTargetTest(unittest.TestCase):
    def test_forwarded_headers_cannot_change_verified_target(self):
        received = []

        async def app(scope, receive, send):
            received.append(scope["_dnsid_sender"].user_name)

        sig = Mock()
        sig.verify_signed_http_request.return_value = SimpleNamespace(domain="sender.example")
        middleware = DnsidSignatureMiddleware(
            app, "tools.example", sig, TOOLS_VERIFY_OPTS,
            public_url="https://tools.example",  # Same middleware serves graph A2A ingress.
        )
        scope = {
            "type": "http", "method": "POST", "path": "/order", "query_string": b"q=1",
            "headers": [
                (b"Host", b"forged.example"),
                (b"x-forwarded-host", b"forged.example"),
                (b"x-forwarded-proto", b"http"),
            ],
        }

        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def send(message):
            pass

        asyncio.run(middleware(scope, receive, send))
        request = sig.verify_signed_http_request.call_args.args[0]
        self.assertEqual(request.url, "https://tools.example/order?q=1")
        self.assertEqual(request.get_header("host"), "tools.example")
        self.assertEqual(received, ["sender.example"])


if __name__ == "__main__":
    unittest.main()
