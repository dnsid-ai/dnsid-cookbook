"""Run from recipe root: .venv/bin/python -m unittest discover -s verify"""

import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agent_card import A2A_VERSION, DNSID_A2A_EXTENSION_URI
from middleware import DnsidSignatureMiddleware


class SignedTargetTest(unittest.TestCase):
    def test_forwarded_headers_cannot_change_verified_target(self):
        received = []

        async def app(scope, receive, send):
            received.append(scope["_dnsid_sender"].user_name)

        sig = Mock()
        sig.verify_signed_http_request.return_value = SimpleNamespace(domain="sender.example")
        middleware = DnsidSignatureMiddleware(
            app, SimpleNamespace(local_domain="service.example"), sig,
            "https://service.example",
        )
        scope = {
            "type": "http", "method": "POST", "path": "/", "query_string": b"q=1",
            "headers": [
                (b"Host", b"forged.example"),
                (b"x-forwarded-host", b"forged.example"),
                (b"x-forwarded-proto", b"http"),
                (b"a2a-version", A2A_VERSION.encode()),
                (b"a2a-extensions", DNSID_A2A_EXTENSION_URI.encode()),
            ],
        }

        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def send(message):
            pass

        asyncio.run(middleware(scope, receive, send))
        request = sig.verify_signed_http_request.call_args.args[0]
        self.assertEqual(request.url, "https://service.example/?q=1")
        self.assertEqual(request.get_header("host"), "service.example")
        self.assertEqual(received, ["sender.example"])


if __name__ == "__main__":
    unittest.main()
