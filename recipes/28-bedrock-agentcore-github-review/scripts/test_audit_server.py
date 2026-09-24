"""Run: uv run --no-project --with 'pyjwt[crypto]' --with httpx python -m unittest discover -s scripts"""

import json
import time
import unittest
from unittest.mock import patch

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

import audit_server


class AuditAuthTest(unittest.TestCase):
    def test_rejects_untrusted_token_and_discovery(self):
        issuer = "https://issuer.example.test"
        audience = "http://localhost:9090"
        subject = "bot.example.test"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update(kid="test-key", use="sig", alg="RS256")
        discovery = {"issuer": issuer, "jwks_uri": issuer + "/.well-known/jwks.json"}
        requests = []

        def handler(request):
            requests.append(str(request.url))
            if request.url.path == "/.well-known/openid-configuration":
                return httpx.Response(200, json=discovery)
            return httpx.Response(200, json={"keys": [jwk]})

        client_type = httpx.Client

        def client(**kwargs):
            return client_type(transport=httpx.MockTransport(handler), **kwargs)

        def token(**overrides):
            claims = {"iss": issuer, "sub": subject, "aud": audience,
                      "iat": int(time.time()), "exp": int(time.time()) + 300}
            claims.update(overrides)
            return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})

        with patch.multiple(audit_server, ISSUER=issuer, SUBJECT=subject, AUDIENCE=audience), \
                patch.object(httpx, "Client", side_effect=client):
            self.assertEqual(audit_server._validate_token(token())["sub"], subject)
            for changed in ({"aud": "http://other.example"}, {"sub": "other.example"}):
                with self.assertRaises(ValueError):
                    audit_server._validate_token(token(**changed))
            requests.clear()
            with self.assertRaises(ValueError):
                audit_server._validate_token(token(iss="https://127.0.0.1"))
            self.assertEqual(requests, [])  # No request may depend on an untrusted iss.

            discovery["jwks_uri"] = "https://127.0.0.1/keys"
            with self.assertRaises(ValueError):
                audit_server._validate_token(token())
            self.assertEqual(requests, [issuer + "/.well-known/openid-configuration"])

            discovery["jwks_uri"] = issuer + "/.well-known/jwks.json"
            discovery["issuer"] = "https://other.example"
            with self.assertRaises(ValueError):
                audit_server._validate_token(token())
            with patch.object(audit_server, "SUBJECT", ""):
                with self.assertRaises(ValueError):
                    audit_server._validate_token(token())


if __name__ == "__main__":
    unittest.main()
