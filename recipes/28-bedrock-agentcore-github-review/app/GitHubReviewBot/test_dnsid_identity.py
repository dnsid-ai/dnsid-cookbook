from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

import dnsid_identity


class MintDnsidTokenTest(TestCase):
    @patch("dnsid_identity.OIDCProfile.from_identity_manager")
    @patch("dnsid_identity.identity_manager_from_dnsid")
    def test_uses_matching_server_side_identity(self, load_manager, make_profile):
        load_manager.return_value = SimpleNamespace(
            local_domain="bot.example.test"
        )
        make_profile.return_value.mint_oidc_token.return_value.access_token = "token"

        token = dnsid_identity.mint_dnsid_token(
            "audience", "bot.example.test", "https://issuer.example.test", "/identity"
        )

        self.assertEqual(token, "token")
        load_manager.assert_called_once_with("/identity")
        options = make_profile.return_value.mint_oidc_token.call_args.args[0]
        self.assertEqual(options.audience, "audience")
        self.assertIn("dnsid:review", options.scope)

    @patch("dnsid_identity.identity_manager_from_dnsid")
    def test_rejects_wrong_identity(self, load_manager):
        load_manager.return_value = SimpleNamespace(
            local_domain="other.example.test"
        )

        with self.assertRaisesRegex(ValueError, "does not match"):
            dnsid_identity.mint_dnsid_token(
                "audience", "bot.example.test", "https://issuer.example.test"
            )
