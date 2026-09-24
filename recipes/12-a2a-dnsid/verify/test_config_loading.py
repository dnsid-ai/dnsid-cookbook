"""Run from recipe root with the unreleased SDK on PYTHONPATH: .venv/bin/python -m unittest discover -s verify"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import identity


ENV = {
    "DNSID_DOMAIN": "alice.dev.dnsid.test",
    "DNSID_GOVERNANCE_ID": "dnsid.test",
    "DNSID_LOG_REF": "c2sp-tlog:testnet:https://registry.dev.dnsid.test#alice.dev.dnsid.test",
    "DNSID_STATUS_URL": "https://alice.dev.dnsid.test/status",
    "DNSID_LOG_POLICY_URL": "https://registry.dev.dnsid.test/policy",
    "DNSID_REGISTRY_URL": "https://registry.dev.dnsid.test",
    "DNSID_API_KEY": "secret",
    "DNSID_CONFIG_DIR": "/provisioned/identity",
    "DNSID_AGENT_PORT": "8080",
    "DNSID_PUBLIC_URL": "https://alice.dev.dnsid.test",
}


class ConfigLoadingTest(unittest.TestCase):
    def test_manager_receives_loaded_config_and_local_overrides(self):
        key = Mock()
        registry = Mock()
        with (
            patch.dict(os.environ, ENV, clear=True),
            patch.object(identity.LocalKeyProvider, "from_cli_directory", return_value=key) as load_key,
            patch.object(identity, "make_log_registry", return_value=registry),
            patch.object(identity, "identity_manager_from_environment") as build,
            patch.object(identity, "RegistryClient") as make_client,
        ):
            result = identity.load_identity()

        load_key.assert_called_once_with("/provisioned/identity")
        config = build.call_args.kwargs["overlay"]
        self.assertEqual(config.identity.capabilities_url, "https://alice.dev.dnsid.test/.well-known/agent-card.json")
        self.assertEqual(config.transport.private_address_hosts, frozenset({".dnsid.test"}))
        self.assertEqual(build.call_args.kwargs["deps"].log_registry, registry)
        self.assertEqual(build.call_args.kwargs["key_provider"], key)
        make_client.assert_called_once_with(ENV["DNSID_REGISTRY_URL"], api_key="secret")
        self.assertEqual(result.agent_port, 8080)
        self.assertEqual(result.public_url, ENV["DNSID_PUBLIC_URL"])

    def test_port_is_required_and_positive(self):
        for port in (None, "", "abc", "0"):
            env = {**ENV}
            if port is None:
                env.pop("DNSID_AGENT_PORT")
            else:
                env["DNSID_AGENT_PORT"] = port
            with self.subTest(port=port), patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(SystemExit, "DNSID_AGENT_PORT must be a positive integer"):
                    identity.load_identity()


if __name__ == "__main__":
    unittest.main()
