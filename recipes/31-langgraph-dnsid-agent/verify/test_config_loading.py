"""Run from recipe root: uv run python -m unittest discover -s verify"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import lifecycle


class ConfigLoadingTest(unittest.TestCase):
    def test_local_zone_is_not_the_agents_governance_identity(self):
        env = {
            "DNSID_DOMAIN": "graph.test",
            "DNSID_GOVERNANCE_ID": "graph.test",
            "DNSID_PRIVATE_HOSTS": ".test",
            "DNSID_LOG_REF": "c2sp-tlog:testnet:https://registry.test#graph.test",
            "DNSID_LOG_POLICY_URL": "https://registry.test/dnsid-policy",
            "DNSID_STATUS_URL": "https://registry.test/v1/status/graph.test",
            "DNSID_REGISTRY_URL": "https://registry.test",
            "DNSID_API_KEY": "testnet",
            "DNSID_CONFIG_DIR": "/provisioned/identity",
            "DNSID_AGENT_PORT": "3101",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(lifecycle.LocalKeyProvider, "from_cli_directory", return_value=Mock()),
            patch.object(lifecycle, "make_log_registry", return_value=Mock()),
            patch.object(lifecycle, "identity_manager_from_environment") as build,
            patch.object(lifecycle, "RegistryClient"),
        ):
            lifecycle.load_identity()
        config = build.call_args.kwargs["overlay"]
        self.assertEqual(config.identity.governance_id, "graph.test")
        self.assertEqual(config.transport.private_address_hosts, frozenset({".test"}))


if __name__ == "__main__":
    unittest.main()
