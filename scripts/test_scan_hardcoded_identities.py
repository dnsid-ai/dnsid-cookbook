#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCAN_PATH = ROOT / "scripts" / "scan-hardcoded-identities.py"

spec = importlib.util.spec_from_file_location("scan_hardcoded_identities", SCAN_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("Could not load scan-hardcoded-identities.py")
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


def findings_for_text(text: str, path: str = "README.md") -> list[str]:
    return scan.findings_for(ROOT / path, text)


class ScanHardcodedIdentitiesTest(unittest.TestCase):
    def test_flags_real_account_and_concrete_dnsid_domain(self) -> None:
        account_id = "446872" + "464738"
        dnsid_subject = "4da8580c9975" + ".lab.dnsid" + ".dev"

        findings = findings_for_text(f"account {account_id}\nsubject {dnsid_subject}\n")

        self.assertTrue(any("real AWS account ID" in finding for finding in findings))
        self.assertTrue(any("concrete DNSid identity" in finding for finding in findings))

    def test_flags_known_legacy_tied_values(self) -> None:
        app_id = "381" + "8219"
        gateway_id = "githubreviewbot-reviewgateway-" + "i1e4rjp8d6"
        secret_name = "dnsid-github-app" + "/private-key"

        findings = findings_for_text(
            f"app {app_id}\ngateway {gateway_id}\nsecret {secret_name}\n",
            "recipes/28-bedrock-agentcore-github-review/README.md",
        )

        self.assertTrue(any("legacy GitHub App ID" in finding for finding in findings))
        self.assertTrue(any("legacy AgentCore Gateway ID" in finding for finding in findings))
        self.assertTrue(any("legacy GitHub App secret name" in finding for finding in findings))

    def test_allows_placeholders_and_product_endpoints(self) -> None:
        text = "\n".join(
            [
                "account 123456789012",
                "account <AWS_ACCOUNT_ID>",
                "issuer https://api.dev.dnsid.ai",
                "issuer https://oidc.dev.dnsid.ai",
                "status https://app.dnsid.ai/v1/status/<your-bot-domain>.dev.dnsid.ai",
                "domain <your-bot-domain>.dev.dnsid.ai",
            ]
        )

        self.assertEqual(findings_for_text(text), [])

    def test_skip_rules_cover_generated_and_dependency_paths(self) -> None:
        self.assertTrue(scan.should_skip(ROOT / "node_modules" / "package" / "index.js"))
        self.assertTrue(scan.should_skip(ROOT / ".venv" / "lib" / "module.py"))
        self.assertTrue(scan.should_skip(ROOT / "recipes" / "example" / "__pycache__" / "x.pyc"))
        self.assertFalse(scan.should_skip(ROOT / "recipes" / "example" / "README.md"))


if __name__ == "__main__":
    unittest.main()
