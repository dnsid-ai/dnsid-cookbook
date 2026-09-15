import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import deploy_gateway  # noqa: E402


def test_deploy_requires_dnsid_agent_domain_before_aws_work(monkeypatch):
    monkeypatch.setenv("DNSID_AGENT_DOMAIN", "")

    def fail_account_id():
        raise AssertionError("account_id should not be called before DNSID_AGENT_DOMAIN validation")

    monkeypatch.setattr(deploy_gateway, "account_id", fail_account_id)

    with pytest.raises(ValueError, match="DNSID_AGENT_DOMAIN"):
        deploy_gateway.main()
