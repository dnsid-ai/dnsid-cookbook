#!/usr/bin/env python3
from __future__ import annotations

import boto3
from dnsid import identity_manager_from_cli_directory

from orders_common.config import load_settings


def main() -> None:
    settings = load_settings()
    if not settings.dnsid_log_policy_url:
        raise ValueError("DNSID_LOG_POLICY_URL is required trusted verifier configuration")
    identity = identity_manager_from_cli_directory(settings.dnsid_config_dir or None)
    account = boto3.client("sts", region_name=settings.aws_region).get_caller_identity()["Account"]
    print(f"✓ DNSid identity loaded: {identity.local_domain}")
    print(f"✓ independently trusted log policy configured: {settings.dnsid_log_policy_url}")
    print(f"✓ AWS account available: {account} ({settings.agentcore_region})")


if __name__ == "__main__":
    main()
