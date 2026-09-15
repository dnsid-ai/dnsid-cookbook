#!/usr/bin/env python3
from __future__ import annotations

import json
import sys

from gateway_resources import (
    GATEWAY_NAME,
    BEDROCK_REGION,
    PREFIX,
    PROVISIONAL_AUDIENCE,
    REGION,
    TARGET_NAME,
    account_id,
    create_or_update_gateway,
    create_or_update_lambda,
    create_or_update_role,
    gateway_role_policy,
    package_lambda,
    protected_resource_metadata,
    require_dnsid_agent_domain,
    save_state,
    target_lambda_policy,
    ensure_gateway_target,
    verified_gateway_audience,
    wait_gateway_ready,
)


def main() -> int:
    require_dnsid_agent_domain()
    account = account_id()
    print(f"deploying OIDC image resources in account {account}, region {REGION}")
    zip_path = package_lambda()

    target_role_arn = create_or_update_role(
        f"{PREFIX}-target-role",
        "lambda.amazonaws.com",
        f"{PREFIX}-target-policy",
        target_lambda_policy(),
    )
    target_lambda_arn = create_or_update_lambda(
        f"{PREFIX}-target",
        target_role_arn,
        zip_path,
    )
    gateway_role_arn = create_or_update_role(
        f"{PREFIX}-gateway-role",
        "bedrock-agentcore.amazonaws.com",
        f"{PREFIX}-gateway-policy",
        gateway_role_policy(target_lambda_arn),
    )

    gateway = create_or_update_gateway(gateway_role_arn, PROVISIONAL_AUDIENCE)
    gateway_id = gateway["gatewayId"]
    gateway = wait_gateway_ready(gateway_id)
    gateway_url = gateway["gatewayUrl"]
    audience = verified_gateway_audience(gateway_url, protected_resource_metadata(gateway_url))

    gateway = create_or_update_gateway(gateway_role_arn, audience)
    gateway = wait_gateway_ready(gateway_id)
    target = ensure_gateway_target(gateway_id, target_lambda_arn)

    state = {
        "account_id": account,
        "region": REGION,
        "bedrock_region": BEDROCK_REGION,
        "gateway_name": GATEWAY_NAME,
        "gateway_id": gateway_id,
        "gateway_arn": gateway.get("gatewayArn"),
        "gateway_url": gateway_url,
        "gateway_audience": audience,
        "gateway_role_arn": gateway_role_arn,
        "target_lambda_arn": target_lambda_arn,
        "target_lambda_role_arn": target_role_arn,
        "gateway_target_id": target["targetId"],
        "gateway_target_name": TARGET_NAME,
        "authorizer_type": "CUSTOM_JWT",
        "target_type": "lambda",
        "interceptor": "none",
        "api_gateway": "none",
    }
    save_state(state)
    print(json.dumps({"status": "ok", **state}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"deploy failed: {exc}", file=sys.stderr)
        raise
