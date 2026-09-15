#!/usr/bin/env python3
from __future__ import annotations

import shutil
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from orders_common.config import load_settings
from scripts.deploy import API_NAME, GATEWAY_NAME, PREFIX, aws, error_code, find_api, find_gateway


def ignore_missing(call: Callable[..., Any], **kwargs: Any) -> None:
    try:
        call(**kwargs)
    except ClientError as exc:
        if error_code(exc) not in {
            "NotFoundException",
            "ResourceNotFoundException",
            "ResourceNotFoundFault",
            "NoSuchEntity",
            "ValidationException",
        }:
            raise


def main() -> None:
    settings = load_settings()
    agentcore = aws(settings, "bedrock-agentcore-control")
    gateway = find_gateway(settings)
    if gateway:
        gateway_id = gateway["gatewayId"]
        targets = agentcore.list_gateway_targets(gatewayIdentifier=gateway_id)
        for target in targets.get("items", []) + targets.get("targets", []):
            ignore_missing(
                agentcore.delete_gateway_target,
                gatewayIdentifier=gateway_id,
                targetId=target["targetId"],
            )
        for _ in range(60):
            remaining = agentcore.list_gateway_targets(gatewayIdentifier=gateway_id)
            if not remaining.get("items") and not remaining.get("targets"):
                break
            time.sleep(2)
        ignore_missing(agentcore.delete_gateway, gatewayIdentifier=gateway_id)

    api = find_api(settings)
    if api:
        ignore_missing(aws(settings, "apigateway").delete_rest_api, restApiId=api["id"])

    lambda_client = aws(settings, "lambda")
    logs = aws(settings, "logs")
    for name in (f"{PREFIX}-target", f"{PREFIX}-interceptor"):
        ignore_missing(lambda_client.delete_function, FunctionName=name)
        ignore_missing(logs.delete_log_group, logGroupName=f"/aws/lambda/{name}")

    ignore_missing(aws(settings, "dynamodb").delete_table, TableName=f"{PREFIX}-replay")

    iam = aws(settings, "iam", region=settings.aws_region)
    for name in (f"{PREFIX}-target-role", f"{PREFIX}-interceptor-role", f"{PREFIX}-gateway-role"):
        ignore_missing(iam.delete_role_policy, RoleName=name, PolicyName=f"{name}-policy")
        ignore_missing(iam.delete_role, RoleName=name)

    shutil.rmtree(settings.artifact_dir, ignore_errors=True)
    print(f"✓ removed {GATEWAY_NAME}, {API_NAME}, Lambdas, replay table, and roles")


if __name__ == "__main__":
    main()
