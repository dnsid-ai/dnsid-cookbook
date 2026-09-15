#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from gateway_resources import PREFIX, REGION, STATE_PATH, account_id, client, error_code, load_state


def main() -> int:
    state = load_state()
    if not state:
        print(json.dumps({"status": "noop", "reason": "state file not found"}))
        return 0
    current_account = account_id()
    state_account = str(state.get("account_id") or "")
    if state_account != current_account:
        raise RuntimeError(
            f"Refusing teardown: state account {state_account} does not match caller {current_account}."
        )

    deleted: list[str] = []
    gateway_id = str(state.get("gateway_id") or "")
    target_id = str(state.get("gateway_target_id") or "")
    if gateway_id and target_id:
        delete_gateway_target(gateway_id, target_id, deleted)
    if gateway_id:
        delete_gateway(gateway_id, deleted)

    for function_name in [f"{PREFIX}-target"]:
        delete_if_exists(
            f"lambda:{function_name}",
            deleted,
            lambda: client("lambda").delete_function(FunctionName=function_name),
            {"ResourceNotFoundException"},
        )

    for role_name, policy_name in [
        (f"{PREFIX}-target-role", f"{PREFIX}-target-policy"),
        (f"{PREFIX}-gateway-role", f"{PREFIX}-gateway-policy"),
    ]:
        iam = client("iam")
        delete_if_exists(
            f"iam-policy:{role_name}/{policy_name}",
            deleted,
            lambda role_name=role_name, policy_name=policy_name: iam.delete_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
            ),
            {"NoSuchEntity"},
        )
        delete_if_exists(
            f"iam-role:{role_name}",
            deleted,
            lambda role_name=role_name: iam.delete_role(RoleName=role_name),
            {"NoSuchEntity"},
        )

    delete_if_exists(
        f"logs:/aws/lambda/{PREFIX}-target",
        deleted,
        lambda: client("logs").delete_log_group(logGroupName=f"/aws/lambda/{PREFIX}-target"),
        {"ResourceNotFoundException"},
    )

    verification = verify_absent(state)
    print(
        json.dumps(
            {
                "status": "ok",
                "region": REGION,
                "state_path": str(STATE_PATH),
                "deleted": deleted,
                "verification": verification,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def delete_gateway_target(gateway_id: str, target_id: str, deleted: list[str]) -> None:
    agentcore = client("bedrock-agentcore-control")
    try:
        agentcore.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
        deleted.append(f"gateway-target:{target_id}")
    except ClientError as exc:
        if error_code(exc) != "ResourceNotFoundException":
            raise
    wait_until_not_found(
        lambda: agentcore.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        {"ResourceNotFoundException"},
    )


def delete_gateway(gateway_id: str, deleted: list[str]) -> None:
    agentcore = client("bedrock-agentcore-control")
    try:
        agentcore.delete_gateway(gatewayIdentifier=gateway_id)
        deleted.append(f"gateway:{gateway_id}")
    except ClientError as exc:
        if error_code(exc) != "ResourceNotFoundException":
            raise
    wait_until_not_found(
        lambda: agentcore.get_gateway(gatewayIdentifier=gateway_id),
        {"ResourceNotFoundException"},
    )


def delete_if_exists(
    label: str,
    deleted: list[str],
    operation: Callable[[], Any],
    not_found_codes: set[str],
) -> None:
    try:
        operation()
        deleted.append(label)
    except ClientError as exc:
        if error_code(exc) not in not_found_codes:
            raise


def wait_until_not_found(operation: Callable[[], Any], not_found_codes: set[str]) -> None:
    for _ in range(60):
        try:
            operation()
        except ClientError as exc:
            if error_code(exc) in not_found_codes:
                return
            raise
        time.sleep(5)
    raise TimeoutError("Timed out waiting for resource deletion.")


def verify_absent(state: dict[str, Any]) -> dict[str, str]:
    checks: dict[str, str] = {}
    gateway_id = str(state.get("gateway_id") or "")
    if gateway_id:
        checks["gateway"] = missing_code(
            lambda: client("bedrock-agentcore-control").get_gateway(
                gatewayIdentifier=gateway_id
            )
        )
    function_name = f"{PREFIX}-target"
    checks["lambda"] = missing_code(
        lambda: client("lambda").get_function(FunctionName=function_name)
    )
    for role_name in [f"{PREFIX}-target-role", f"{PREFIX}-gateway-role"]:
        checks[f"role:{role_name}"] = missing_code(
            lambda role_name=role_name: client("iam").get_role(RoleName=role_name)
        )
    checks["log-groups"] = json.dumps(
        client("logs").describe_log_groups(
            logGroupNamePrefix=f"/aws/lambda/{PREFIX}"
        ).get("logGroups", [])
    )
    return checks


def missing_code(operation: Callable[[], Any]) -> str:
    try:
        operation()
    except ClientError as exc:
        return error_code(exc)
    return "PRESENT"


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"teardown failed: {exc}", file=sys.stderr)
        raise
