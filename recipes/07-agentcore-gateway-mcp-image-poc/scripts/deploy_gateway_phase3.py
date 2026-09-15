#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from typing import Any

from botocore.exceptions import ClientError

from gateway_resources import (
    BEDROCK_REGION,
    DNSID_ISSUER,
    EXPECTED_DNSID_SUB,
    GATEWAY_NAME,
    PREFIX,
    PROVISIONAL_AUDIENCE,
    REGION,
    STAGE_NAME,
    TARGET_NAME,
    TRUSTED_REQUEST_HEADERS,
    account_id,
    allowed_target_execute_api_arns,
    client,
    create_or_update_lambda,
    create_or_update_role,
    ensure_bucket,
    ensure_lambda_permission,
    error_code,
    execute_api_arn,
    find_rest_api,
    gateway_authorizer_config,
    gateway_interceptors,
    gateway_protocol_config,
    get_gateway_by_name,
    import_or_update_rest_api,
    load_state,
    package_lambda,
    prune_lambda_permissions,
    protected_resource_metadata,
    render_openapi,
    require_dnsid_agent_domain,
    restrict_rest_api_to_gateway_role,
    rest_api_gateway_policy,
    rest_api_base_url,
    save_state,
    tags_dict,
    wait_for_lambda_update,
    wait_gateway_ready,
    wait_target_ready,
)


DISCOVERY_FILTER_MODE = "response_interceptor"


def main() -> int:
    global EXPECTED_DNSID_SUB
    EXPECTED_DNSID_SUB = require_dnsid_agent_domain()
    account = account_id()
    state = load_state()
    bucket = state.get("artifact_bucket") or f"dnsid-image-poc-{account}-{REGION}"
    prefix = state.get("artifact_prefix") or "phase3"
    print(f"deploying Phase 3 resources in account {account}, region {REGION}")

    ensure_bucket(bucket, REGION)
    zip_path = package_lambda()

    target_role_arn = create_or_update_role(
        f"{PREFIX}-target-role",
        "lambda.amazonaws.com",
        "phase3-target-lambda-policy",
        target_lambda_policy(bucket, prefix),
    )
    interceptor_role_arn = create_or_update_role(
        f"{PREFIX}-interceptor-role",
        "lambda.amazonaws.com",
        "phase3-interceptor-lambda-policy",
        interceptor_lambda_policy(),
    )

    target_function_name = f"{PREFIX}-target"
    interceptor_function_name = f"{PREFIX}-interceptor"
    target_arn = create_or_update_lambda(
        target_function_name,
        target_role_arn,
        "image_poc.aws_handler.lambda_handler",
        zip_path,
        {
            "ARTIFACT_BUCKET": bucket,
            "ARTIFACT_PREFIX": prefix,
            "BEDROCK_REGION": BEDROCK_REGION,
            "BEDROCK_IMAGE_MODEL_ID": "stability.sd3-5-large-v1:0",
            "EXPECTED_DNSID_SUB": EXPECTED_DNSID_SUB,
        },
    )
    interceptor_arn = create_or_update_lambda(
        interceptor_function_name,
        interceptor_role_arn,
        "image_poc.interceptor.lambda_handler",
        zip_path,
        {
            "EXPECTED_DNSID_SUB": EXPECTED_DNSID_SUB,
            "EXPECTED_DNSID_ISS": DNSID_ISSUER,
            "EXPECTED_GATEWAY_AUDIENCE": state.get("gateway_audience", PROVISIONAL_AUDIENCE),
            "FILTER_TOOLS_LIST": "true",
        },
        timeout=60,
    )

    api_name = f"{PREFIX}-api"
    existing_rest_api_id = existing_rest_api_id_by_state_or_name(
        state.get("rest_api_id"),
        api_name,
    )
    gateway_role_arn = None
    openapi_policy = None
    if existing_rest_api_id:
        gateway_role_arn = create_or_update_role(
            f"{PREFIX}-gateway-role",
            "bedrock-agentcore.amazonaws.com",
            "phase3-gateway-policy",
            gateway_role_policy(account, str(existing_rest_api_id), interceptor_arn),
        )
        openapi_policy = rest_api_gateway_policy(
            str(existing_rest_api_id),
            account,
            gateway_role_arn,
            REGION,
        )

    rest_api_id = import_or_update_rest_api(
        api_name,
        render_openapi(target_arn, REGION, resource_policy=openapi_policy),
        rest_api_id=existing_rest_api_id,
    )
    if gateway_role_arn is None:
        gateway_role_arn = create_or_update_role(
            f"{PREFIX}-gateway-role",
            "bedrock-agentcore.amazonaws.com",
            "phase3-gateway-policy",
            gateway_role_policy(account, rest_api_id, interceptor_arn),
        )
    restrict_rest_api_to_gateway_role(rest_api_id, account, gateway_role_arn, REGION)

    target_source_arns = allowed_target_execute_api_arns(account, rest_api_id, REGION)
    ensure_lambda_permission(
        target_function_name,
        "phase3-apigateway-invoke",
        target_source_arns[0],
    )
    ensure_lambda_permission(
        target_function_name,
        "phase3-apigateway-invoke-whoami",
        target_source_arns[1],
    )
    prune_lambda_permissions(
        target_function_name,
        {"phase3-apigateway-invoke", "phase3-apigateway-invoke-whoami"},
    )
    prune_lambda_permissions(interceptor_function_name, set())

    existing_gateway = get_gateway_by_name(GATEWAY_NAME)
    if existing_gateway:
        gateway_id = existing_gateway["gatewayId"]
        subject_enforcement = "gateway_custom_claims"
        gateway = wait_gateway_ready(gateway_id)
    else:
        gateway, subject_enforcement = ensure_gateway(
            gateway_role_arn,
            interceptor_arn,
            PROVISIONAL_AUDIENCE,
            include_custom_claims=True,
        )
        gateway_id = gateway["gatewayId"]
        gateway = wait_gateway_ready(gateway_id)
    gateway_url = gateway["gatewayUrl"]

    metadata = protected_resource_metadata(gateway_url)
    audience = verified_gateway_audience(gateway_url, metadata)

    gateway, subject_enforcement = update_gateway_authorizer(
        gateway_id,
        gateway_role_arn,
        interceptor_arn,
        audience,
        include_custom_claims=(subject_enforcement == "gateway_custom_claims"),
    )
    gateway = wait_gateway_ready(gateway_id)

    update_interceptor_audience(interceptor_function_name, audience)
    target = ensure_gateway_target(gateway_id, rest_api_id)

    state.update(
        {
            "account_id": account,
            "region": REGION,
            "artifact_bucket": bucket,
            "artifact_prefix": prefix,
            "target_lambda_role_arn": target_role_arn,
            "interceptor_lambda_role_arn": interceptor_role_arn,
            "target_lambda_arn": target_arn,
            "interceptor_lambda_arn": interceptor_arn,
            "rest_api_id": rest_api_id,
            "api_base_url": rest_api_base_url(rest_api_id, REGION),
            "gateway_role_arn": gateway_role_arn,
            "gateway_id": gateway_id,
            "gateway_arn": gateway.get("gatewayArn"),
            "gateway_url": gateway_url,
            "gateway_audience": audience,
            "discovery_filter_mode": DISCOVERY_FILTER_MODE,
            "native_discovery_filter_observed": False,
            "subject_enforcement": subject_enforcement,
            "gateway_target_id": target["targetId"],
            "gateway_target_name": TARGET_NAME,
            "stage": STAGE_NAME,
        }
    )
    save_state(state)
    print(
        json.dumps(
            {
                "status": "ok",
                "gateway_id": gateway_id,
                "gateway_url": gateway_url,
                "gateway_audience": audience,
                "discovery_filter_mode": DISCOVERY_FILTER_MODE,
                "subject_enforcement": subject_enforcement,
                "rest_api_id": rest_api_id,
                "target_id": target["targetId"],
                "state_path": str(state_path_for_output()),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def logs_policy_statement() -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Action": [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
        ],
        "Resource": "arn:aws:logs:*:*:*",
    }


def interceptor_lambda_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [logs_policy_statement()],
    }


def target_lambda_policy(bucket: str, prefix: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            logs_policy_statement(),
            {
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel"],
                "Resource": f"arn:aws:bedrock:{BEDROCK_REGION}::foundation-model/stability.sd3-5-large-v1:0",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject"],
                "Resource": f"arn:aws:s3:::{bucket}/{prefix}/*",
            },
        ],
    }


def gateway_role_policy(account: str, rest_api_id: str, interceptor_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "execute-api:Invoke",
                "Resource": allowed_target_execute_api_arns(account, rest_api_id, REGION),
            },
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": [interceptor_arn, f"{interceptor_arn}:*"],
            },
        ],
    }


def existing_rest_api_id_by_state_or_name(state_rest_api_id: Any, name: str) -> str | None:
    if state_rest_api_id:
        try:
            rest_api = client("apigateway").get_rest_api(restApiId=str(state_rest_api_id))
            return str(rest_api["id"])
        except ClientError as exc:
            if error_code(exc) != "NotFoundException":
                raise
    existing = find_rest_api(name)
    if not existing:
        return None
    return str(existing["id"])


def normalize_url(value: str) -> str:
    return value.rstrip("/")


def verified_gateway_audience(gateway_url: str, metadata: dict[str, Any]) -> str:
    audience = metadata.get("resource")
    if not audience or not isinstance(audience, str):
        raise RuntimeError("Gateway protected-resource metadata did not include resource.")
    if normalize_url(audience) != normalize_url(gateway_url):
        raise RuntimeError("Gateway protected-resource metadata did not match the Gateway MCP URL.")
    return audience


def ensure_gateway(
    role_arn: str,
    interceptor_arn: str,
    audience: str,
    include_custom_claims: bool,
) -> tuple[dict[str, Any], str]:
    agentcore = client("bedrock-agentcore-control")
    existing = get_gateway_by_name(GATEWAY_NAME)
    subject_enforcement = "gateway_custom_claims" if include_custom_claims else "downstream"
    if existing:
        gateway_id = existing["gatewayId"]
        gateway, subject_enforcement = update_gateway_authorizer(
            gateway_id,
            role_arn,
            interceptor_arn,
            audience,
            include_custom_claims=include_custom_claims,
        )
        return gateway, subject_enforcement

    params = gateway_params(role_arn, interceptor_arn, audience, include_custom_claims)
    try:
        return agentcore.create_gateway(**params), subject_enforcement
    except ClientError as exc:
        if not include_custom_claims or "custom" not in str(exc).lower():
            raise
        params = gateway_params(role_arn, interceptor_arn, audience, False)
        return agentcore.create_gateway(**params), "downstream"


def update_gateway_authorizer(
    gateway_id: str,
    role_arn: str,
    interceptor_arn: str,
    audience: str,
    include_custom_claims: bool,
) -> tuple[dict[str, Any], str]:
    agentcore = client("bedrock-agentcore-control")
    params = gateway_params(role_arn, interceptor_arn, audience, include_custom_claims)
    params.pop("clientToken", None)
    params.pop("tags", None)
    params["gatewayIdentifier"] = gateway_id
    try:
        return agentcore.update_gateway(**params), (
            "gateway_custom_claims" if include_custom_claims else "downstream"
        )
    except ClientError as exc:
        if not include_custom_claims or "custom" not in str(exc).lower():
            raise
        params = gateway_params(role_arn, interceptor_arn, audience, False)
        params["gatewayIdentifier"] = gateway_id
        params.pop("clientToken", None)
        params.pop("tags", None)
        return agentcore.update_gateway(**params), "downstream"


def gateway_params(
    role_arn: str,
    interceptor_arn: str,
    audience: str,
    include_custom_claims: bool,
) -> dict[str, Any]:
    return {
        "name": GATEWAY_NAME,
        "description": "Phase 3 DNSid MCP image PoC Gateway",
        "roleArn": role_arn,
        "protocolType": "MCP",
        "protocolConfiguration": gateway_protocol_config(),
        "authorizerType": "CUSTOM_JWT",
        "authorizerConfiguration": gateway_authorizer_config(
            audience,
            include_custom_claims=include_custom_claims,
        ),
        "interceptorConfigurations": gateway_interceptors(interceptor_arn),
        "tags": tags_dict(),
    }


def update_interceptor_audience(
    function_name: str,
    audience: str,
) -> None:
    lambda_client = client("lambda")
    lambda_client.update_function_configuration(
        FunctionName=function_name,
        Environment={
            "Variables": {
                "EXPECTED_DNSID_SUB": EXPECTED_DNSID_SUB,
                "EXPECTED_DNSID_ISS": DNSID_ISSUER,
                "EXPECTED_GATEWAY_AUDIENCE": audience,
                "FILTER_TOOLS_LIST": "true",
            }
        },
    )
    wait_for_lambda_update(function_name)


def ensure_gateway_target(gateway_id: str, rest_api_id: str) -> dict[str, Any]:
    agentcore = client("bedrock-agentcore-control")
    existing = None
    for target in agentcore.list_gateway_targets(gatewayIdentifier=gateway_id).get(
        "items", []
    ) + agentcore.list_gateway_targets(gatewayIdentifier=gateway_id).get("targets", []):
        if target.get("name") == TARGET_NAME:
            existing = target
            break

    config = target_params(gateway_id, rest_api_id)
    if existing:
        config["targetId"] = existing["targetId"]
        target = agentcore.update_gateway_target(**config)
    else:
        target = agentcore.create_gateway_target(**config)

    target_id = target.get("targetId") or existing["targetId"]
    target = wait_target_ready(gateway_id, target_id)
    try:
        agentcore.synchronize_gateway_targets(
            gatewayIdentifier=gateway_id,
            targetIdList=[target_id],
        )
    except ClientError as exc:
        if error_code(exc) not in {"ValidationException", "ConflictException"}:
            raise
    return wait_target_ready(gateway_id, target_id)


def target_params(gateway_id: str, rest_api_id: str) -> dict[str, Any]:
    return {
        "gatewayIdentifier": gateway_id,
        "name": TARGET_NAME,
        "description": "API Gateway target for DNSid image PoC tools",
        "targetConfiguration": {
            "mcp": {
                "apiGateway": {
                    "restApiId": rest_api_id,
                    "stage": STAGE_NAME,
                    "apiGatewayToolConfiguration": {
                        "toolOverrides": [
                            {
                                "name": "generate_image",
                                "description": "Generate a Bedrock image with trusted DNSid context.",
                                "path": "/generate-image",
                                "method": "POST",
                            },
                            {
                                "name": "whoami_dnsid",
                                "description": "Return trusted DNSid context visible to the target.",
                                "path": "/whoami-dnsid",
                                "method": "POST",
                            },
                        ],
                        "toolFilters": [
                            {"filterPath": "/generate-image", "methods": ["POST"]},
                            {"filterPath": "/whoami-dnsid", "methods": ["POST"]},
                        ],
                    },
                }
            }
        },
        "credentialProviderConfigurations": [
            {"credentialProviderType": "GATEWAY_IAM_ROLE"}
        ],
        "metadataConfiguration": {
            "allowedRequestHeaders": TRUSTED_REQUEST_HEADERS,
        },
    }


def state_path_for_output() -> str:
    from gateway_resources import STATE_PATH

    return STATE_PATH.relative_to(STATE_PATH.parents[2]).as_posix()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"deploy failed: {exc}", file=sys.stderr)
        raise
