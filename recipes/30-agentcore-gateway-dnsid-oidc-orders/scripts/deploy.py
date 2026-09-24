#!/usr/bin/env python3
from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from dnsid import identity_manager_from_dnsid

from orders_common.config import Settings, load_settings
from scripts.common import write_json


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "dnsid-order-proof"
GATEWAY_NAME = "DnsidOrderProofGateway"
TARGET_NAME = "OrderTarget"
API_NAME = f"{PREFIX}-api"
STAGE = "orders"
PROVISIONAL_AUDIENCE = "urn:amazon:bedrock-agentcore:gateway:dnsid-order-proof"
DNSID_DEPENDENCY = "dnsid @ git+https://github.com/dnsid-ai/dnsid-py@v0.19.1"


def aws(settings: Settings, service: str, *, region: str | None = None) -> Any:
    return boto3.client(
        service,
        region_name=region or settings.agentcore_region,
        config=Config(connect_timeout=10, read_timeout=120, retries={"max_attempts": 3, "mode": "standard"}),
    )


def error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def tags() -> dict[str, str]:
    return {"Project": "dnsid-cookbook", "Recipe": "30-agentcore-gateway-dnsid-oidc-orders"}


def iam_tags() -> list[dict[str, str]]:
    return [{"Key": key, "Value": value} for key, value in tags().items()]


def log_policy() -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:*",
    }


def ensure_role(settings: Settings, name: str, principal: str, policy: dict[str, Any]) -> str:
    iam = aws(settings, "iam", region=settings.aws_region)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    try:
        role = iam.get_role(RoleName=name)["Role"]
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust))
    except ClientError as exc:
        if error_code(exc) != "NoSuchEntity":
            raise
        role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=iam_tags())["Role"]
    iam.put_role_policy(RoleName=name, PolicyName=f"{name}-policy", PolicyDocument=json.dumps(policy))
    return str(role["Arn"])


def ensure_replay_table(settings: Settings, name: str) -> str:
    dynamodb = aws(settings, "dynamodb")
    try:
        table = dynamodb.describe_table(TableName=name)["Table"]
    except ClientError as exc:
        if error_code(exc) != "ResourceNotFoundException":
            raise
        table = dynamodb.create_table(
            TableName=name,
            AttributeDefinitions=[{"AttributeName": "nonce", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "nonce", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
            Tags=[{"Key": key, "Value": value} for key, value in tags().items()],
        )["TableDescription"]
        dynamodb.get_waiter("table_exists").wait(TableName=name)
        table = dynamodb.describe_table(TableName=name)["Table"]
    try:
        dynamodb.update_time_to_live(
            TableName=name,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "expires_at"},
        )
    except ClientError as exc:
        if error_code(exc) != "ValidationException":
            raise
    return str(table["TableArn"])


def package_lambda(settings: Settings) -> Path:
    build = settings.artifact_dir / "build"
    dependencies = build / "dependencies"
    shutil.rmtree(dependencies, ignore_errors=True)
    dependencies.mkdir(parents=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--quiet",
            "--target",
            str(dependencies),
            "--platform",
            "manylinux2014_x86_64",
            "--python-version",
            "3.12",
            "--implementation",
            "cp",
            "--only-binary=:all:",
            DNSID_DEPENDENCY,
        ],
        check=True,
    )
    path = build / "lambda.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for source in (dependencies, ROOT / "src"):
            for file in sorted(source.rglob("*")):
                if (
                    file.is_file()
                    and "__pycache__" not in file.parts
                    and not any(part.endswith(".egg-info") for part in file.parts)
                ):
                    archive.write(file, file.relative_to(source))
    return path


def wait_lambda(settings: Settings, name: str) -> None:
    client = aws(settings, "lambda")
    for _ in range(60):
        status = client.get_function_configuration(FunctionName=name)
        if status.get("LastUpdateStatus") in {None, "Successful"}:
            return
        if status.get("LastUpdateStatus") == "Failed":
            raise RuntimeError(str(status.get("LastUpdateStatusReason")))
        time.sleep(2)
    raise TimeoutError(f"timed out waiting for Lambda {name}")


def ensure_lambda(
    settings: Settings,
    name: str,
    role: str,
    handler: str,
    package: Path,
    environment: dict[str, str],
    *,
    memory: int = 256,
) -> str:
    client = aws(settings, "lambda")
    code = package.read_bytes()
    try:
        current = client.get_function(FunctionName=name)["Configuration"]
        client.update_function_code(FunctionName=name, ZipFile=code)
        wait_lambda(settings, name)
        client.update_function_configuration(
            FunctionName=name,
            Runtime="python3.12",
            Role=role,
            Handler=handler,
            Timeout=60,
            MemorySize=memory,
            Environment={"Variables": environment},
        )
        wait_lambda(settings, name)
        return str(current["FunctionArn"])
    except ClientError as exc:
        if error_code(exc) != "ResourceNotFoundException":
            raise
    result = client.create_function(
        FunctionName=name,
        Runtime="python3.12",
        Role=role,
        Handler=handler,
        Code={"ZipFile": code},
        Timeout=60,
        MemorySize=memory,
        Environment={"Variables": environment},
        Tags=tags(),
    )
    wait_lambda(settings, name)
    return str(result["FunctionArn"])


def render_openapi(settings: Settings, function_arn: str) -> bytes:
    document = json.loads((ROOT / "infra" / "orders.openapi.json").read_text())
    document["paths"]["/orders"]["post"]["x-amazon-apigateway-integration"] = {
        "type": "aws_proxy",
        "httpMethod": "POST",
        "uri": (
            f"arn:aws:apigateway:{settings.agentcore_region}:lambda:path/2015-03-31/"
            f"functions/{function_arn}/invocations"
        ),
    }
    return json.dumps(document).encode()


def find_api(settings: Settings) -> dict[str, Any] | None:
    client = aws(settings, "apigateway")
    for page in client.get_paginator("get_rest_apis").paginate():
        for item in page.get("items", []):
            if item.get("name") == API_NAME:
                return item
    return None


def ensure_api(settings: Settings, function_arn: str) -> str:
    client = aws(settings, "apigateway")
    body = render_openapi(settings, function_arn)
    existing = find_api(settings)
    if existing:
        api_id = existing["id"]
        client.put_rest_api(restApiId=api_id, mode="overwrite", failOnWarnings=False, body=body)
    else:
        api_id = client.import_rest_api(failOnWarnings=False, body=body, parameters={"endpointConfigurationTypes": "REGIONAL"})["id"]
        client.update_rest_api(restApiId=api_id, patchOperations=[{"op": "replace", "path": "/name", "value": API_NAME}])
    for attempt in range(6):
        try:
            client.create_deployment(restApiId=api_id, stageName=STAGE)
            break
        except ClientError as exc:
            if error_code(exc) not in {"TooManyRequestsException", "LimitExceededException"} or attempt == 5:
                raise
            time.sleep(2**attempt)
    return str(api_id)


def allow_api_gateway(settings: Settings, function_name: str, api_id: str, account: str) -> None:
    client = aws(settings, "lambda")
    try:
        client.add_permission(
            FunctionName=function_name,
            StatementId=f"{PREFIX}-api",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=f"arn:aws:execute-api:{settings.agentcore_region}:{account}:{api_id}/*/POST/orders",
        )
    except ClientError as exc:
        if error_code(exc) != "ResourceConflictException":
            raise


def find_gateway(settings: Settings) -> dict[str, Any] | None:
    client = aws(settings, "bedrock-agentcore-control")
    for page in client.get_paginator("list_gateways").paginate():
        for item in page.get("items", []) + page.get("gateways", []):
            if item.get("name") == GATEWAY_NAME:
                return item
    return None


def gateway_parameters(
    settings: Settings,
    role_arn: str,
    interceptor_arn: str,
    audience: str,
    subject: str,
    include_subject_claim: bool,
) -> dict[str, Any]:
    authorizer: dict[str, Any] = {
        "discoveryUrl": "https://oidc.dnsid.dev/.well-known/openid-configuration",
        "allowedAudience": [audience],
    }
    if include_subject_claim:
        authorizer["customClaims"] = [
            {
                "inboundTokenClaimName": "sub",
                "inboundTokenClaimValueType": "STRING",
                "authorizingClaimMatchValue": {
                    "claimMatchValue": {"matchValueString": subject},
                    "claimMatchOperator": "EQUALS",
                },
            }
        ]
    return {
        "name": GATEWAY_NAME,
        "description": "One order tool protected by DNSid",
        "roleArn": role_arn,
        "protocolType": "MCP",
        "protocolConfiguration": {
            "mcp": {
                "instructions": "Place a small order after DNSid verification.",
                "streamingConfiguration": {"enableResponseStreaming": False},
                "sessionConfiguration": {"sessionTimeoutInSeconds": 900},
            }
        },
        "authorizerType": "CUSTOM_JWT",
        "authorizerConfiguration": {"customJWTAuthorizer": authorizer},
        "interceptorConfigurations": [
            {
                "interceptor": {"lambda": {"arn": interceptor_arn}},
                "interceptionPoints": ["REQUEST"],
                "inputConfiguration": {"passRequestHeaders": True},
            }
        ],
        "tags": tags(),
    }


def ensure_gateway(
    settings: Settings,
    role_arn: str,
    interceptor_arn: str,
    audience: str,
    subject: str,
    include_subject_claim: bool = True,
) -> dict[str, Any]:
    client = aws(settings, "bedrock-agentcore-control")
    params = gateway_parameters(settings, role_arn, interceptor_arn, audience, subject, include_subject_claim)
    existing = find_gateway(settings)
    if existing:
        params["gatewayIdentifier"] = existing["gatewayId"]
        params.pop("tags")
        operation = client.update_gateway
    else:
        operation = client.create_gateway
    try:
        gateway = operation(**params)
    except ClientError as exc:
        if not include_subject_claim or "custom" not in str(exc).lower():
            raise
        return ensure_gateway(settings, role_arn, interceptor_arn, audience, subject, False)
    gateway_id = gateway.get("gatewayId") or existing["gatewayId"]
    for _ in range(90):
        gateway = client.get_gateway(gatewayIdentifier=gateway_id)
        if gateway.get("status") == "READY":
            return gateway
        if gateway.get("status") in {"FAILED", "DELETING"}:
            raise RuntimeError(f"Gateway entered {gateway.get('status')}")
        time.sleep(4)
    raise TimeoutError("timed out waiting for AgentCore Gateway")


def gateway_audience(url: str) -> str:
    request = urllib.request.Request(
        url.replace("/mcp", "/.well-known/oauth-protected-resource"),
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        metadata = json.loads(response.read())
    audience = metadata.get("resource")
    if not isinstance(audience, str) or audience.rstrip("/") != url.rstrip("/"):
        raise RuntimeError("Gateway metadata did not contain its MCP URL as the resource")
    return audience


def ensure_target(settings: Settings, gateway_id: str, api_id: str) -> dict[str, Any]:
    client = aws(settings, "bedrock-agentcore-control")
    listed = client.list_gateway_targets(gatewayIdentifier=gateway_id)
    existing = next(
        (
            target
            for target in listed.get("items", []) + listed.get("targets", [])
            if target.get("name") == TARGET_NAME
        ),
        None,
    )
    params = {
        "gatewayIdentifier": gateway_id,
        "name": TARGET_NAME,
        "description": "The recipe's single order tool",
        "targetConfiguration": {
            "mcp": {
                "apiGateway": {
                    "restApiId": api_id,
                    "stage": STAGE,
                    "apiGatewayToolConfiguration": {
                        "toolOverrides": [
                            {
                                "name": "place_order",
                                "description": "Place a small illustrative order.",
                                "path": "/orders",
                                "method": "POST",
                            }
                        ],
                        "toolFilters": [{"filterPath": "/orders", "methods": ["POST"]}],
                    },
                }
            }
        },
        "credentialProviderConfigurations": [{"credentialProviderType": "GATEWAY_IAM_ROLE"}],
        "metadataConfiguration": {
            "allowedRequestHeaders": ["x-dnsid-status", "x-dnsid-sub", "x-gateway-sentinel"]
        },
    }
    if existing:
        params["targetId"] = existing["targetId"]
        target = client.update_gateway_target(**params)
        target_id = existing["targetId"]
    else:
        target = client.create_gateway_target(**params)
        target_id = target["targetId"]
    for _ in range(90):
        target = client.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
        if target.get("status") == "READY":
            break
        if target.get("status") in {"FAILED", "DELETING"}:
            raise RuntimeError(f"Gateway target entered {target.get('status')}")
        time.sleep(4)
    else:
        raise TimeoutError("timed out waiting for Gateway target")
    try:
        client.synchronize_gateway_targets(gatewayIdentifier=gateway_id, targetIdList=[target_id])
    except ClientError as exc:
        if error_code(exc) not in {"ValidationException", "ConflictException"}:
            raise
    for _ in range(90):
        target = client.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
        if target.get("status") == "READY":
            return target
        if target.get("status") in {"FAILED", "DELETING"}:
            raise RuntimeError(f"Gateway target entered {target.get('status')}")
        time.sleep(4)
    raise TimeoutError("timed out synchronizing Gateway target")


def main() -> None:
    settings = load_settings()
    identity = identity_manager_from_dnsid(settings.dnsid_config_dir or None)
    config = identity.config.identity
    account = str(aws(settings, "sts", region=settings.aws_region).get_caller_identity()["Account"])
    package = package_lambda(settings)
    replay_name = f"{PREFIX}-replay"
    replay_arn = ensure_replay_table(settings, replay_name)
    sentinel = secrets.token_urlsafe(32)

    target_role = ensure_role(
        settings,
        f"{PREFIX}-target-role",
        "lambda.amazonaws.com",
        {"Version": "2012-10-17", "Statement": [log_policy()]},
    )
    interceptor_role = ensure_role(
        settings,
        f"{PREFIX}-interceptor-role",
        "lambda.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                log_policy(),
                {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": replay_arn},
            ],
        },
    )
    time.sleep(8)
    target_name = f"{PREFIX}-target"
    interceptor_name = f"{PREFIX}-interceptor"
    target_arn = ensure_lambda(
        settings,
        target_name,
        target_role,
        "orders_target.lambda_handler.lambda_handler",
        package,
        {"GATEWAY_SENTINEL": sentinel},
        memory=128,
    )
    interceptor_arn = ensure_lambda(
        settings,
        interceptor_name,
        interceptor_role,
        "orders_interceptor.lambda_handler.lambda_handler",
        package,
        {
            "EXPECTED_DNSID_SUB": config.domain,
            "DNSID_LOG_POLICY_URL": settings.dnsid_log_policy_url,
            "GATEWAY_SENTINEL": sentinel,
            "REPLAY_TABLE": replay_name,
        },
        memory=512,
    )
    api_id = ensure_api(settings, target_arn)
    allow_api_gateway(settings, target_name, api_id, account)
    gateway_role = ensure_role(
        settings,
        f"{PREFIX}-gateway-role",
        "bedrock-agentcore.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "execute-api:Invoke",
                    "Resource": f"arn:aws:execute-api:{settings.agentcore_region}:{account}:{api_id}/*/POST/orders",
                },
                {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": [interceptor_arn, f"{interceptor_arn}:*"],
                },
            ],
        },
    )
    time.sleep(8)
    gateway = ensure_gateway(settings, gateway_role, interceptor_arn, PROVISIONAL_AUDIENCE, config.domain)
    audience = gateway_audience(str(gateway["gatewayUrl"]))
    gateway = ensure_gateway(settings, gateway_role, interceptor_arn, audience, config.domain)
    target = ensure_target(settings, str(gateway["gatewayId"]), api_id)
    write_json(
        settings.state_path,
        {
            "api_id": api_id,
            "audience": audience,
            "gateway_id": gateway["gatewayId"],
            "gateway_url": gateway["gatewayUrl"],
            "interceptor_function": interceptor_name,
            "replay_table": replay_name,
            "subject": config.domain,
            "target_function": target_name,
            "target_id": target["targetId"],
            "target_name": TARGET_NAME,
        },
    )
    print(f"✓ deployed one AgentCore Gateway tool for {config.domain}")
    print(f"✓ Gateway audience: {audience}")
    print(f"✓ deployment state: {settings.state_path}")


if __name__ == "__main__":
    main()
