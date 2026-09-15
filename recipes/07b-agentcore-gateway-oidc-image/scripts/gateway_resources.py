from __future__ import annotations

import json
import os
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from oidc_image.config import (
    DEFAULT_AGENTCORE_REGION,
    DEFAULT_BEDROCK_IMAGE_MODEL_ID,
    DEFAULT_BEDROCK_REGION,
    load_dnsid_settings,
)


RECIPE_ROOT = Path(__file__).resolve().parents[1]
STATE_PATH = RECIPE_ROOT / ".artifacts" / "gateway" / "oidc-image-state.json"
BUILD_DIR = RECIPE_ROOT / ".artifacts" / "gateway" / "build"

REGION = os.environ.get("AGENTCORE_REGION", DEFAULT_AGENTCORE_REGION)
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", DEFAULT_BEDROCK_REGION)
BEDROCK_IMAGE_MODEL_ID = os.environ.get("BEDROCK_IMAGE_MODEL_ID", DEFAULT_BEDROCK_IMAGE_MODEL_ID)
PREFIX = "dnsid-oidc-image"
GATEWAY_NAME = "DnsidOidcImageGateway"
TARGET_NAME = "ImageLambdaTarget"
PROVISIONAL_AUDIENCE = "urn:amazon:bedrock-agentcore:gateway:oidc-image"
DNSID_SETTINGS = load_dnsid_settings(require_https=True, require_agent_domain=False)
DNSID_ISSUER = DNSID_SETTINGS.server
EXPECTED_DNSID_SUB = DNSID_SETTINGS.agent_domain


def require_dnsid_agent_domain() -> str:
    return load_dnsid_settings(require_https=True).agent_domain


def client(service: str, region: str = REGION) -> Any:
    return boto3.client(
        service,
        region_name=region,
        config=Config(
            connect_timeout=10,
            read_timeout=120,
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )


def account_id() -> str:
    return client("sts").get_caller_identity()["Account"]


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def load_state(path: Path = STATE_PATH) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_state(state: dict[str, Any], path: Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(f"{path.suffix}.tmp")
    temp_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp_path.replace(path)


def tags_dict() -> dict[str, str]:
    return {
        "Project": "dnsid-cookbook",
        "Recipe": "07b-agentcore-gateway-oidc-image",
    }


def tags_list() -> list[dict[str, str]]:
    return [{"Key": key, "Value": value} for key, value in tags_dict().items()]


def require_recipe_owned(actual_tags: dict[str, str], label: str) -> None:
    expected = tags_dict()
    mismatches = {
        key: {"expected": expected_value, "actual": actual_tags.get(key)}
        for key, expected_value in expected.items()
        if actual_tags.get(key) != expected_value
    }
    if mismatches:
        raise RuntimeError(
            f"Refusing to update existing {label}: tags do not match this recipe "
            f"({json.dumps(mismatches, sort_keys=True)})."
        )


def role_tags(iam: Any, role_name: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    paginator = iam.get_paginator("list_role_tags")
    for page in paginator.paginate(RoleName=role_name):
        for tag in page.get("Tags", []):
            tags[str(tag["Key"])] = str(tag["Value"])
    return tags


def gateway_tags(agentcore: Any, gateway: dict[str, Any]) -> dict[str, str]:
    arn = gateway.get("gatewayArn")
    if not arn and gateway.get("gatewayId"):
        gateway = agentcore.get_gateway(gatewayIdentifier=gateway["gatewayId"])
        arn = gateway.get("gatewayArn")
    if not arn:
        raise RuntimeError("Refusing to update existing Gateway without gatewayArn.")
    response = agentcore.list_tags_for_resource(resourceArn=arn)
    tags = response.get("tags", {})
    return {str(key): str(value) for key, value in tags.items()}


def package_lambda() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = BUILD_DIR / "oidc-image-lambda.zip"
    src_root = RECIPE_ROOT / "src"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((src_root / "oidc_image").glob("*.py")):
            archive.write(path, path.relative_to(src_root))
    return zip_path


def create_or_update_role(
    name: str,
    service_principal: str,
    policy_name: str,
    policy_document: dict[str, Any],
) -> str:
    iam = client("iam")
    assume_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        role = iam.get_role(RoleName=name)["Role"]
        require_recipe_owned(role_tags(iam, name), f"IAM role {name}")
        iam.update_assume_role_policy(
            RoleName=name,
            PolicyDocument=json.dumps(assume_policy),
        )
    except ClientError as exc:
        if error_code(exc) != "NoSuchEntity":
            raise
        role = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(assume_policy),
            Tags=tags_list(),
        )["Role"]

    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_document),
    )
    for policy_name_existing in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
        if policy_name_existing != policy_name and policy_name_existing.startswith(PREFIX):
            iam.delete_role_policy(RoleName=name, PolicyName=policy_name_existing)
    iam.tag_role(RoleName=name, Tags=tags_list())
    time.sleep(8)
    return role["Arn"]


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


def target_lambda_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            logs_policy_statement(),
            {
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel"],
                "Resource": f"arn:aws:bedrock:{BEDROCK_REGION}::foundation-model/{BEDROCK_IMAGE_MODEL_ID}",
            },
        ],
    }


def gateway_role_policy(lambda_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": [lambda_arn, f"{lambda_arn}:*"],
            }
        ],
    }


def create_or_update_lambda(function_name: str, role_arn: str, zip_path: Path) -> str:
    lambda_client = client("lambda")
    code = zip_path.read_bytes()
    environment = {
        "Variables": {
            "BEDROCK_REGION": BEDROCK_REGION,
            "BEDROCK_IMAGE_MODEL_ID": BEDROCK_IMAGE_MODEL_ID,
        }
    }
    try:
        current = lambda_client.get_function(FunctionName=function_name)["Configuration"]
        require_recipe_owned(
            lambda_client.list_tags(Resource=current["FunctionArn"]).get("Tags", {}),
            f"Lambda function {function_name}",
        )
        lambda_client.update_function_code(FunctionName=function_name, ZipFile=code)
        wait_for_lambda_update(function_name)
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="oidc_image.lambda_handler.lambda_handler",
            Timeout=180,
            MemorySize=512,
            Environment=environment,
        )
        wait_for_lambda_update(function_name)
        arn = current["FunctionArn"]
    except ClientError as exc:
        if error_code(exc) != "ResourceNotFoundException":
            raise
        arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="oidc_image.lambda_handler.lambda_handler",
            Code={"ZipFile": code},
            Timeout=180,
            MemorySize=512,
            Environment=environment,
            Tags=tags_dict(),
        )["FunctionArn"]
        wait_for_lambda_update(function_name)
    lambda_client.tag_resource(Resource=arn, Tags=tags_dict())
    return arn


def wait_for_lambda_update(function_name: str) -> None:
    lambda_client = client("lambda")
    for _ in range(60):
        config = lambda_client.get_function_configuration(FunctionName=function_name)
        if config.get("LastUpdateStatus") in (None, "Successful"):
            return
        if config.get("LastUpdateStatus") == "Failed":
            raise RuntimeError(f"Lambda update failed: {config.get('LastUpdateStatusReason')}")
        time.sleep(2)
    raise TimeoutError(f"Timed out waiting for Lambda {function_name}.")


def gateway_authorizer_config(audience: str) -> dict[str, Any]:
    expected_sub = require_dnsid_agent_domain()
    return {
        "customJWTAuthorizer": {
            "discoveryUrl": f"{DNSID_ISSUER}/.well-known/openid-configuration",
            "allowedAudience": [audience],
            "customClaims": [
                {
                    "inboundTokenClaimName": "sub",
                    "inboundTokenClaimValueType": "STRING",
                    "authorizingClaimMatchValue": {
                        "claimMatchValue": {"matchValueString": expected_sub},
                        "claimMatchOperator": "EQUALS",
                    },
                }
            ],
        }
    }


def gateway_protocol_config() -> dict[str, Any]:
    return {
        "mcp": {
            "instructions": (
                "Expose a minimal DNSid OIDC image generation tool through "
                "AgentCore Gateway."
            ),
            "streamingConfiguration": {"enableResponseStreaming": False},
            "sessionConfiguration": {"sessionTimeoutInSeconds": 900},
        }
    }


def gateway_params(role_arn: str, audience: str) -> dict[str, Any]:
    return {
        "name": GATEWAY_NAME,
        "description": "Minimal DNSid OIDC image generation Gateway",
        "roleArn": role_arn,
        "protocolType": "MCP",
        "protocolConfiguration": gateway_protocol_config(),
        "authorizerType": "CUSTOM_JWT",
        "authorizerConfiguration": gateway_authorizer_config(audience),
        "tags": tags_dict(),
        "clientToken": str(uuid.uuid4()),
    }


def get_gateway_by_name(name: str) -> dict[str, Any] | None:
    agentcore = client("bedrock-agentcore-control")
    paginator = agentcore.get_paginator("list_gateways")
    for page in paginator.paginate():
        for gateway in page.get("items", []) + page.get("gateways", []):
            if gateway.get("name") == name:
                return gateway
    return None


def create_or_update_gateway(role_arn: str, audience: str) -> dict[str, Any]:
    agentcore = client("bedrock-agentcore-control")
    existing = get_gateway_by_name(GATEWAY_NAME)
    params = gateway_params(role_arn, audience)
    if existing:
        require_recipe_owned(gateway_tags(agentcore, existing), f"Gateway {GATEWAY_NAME}")
        params["gatewayIdentifier"] = existing["gatewayId"]
        params.pop("clientToken", None)
        params.pop("tags", None)
        return agentcore.update_gateway(**params)
    return agentcore.create_gateway(**params)


def wait_gateway_ready(gateway_id: str) -> dict[str, Any]:
    agentcore = client("bedrock-agentcore-control")
    for _ in range(90):
        gateway = agentcore.get_gateway(gatewayIdentifier=gateway_id)
        status = gateway.get("status")
        if status == "READY":
            return gateway
        if status in {"FAILED", "DELETING"}:
            raise RuntimeError(f"Gateway {gateway_id} status is {status}.")
        time.sleep(4)
    raise TimeoutError(f"Timed out waiting for Gateway {gateway_id}.")


def protected_resource_metadata(gateway_url: str) -> dict[str, Any]:
    metadata_url = gateway_url.replace("/mcp", "/.well-known/oauth-protected-resource")
    request = urllib.request.Request(metadata_url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def verified_gateway_audience(gateway_url: str, metadata: dict[str, Any]) -> str:
    audience = metadata.get("resource")
    if not audience or not isinstance(audience, str):
        raise RuntimeError("Gateway protected-resource metadata did not include resource.")
    if audience.rstrip("/") != gateway_url.rstrip("/"):
        raise RuntimeError("Gateway protected-resource metadata did not match Gateway URL.")
    return audience


def tool_schema() -> list[dict[str, Any]]:
    return [
        {
            "name": "generate_image",
            "description": "Generate a PNG image with Amazon Bedrock after Gateway OIDC auth.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Image prompt, up to 1000 characters.",
                    },
                    "style": {
                        "type": "string",
                        "description": "One of product, illustration, cinematic, natural.",
                    },
                    "size": {
                        "type": "string",
                        "description": "Image size. This recipe supports 1024x1024.",
                    },
                },
                "required": ["prompt"],
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "ok": {"type": "boolean"},
                    "image_base64": {"type": "string"},
                    "image_sha256": {"type": "string"},
                    "mime_type": {"type": "string"},
                    "width": {"type": "integer"},
                    "height": {"type": "integer"},
                    "model_id": {"type": "string"},
                    "model_region": {"type": "string"},
                    "request_id": {"type": "string"},
                },
            },
        }
    ]


def target_params(gateway_id: str, lambda_arn: str) -> dict[str, Any]:
    return {
        "gatewayIdentifier": gateway_id,
        "name": TARGET_NAME,
        "description": "Direct Lambda target for DNSid OIDC image generation",
        "targetConfiguration": {
            "mcp": {
                "lambda": {
                    "lambdaArn": lambda_arn,
                    "toolSchema": {"inlinePayload": tool_schema()},
                }
            }
        },
        "credentialProviderConfigurations": [
            {"credentialProviderType": "GATEWAY_IAM_ROLE"}
        ],
    }


def ensure_gateway_target(gateway_id: str, lambda_arn: str) -> dict[str, Any]:
    agentcore = client("bedrock-agentcore-control")
    existing = None
    response = agentcore.list_gateway_targets(gatewayIdentifier=gateway_id)
    for target in response.get("items", []) + response.get("targets", []):
        if target.get("name") == TARGET_NAME:
            existing = target
            break
    params = target_params(gateway_id, lambda_arn)
    if existing:
        params["targetId"] = existing["targetId"]
        target = agentcore.update_gateway_target(**params)
        target_id = target.get("targetId") or existing["targetId"]
    else:
        target = agentcore.create_gateway_target(**params)
        target_id = target["targetId"]
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


def wait_target_ready(gateway_id: str, target_id: str) -> dict[str, Any]:
    agentcore = client("bedrock-agentcore-control")
    for _ in range(90):
        target = agentcore.get_gateway_target(
            gatewayIdentifier=gateway_id,
            targetId=target_id,
        )
        status = target.get("status")
        if status == "READY":
            return target
        if status in {"FAILED", "DELETING"}:
            raise RuntimeError(f"Gateway target {target_id} status is {status}.")
        time.sleep(4)
    raise TimeoutError(f"Timed out waiting for Gateway target {target_id}.")
