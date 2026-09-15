from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from image_poc.config import load_dnsid_settings


RECIPE_ROOT = Path(__file__).resolve().parents[1]
STATE_PATH = RECIPE_ROOT / ".artifacts" / "gateway" / "phase3-state.json"
BUILD_DIR = RECIPE_ROOT / ".artifacts" / "gateway" / "build"
OPENAPI_TEMPLATE = RECIPE_ROOT / "infra" / "openapi" / "image-api.openapi.json"

REGION = "us-east-1"
BEDROCK_REGION = "us-west-2"
PREFIX = "dnsid-image-poc-phase3"
STAGE_NAME = "phase3"
GATEWAY_NAME = "DnsidImagePocPhase3Gateway"
TARGET_NAME = "ImageApiTarget"
PROVISIONAL_AUDIENCE = "urn:amazon:bedrock-agentcore:gateway:mcp-image-poc"
DNSID_SETTINGS = load_dnsid_settings(require_https=True, require_agent_domain=False)
EXPECTED_DNSID_SUB = DNSID_SETTINGS.agent_domain
DNSID_AGENT_DOMAIN = EXPECTED_DNSID_SUB
DNSID_SERVER = DNSID_SETTINGS.server
DNSID_ISSUER = DNSID_SERVER
DNSID_CLI = DNSID_SETTINGS.cli

TRUSTED_REQUEST_HEADERS = [
    "x-dnsid-sub",
    "x-dnsid-iss",
    "x-dnsid-aud",
    "x-dnsid-jti",
    "x-dnsid-domain",
    "x-dnsid-scope",
    "x-dnsid-auth-mode",
    "x-dnsid-verified-at",
    "x-gateway-request-id",
    "x-correlation-id",
]

ALLOWED_TARGET_ROUTES = (
    ("POST", "generate-image"),
    ("POST", "whoami-dnsid"),
)


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
        "Recipe": "07-agentcore-gateway-mcp-image-poc",
        "Phase": "3",
    }


def tags_list() -> list[dict[str, str]]:
    return [{"Key": key, "Value": value} for key, value in tags_dict().items()]


def render_openapi(
    lambda_arn: str,
    region: str = REGION,
    resource_policy: dict[str, Any] | None = None,
) -> str:
    template = OPENAPI_TEMPLATE.read_text(encoding="utf-8")
    integration_uri = (
        f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/"
        f"{lambda_arn}/invocations"
    )
    rendered = template.replace("{{integration_uri}}", integration_uri)
    if resource_policy is None:
        return rendered
    openapi = json.loads(rendered)
    openapi["x-amazon-apigateway-policy"] = resource_policy
    return json.dumps(openapi, sort_keys=True)


def package_lambda() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = BUILD_DIR / "image-poc-lambda.zip"
    src_root = RECIPE_ROOT / "src"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((src_root / "image_poc").glob("*.py")):
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
    delete_stale_role_policies(iam, name, policy_name)
    detach_stale_managed_policies(iam, name)
    try:
        iam.tag_role(RoleName=name, Tags=tags_list())
    except ClientError:
        pass
    wait_for_iam()
    return role["Arn"]


def delete_stale_role_policies(iam: Any, role_name: str, expected_policy_name: str) -> None:
    paginator = iam.get_paginator("list_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for policy_name in page.get("PolicyNames", []):
            if policy_name == expected_policy_name:
                continue
            if is_recipe_policy_name(policy_name):
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)


def detach_stale_managed_policies(iam: Any, role_name: str) -> None:
    paginator = iam.get_paginator("list_attached_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for policy in page.get("AttachedPolicies", []):
            policy_name = str(policy.get("PolicyName") or "")
            policy_arn = str(policy.get("PolicyArn") or "")
            if is_recipe_policy_name(policy_name) or f":policy/{PREFIX}" in policy_arn:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)


def is_recipe_policy_name(policy_name: str) -> bool:
    return policy_name.startswith("phase3-") or policy_name.startswith(PREFIX)


def wait_for_iam() -> None:
    time.sleep(8)


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def ensure_bucket(bucket: str, region: str = REGION) -> None:
    s3 = client("s3", region)
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") not in {404, 403}:
            raise
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    try:
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": tags_list()})
    except ClientError:
        pass


def create_or_update_lambda(
    function_name: str,
    role_arn: str,
    handler: str,
    zip_path: Path,
    environment: dict[str, str],
    timeout: int = 180,
) -> str:
    lambda_client = client("lambda")
    code = zip_path.read_bytes()
    try:
        current = lambda_client.get_function(FunctionName=function_name)["Configuration"]
        lambda_client.update_function_code(FunctionName=function_name, ZipFile=code)
        wait_for_lambda_update(function_name)
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler=handler,
            Timeout=timeout,
            MemorySize=512,
            Environment={"Variables": environment},
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
            Handler=handler,
            Code={"ZipFile": code},
            Timeout=timeout,
            MemorySize=512,
            Environment={"Variables": environment},
            Tags=tags_dict(),
        )["FunctionArn"]
        wait_for_lambda_update(function_name)
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


def find_rest_api(name: str) -> dict[str, Any] | None:
    apigw = client("apigateway")
    paginator = apigw.get_paginator("get_rest_apis")
    for page in paginator.paginate():
        for item in page.get("items", []):
            if item.get("name") == name:
                return item
    return None


def import_or_update_rest_api(
    name: str,
    openapi_body: str,
    rest_api_id: str | None = None,
) -> str:
    apigw = client("apigateway")
    existing = None
    if rest_api_id:
        try:
            existing = apigw.get_rest_api(restApiId=rest_api_id)
        except ClientError as exc:
            if error_code(exc) != "NotFoundException":
                raise
    if existing is None:
        existing = find_rest_api(name)
    if existing:
        rest_api_id = existing["id"]
        apigw.put_rest_api(
            restApiId=rest_api_id,
            mode="overwrite",
            failOnWarnings=False,
            body=openapi_body.encode("utf-8"),
        )
    else:
        rest_api_id = apigw.import_rest_api(
            failOnWarnings=False,
            body=openapi_body.encode("utf-8"),
        )["id"]
    apigw.update_rest_api(
        restApiId=rest_api_id,
        patchOperations=[{"op": "replace", "path": "/name", "value": name}],
    )
    create_rest_api_deployment(
        apigw,
        rest_api_id,
        "Phase 3 AgentCore Gateway target deployment",
    )
    return rest_api_id


def restrict_rest_api_to_gateway_role(
    rest_api_id: str,
    account: str,
    gateway_role_arn: str,
    region: str = REGION,
) -> None:
    apigw = client("apigateway")
    policy = rest_api_gateway_policy(rest_api_id, account, gateway_role_arn, region)
    value = json.dumps(policy)
    try:
        apigw.update_rest_api(
            restApiId=rest_api_id,
            patchOperations=[{"op": "replace", "path": "/policy", "value": value}],
        )
    except ClientError as exc:
        if error_code(exc) != "BadRequestException":
            raise
        apigw.update_rest_api(
            restApiId=rest_api_id,
            patchOperations=[{"op": "add", "path": "/policy", "value": value}],
        )
    create_rest_api_deployment(
        apigw,
        rest_api_id,
        "Phase 3 AgentCore Gateway target policy deployment",
    )


def create_rest_api_deployment(apigw: Any, rest_api_id: str, description: str) -> None:
    for attempt in range(6):
        try:
            apigw.create_deployment(
                restApiId=rest_api_id,
                stageName=STAGE_NAME,
                description=description,
            )
            return
        except ClientError as exc:
            if error_code(exc) not in {"TooManyRequestsException", "LimitExceededException"}:
                raise
            if attempt == 5:
                raise
            time.sleep(2**attempt)


def rest_api_gateway_policy(
    rest_api_id: str,
    account: str,
    gateway_role_arn: str,
    region: str = REGION,
) -> dict[str, Any]:
    allowed_resources = allowed_target_execute_api_arns(account, rest_api_id, region)
    allowed_principal_arns = [
        gateway_role_arn,
        assumed_role_arn_pattern(gateway_role_arn),
    ]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyNonGatewayRoleInvoke",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "execute-api:Invoke",
                "Resource": execute_api_arn(account, rest_api_id, region),
                "Condition": {
                    "ArnNotLike": {"aws:PrincipalArn": allowed_principal_arns},
                },
            },
            {
                "Sid": "AllowGatewayRoleInvoke",
                "Effect": "Allow",
                "Principal": {"AWS": gateway_role_arn},
                "Action": "execute-api:Invoke",
                "Resource": allowed_resources,
            }
        ],
    }


def assumed_role_arn_pattern(role_arn: str) -> str:
    parts = role_arn.split(":")
    if len(parts) < 6 or ":role/" not in role_arn:
        return role_arn
    account = parts[4]
    role_path = role_arn.split(":role/", 1)[1]
    role_name = role_path.rsplit("/", 1)[-1]
    return f"arn:aws:sts::{account}:assumed-role/{role_name}/*"


def ensure_lambda_permission(function_name: str, statement_id: str, source_arn: str) -> None:
    lambda_client = client("lambda")
    try:
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as exc:
        if error_code(exc) != "ResourceConflictException":
            raise
        if lambda_permission_source_arn(lambda_client, function_name, statement_id) == source_arn:
            return
        lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=statement_id,
        )
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )


def prune_lambda_permissions(function_name: str, allowed_statement_ids: set[str]) -> None:
    lambda_client = client("lambda")
    try:
        policy = json.loads(lambda_client.get_policy(FunctionName=function_name)["Policy"])
    except ClientError as exc:
        if error_code(exc) == "ResourceNotFoundException":
            return
        raise
    for statement in policy.get("Statement", []):
        sid = str(statement.get("Sid") or "")
        if sid.startswith("phase3-") and sid not in allowed_statement_ids:
            lambda_client.remove_permission(FunctionName=function_name, StatementId=sid)


def lambda_permission_source_arn(
    lambda_client: Any,
    function_name: str,
    statement_id: str,
) -> str | None:
    try:
        policy = json.loads(lambda_client.get_policy(FunctionName=function_name)["Policy"])
    except ClientError as exc:
        if error_code(exc) == "ResourceNotFoundException":
            return None
        raise
    for statement in policy.get("Statement", []):
        if statement.get("Sid") != statement_id:
            continue
        condition = statement.get("Condition", {})
        for operator in ("ArnLike", "ArnEquals"):
            source_arn = condition.get(operator, {}).get("AWS:SourceArn")
            if source_arn:
                return str(source_arn)
    return None


def gateway_authorizer_config(
    audience: str,
    include_custom_claims: bool = True,
) -> dict[str, Any]:
    expected_sub = require_dnsid_agent_domain()
    config: dict[str, Any] = {
        "customJWTAuthorizer": {
            "discoveryUrl": f"{DNSID_ISSUER}/.well-known/openid-configuration",
            "allowedAudience": [audience],
        }
    }
    if include_custom_claims:
        config["customJWTAuthorizer"]["customClaims"] = [
            {
                "inboundTokenClaimName": "sub",
                "inboundTokenClaimValueType": "STRING",
                "authorizingClaimMatchValue": {
                    "claimMatchValue": {"matchValueString": expected_sub},
                    "claimMatchOperator": "EQUALS",
                },
            }
        ]
    return config


def gateway_protocol_config() -> dict[str, Any]:
    return {
        "mcp": {
            "instructions": (
                "Expose image generation and DNSid identity tools for the "
                "dnsid cookbook AgentCore Gateway image PoC."
            ),
            "streamingConfiguration": {"enableResponseStreaming": False},
            "sessionConfiguration": {"sessionTimeoutInSeconds": 900},
        }
    }


def gateway_interceptors(interceptor_arn: str) -> list[dict[str, Any]]:
    return [
        {
            "interceptor": {"lambda": {"arn": interceptor_arn}},
            "interceptionPoints": ["REQUEST", "RESPONSE"],
            "inputConfiguration": {"passRequestHeaders": True},
        }
    ]


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


def get_gateway_by_name(name: str) -> dict[str, Any] | None:
    agentcore = client("bedrock-agentcore-control")
    paginator = agentcore.get_paginator("list_gateways")
    for page in paginator.paginate():
        for gateway in page.get("items", []) + page.get("gateways", []):
            if gateway.get("name") == name:
                return gateway
    return None


def protected_resource_metadata(gateway_url: str) -> dict[str, Any]:
    metadata_url = gateway_url.replace("/mcp", "/.well-known/oauth-protected-resource")
    request = urllib.request.Request(metadata_url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def rest_api_base_url(rest_api_id: str, region: str = REGION) -> str:
    return f"https://{rest_api_id}.execute-api.{region}.amazonaws.com/{STAGE_NAME}"


def execute_api_arn(
    account: str,
    rest_api_id: str,
    region: str = REGION,
    method: str = "*",
    path: str = "*",
) -> str:
    return (
        f"arn:aws:execute-api:{region}:{account}:{rest_api_id}/"
        f"{STAGE_NAME}/{method}/{path.lstrip('/')}"
    )


def allowed_target_execute_api_arns(
    account: str,
    rest_api_id: str,
    region: str = REGION,
) -> list[str]:
    return [
        execute_api_arn(account, rest_api_id, region, method, path)
        for method, path in ALLOWED_TARGET_ROUTES
    ]
