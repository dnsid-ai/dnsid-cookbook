import importlib
import json
import sys
from pathlib import Path

from botocore.exceptions import ClientError


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import gateway_resources  # noqa: E402
from gateway_resources import (  # noqa: E402
    allowed_target_execute_api_arns,
    gateway_interceptors,
    lambda_permission_source_arn,
    load_state,
    render_openapi,
    save_state,
    tags_dict,
)


def test_dnsid_gateway_configuration_is_env_overridable(monkeypatch):
    monkeypatch.setenv("DNSID_CLI", "/opt/dnsid/bin/dnsid")
    monkeypatch.setenv("DNSID_SERVER", "https://dnsid.example.test/")
    monkeypatch.setenv("DNSID_AGENT_DOMAIN", "agent.example.test")
    reloaded = importlib.reload(gateway_resources)
    try:
        assert reloaded.DNSID_CLI == "/opt/dnsid/bin/dnsid"
        assert reloaded.DNSID_SERVER == "https://dnsid.example.test"
        assert reloaded.DNSID_ISSUER == "https://dnsid.example.test"
        assert reloaded.DNSID_AGENT_DOMAIN == "agent.example.test"
        assert reloaded.EXPECTED_DNSID_SUB == "agent.example.test"

        authorizer = reloaded.gateway_authorizer_config("gateway-audience")
        custom_jwt = authorizer["customJWTAuthorizer"]
        assert (
            custom_jwt["discoveryUrl"]
            == "https://dnsid.example.test/.well-known/openid-configuration"
        )
        assert (
            custom_jwt["customClaims"][0]["authorizingClaimMatchValue"]["claimMatchValue"][
                "matchValueString"
            ]
            == "agent.example.test"
        )
    finally:
        monkeypatch.delenv("DNSID_CLI", raising=False)
        monkeypatch.delenv("DNSID_SERVER", raising=False)
        monkeypatch.delenv("DNSID_AGENT_DOMAIN", raising=False)
        importlib.reload(gateway_resources)


def test_gateway_interceptor_configuration_includes_response_filtering():
    interceptors = gateway_interceptors("arn:aws:lambda:us-east-1:123:function:test")

    assert interceptors == [
        {
            "interceptor": {
                "lambda": {"arn": "arn:aws:lambda:us-east-1:123:function:test"}
            },
            "interceptionPoints": ["REQUEST", "RESPONSE"],
            "inputConfiguration": {"passRequestHeaders": True},
        }
    ]


def test_resource_tags_use_numbered_recipe_name():
    assert tags_dict()["Recipe"] == "07-agentcore-gateway-mcp-image-poc"


def test_state_load_tolerates_corrupt_file(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text("{not json", encoding="utf-8")

    assert load_state(state_path) == {}


def test_state_save_writes_complete_json_atomically(tmp_path):
    state_path = tmp_path / "state.json"

    save_state({"gateway_id": "gw"}, state_path)

    assert json.loads(state_path.read_text(encoding="utf-8")) == {"gateway_id": "gw"}
    assert not (tmp_path / "state.json.tmp").exists()


def test_lambda_permission_source_arn_finds_existing_statement():
    class FakeLambdaClient:
        def get_policy(self, FunctionName):
            return {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Sid": "phase3-apigateway-invoke",
                                "Condition": {
                                    "ArnLike": {
                                        "AWS:SourceArn": "arn:aws:execute-api:us-east-1:123:api/*/*/*"
                                    }
                                },
                            }
                        ]
                    }
                )
            }

    assert (
        lambda_permission_source_arn(
            FakeLambdaClient(),
            "function-name",
            "phase3-apigateway-invoke",
        )
        == "arn:aws:execute-api:us-east-1:123:api/*/*/*"
    )


def test_ensure_lambda_permission_replaces_stale_source_arn(monkeypatch):
    class FakeLambdaClient:
        def __init__(self):
            self.add_calls = []
            self.remove_calls = []

        def add_permission(self, **kwargs):
            self.add_calls.append(kwargs)
            if len(self.add_calls) == 1:
                raise ClientError(
                    {"Error": {"Code": "ResourceConflictException"}},
                    "AddPermission",
                )

        def get_policy(self, FunctionName):
            return {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Sid": "phase3-apigateway-invoke",
                                "Condition": {
                                    "ArnLike": {
                                        "AWS:SourceArn": "arn:aws:execute-api:us-east-1:123:old/*/*/*"
                                    }
                                },
                            }
                        ]
                    }
                )
            }

        def remove_permission(self, **kwargs):
            self.remove_calls.append(kwargs)

    fake = FakeLambdaClient()
    monkeypatch.setattr(gateway_resources, "client", lambda service: fake)

    gateway_resources.ensure_lambda_permission(
        "function-name",
        "phase3-apigateway-invoke",
        "arn:aws:execute-api:us-east-1:123:new/*/*/*",
    )

    assert fake.remove_calls == [
        {"FunctionName": "function-name", "StatementId": "phase3-apigateway-invoke"}
    ]
    assert fake.add_calls[-1]["SourceArn"] == "arn:aws:execute-api:us-east-1:123:new/*/*/*"


def test_create_or_update_role_prunes_stale_recipe_policies(monkeypatch):
    class FakePaginator:
        def __init__(self, pages):
            self.pages = pages

        def paginate(self, **kwargs):
            return self.pages

    class FakeIamClient:
        def __init__(self):
            self.deleted = []
            self.detached = []
            self.put_policies = []

        def get_role(self, RoleName):
            return {"Role": {"Arn": f"arn:aws:iam::123:role/{RoleName}"}}

        def update_assume_role_policy(self, **kwargs):
            pass

        def put_role_policy(self, **kwargs):
            self.put_policies.append(kwargs)

        def tag_role(self, **kwargs):
            pass

        def get_paginator(self, name):
            if name == "list_role_policies":
                return FakePaginator(
                    [
                        {
                            "PolicyNames": [
                                "phase3-stale-policy",
                                "phase3-target-lambda-policy",
                                "unrelated-policy",
                            ]
                        }
                    ]
                )
            if name == "list_attached_role_policies":
                return FakePaginator(
                    [
                        {
                            "AttachedPolicies": [
                                {
                                    "PolicyName": "phase3-managed-stale",
                                    "PolicyArn": "arn:aws:iam::123:policy/phase3-managed-stale",
                                },
                                {
                                    "PolicyName": "ReadOnlyAccess",
                                    "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                                },
                            ]
                        }
                    ]
                )
            raise AssertionError(f"unexpected paginator {name}")

        def delete_role_policy(self, **kwargs):
            self.deleted.append(kwargs)

        def detach_role_policy(self, **kwargs):
            self.detached.append(kwargs)

    fake = FakeIamClient()
    monkeypatch.setattr(gateway_resources, "client", lambda service: fake)
    monkeypatch.setattr(gateway_resources, "wait_for_iam", lambda: None)

    gateway_resources.create_or_update_role(
        "role-name",
        "lambda.amazonaws.com",
        "phase3-target-lambda-policy",
        {"Version": "2012-10-17", "Statement": []},
    )

    assert fake.deleted == [
        {"RoleName": "role-name", "PolicyName": "phase3-stale-policy"}
    ]
    assert fake.detached == [
        {
            "RoleName": "role-name",
            "PolicyArn": "arn:aws:iam::123:policy/phase3-managed-stale",
        }
    ]


def test_prune_lambda_permissions_removes_stale_phase3_sids(monkeypatch):
    class FakeLambdaClient:
        def __init__(self):
            self.remove_calls = []

        def get_policy(self, FunctionName):
            return {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {"Sid": "phase3-apigateway-invoke"},
                            {"Sid": "phase3-stale-wide-invoke"},
                            {"Sid": "other-service-permission"},
                        ]
                    }
                )
            }

        def remove_permission(self, **kwargs):
            self.remove_calls.append(kwargs)

    fake = FakeLambdaClient()
    monkeypatch.setattr(gateway_resources, "client", lambda service: fake)

    gateway_resources.prune_lambda_permissions(
        "function-name",
        {"phase3-apigateway-invoke"},
    )

    assert fake.remove_calls == [
        {"FunctionName": "function-name", "StatementId": "phase3-stale-wide-invoke"}
    ]


def test_restrict_rest_api_to_gateway_role_applies_resource_policy(monkeypatch):
    class FakeApiGatewayClient:
        def __init__(self):
            self.patch_operations = []
            self.deployments = []

        def update_rest_api(self, **kwargs):
            self.patch_operations.extend(kwargs["patchOperations"])

        def create_deployment(self, **kwargs):
            self.deployments.append(kwargs)

    fake = FakeApiGatewayClient()
    monkeypatch.setattr(gateway_resources, "client", lambda service: fake)

    gateway_resources.restrict_rest_api_to_gateway_role(
        "api123",
        "123456789012",
        "arn:aws:iam::123456789012:role/gateway-role",
        region="us-east-1",
    )

    policy = json.loads(fake.patch_operations[0]["value"])
    deny, allow = policy["Statement"]
    assert deny["Effect"] == "Deny"
    assert deny["Principal"] == "*"
    assert deny["Condition"] == {
        "ArnNotLike": {
            "aws:PrincipalArn": [
                "arn:aws:iam::123456789012:role/gateway-role",
                "arn:aws:sts::123456789012:assumed-role/gateway-role/*",
            ]
        }
    }
    assert allow["Effect"] == "Allow"
    assert allow["Principal"] == {
        "AWS": "arn:aws:iam::123456789012:role/gateway-role"
    }
    assert allow["Resource"] == [
        "arn:aws:execute-api:us-east-1:123456789012:api123/phase3/POST/generate-image",
        "arn:aws:execute-api:us-east-1:123456789012:api123/phase3/POST/whoami-dnsid",
    ]
    assert fake.deployments[0]["restApiId"] == "api123"


def test_create_rest_api_deployment_retries_throttle(monkeypatch):
    class FakeApiGatewayClient:
        def __init__(self):
            self.calls = 0

        def create_deployment(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise ClientError(
                    {"Error": {"Code": "TooManyRequestsException"}},
                    "CreateDeployment",
                )
            assert kwargs == {
                "restApiId": "api123",
                "stageName": "phase3",
                "description": "deployment",
            }

    fake = FakeApiGatewayClient()
    sleeps = []
    monkeypatch.setattr(gateway_resources.time, "sleep", lambda seconds: sleeps.append(seconds))

    gateway_resources.create_rest_api_deployment(fake, "api123", "deployment")

    assert fake.calls == 2
    assert sleeps == [1]


def test_assumed_role_arn_pattern_strips_role_path():
    assert (
        gateway_resources.assumed_role_arn_pattern(
            "arn:aws:iam::123456789012:role/service/gateway-role"
        )
        == "arn:aws:sts::123456789012:assumed-role/gateway-role/*"
    )


def test_allowed_target_execute_api_arns_are_tool_routes_only():
    assert allowed_target_execute_api_arns("123456789012", "api123", "us-east-1") == [
        "arn:aws:execute-api:us-east-1:123456789012:api123/phase3/POST/generate-image",
        "arn:aws:execute-api:us-east-1:123456789012:api123/phase3/POST/whoami-dnsid",
    ]


def test_render_openapi_embeds_resource_policy(monkeypatch, tmp_path):
    template = tmp_path / "openapi.json"
    template.write_text(
        json.dumps(
            {
                "openapi": "3.0.1",
                "paths": {
                    "/generate-image": {
                        "post": {
                            "x-amazon-apigateway-integration": {
                                "uri": "{{integration_uri}}"
                            }
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(gateway_resources, "OPENAPI_TEMPLATE", template)

    policy = gateway_resources.rest_api_gateway_policy(
        "api123",
        "123456789012",
        "arn:aws:iam::123456789012:role/gateway-role",
    )
    rendered = json.loads(
        render_openapi(
            "arn:aws:lambda:us-east-1:123456789012:function:target",
            resource_policy=policy,
        )
    )

    assert rendered["x-amazon-apigateway-policy"] == policy
    assert (
        rendered["paths"]["/generate-image"]["post"]["x-amazon-apigateway-integration"][
            "uri"
        ]
        == "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/"
        "arn:aws:lambda:us-east-1:123456789012:function:target/invocations"
    )
