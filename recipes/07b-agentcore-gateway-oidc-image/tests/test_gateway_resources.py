import importlib
import json
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import gateway_resources  # noqa: E402
from gateway_resources import (  # noqa: E402
    GATEWAY_NAME,
    PREFIX,
    TARGET_NAME,
    gateway_authorizer_config,
    gateway_params,
    load_state,
    require_recipe_owned,
    save_state,
    tags_dict,
    target_params,
    tool_schema,
    verified_gateway_audience,
)


@pytest.fixture(autouse=True)
def dnsid_agent_domain(monkeypatch):
    monkeypatch.setenv("DNSID_AGENT_DOMAIN", "agent.example.com")


def test_gateway_configuration_is_env_overridable(monkeypatch):
    monkeypatch.setenv("DNSID_SERVER", "https://issuer.example.test/")
    monkeypatch.setenv("DNSID_AGENT_DOMAIN", "agent.example.test")
    monkeypatch.setenv("AGENTCORE_REGION", "us-west-2")
    monkeypatch.setenv("BEDROCK_REGION", "eu-central-1")
    monkeypatch.setenv("BEDROCK_IMAGE_MODEL_ID", "test-model")
    reloaded = importlib.reload(gateway_resources)
    try:
        assert reloaded.REGION == "us-west-2"
        assert reloaded.BEDROCK_REGION == "eu-central-1"
        assert reloaded.BEDROCK_IMAGE_MODEL_ID == "test-model"
        assert reloaded.DNSID_ISSUER == "https://issuer.example.test"
        assert reloaded.EXPECTED_DNSID_SUB == "agent.example.test"

        authorizer = reloaded.gateway_authorizer_config("gateway-audience")
        custom_jwt = authorizer["customJWTAuthorizer"]
        assert (
            custom_jwt["discoveryUrl"]
            == "https://issuer.example.test/.well-known/openid-configuration"
        )
        assert custom_jwt["allowedAudience"] == ["gateway-audience"]
        assert (
            custom_jwt["customClaims"][0]["authorizingClaimMatchValue"]["claimMatchValue"][
                "matchValueString"
            ]
            == "agent.example.test"
        )
    finally:
        for name in [
            "DNSID_SERVER",
            "DNSID_AGENT_DOMAIN",
            "AGENTCORE_REGION",
            "BEDROCK_REGION",
            "BEDROCK_IMAGE_MODEL_ID",
        ]:
            monkeypatch.delenv(name, raising=False)
        importlib.reload(gateway_resources)


def test_tags_use_new_recipe_name():
    assert tags_dict() == {
        "Project": "dnsid-cookbook",
        "Recipe": "07b-agentcore-gateway-oidc-image",
    }


def test_require_recipe_owned_rejects_ambiguous_existing_resources():
    with pytest.raises(RuntimeError, match="Refusing to update existing Lambda"):
        require_recipe_owned({"Project": "dnsid-cookbook"}, "Lambda function test")


def test_state_helpers_tolerate_corrupt_file_and_write_atomically(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text("{not json", encoding="utf-8")
    assert load_state(state_path) == {}

    save_state({"gateway_id": "gw"}, state_path)

    assert json.loads(state_path.read_text(encoding="utf-8")) == {"gateway_id": "gw"}
    assert not (tmp_path / "state.json.tmp").exists()


def test_gateway_params_use_custom_jwt_without_interceptors_or_api_gateway():
    params = gateway_params("arn:aws:iam::123:role/gateway", "audience")

    assert params["name"] == GATEWAY_NAME
    assert params["authorizerType"] == "CUSTOM_JWT"
    assert params["authorizerConfiguration"] == gateway_authorizer_config("audience")
    assert "interceptorConfigurations" not in params
    assert "apiGateway" not in json.dumps(params)


def test_target_params_create_direct_lambda_mcp_target():
    params = target_params(
        "gateway-id",
        "arn:aws:lambda:us-east-1:123:function:dnsid-oidc-image-target",
    )

    assert params["gatewayIdentifier"] == "gateway-id"
    assert params["name"] == TARGET_NAME
    assert params["targetConfiguration"]["mcp"]["lambda"]["lambdaArn"].endswith(
        ":function:dnsid-oidc-image-target"
    )
    assert params["credentialProviderConfigurations"] == [
        {"credentialProviderType": "GATEWAY_IAM_ROLE"}
    ]
    assert "openApiSchema" not in json.dumps(params)


def test_tool_schema_exposes_only_generate_image():
    schema = tool_schema()

    assert [tool["name"] for tool in schema] == ["generate_image"]
    generate = schema[0]
    assert generate["inputSchema"]["required"] == ["prompt"]
    assert "dnsid_context" not in json.dumps(generate)


def test_verified_gateway_audience_requires_metadata_resource_to_match_url():
    metadata = {
        "resource": "https://abc.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"
    }

    assert verified_gateway_audience(metadata["resource"], metadata) == metadata["resource"]

    with pytest.raises(RuntimeError):
        verified_gateway_audience("https://different.example/mcp", metadata)


def test_recipe_prefix_is_specific_to_new_stack():
    assert PREFIX == "dnsid-oidc-image"


def test_create_or_update_role_refuses_same_name_role_without_recipe_tags(monkeypatch):
    class FakePaginator:
        def paginate(self, **kwargs):
            return [{"Tags": [{"Key": "Project", "Value": "other"}]}]

    class FakeIam:
        def get_role(self, **kwargs):
            return {"Role": {"Arn": "arn:aws:iam::123:role/test"}}

        def get_paginator(self, name):
            assert name == "list_role_tags"
            return FakePaginator()

    monkeypatch.setattr(gateway_resources, "client", lambda service: FakeIam())

    with pytest.raises(RuntimeError, match="IAM role dnsid-oidc-image-target-role"):
        gateway_resources.create_or_update_role(
            "dnsid-oidc-image-target-role",
            "lambda.amazonaws.com",
            "policy",
            {"Version": "2012-10-17", "Statement": []},
        )


def test_create_or_update_lambda_refuses_same_name_function_without_recipe_tags(monkeypatch, tmp_path):
    class FakeLambda:
        def get_function(self, **kwargs):
            return {
                "Configuration": {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123:function:test"
                }
            }

        def list_tags(self, **kwargs):
            return {"Tags": {"Project": "other"}}

    zip_path = tmp_path / "lambda.zip"
    zip_path.write_bytes(b"zip")
    monkeypatch.setattr(gateway_resources, "client", lambda service: FakeLambda())

    with pytest.raises(RuntimeError, match="Lambda function dnsid-oidc-image-target"):
        gateway_resources.create_or_update_lambda(
            "dnsid-oidc-image-target",
            "arn:aws:iam::123:role/test",
            zip_path,
        )


def test_create_or_update_gateway_refuses_same_name_gateway_without_recipe_tags(monkeypatch):
    class FakeAgentCore:
        def list_tags_for_resource(self, **kwargs):
            return {"tags": {"Project": "other"}}

    monkeypatch.setattr(
        gateway_resources,
        "get_gateway_by_name",
        lambda name: {
            "gatewayId": "gateway-id",
            "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123:gateway/test",
        },
    )
    monkeypatch.setattr(gateway_resources, "client", lambda service: FakeAgentCore())

    with pytest.raises(RuntimeError, match="Gateway DnsidOidcImageGateway"):
        gateway_resources.create_or_update_gateway("arn:aws:iam::123:role/test", "aud")


def test_gateway_tags_hydrates_gateway_arn_when_list_response_omits_it():
    class FakeAgentCore:
        def __init__(self):
            self.get_calls = []
            self.tag_calls = []

        def get_gateway(self, **kwargs):
            self.get_calls.append(kwargs)
            return {"gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123:gateway/test"}

        def list_tags_for_resource(self, **kwargs):
            self.tag_calls.append(kwargs)
            return {"tags": tags_dict()}

    fake = FakeAgentCore()

    assert gateway_resources.gateway_tags(fake, {"gatewayId": "gateway-id"}) == tags_dict()
    assert fake.get_calls == [{"gatewayIdentifier": "gateway-id"}]
    assert fake.tag_calls == [
        {"resourceArn": "arn:aws:bedrock-agentcore:us-east-1:123:gateway/test"}
    ]
