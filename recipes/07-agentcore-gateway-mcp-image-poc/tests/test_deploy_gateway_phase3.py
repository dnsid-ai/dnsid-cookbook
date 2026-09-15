import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import deploy_gateway_phase3 as deploy  # noqa: E402
from deploy_gateway_phase3 import (  # noqa: E402
    existing_rest_api_id_by_state_or_name,
    gateway_role_policy,
    interceptor_lambda_policy,
    target_lambda_policy,
    verified_gateway_audience,
)


@pytest.fixture(autouse=True)
def dnsid_agent_domain(monkeypatch):
    monkeypatch.setenv("DNSID_AGENT_DOMAIN", "agent.example.com")


def actions(policy):
    found = set()
    for statement in policy["Statement"]:
        values = statement["Action"]
        if isinstance(values, str):
            found.add(values)
        else:
            found.update(values)
    return found


def test_interceptor_lambda_policy_has_no_target_permissions():
    policy = interceptor_lambda_policy()

    assert "bedrock:InvokeModel" not in actions(policy)
    assert "s3:PutObject" not in actions(policy)
    assert "s3:GetObject" not in actions(policy)


def test_target_lambda_policy_keeps_model_and_artifact_permissions():
    policy = target_lambda_policy("bucket", "phase3")

    assert "bedrock:InvokeModel" in actions(policy)
    assert "s3:PutObject" in actions(policy)
    assert "s3:GetObject" in actions(policy)


def test_gateway_role_policy_invokes_only_allowed_api_routes():
    policy = gateway_role_policy(
        "123456789012",
        "api123",
        "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
    )

    invoke_statement = policy["Statement"][0]
    assert invoke_statement["Action"] == "execute-api:Invoke"
    assert invoke_statement["Resource"] == [
        "arn:aws:execute-api:us-east-1:123456789012:api123/phase3/POST/generate-image",
        "arn:aws:execute-api:us-east-1:123456789012:api123/phase3/POST/whoami-dnsid",
    ]


def test_main_restricts_rest_api_before_lambda_permission(monkeypatch, tmp_path):
    calls = []
    state = {"rest_api_id": "api123"}
    rendered_openapi = {}

    monkeypatch.setattr(deploy, "account_id", lambda: "123456789012")
    monkeypatch.setattr(deploy, "load_state", lambda: state)
    monkeypatch.setattr(deploy, "ensure_bucket", lambda *args, **kwargs: None)
    monkeypatch.setattr(deploy, "package_lambda", lambda: tmp_path / "lambda.zip")
    monkeypatch.setattr(
        deploy,
        "create_or_update_lambda",
        lambda name, *args, **kwargs: f"arn:aws:lambda:us-east-1:123456789012:function:{name}",
    )

    def create_or_update_role(name, *args, **kwargs):
        calls.append(("role", name))
        return f"arn:aws:iam::123456789012:role/{name}"

    def fake_render_openapi(target_arn, region, resource_policy=None):
        rendered_openapi["resource_policy"] = resource_policy
        return "openapi"

    monkeypatch.setattr(deploy, "create_or_update_role", create_or_update_role)
    monkeypatch.setattr(
        deploy,
        "existing_rest_api_id_by_state_or_name",
        lambda state_rest_api_id, name: "api123",
    )
    monkeypatch.setattr(deploy, "render_openapi", fake_render_openapi)
    monkeypatch.setattr(
        deploy,
        "import_or_update_rest_api",
        lambda *args, **kwargs: calls.append(("import", kwargs.get("rest_api_id")))
        or "api123",
    )
    monkeypatch.setattr(
        deploy,
        "restrict_rest_api_to_gateway_role",
        lambda *args, **kwargs: calls.append(("restrict", None)),
    )
    monkeypatch.setattr(
        deploy,
        "ensure_lambda_permission",
        lambda *args, **kwargs: calls.append(("permission", args[1])),
    )
    monkeypatch.setattr(deploy, "prune_lambda_permissions", lambda *args, **kwargs: None)
    monkeypatch.setattr(deploy, "get_gateway_by_name", lambda name: {"gatewayId": "gw"})
    monkeypatch.setattr(
        deploy,
        "wait_gateway_ready",
        lambda gateway_id: {
            "gatewayId": gateway_id,
            "gatewayUrl": "https://gateway.example/mcp",
            "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw",
        },
    )
    monkeypatch.setattr(
        deploy,
        "protected_resource_metadata",
        lambda gateway_url: {"resource": "https://gateway.example/mcp"},
    )
    monkeypatch.setattr(
        deploy,
        "update_gateway_authorizer",
        lambda *args, **kwargs: (
            {
                "gatewayId": "gw",
                "gatewayUrl": "https://gateway.example/mcp",
                "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw",
            },
            "gateway_custom_claims",
        ),
    )
    monkeypatch.setattr(deploy, "update_interceptor_audience", lambda *args, **kwargs: None)
    monkeypatch.setattr(deploy, "ensure_gateway_target", lambda *args, **kwargs: {"targetId": "target"})
    monkeypatch.setattr(deploy, "save_state", lambda value: state.update(value))
    monkeypatch.setattr(deploy, "state_path_for_output", lambda: tmp_path / "state.json")

    assert deploy.main() == 0

    import_index = calls.index(("import", "api123"))
    restrict_index = calls.index(("restrict", None))
    first_permission_index = min(
        index for index, call in enumerate(calls) if call[0] == "permission"
    )
    assert rendered_openapi["resource_policy"]["Statement"][0]["Sid"] == "DenyNonGatewayRoleInvoke"
    assert import_index < restrict_index
    assert restrict_index < first_permission_index


def test_gateway_params_omits_debug_exception_level():
    params = deploy.gateway_params(
        "arn:aws:iam::123456789012:role/gateway",
        "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
        "https://gateway.example/mcp",
        include_custom_claims=True,
    )

    assert "exceptionLevel" not in params


@pytest.mark.parametrize(
    (
        "existing_gateway",
        "ensure_gateway_subject",
        "authorizer_subject",
        "expected_subject",
        "expected_update_include_custom_claims",
    ),
    [
        # Existing-gateway rows skip ensure_gateway; None marks that return mode unused.
        ({"gatewayId": "gw"}, None, "gateway_custom_claims", "gateway_custom_claims", True),
        ({"gatewayId": "gw"}, None, "downstream", "downstream", True),
        (None, "gateway_custom_claims", "gateway_custom_claims", "gateway_custom_claims", True),
        (None, "gateway_custom_claims", "downstream", "downstream", True),
        (None, "downstream", "downstream", "downstream", False),
    ],
)
def test_main_records_subject_enforcement_and_discovery_filter_mode(
    monkeypatch,
    tmp_path,
    existing_gateway,
    ensure_gateway_subject,
    authorizer_subject,
    expected_subject,
    expected_update_include_custom_claims,
):
    state = {"rest_api_id": "api123"}

    monkeypatch.setattr(deploy, "account_id", lambda: "123456789012")
    monkeypatch.setattr(deploy, "load_state", lambda: state)
    monkeypatch.setattr(deploy, "ensure_bucket", lambda *args, **kwargs: None)
    monkeypatch.setattr(deploy, "package_lambda", lambda: tmp_path / "lambda.zip")
    monkeypatch.setattr(
        deploy,
        "create_or_update_lambda",
        lambda name, *args, **kwargs: f"arn:aws:lambda:us-east-1:123456789012:function:{name}",
    )
    monkeypatch.setattr(
        deploy,
        "create_or_update_role",
        lambda name, *args, **kwargs: f"arn:aws:iam::123456789012:role/{name}",
    )
    monkeypatch.setattr(
        deploy,
        "existing_rest_api_id_by_state_or_name",
        lambda state_rest_api_id, name: "api123",
    )
    monkeypatch.setattr(deploy, "render_openapi", lambda *args, **kwargs: "openapi")
    monkeypatch.setattr(deploy, "import_or_update_rest_api", lambda *args, **kwargs: "api123")
    monkeypatch.setattr(deploy, "restrict_rest_api_to_gateway_role", lambda *args, **kwargs: None)
    monkeypatch.setattr(deploy, "ensure_lambda_permission", lambda *args, **kwargs: None)
    monkeypatch.setattr(deploy, "prune_lambda_permissions", lambda *args, **kwargs: None)
    monkeypatch.setattr(deploy, "get_gateway_by_name", lambda name: existing_gateway)
    monkeypatch.setattr(
        deploy,
        "wait_gateway_ready",
        lambda gateway_id: {
            "gatewayId": gateway_id,
            "gatewayUrl": "https://gateway.example/mcp",
            "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw",
        },
    )
    monkeypatch.setattr(
        deploy,
        "protected_resource_metadata",
        lambda gateway_url: {"resource": "https://gateway.example/mcp"},
    )
    ensure_gateway_calls = []
    authorizer_updates = []

    def ensure_gateway(*args, **kwargs):
        ensure_gateway_calls.append(
            {
                "role_arn": args[0],
                "interceptor_arn": args[1],
                "audience": args[2],
                "include_custom_claims": kwargs["include_custom_claims"],
            }
        )
        assert ensure_gateway_subject is not None
        return (
            {
                "gatewayId": "gw",
                "gatewayUrl": "https://gateway.example/mcp",
                "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw",
            },
            ensure_gateway_subject,
        )

    monkeypatch.setattr(deploy, "ensure_gateway", ensure_gateway)

    def update_gateway_authorizer(*args, **kwargs):
        if not kwargs["include_custom_claims"]:
            assert authorizer_subject == "downstream"
        authorizer_updates.append(
            {
                "gateway_id": args[0],
                "audience": args[3],
                "include_custom_claims": kwargs["include_custom_claims"],
            }
        )
        return (
            {
                "gatewayId": "gw",
                "gatewayUrl": "https://gateway.example/mcp",
                "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw",
            },
            authorizer_subject,
        )

    monkeypatch.setattr(deploy, "update_gateway_authorizer", update_gateway_authorizer)
    monkeypatch.setattr(deploy, "update_interceptor_audience", lambda *args, **kwargs: None)
    monkeypatch.setattr(deploy, "ensure_gateway_target", lambda *args, **kwargs: {"targetId": "target"})
    monkeypatch.setattr(deploy, "save_state", lambda value: state.update(value))
    monkeypatch.setattr(deploy, "state_path_for_output", lambda: tmp_path / "state.json")

    assert deploy.main() == 0

    if existing_gateway:
        assert ensure_gateway_calls == []
    else:
        assert ensure_gateway_calls == [
            {
                "role_arn": "arn:aws:iam::123456789012:role/dnsid-image-poc-phase3-gateway-role",
                "interceptor_arn": "arn:aws:lambda:us-east-1:123456789012:function:dnsid-image-poc-phase3-interceptor",
                "audience": deploy.PROVISIONAL_AUDIENCE,
                "include_custom_claims": True,
            }
        ]
    assert authorizer_updates == [
        {
            "gateway_id": "gw",
            "audience": "https://gateway.example/mcp",
            "include_custom_claims": expected_update_include_custom_claims,
        }
    ]
    assert state["subject_enforcement"] == expected_subject
    assert state["gateway_audience"] == "https://gateway.example/mcp"
    assert state["discovery_filter_mode"] == "response_interceptor"
    assert state["native_discovery_filter_observed"] is False


def test_ensure_gateway_updates_existing_gateway(monkeypatch):
    calls = []
    existing = {"gatewayId": "gw"}
    updated = {
        "gatewayId": "gw",
        "gatewayUrl": "https://gateway.example/mcp",
        "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw",
    }

    def update_gateway_authorizer(*args, **kwargs):
        calls.append(
            {
                "gateway_id": args[0],
                "audience": args[3],
                "include_custom_claims": kwargs["include_custom_claims"],
            }
        )
        return updated, "gateway_custom_claims"

    monkeypatch.setattr(deploy, "client", lambda service: object())
    monkeypatch.setattr(deploy, "get_gateway_by_name", lambda name: existing)
    monkeypatch.setattr(deploy, "update_gateway_authorizer", update_gateway_authorizer)

    gateway, subject_enforcement = deploy.ensure_gateway(
        "arn:aws:iam::123456789012:role/gateway",
        "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
        "https://gateway.example/mcp",
        include_custom_claims=True,
    )

    assert gateway == updated
    assert subject_enforcement == "gateway_custom_claims"
    assert calls == [
        {
            "gateway_id": "gw",
            "audience": "https://gateway.example/mcp",
            "include_custom_claims": True,
        }
    ]


class FakeAgentCore:
    def __init__(self, create_errors=None, update_errors=None):
        self.create_calls = []
        self.update_calls = []
        self.create_errors = list(create_errors or [])
        self.update_errors = list(update_errors or [])

    def create_gateway(self, **params):
        self.create_calls.append(params)
        if self.create_errors:
            raise self.create_errors.pop(0)("CreateGateway")
        return {"gatewayId": "created"}

    def update_gateway(self, **params):
        self.update_calls.append(params)
        if self.update_errors:
            raise self.update_errors.pop(0)("UpdateGateway")
        return {"gatewayId": "updated"}

    def assert_no_remaining_errors(self):
        assert self.create_errors == []
        assert self.update_errors == []


def custom_claims_error(operation):
    # The deploy fallback retries without customClaims when str(ClientError)
    # contains "custom" case-insensitively and custom claims were requested.
    return deploy.ClientError(
        {
            "Error": {
                "Code": "ValidationException",
                "Message": "customClaims are not supported",
            }
        },
        operation,
    )


def access_denied_error(operation):
    return deploy.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "access denied"}},
        operation,
    )


def unrelated_custom_error(operation):
    return deploy.ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "custom permission boundary denied",
            }
        },
        operation,
    )


def test_gateway_authorizer_keeps_custom_claims_when_first_attempt_succeeds(monkeypatch):
    fake = FakeAgentCore()

    monkeypatch.setattr(deploy, "client", lambda service: fake)
    monkeypatch.setattr(deploy, "get_gateway_by_name", lambda name: None)

    gateway, subject_enforcement = deploy.ensure_gateway(
        "arn:aws:iam::123456789012:role/gateway",
        "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
        "https://gateway.example/mcp",
        include_custom_claims=True,
    )
    assert gateway == {"gatewayId": "created"}
    assert subject_enforcement == "gateway_custom_claims"
    assert len(fake.create_calls) == 1
    assert "customClaims" in fake.create_calls[0]["authorizerConfiguration"]["customJWTAuthorizer"]

    gateway, subject_enforcement = deploy.update_gateway_authorizer(
        "gw",
        "arn:aws:iam::123456789012:role/gateway",
        "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
        "https://gateway.example/mcp",
        include_custom_claims=True,
    )
    assert gateway == {"gatewayId": "updated"}
    assert subject_enforcement == "gateway_custom_claims"
    assert len(fake.update_calls) == 1
    assert fake.update_calls[0]["gatewayIdentifier"] == "gw"
    assert "customClaims" in fake.update_calls[0]["authorizerConfiguration"]["customJWTAuthorizer"]


def test_gateway_authorizer_falls_back_to_downstream_when_custom_claims_rejected(monkeypatch):
    fake = FakeAgentCore(
        create_errors=[custom_claims_error],
        update_errors=[custom_claims_error],
    )

    monkeypatch.setattr(deploy, "client", lambda service: fake)
    monkeypatch.setattr(deploy, "get_gateway_by_name", lambda name: None)

    gateway, subject_enforcement = deploy.ensure_gateway(
        "arn:aws:iam::123456789012:role/gateway",
        "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
        "https://gateway.example/mcp",
        include_custom_claims=True,
    )
    assert gateway == {"gatewayId": "created"}
    assert subject_enforcement == "downstream"
    assert "customClaims" in fake.create_calls[0]["authorizerConfiguration"]["customJWTAuthorizer"]
    assert "customClaims" not in fake.create_calls[1]["authorizerConfiguration"]["customJWTAuthorizer"]

    gateway, subject_enforcement = deploy.update_gateway_authorizer(
        "gw",
        "arn:aws:iam::123456789012:role/gateway",
        "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
        "https://gateway.example/mcp",
        include_custom_claims=True,
    )
    assert gateway == {"gatewayId": "updated"}
    assert subject_enforcement == "downstream"
    assert fake.update_calls[0]["gatewayIdentifier"] == "gw"
    assert fake.update_calls[1]["gatewayIdentifier"] == "gw"
    assert "customClaims" in fake.update_calls[0]["authorizerConfiguration"]["customJWTAuthorizer"]
    assert "customClaims" not in fake.update_calls[1]["authorizerConfiguration"]["customJWTAuthorizer"]
    assert "tags" not in fake.update_calls[0]
    assert "clientToken" not in fake.update_calls[0]
    assert "tags" not in fake.update_calls[1]
    assert "clientToken" not in fake.update_calls[1]
    fake.assert_no_remaining_errors()


def test_fallback_classifier_matches_any_error_mentioning_custom(monkeypatch):
    # Characterizes the current loose classifier: any ClientError text containing
    # "custom" case-insensitively triggers fallback when custom claims were requested. The
    # interceptor still checks sub in both modes. Tighten this classifier if
    # Gateway-level subject enforcement should fail closed for unrelated errors.
    fake = FakeAgentCore(
        create_errors=[unrelated_custom_error],
        update_errors=[unrelated_custom_error],
    )

    monkeypatch.setattr(deploy, "client", lambda service: fake)
    monkeypatch.setattr(deploy, "get_gateway_by_name", lambda name: None)

    gateway, subject_enforcement = deploy.ensure_gateway(
        "arn:aws:iam::123456789012:role/gateway",
        "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
        "https://gateway.example/mcp",
        include_custom_claims=True,
    )

    assert gateway == {"gatewayId": "created"}
    assert subject_enforcement == "downstream"
    assert len(fake.create_calls) == 2
    assert "customClaims" in fake.create_calls[0]["authorizerConfiguration"]["customJWTAuthorizer"]
    assert "customClaims" not in fake.create_calls[1]["authorizerConfiguration"]["customJWTAuthorizer"]

    gateway, subject_enforcement = deploy.update_gateway_authorizer(
        "gw",
        "arn:aws:iam::123456789012:role/gateway",
        "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
        "https://gateway.example/mcp",
        include_custom_claims=True,
    )

    assert gateway == {"gatewayId": "updated"}
    assert subject_enforcement == "downstream"
    assert len(fake.update_calls) == 2
    assert "customClaims" in fake.update_calls[0]["authorizerConfiguration"]["customJWTAuthorizer"]
    assert "customClaims" not in fake.update_calls[1]["authorizerConfiguration"]["customJWTAuthorizer"]
    fake.assert_no_remaining_errors()


def test_gateway_authorizer_propagates_non_custom_claim_errors(monkeypatch):
    fake = FakeAgentCore(
        create_errors=[access_denied_error],
        update_errors=[access_denied_error],
    )

    monkeypatch.setattr(deploy, "client", lambda service: fake)
    monkeypatch.setattr(deploy, "get_gateway_by_name", lambda name: None)

    with pytest.raises(deploy.ClientError):
        deploy.ensure_gateway(
            "arn:aws:iam::123456789012:role/gateway",
            "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
            "https://gateway.example/mcp",
            include_custom_claims=True,
        )
    assert len(fake.create_calls) == 1

    with pytest.raises(deploy.ClientError):
        deploy.update_gateway_authorizer(
            "gw",
            "arn:aws:iam::123456789012:role/gateway",
            "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
            "https://gateway.example/mcp",
            include_custom_claims=True,
        )
    assert len(fake.update_calls) == 1
    fake.assert_no_remaining_errors()


def test_gateway_authorizer_propagates_custom_claim_errors_when_custom_claims_disabled(monkeypatch):
    fake = FakeAgentCore(
        create_errors=[custom_claims_error],
        update_errors=[custom_claims_error],
    )

    monkeypatch.setattr(deploy, "client", lambda service: fake)
    monkeypatch.setattr(deploy, "get_gateway_by_name", lambda name: None)

    with pytest.raises(deploy.ClientError):
        deploy.ensure_gateway(
            "arn:aws:iam::123456789012:role/gateway",
            "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
            "https://gateway.example/mcp",
            include_custom_claims=False,
        )
    assert len(fake.create_calls) == 1

    with pytest.raises(deploy.ClientError):
        deploy.update_gateway_authorizer(
            "gw",
            "arn:aws:iam::123456789012:role/gateway",
            "arn:aws:lambda:us-east-1:123456789012:function:interceptor",
            "https://gateway.example/mcp",
            include_custom_claims=False,
        )
    assert len(fake.update_calls) == 1
    fake.assert_no_remaining_errors()


def test_verified_gateway_audience_requires_exact_gateway_resource():
    assert (
        verified_gateway_audience(
            "https://gateway.example/mcp",
            {"resource": "https://gateway.example/mcp/"},
        )
        == "https://gateway.example/mcp/"
    )

    with pytest.raises(RuntimeError, match="did not match"):
        verified_gateway_audience(
            "https://gateway.example/mcp",
            {"resource": "https://other.example/mcp"},
        )

    with pytest.raises(RuntimeError, match="did not include resource"):
        verified_gateway_audience("https://gateway.example/mcp", {"resource": ""})


def test_existing_rest_api_id_resolves_state_id_before_name(monkeypatch):
    class FakeApiGatewayClient:
        def get_rest_api(self, **kwargs):
            assert kwargs == {"restApiId": "state-api"}
            return {"id": "state-api"}

    monkeypatch.setattr(deploy, "client", lambda service: FakeApiGatewayClient())
    monkeypatch.setattr(deploy, "find_rest_api", lambda name: {"id": "named-api"})

    assert existing_rest_api_id_by_state_or_name("state-api", "api-name") == "state-api"


def test_existing_rest_api_id_falls_back_when_state_id_is_stale(monkeypatch):
    class FakeApiGatewayClient:
        def get_rest_api(self, **kwargs):
            raise deploy.ClientError(
                {"Error": {"Code": "NotFoundException"}},
                "GetRestApi",
            )

    monkeypatch.setattr(deploy, "client", lambda service: FakeApiGatewayClient())
    monkeypatch.setattr(deploy, "find_rest_api", lambda name: {"id": "named-api"})

    assert existing_rest_api_id_by_state_or_name("stale-api", "api-name") == "named-api"
