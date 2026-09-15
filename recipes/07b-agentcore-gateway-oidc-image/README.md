# Recipe 07b — Minimal AgentCore Gateway OIDC image tool

> Generate a Bedrock image through an AgentCore Gateway MCP tool protected by DNSid OIDC.

**Spec version:** `draft-dnsid-agentcore-gateway-oidc-image-minimal`
**Status:** deploy-only
**Standards used:** RFC 7517 (JWKS), RFC 7519 (JWT), OIDC discovery, Model Context Protocol (MCP), Amazon Bedrock AgentCore Gateway `CUSTOM_JWT`
**Estimated time:** ~25 minutes with AWS and DNSid lab credentials

---

## What you'll build

This recipe creates a minimal Amazon Bedrock AgentCore Gateway MCP endpoint. Gateway validates a DNSid-issued JWT through OIDC discovery and JWKS, checks the token audience against the Gateway protected resource, enforces the configured DNSid subject with Gateway custom claims, and invokes a direct Lambda MCP target named `generate_image`. The Lambda target calls Bedrock image generation and returns a PNG as base64 plus non-secret metadata.

This is intentionally smaller than Recipe 07. It does not create an API Gateway bridge, request or response interceptor Lambda, S3 bucket, audit log, local browser UI, or target-side trusted identity headers. Authorization happens at Gateway. The target receives only the tool arguments and should not claim to know the DNSid identity unless a future Gateway surface forwards verified claims without custom plumbing.

For the component wiring and runtime flow, see [architecture.md](architecture.md).

## Why this matters

The previous image recipe already used DNSid OIDC through AgentCore Gateway `CUSTOM_JWT`, but it also carried custom stack pieces around that path: Gateway interceptors, an API Gateway bridge, trusted-header normalization, response filtering, and S3 audit/artifact storage. This recipe shows the simpler OIDC-adapter shape: configure Gateway with the DNSid issuer, allowed audience, and subject claim; then use the managed MCP Lambda target directly.

## Prerequisites

- Python 3.11+
- `make`
- AWS CLI credentials with permission to create recipe-owned AgentCore Gateway, Lambda, IAM, and CloudWatch resources
- Bedrock model access for `stability.sd3-5-large-v1:0` in `us-west-2`, or set `BEDROCK_IMAGE_MODEL_ID` and `BEDROCK_REGION`
- DNSid OIDC issuer. Defaults to `https://oidc.dnsid.dev`; override with `DNSID_SERVER`
- DNSid lab agent domain provided with `DNSID_AGENT_DOMAIN`
- A server-side DNSid identity directory containing `config.json` and `private.jwk`; set `DNSID_CONFIG_DIR` when it is not the current CLI identity

This recipe is deploy-only. The local tests and probes validate packaging, OIDC discovery, token minting, and Bedrock model access, but the full MCP path requires AWS resources.

## AWS resources

`make deploy-gateway` creates or updates only resources tagged:

```text
Project=dnsid-cookbook
Recipe=07b-agentcore-gateway-oidc-image
```

Resource names use the `dnsid-oidc-image` prefix:

- AgentCore Gateway `DnsidOidcImageGateway`
- AgentCore Gateway target `ImageLambdaTarget`
- Lambda function `dnsid-oidc-image-target`
- IAM roles `dnsid-oidc-image-target-role` and `dnsid-oidc-image-gateway-role`
- CloudWatch log group `/aws/lambda/dnsid-oidc-image-target`
- Local state file `.artifacts/gateway/oidc-image-state.json`

It does not create API Gateway, interceptor Lambdas, S3 buckets, DNSid identities, DNS records, or browser-hosted assets.

## Step 1 — Install the recipe environment

```bash
cd recipes/07b-agentcore-gateway-oidc-image
make setup
```

This creates `.venv/` and installs the recipe package in editable mode.

## Step 2 — Probe DNSid OIDC

```bash
make probe-oidc
```

The probe loads the operational key through `dnsid-py` and performs the JWT bearer token exchange without launching the CLI.

Expected output shape:

```json
{
  "status": "ok",
  "dnsid_oidc": {
    "issuer": "https://oidc.dnsid.dev",
    "jwks_uri": "https://oidc.dnsid.dev/.well-known/jwks.json"
  },
  "token_claims": {
    "sub": "<your-agent-domain>",
    "aud": "dnsid-cookbook-probe",
    "jti_present": true
  }
}
```

The probe never prints the bearer token.

## Step 3 — Probe the Bedrock image model

```bash
make probe-model
```

Expected output shape:

```json
{
  "status": "ok",
  "selected_model_id": "stability.sd3-5-large-v1:0",
  "region": "us-west-2",
  "mime_type": "image/png",
  "width": 1024,
  "height": 1024
}
```

This invokes the configured Bedrock model and may incur AWS cost.

## Step 4 — Deploy Gateway

```bash
make deploy-gateway
```

The deploy script:

1. Packages the Lambda MCP target.
2. Creates or updates the Lambda and Gateway IAM roles.
3. Creates or updates the AgentCore Gateway with provisional `CUSTOM_JWT` audience.
4. Reads the Gateway protected-resource metadata.
5. Updates `allowedAudience` to the Gateway MCP URL.
6. Creates or updates the direct Lambda MCP target.
7. Writes `.artifacts/gateway/oidc-image-state.json`.

Expected output shape:

```json
{
  "status": "ok",
  "authorizer_type": "CUSTOM_JWT",
  "target_type": "lambda",
  "interceptor": "none",
  "api_gateway": "none",
  "gateway_audience": "https://.../mcp"
}
```

## Step 5 — Verify the real DNSid/Gateway MCP path

```bash
make verify
```

The verifier mints short-lived DNSid tokens through the local CLI and checks:

- missing token is rejected
- wrong-audience token is rejected
- unsigned forged token is rejected
- MCP initialize returns a session
- `tools/list` exposes the direct `generate_image` tool
- `tools/call` returns a valid 1024 x 1024 PNG through Bedrock
- the target response does not include target-side identity claims such as `dnsid_context`

Expected output includes only non-secret metadata:

```json
{
  "status": "ok",
  "missing_token_status": 401,
  "session_id_present": true,
  "artifact": {
    "mime_type": "image/png",
    "width": 1024,
    "height": 1024
  }
}
```

## Step 6 — Tear down

```bash
make teardown-gateway
```

The teardown script requires the local state file and refuses to run if the state account does not match the active AWS caller. It deletes the Gateway target, Gateway, Lambda, IAM inline policies and roles, and Lambda log group, then verifies those resources are absent.

If the state file is missing, inventory AWS by tag and name before deleting anything manually. Do not delete resources that are not clearly owned by this recipe.

## Local validation

```bash
make test
make coverage
```

These tests do not call AWS. They validate the OIDC/Gateway configuration shape, request validation, Bedrock response parsing, Lambda response contract, and state-file helpers.
