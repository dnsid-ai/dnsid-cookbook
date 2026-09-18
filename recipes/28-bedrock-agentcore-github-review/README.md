# Recipe 28 — GitHub code review bot on Amazon Bedrock AgentCore

> *A Strands agent deployed to AgentCore Runtime that reviews GitHub PRs — with a DNSid attribution footer on every comment and an AgentCore Gateway routing audit calls through a managed Lambda backend.*

**Spec version:** `dnsid-draft01`
**Status:** deploy-only
**Standards used:** OIDC Core, RFC 7517, RFC 7519, RFC 7523 (JWT Bearer)
**Estimated time:** ~45 minutes

> **Deploy-only:** this recipe needs an AWS account, a GitHub App, and a
> server-side DNSid identity directory. Its managed Gateway path is not part of
> the cookbook's hermetic testnet matrix. It proves the bot's outbound identity
> at `ReviewGateway`; Runtime caller authentication is deployment-specific.

---

## What you'll build

A GitHub code review bot deployed to Amazon Bedrock AgentCore Runtime with an AgentCore MCP Gateway. You invoke it with a prompt like `"Review PR #42 in owner/repo"`. The bot fetches the PR diff, runs a Claude-powered review via the Strands agent framework, posts a structured comment to GitHub, and records the audit via the ReviewGateway's `record_audit` MCP tool — with every comment attributing authorship to the bot's DNSid domain.

Two identities are active throughout:

- **Bot identity** (`<your-bot-domain>.dev.dnsid.ai`) — the agent doing the work. Posted as an attribution footer on every review comment, with a link to verify its identity via DNSid.
- **GitHub identity** — the bot authenticates to GitHub as your GitHub App using installation tokens scoped per-repository. No PAT required; works across any org where that app is installed.

## Why this matters

AgentCore handles the runtime and wires up credential management, but it has no native answer for cross-boundary agent identity — who wrote this review, and how does a reader know it wasn't spoofed? IAM covers intra-AWS trust. DNSid covers the cross-boundary case.

After this recipe: every review comment carries a cryptographically verifiable attribution footer. Anyone can click the link and confirm the domain that signed the review, without trusting any intermediary. The AgentCore Gateway shows how tool calls can be routed through a managed infrastructure layer without giving up that identity story.

## Key design decisions

**GitHub App over PAT.** A GitHub App authenticates using short-lived installation tokens minted per-repository. Install your app on an org; the bot works there immediately. No token rotation, no per-user PATs.

**Private key in Secrets Manager.** The App's private key is stored in the Secrets Manager secret named by `GITHUB_APP_KEY_SECRET_NAME`. The CDK stack grants the runtime's IAM execution role `secretsmanager:GetSecretValue` and injects `GITHUB_APP_KEY_SECRET_ARN` as an env var. Locally, set `GITHUB_APP_KEY_PATH` to the downloaded `.pem` file.

**AgentCore Gateway for audit routing.** The `ReviewGateway` (MCP gateway, `authorizerType: CUSTOM_JWT`) exposes a `record_audit` tool backed by a Lambda function. The bot presents its own DNSid OIDC token (scope: `dnsid:review`) as Bearer auth; the gateway validates it against DNSid's OIDC discovery endpoint before routing to the Lambda. The runtime calls the gateway via Strands `MCPClient` using the auto-injected `AGENTCORE_GATEWAY_REVIEWGATEWAY_URL` env var.

**DNSid identity at attribution.** The bot's DNSid domain is appended to every GitHub review comment as a verifiable footer. Anyone can run `dnsid record verify --domain <your-bot-domain>.dev.dnsid.ai` to confirm the signature.

**DNSid + AgentCore CUSTOM_JWT — what it takes to make it work end-to-end.** The MCP 2025-03-26 protocol layer requires a `scope` claim in the Bearer token in addition to the JWT being valid. DNSid tokens now carry `scope: dnsid:review`; the gateway is configured with `allowedScopes: ["dnsid:review"]`. Without the scope claim, requests that pass JWT auth still get `403 insufficient_scope` from the MCP layer.

| Request | Response | Meaning |
|---|---|---|
| No token | `401 Unauthorized` | JWT auth layer rejected |
| Valid DNSid token, no scope | `403 insufficient_scope` | JWT auth passed; MCP scope check failed |
| Valid DNSid token, scope `dnsid:review` | `200` | Full end-to-end success |

## Concepts

- **DNSid binding** — a TXT record at `_dnsid.<domain>` pointing to a JWKS. A verifier resolves the TXT record and fetches the public key from the URL it contains. Any service can verify any other service's identity on first contact, without a pre-shared secret.
- **OIDC token** — a short-lived signed JWT issued against the agent's DNSid OIDC endpoint. The `iss` claim is the agent's domain; the signature verifies against the JWKS at `/.well-known/jwks.json`. Standard OIDC libraries validate it.
- **AgentCore Runtime** — AWS managed execution environment for agents. Takes a zip of your Python code, handles scaling and session lifecycle, exposes an HTTPS invocation endpoint.
- **AgentCore Gateway (MCP)** — a managed MCP endpoint in front of tool backends (Lambda, MCP servers, API Gateway, etc.). Supports `NONE`, `AWS_IAM`, and `CUSTOM_JWT` inbound auth. The gateway auto-injects `AGENTCORE_GATEWAY_<NAME>_URL` and `AGENTCORE_GATEWAY_<NAME>_AUTH_TYPE` env vars into the runtime.
- **CUSTOM_JWT authorizer** — validates inbound JWT tokens against a configured OIDC discovery endpoint. Requires `allowedScopes`, `allowedAudience`, `allowedClients`, or `customClaims` in the config. The MCP protocol layer additionally requires the token to carry a `scope` claim — JWT validation passing is not sufficient on its own.
- **Strands** — AWS open-source Python agent framework. An `Agent` takes a model and a list of `@tool`-decorated functions; it runs the model-call/tool-execution loop. No orchestration graph required.
- **GitHub App** — a GitHub integration that authenticates as itself (not a user). Uses a private key to mint short-lived installation tokens scoped to specific repositories or orgs.

## Architecture

For the dedicated component wiring and runtime flow, see [architecture.md](architecture.md).

```
Caller ──► AgentCore Runtime ──► Claude (via Bedrock)
                                       │
                                       │ tools
                                       ▼
                               get_pr_diff / get_pr_metadata
                               post_review_comment  ──► GitHub API
                                   │                  (GitHub App token)
                               audit_review
                                   │
                                   ├── AGENTCORE_GATEWAY_REVIEWGATEWAY_URL set?
                                   │     ▼ yes (auto-injected by CDK)
                                   │   MCPClient ──► ReviewGateway (MCP, CUSTOM_JWT)
                                   │   (DNSid token,   │ validates dnsid:review scope
                                   │   scope:review)   ▼
                                   │                record_audit Lambda
                                   │
                                   └── fallback: direct HTTP POST
                                         ──► AUDIT_ENDPOINT
                                             (DNSid OIDC token)

Review comment posted to PR:
  "Reviewed by `<your-bot-domain>.dev.dnsid.ai` — verify identity"
```

**Deployed resources:**

| Resource | ARN / URL |
|---|---|
| Runtime | `arn:aws:bedrock-agentcore:us-east-1:<AWS_ACCOUNT_ID>:runtime/<RUNTIME_ID>` |
| ReviewGateway | `arn:aws:bedrock-agentcore:us-east-1:<AWS_ACCOUNT_ID>:gateway/<GATEWAY_ID>` |
| ReviewGateway MCP URL | `https://<GATEWAY_ID>.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp` |
| AuditBackend Lambda | `arn:aws:lambda:us-east-1:<AWS_ACCOUNT_ID>:function:GitHubReviewBot-AuditBackend` |

## Prerequisites

> **Observability note.** The deployed bot depends on `aws-opentelemetry-distro`, which AgentCore uses to
> emit traces and metrics to **your own** AWS account (CloudWatch / X-Ray). Nothing is sent to DNSid or
> Known Systems. Set `enableOtel: false` in the AgentCore config to turn it off.

- Python 3.11+, `uv`
- Node.js 20+ (for the AgentCore CLI)
- AWS CLI with credentials for account `<AWS_ACCOUNT_ID>`, region `us-east-1`
- AWS CDK: `npm install -g aws-cdk`
- AgentCore CLI: `npm install -g @aws/agentcore`
- `dnsid` CLI for identity setup and manual invocation — authenticate with `dnsid auth login`
- A server-side DNSid identity directory containing `config.json` and `private.jwk`; set `DNSID_CONFIG_DIR`
- A GitHub App installed on the target org
- The App's private key in AWS Secrets Manager, with the secret name exported as `GITHUB_APP_KEY_SECRET_NAME`
- AWS credentials with Bedrock model access on `us.anthropic.claude-sonnet-4-6`

## Step 1 — Install your GitHub App

Install your GitHub App on the org containing the repos you want to review. Select **All repositories** or specific repos.

The app needs `Pull requests: read & write` and `Contents: read`. No webhook setup is needed for manual invocation.

## Step 2 — Configure your environment

Copy the env template and fill in local values:

```bash
cp agentcore/.env.local.example agentcore/.env.local
# edit agentcore/.env.local
```

Key values:

| Variable | Value |
|---|---|
| `GITHUB_APP_ID` | Your GitHub App ID |
| `GITHUB_APP_KEY_PATH` | Path to the downloaded `.pem` private key file |
| `GITHUB_APP_KEY_SECRET_NAME` | Secrets Manager secret name for deployed runtime private-key access |
| `BOT_DOMAIN` | Your lab agent domain, e.g. `<your-bot-domain>.dev.dnsid.ai` |
| `DNSID_CONFIG_DIR` | Server-side directory containing the bot's `config.json` and `private.jwk` |
| `DNSID_SERVER` | DNSid OIDC server, normally `https://api.dnsid.ai` |
| `AUDIT_ENDPOINT` | `http://localhost:9090` for local testing (optional) |
| `REVIEW_GATEWAY_MCP_URL` | Leave blank locally; CDK auto-injects `AGENTCORE_GATEWAY_REVIEWGATEWAY_URL` in deployed env |
| `AWS_*` | Leave blank if already set in your shell environment |

## Step 3 — Ensure the private key is in Secrets Manager (deployed only)

The deployed runtime fetches the GitHub App private key from Secrets Manager. If it's not there yet:

```bash
aws secretsmanager create-secret \
  --name "$GITHUB_APP_KEY_SECRET_NAME" \
  --secret-string "$(cat /path/to/github-app.private-key.pem)" \
  --region us-east-1
```

The secret must exist in the AWS account and region you deploy to before `make deploy`.

## Step 4 — Test locally

```bash
make setup   # installs Python dependencies into .venv
make dev     # starts agentcore dev server on localhost:8080
```

Run `make verify` for the local SDK identity/token-minting check; it does not require an AWS account.

In another terminal:

```bash
agentcore invoke "Review PR #1 in owner/repo"
```

The local server does not enforce inbound auth. The bot fetches the PR, runs the review, and posts a comment to GitHub using the App installation token for that repo.

Optionally, start the audit server to test the direct-HTTP audit path:

```bash
ALLOWED_ISSUERS=<your-bot-domain>.dev.dnsid.ai \
  python scripts/audit_server.py
# → [audit] listening on :9090
```

## Step 5 — Deploy

```bash
export GITHUB_APP_ID=<GITHUB_APP_ID>
export GITHUB_APP_KEY_SECRET_NAME=github-review-bot/private-key
export BOT_DOMAIN=<your-bot-domain>.dev.dnsid.ai
make deploy
# or directly:
agentcore deploy --target default -y
```

The CDK stack:
- Creates the AgentCore Runtime with `PYTHON_3_14` runtime
- Creates the `ReviewGateway` (MCP gateway, `authorizerType: CUSTOM_JWT`, `allowedScopes: ["dnsid:review"]`) with `AuditBackend` Lambda backend
- Grants the runtime's IAM role `secretsmanager:GetSecretValue` on the configured GitHub App key secret
- Injects `GITHUB_APP_ID`, `GITHUB_APP_KEY_SECRET_ARN`, and `BOT_DOMAIN` as env vars
- Requires the runtime environment to provide the bot's `DNSID_CONFIG_DIR`; this deploy-only recipe does not provision private DNSid key material
- Auto-injects `AGENTCORE_GATEWAY_REVIEWGATEWAY_URL` and `AGENTCORE_GATEWAY_REVIEWGATEWAY_AUTH_TYPE`

Deployment takes 5–8 minutes.

## Step 6 — Invoke

```bash
agentcore invoke "Review PR #42 in owner/repo" --target default
```

The bot:
1. Calls `get_pr_metadata` — fetches title, author, branches
2. Calls `get_pr_diff` — fetches file patches (truncated at 32 KB)
3. Reviews with Claude Sonnet
4. Calls `post_review_comment` — posts the review to GitHub with attribution footer
5. Calls `audit_review` → presents DNSid token (scope `dnsid:review`) to `ReviewGateway` via MCP → `record_audit` Lambda logs the entry

## Verify

After invocation, open the PR on GitHub. The review comment ends with:

```
---
*Reviewed by `<your-bot-domain>.dev.dnsid.ai` — [verify identity](https://app.dnsid.ai/v1/status/<your-bot-domain>.dev.dnsid.ai)*
```

Click **verify identity** to confirm the DNSid binding for the bot's domain. You can also verify from the CLI:

```bash
dnsid record verify --domain <your-bot-domain>.dev.dnsid.ai
```

### Validate the gateway identity flows

The deployed `ReviewGateway` uses `authorizerType: CUSTOM_JWT` with DNSid's OIDC discovery endpoint and `allowedScopes: ["dnsid:review"]`.

```bash
GATEWAY=https://<GATEWAY_ID>.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp

# 1. No token → 401
curl -s -o /dev/null -w "%{http_code}" -X POST "$GATEWAY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1}'
# → 401

# 2. Valid DNSid token with scope → 200
TOKEN=$(dnsid token --domain <your-bot-domain>.dev.dnsid.ai --audience "$GATEWAY")
curl -s -o /dev/null -w "%{http_code}" -X POST "$GATEWAY" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1}'
# → 200
```

To verify end-to-end routing, invoke the agent and check CloudWatch logs:

```bash
agentcore invoke "Review PR #1 in owner/repo" --target default
aws logs tail /aws/lambda/GitHubReviewBot-AuditBackend --follow
```

## What the code does

| File | Purpose |
|---|---|
| `app/GitHubReviewBot/main.py` | Agent entrypoint — Strands tools + BedrockAgentCoreApp |
| `app/GitHubReviewBot/dnsid_identity.py` | Server-side DNSid identity loading and OIDC token minting |
| `app/audit_lambda/handler.py` | Lambda backing the `record_audit` MCP tool |
| `agentcore/agentcore.json` | AgentCore project spec — runtime + ReviewGateway config |
| `agentcore/cdk/lib/cdk-stack.ts` | CDK stack — Secrets Manager grant + env var injection |

### `audit_review` — gateway routing

```python
@tool
def audit_review(pr_url: str, summary: str) -> str:
    # Auto-injected by AgentCore CDK construct when ReviewGateway is deployed.
    gateway_url = (
        os.environ.get("AGENTCORE_GATEWAY_REVIEWGATEWAY_URL")
        or os.environ.get("REVIEW_GATEWAY_MCP_URL", "")
    )
    if gateway_url:
        return _audit_via_gateway(gateway_url, pr_url, summary)
    # fallback: direct HTTP POST to AUDIT_ENDPOINT

def _audit_via_gateway(gateway_url: str, pr_url: str, summary: str) -> str:
    token = _get_dnsid_token(audience=gateway_url)
    headers = {"Authorization": f"Bearer {token}"}
    client = MCPClient(lambda: streamablehttp_client(gateway_url, headers=headers))
    with client:
        result = client.call_tool_sync(
            tool_use_id="audit_review",
            name="record_audit",
            arguments={"pr_url": pr_url, "summary": summary},
        )
    return f"Audit recorded via gateway: {result}"
```

The bot uses `dnsid-py`'s `OIDCProfile` to mint a DNSid token (scope `dnsid:review`) from its server-side operational key and passes it as Bearer auth. The gateway validates it (CUSTOM_JWT, `allowedScopes: ["dnsid:review"]`) before routing to the Lambda. `AGENTCORE_GATEWAY_REVIEWGATEWAY_URL` is auto-injected by the CDK construct.

### ReviewGateway configuration (`agentcore.json`)

```json
{
  "name": "ReviewGateway",
  "authorizerType": "CUSTOM_JWT",
  "authorizerConfiguration": {
    "customJwtAuthorizer": {
      "discoveryUrl": "https://api.dnsid.ai/.well-known/openid-configuration",
      "allowedScopes": ["dnsid:review"]
    }
  },
  "targets": [{
    "name": "AuditBackend",
    "targetType": "lambda",
    "toolDefinitions": [{
      "name": "record_audit",
      "inputSchema": { "type": "object", "properties": {
        "pr_url": { "type": "string" },
        "summary": { "type": "string" }
      }}
    }],
    "compute": {
      "host": "Lambda",
      "implementation": { "language": "Python", "path": "app/audit_lambda/", "handler": "handler.lambda_handler" },
      "pythonVersion": "PYTHON_3_13"
    }
  }]
}
```

### `_github_integration()` — GitHub App auth

```python
@functools.lru_cache(maxsize=1)
def _github_integration() -> GithubIntegration:
    # Local: reads .pem from GITHUB_APP_KEY_PATH
    # Deployed: fetches from Secrets Manager via GITHUB_APP_KEY_SECRET_ARN
    return GithubIntegration(auth=Auth.AppAuth(int(app_id), private_key))

def _github_client(owner: str, repo: str) -> Github:
    gi = _github_integration()
    installation = gi.get_repo_installation(owner, repo)
    token = gi.get_access_token(installation.id)
    return Github(token.token)
```

`get_repo_installation()` resolves the correct installation for the org/repo automatically. Adding the bot to a new org requires only installing the GitHub App — no code changes.

## Tested against

- dnsid-ai/dnsid [PR #906](https://github.com/dnsid-ai/dnsid/pull/906#issuecomment-4513908042)
- dnsid-ai/dnsid [PR #908](https://github.com/dnsid-ai/dnsid/pull/908)

Both reviews were posted by the deployed agent authenticated as a GitHub App, with the correct DNSid attribution footer.

## Adding a new org

1. Install your GitHub App on the org
2. Invoke: `agentcore invoke "Review PR #N in org/repo"`

No redeployment, no config changes, no new tokens. `get_repo_installation()` finds the installation automatically.

## Glossary

- **AgentCore Runtime** — the managed execution environment that runs your agent code.
- **AgentCore Gateway (MCP)** — managed MCP proxy in front of tool backends. Exposes tools to agents via MCP protocol. Supports `NONE`, `AWS_IAM`, and `CUSTOM_JWT` inbound auth.
- **CUSTOM_JWT authorizer** — validates inbound JWT tokens against a configured OIDC discovery URL. The MCP protocol layer also requires a `scope` claim in the token; configure `allowedScopes` in the gateway and ensure the token carries a matching scope.
- **GitHub App** — GitHub integration that authenticates as itself using private key + installation tokens. Multi-org, no PAT rotation.
- **JWT Bearer grant (RFC 7523)** — the grant type DNSid uses for OIDC token issuance. The agent signs an assertion with its Ed25519 private key; DNSid verifies the assertion and returns an RS256 token.
- **OIDC** — OpenID Connect. DNSid implements a standard OIDC issuer; standard OIDC libraries (including AgentCore's CUSTOM_JWT authorizer) validate its tokens.
- **Strands** — AWS open-source Python agent framework. `Agent` + `@tool` decorators handle the model-call/tool-execution loop.
