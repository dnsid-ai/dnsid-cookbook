# DNSid OIDC AgentCore Gateway orders demo plan

Status: planning artifact

This plan is for a future cookbook recipe that demonstrates a cross-organization order flow:

- Org A: `bank-a.example`, with procurement agent `agent.bank-a.example` running on Amazon Bedrock AgentCore Runtime.
- Org B: `supplier-b.example`, with an Order API exposed as MCP tools through Amazon Bedrock AgentCore Gateway.
- Trust fabric: public DNS plus DNSid records. There is no pre-shared API key, static partner secret, or prior key exchange between Org A and Org B.

## Goal and narrative

The demo shows a bank procurement agent placing a small supplier order across an organizational boundary. Org B is the relying party. Org B verifies the caller's DNSid identity, validates the Gateway bearer token, checks live DNSid status, applies a deterministic policy gate, then lets the Order API create the order.

The visible story is browser-driven, not just a CLI transcript. The operator
opens Org A's procurement-agent chat UI, sends a normal purchasing prompt, and
watches Org B's separate observer UI record each inbound Gateway/tool attempt.

The visible story is four beats:

1. Join: `agent.bank-a.example` reaches Org B for the first time and is recognized from DNSid, not from a pre-registered key.
2. Short task: the procurement agent places one low-risk order.
3. Revoke mid-flow: the owner of `agent.bank-a.example` revokes the agent while the session and JWT are still alive.
4. Cut-off on next action: the next sensitive action is denied by a synchronous `su` status check, visibly because of the owner revoke and not because the token expired.

The language in the recipe must stay precise:

- `verify`: establish DNSid identity by resolving DNSid and verifying the accountable-entity signature.
- `validate`: check token-level JWT properties in the Gateway authorizer.
- `trust decision`: deterministic allow/deny from DNSid verification, JWT validation, live status, and policy evaluation together.

The LLM is never in the trust path. It may choose tool arguments, but it does not decide whether the call is trusted.

## End-state demo surface

The cookbook must drive toward a deployed Bedrock/AgentCore demo. Local mocks,
direct Gateway probes, and CLI commands are allowed as backup diagnostics, but
the primary demo path is:

1. Deployed Org A AgentCore Runtime runs the procurement agent.
2. Deployed Org B AgentCore Gateway fronts the order tools.
3. A browser chat surface sends the operator's prompt to the deployed Runtime.
4. A separate browser observer surface shows Org B evidence for every inbound
   Gateway/tool attempt in the demo.

The Org A chat surface is the user trigger. A human/operator message such as
"order 10 cases of demo packing labels" is submitted to the Runtime-backed chat
UI with a session ID. The browser does not call Org B Gateway directly and does
not receive the DNSid bearer token, signing key, `su` result, or trusted
identity headers.

Prompt-to-tool mapping stays outside the trust path:

- The LLM may translate the chat prompt into a proposed tool name and arguments.
- Runtime code validates the proposed tool against the allowed order tools,
  normalizes arguments, enforces local shape checks, mints the DNSid OIDC token,
  signs the canonical action proof, and calls the Org B Gateway MCP endpoint.
- The LLM cannot set `dnsid_sub`, owner domain, `su_status`, token metadata,
  policy outcome, trusted headers, or order-created evidence.
- If the LLM proposes an over-limit amount, unsupported SKU, or missing field,
  deterministic validation or Org B policy rejects the call. A caller-supplied
  "verified" field is ignored.

The exact UI host is an implementation choice to confirm. Current local sources
prove a Recipe 07-style local browser UI that drives deployed Gateway calls, and
Recipe 28 proves deployed Runtime invocation. If AgentCore provides a hosted
Runtime chat UI suitable for cookbook automation, use it. Otherwise, build a
recipe-owned local browser UI whose chat endpoint invokes the deployed Runtime;
the claim should be "Runtime-backed chat UI", not "AWS-hosted chat UI".

## What the existing recipes already prove

Recipe 07, `recipes/07-agentcore-gateway-mcp-image-poc`, is the closest deployed pattern. It uses AgentCore Gateway with `CUSTOM_JWT`, API Gateway/Lambda as the tool backend, Gateway request/response interceptors, Gateway-audience discovery from `/.well-known/oauth-protected-resource`, trusted `x-dnsid-*` headers injected by the interceptor, a resource policy that denies direct target invocation, S3 audit artifacts, and a local browser UI. The browser UI calls only a local backend; that backend mints tokens server-side, invokes the deployed Gateway MCP path, returns safe display metadata, and is checked with Browser Console Bridge for visible UI state, no console errors, and no token/presigned-URL leakage.

Recipe 07b, `recipes/07b-agentcore-gateway-oidc-image`, proves the minimal OIDC adapter shape. It configures Gateway `CUSTOM_JWT` with DNSid OIDC discovery, `allowedAudience`, and a `customClaims` `sub` match, then invokes a direct Lambda MCP target. It intentionally removes API Gateway, interceptors, S3 audit, and target-side identity context.

Recipe 28, `recipes/28-bedrock-agentcore-github-review`, proves the AgentCore Runtime caller shape. A Runtime-hosted agent obtains a DNSid token and calls an AgentCore Gateway MCP endpoint. It also shows a Gateway configured with `allowedScopes` and a Runtime app using the Gateway URL from configuration.

The orders recipe differs from all three:

- It uses cross-organization actor names rather than a lab image or GitHub bot identity.
- It requires a live DNSid `su` status check on each sensitive action, so JWT validation alone is not enough.
- It includes an accountable-entity signature proof over the action payload, not just a bearer token.
- It needs a deterministic policy gate for order actions and amounts.
- It must show mid-flow revocation cutting off the next sensitive action while the token is still unexpired.
- It needs two human-facing UI surfaces: Org A chat to trigger the Runtime and Org B observer to prove every accepted and rejected attempt.

## Architecture choice

Chosen path: start from Recipe 07's API Gateway target pattern, then add the OIDC minimalism from Recipe 07b and the Runtime caller from Recipe 28.

The Order API is an API Gateway REST API backed by Lambda, exposed through AgentCore Gateway as an MCP target. The Gateway has:

- `authorizerType: CUSTOM_JWT`
- DNSid OIDC `discoveryUrl`
- `allowedAudience` set to the Gateway MCP protected resource
- `allowedScopes`, if the DNSid token surface supports a stable scope claim for this use case
- a REQUEST interceptor that verifies the DNSid action proof and performs the synchronous `su` status check
- a Policy in AgentCore engine in `ENFORCE` mode for deterministic tool authorization

Why not the direct Lambda target from 07b? The direct target is the right minimal OIDC teaching case, but this demo needs trusted identity context at the Order API and a visible API boundary. The existing 07 API Gateway target already demonstrates the trusted-header and direct-invocation-deny pattern this flow needs.

Why not make Org B a DNSid agent? Org B is the relying party/verifier. It does not need to publish a DNSid agent identity just to verify Org A. Add a Supplier B DNSid identity only for an optional extension where Supplier B signs the order receipt or where the demo requires mutual identity.

## Actor and resource model

Org A resources:

- `bank-a.example`: accountable owner domain.
- `agent.bank-a.example`: procurement agent DNSid subject.
- `_dnsid.agent.bank-a.example`: TXT binding with `ku` and `su`.
- JWKS at the `ku` URI: public key used to verify the action proof.
- Status endpoint at the `su` URI: returns active/ready before revoke and revoked after owner revoke.
- AgentCore Runtime app: prompts the model, constructs order intents, mints DNSid OIDC tokens, signs action proofs with the shared SDK, and calls Org B Gateway MCP.
- Org A chat UI: browser surface for the operator. It sends chat messages and session IDs to the Runtime invocation path, displays the agent response, and links each attempted order action to the Org B observer by correlation ID. It does not expose tokens or signing material.

Org B resources:

- `supplier-b.example`: relying party organization.
- AgentCore Gateway: MCP front door for order tools.
- Gateway REQUEST interceptor Lambda: verifier for DNSid proof and live `su` status.
- Policy in AgentCore engine: deterministic allow/deny for tool/action/input.
- API Gateway REST API: Order API target, reachable only from the Gateway execution role.
- Order Lambda: implements `join`, `place_order`, `get_order`, and `cancel_order` demo endpoints.
- Observer audit sink: stores one sanitized event per inbound demo attempt and follow-on Order API result. It should be backed by deployable AWS storage, following Recipe 07's S3 audit-artifact pattern unless implementation chooses a queryable table for the live UI.
- Org B observer UI: separate browser surface for the relying party. It shows a live timeline/table of accepted and rejected attempts, with revoked-identity denials pinned and visually distinct from ordinary validation or policy failures.
- CloudWatch logs: evidence source for JWT validation outcome, DNSid verification outcome, `su` status check, policy decision, and Order API result. If AgentCore Gateway does not expose enough per-request log detail for pre-interceptor authorization failures, the implementation must keep that as a documented gap and only claim full observer coverage for the scripted demo attempts it can record.

No Org B DNSid agent is required for the base recipe. Optional extension:

- `orders.supplier-b.example` signs order receipts with DNSid, so Bank A can verify Supplier B's response attribution.

## Trust boundary diagram

```text
Operator browser
  |
  | chat message + session ID
  v
Org A Runtime chat UI
  |
  v
Org A AgentCore Runtime
  - LLM proposes order task
  - runtime code validates and normalizes proposed tool args
  - runtime code mints DNSid OIDC JWT
  - runtime code signs canonical action proof
  |
  | MCP over HTTPS
  | Authorization: Bearer <DNSid OIDC JWT>
  | X-DNSid-Action-Proof: <signed proof>
  v
Org B AgentCore Gateway
  - validates JWT with CUSTOM_JWT
  - exposes Order API as MCP tools
  - emits/records Gateway-level auth outcome when available
  |
  v
Gateway REQUEST interceptor
  - resolves _dnsid.agent.bank-a.example
  - fetches ku JWKS
  - verifies accountable-entity action signature
  - synchronously calls su status endpoint
  - strips caller-supplied x-dnsid-* headers
  - injects trusted x-dnsid-* headers
  |
  v
Policy in AgentCore
  - evaluates principal, action, resource, and tool input
  - default deny; explicit permit for allowed order actions
  |
  v
API Gateway REST API
  - resource policy permits only Gateway role
  |
  v
Order Lambda
  - requires trusted DNSid context headers
  - creates or rejects the order
  - logs evidence

Org B observer UI
  ^
  |
  +-- observer audit sink + CloudWatch-derived evidence
      - shows every accepted/rejected demo attempt
      - highlights revoked-identity denials
      - correlates Runtime response, Gateway attempt, policy decision,
        Order API result, and order-not-created proof
```

The exact ordering between the interceptor and Policy in AgentCore must be confirmed during implementation. Correctness must not depend on a fragile ordering assumption. Every sensitive Order API endpoint must require trusted verifier output, and every tool invocation must pass the policy gate before an order is created.

## Pre-baked setup

DNSid setup:

- Provision `agent.bank-a.example` with an active `_dnsid` TXT record:

  ```text
  v=dnsid1;ku=https://agent.bank-a.example/.well-known/jwks.json;su=https://agent.bank-a.example/status
  ```

- Preload the corresponding private key into the Org A Runtime environment through a demo-safe secret mechanism.
- Ensure the DNSid OIDC issuer can mint tokens where:
  - `sub=agent.bank-a.example`
  - `aud=<Gateway MCP URL>`
  - `scope` includes the order scope if scopes are supported for this issuer
  - `exp` is long enough to survive the revoke and cut-off beats
  - `jti` is present for audit correlation
- Provide a deterministic status-control command for the demo owner. The implementation must confirm the exact shared SDK or lab CLI surface before coding. If the public SDK cannot mutate demo status, use a pre-baked lab status endpoint and document that limitation.

AWS setup:

- Deploy the Org B Gateway in `us-east-1`.
- Deploy the Org A Runtime in `us-east-1` using the Recipe 28 caller shape.
- Discover the Gateway MCP audience from `/.well-known/oauth-protected-resource` and update `allowedAudience` to match it.
- Deploy the Order API Lambda and API Gateway REST API.
- Deploy the observer audit sink and any lightweight read API needed by the Org B observer UI.
- Attach the REST API stage as a Gateway target with tool filters and tool names:
  - `join_supplier`
  - `place_order`
  - `get_order`
  - `cancel_order`
- Attach a REQUEST interceptor Lambda with `passRequestHeaders=true`.
- Attach Policy in AgentCore in `ENFORCE` mode.
- Add a REST API resource policy that denies direct calls unless the principal is the Gateway execution role.
- Enable CloudWatch logging for Gateway, interceptor, API Gateway, and Lambda.

Repository setup:

- New recipe path should be `recipes/30-agentcore-gateway-dnsid-oidc-orders/`.
- Use `make setup`, `make deploy`, `make verify`, `make ui`, `make demo-join`, `make demo-short-task`, `make owner-revoke`, `make demo-cutoff`, and `make verify-browser`.
- Keep generated state under `.artifacts/`, following recipes 07 and 07b.
- Keep tokens and private keys out of logs. Log token hashes, `jti` hashes, proof hashes, and status evidence only.
- The default UI mode must drive deployed Runtime/Gateway resources. Local fixture mode is allowed only for fallback diagnostics and must be visibly labeled.

## Exact DNSid/OIDC/Gateway flow

### Token validation

The Org A runtime mints a DNSid OIDC token for the Gateway audience:

```bash
dnsid token \
  --domain agent.bank-a.example \
  --audience "$SUPPLIER_B_GATEWAY_MCP_URL" \
  --scope dnsid:orders
```

Gateway validates this token with `CUSTOM_JWT`:

- OIDC discovery is fetched from the DNSid issuer's `/.well-known/openid-configuration`.
- JWKS is fetched from the issuer metadata.
- JWT signature, issuer, audience, expiry, and configured scopes/custom claims are checked.
- Missing/invalid token returns `401`.
- Valid token with insufficient scope returns `403 insufficient_scope` when scopes are configured.

This is validation, not the full DNSid trust decision.

### DNSid verification and live status

For every sensitive action, the runtime signs a canonical action payload with the private key for `agent.bank-a.example`. The proof should cover:

- DNSid subject: `agent.bank-a.example`
- Gateway audience
- token `jti` or token hash
- MCP method: `tools/call`
- tool name
- normalized tool arguments hash
- timestamp
- nonce or request ID

The interceptor verifies the proof:

1. Read the subject and key ID from the proof.
2. Resolve `_dnsid.agent.bank-a.example`.
3. Fetch the JWKS from the `ku` URI.
4. Verify the action signature.
5. Check the DNSid binding/registry signature through the shared SDK.
6. Call the `su` URI synchronously with no cache for `place_order` and `cancel_order`.
7. Require active/ready status. Reject revoked, missing, stale, or unverifiable status.
8. Strip caller-supplied `x-dnsid-*` headers and inject trusted headers.

This is verification.

### Policy gate

Policy in AgentCore evaluates the action after token validation and before any accepted order is committed. Base policy:

- permit `join_supplier` for verified DNSid callers with the order scope
- permit `place_order` only when:
  - caller DNSid subject is `agent.bank-a.example` or belongs to an explicitly configured buyer domain for the demo
  - `currency == "USD"`
  - `amount <= 1000`
  - `sku` is in the demo catalog
  - `status_check_result == "active"` if that verified context is exposed to the policy engine
- forbid all order-changing actions by default when the proof/status context is missing

If Policy in AgentCore cannot consume the interceptor-produced verified context, keep the policy gate on JWT principal and tool input, and enforce proof/status in the interceptor and Order API. Do not let the LLM or a caller-supplied field stand in for the status result.

### Target execution

The Order API only processes mutating requests when the trusted verifier context is present. It logs:

- `dnsid_sub`
- `dnsid_owner_domain`
- `jwt_iss`
- `jwt_aud_hash`
- `jwt_jti_hash`
- `proof_hash`
- `su_url_hash`
- `su_status`
- `su_checked_at`
- `token_exp`
- `policy_decision`
- `tool_name`
- `order_id`
- `decision_id` or correlation ID
- `request_id`
- `runtime_session_id_hash`
- `mcp_session_id_hash`
- `http_status`
- `mcp_error_code`
- `rejection_source`
- `rejection_reason`
- `order_created`

### Observer UI and audit contract

Org B's observer UI is a separate relying-party view. It is not embedded in
the Org A chat page, and it must not depend on any caller-supplied identity
field. The UI reads sanitized audit events from Org B-owned storage and, where
available, CloudWatch/Gateway evidence.

For every inbound Gateway/tool attempt in the demo, the observer shows:

- timestamp and correlation ID
- Runtime session hash and MCP session hash
- tool name and normalized argument summary
- caller DNSid subject and owner domain, if verified
- JWT issuer, audience hash, `jti` hash, token expiry, and whether the token was still unexpired at decision time
- proof hash, proof verification result, and signing key ID
- `su` URL hash, `su_status`, `su_checked_at`, and status latency
- policy mode, policy decision, and policy reason/code
- Gateway/interceptor/Order API status code and error code
- order ID for accepted creates, or explicit `order_created=false` for denied mutating requests
- audit event source: `gateway_auth`, `interceptor`, `policy`, `order_api`, or `verifier_probe`

Accepted calls must show a linked chain from chat message to Runtime invocation,
Gateway tool call, policy allow, and Order API create/read result. Rejected
calls must show the first rejecting layer and the proof that later layers did
not create an order.

Revoked-identity denials get a distinct high-priority treatment:

- row/status label: `revoked identity denied`
- denial reason: `dnsid_status_revoked`
- owner revoke time from the status-control command or status endpoint
- `su_status=revoked` and `su_checked_at` after the owner revoke time
- `token_exp` after `su_checked_at`, proving the JWT was still alive
- same `dnsid_sub` as the earlier accepted order
- same or linked Runtime session, when the demo reuses the session
- `order_created=false`, plus an order-store lookup or count showing no new order was committed after the denial

The observer can use a local browser server in the Recipe 07 pattern, but its
default data source must be deployed evidence from the Org B stack. Fixture
mode is acceptable only for local UI development and must be visibly labeled.

The implementation must resolve one logging gap before making a broad claim:
the current local validation does not prove that AgentCore Gateway exposes a
complete per-request event for requests rejected before a REQUEST interceptor
runs. If that surface is unavailable, the recipe can still show every scripted
demo attempt by having the verifier/chat driver pre-assign correlation IDs and
record expected Gateway-auth negative probes, but it must not claim arbitrary
internet-wide unauthenticated traffic coverage.

## Live demo beats

These commands are proposed recipe commands.

### Beat 1: Join

Command:

```bash
make demo-join
```

Browser action:

- Open the Org A chat UI.
- Send: `Join Supplier B's order gateway as agent.bank-a.example and report the verified identity.`
- Keep the Org B observer UI open in a separate browser tab/window.

Underlying call:

```bash
agentcore invoke --runtime BankAProcurementAgent \
  "Join Supplier B's order gateway as agent.bank-a.example and report the verified identity."
```

Expected visible output:

```json
{
  "ok": true,
  "beat": "join",
  "dnsid_sub": "agent.bank-a.example",
  "supplier": "supplier-b.example",
  "verified": true,
  "validated": true,
  "status": "active",
  "policy_decision": "allow"
}
```

Evidence:

- Gateway log: token validation accepted `sub=agent.bank-a.example`.
- Interceptor log: DNSid proof verified, live `su` returned active.
- Policy log: `join_supplier` allowed.
- Order API log: session or join record created with correlation ID.
- Observer UI: one accepted `join_supplier` row with matching correlation ID, token metadata, proof metadata, active `su` result, policy allow, and no secret material.

Backup:

- `make demo-join-local` runs the same verifier path against a local status fixture and local Order API without invoking the deployed Runtime.

### Beat 2: Short task

Command:

```bash
make demo-short-task
```

Browser action:

- In the same Org A chat session, send: `Order 10 cases of demo packing labels from Supplier B under the demo spend limit.`
- Watch the Org B observer UI append the accepted `place_order` row.

Underlying call:

```bash
agentcore invoke --runtime BankAProcurementAgent \
  "Order 10 cases of demo packing labels from Supplier B under the demo spend limit."
```

Expected visible output:

```json
{
  "ok": true,
  "beat": "short_task",
  "order_id": "ord-demo-...",
  "sku": "LABEL-CASE",
  "quantity": 10,
  "amount": 250,
  "dnsid_sub": "agent.bank-a.example",
  "trust_decision": "allow"
}
```

Evidence:

- Interceptor log shows `su_status=active`.
- Policy log shows `place_order` allowed because amount and SKU satisfy policy.
- Order API log shows `order_created=true` with the same correlation ID.
- Observer UI shows `order_created=true`, order ID, amount, SKU, active status, unexpired token, and policy allow for the same correlation ID shown by the chat response.

Backup:

- `make demo-short-task-direct` calls the Gateway MCP endpoint directly with a minted token and signed proof, bypassing the LLM while preserving the trust path.

### Beat 3: Revoke mid-flow

Command:

```bash
make owner-revoke DNSID_AGENT_DOMAIN=agent.bank-a.example
```

Browser action:

- Run the owner revoke command from the recipe terminal while leaving both browser tabs open.
- The Org B observer UI should show a visible owner-revoke marker or banner once the status-control command writes the revoke evidence into the audit stream.

Expected visible output:

```json
{
  "ok": true,
  "beat": "revoke_mid_flow",
  "dnsid_sub": "agent.bank-a.example",
  "owner_action": "revoked",
  "status": "revoked",
  "revoked_at": "<timestamp>"
}
```

Evidence:

- Status endpoint returns revoked from the `su` URI.
- Previously minted token remains unexpired. The script should print safe decoded token metadata:

  ```json
  {
    "sub": "agent.bank-a.example",
    "jti_present": true,
    "exp_after_now": true
  }
  ```
- Observer UI records `owner_revoked_at` for `agent.bank-a.example` so the next denial can be compared against the revoke time.

Backup:

- If the DNSid lab status-control surface is unavailable, use the pre-baked demo status endpoint toggle and clearly label it as a fixture. Do not claim this proves production DNSid status mutation.

### Beat 4: Cut-off on next action

Command:

```bash
make demo-cutoff REUSE_PRE_REVOKE_TOKEN=1
```

Browser action:

- In the existing Org A chat session, send: `Place another order for demo packing labels.`
- Watch the Org B observer UI append a highlighted `revoked identity denied` row.

Underlying call:

```bash
agentcore invoke --runtime BankAProcurementAgent \
  "Place another order for demo packing labels."
```

Expected visible output:

```json
{
  "ok": false,
  "beat": "cutoff",
  "trust_decision": "deny",
  "reason": "dnsid_status_revoked",
  "dnsid_sub": "agent.bank-a.example",
  "token_exp_after_now": true
}
```

Evidence:

- Gateway may still validate the JWT because the token has not expired.
- Interceptor synchronously calls `su` and receives revoked.
- The Order API does not create a new order.
- Logs tie the denial to the owner revoke timestamp and the same DNSid subject.
- Observer UI highlights `dnsid_status_revoked`, shows `token_exp_after_now=true`, shows `su_checked_at` after `owner_revoked_at`, and shows `order_created=false` plus an order-store count or lookup proving no denied order was committed.

Backup:

- `make demo-cutoff-direct` reuses the captured token/proof fixture against the Gateway endpoint and verifies that no new order row exists.

## AWS surfaces and official documentation links

Use these AWS surfaces:

- Amazon Bedrock AgentCore Runtime for Org A's hosted procurement agent: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html>
- AgentCore CLI deployment and invocation for Runtime: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-get-started-cli.html>
- Amazon Bedrock AgentCore Gateway as the MCP front door: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html>
- Gateway core concepts, targets, and authorizers: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-core-concepts.html>
- Gateway inbound JWT authorization: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-inbound-auth.html>
- `CUSTOM_JWT` authorizer configuration: <https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CustomJWTAuthorizerConfiguration.html>
- Gateway creation API: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-create-api.html>
- API Gateway REST API stage as a Gateway target: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-add-target-api-target-config.html>
- API Gateway guide for adding a REST API target to AgentCore Gateway: <https://docs.aws.amazon.com/apigateway/latest/developerguide/mcp-server.html>
- Gateway interceptors: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors.html>
- Fine-grained Gateway access control: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-fine-grained-access-control.html>
- Policy in AgentCore and Cedar: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html>
- Cedar policy semantics in AgentCore: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-understanding-cedar.html>
- Policy engine association with Gateway: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/create-gateway-with-policy.html>
- Policy engine configuration modes: <https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_GatewayPolicyEngineConfiguration.html>

## Cookbook file and recipe structure proposal

```text
recipes/30-agentcore-gateway-dnsid-oidc-orders/
  README.md
  Makefile
  pyproject.toml
  app/
    bank_a_procurement_agent/
      main.py
      order_gateway_client.py
      dnsid_proof.py
    demo_console/
      server.py
      chat_runtime_client.py
      observer_events.py
      static/
        org-a-chat.html
        org-b-observer.html
        app.js
        styles.css
  src/
    orders_api/
      lambda_handler.py
      verifier_context.py
      order_store.py
      validation.py
    orders_interceptor/
      lambda_handler.py
      dnsid_verify.py
  infra/
    openapi/orders.openapi.json
    policy/orders.cedar
  scripts/
    deploy_gateway.py
    teardown_gateway.py
    gateway_resources.py
    probe_oidc.py
    probe_dnsid_status.py
    verify_gateway.py
    verify_browser.py
    demo_join.py
    demo_short_task.py
    owner_revoke.py
    demo_cutoff.py
  tests/
    test_dnsid_proof.py
    test_interceptor.py
    test_order_api.py
    test_policy_fixtures.py
    test_verify_gateway.py
    test_demo_console.py
    test_observer_events.py
    test_browser_walkthrough_contract.py
    test_docs_conventions.py
```

Recipe README structure should follow `RECIPE_TEMPLATE.md`: what you build, why it matters, prerequisites, concepts, stack, steps, run it, verify, what to try next, and glossary.

## Setup and demo impact from the UI requirement

The chat and observer UIs make this recipe materially larger than a direct
Gateway verification recipe:

- Setup effort increases from "deploy Gateway target and run verifier" to
  "deploy Runtime, Gateway target, observer audit sink, Order API, and run
  local browser UI checks that drive deployed resources."
- The README needs separate setup tracks for AWS deployment, DNSid status
  control, local browser UI, Browser Console Bridge, and teardown.
- Recipe structure needs a `demo_console` browser app in addition to Runtime,
  interceptor, Order API, policy, and verification scripts.
- Demo beats move from command-only output to paired browser state: Org A chat
  transcript plus Org B observer timeline.
- Acceptance tests must verify the browser-visible workflow and the persisted
  audit evidence, not just Gateway HTTP status codes.
- The final dev-loop implementation must include a Browser Console Bridge
  walkthrough against deployed Bedrock/AgentCore surfaces before it can be
  called complete.

## Implementation milestones

1. Scaffold the recipe and docs skeleton.
2. Build local proof signing and verification helpers around the shared DNSid SDK.
3. Implement Order API Lambda with local in-memory state and trusted-header requirements.
4. Implement REQUEST interceptor: JWT-claim extraction, proof verification, live `su` check, trusted header injection, and fail-closed errors.
5. Implement the observer audit event model and storage path before building the UI, so every accepted and rejected path has a single event contract.
6. Implement Gateway/API Gateway deploy script using the Recipe 07 pattern.
7. Add Policy in AgentCore setup and Cedar policy.
8. Implement Org A Runtime app using the Recipe 28 Runtime pattern.
9. Implement the Runtime-backed Org A chat UI and separate Org B observer UI. Default mode must call deployed Runtime/Gateway resources; local fixture mode must be visibly labeled.
10. Add demo commands for the four beats.
11. Add automated verification for missing token, wrong audience, unsigned/invalid proof, active status allow, revoked status deny, policy deny, direct API denial, observer event creation, and order-not-created proof.
12. Add Browser Console Bridge walkthrough automation for the deployed demo path.
13. Add dry-run docs and teardown.

## Acceptance tests

Minimum automated checks:

- `make test` passes local unit tests.
- `make verify` deploys or uses deployed resources and proves:
  - missing token is rejected
  - wrong audience token is rejected
  - unsigned/forged token is rejected
  - missing proof is rejected
  - proof signed by a different DNSid subject is rejected
  - active `su` status permits an otherwise valid low-risk order
  - revoked `su` status denies the next sensitive action with an unexpired token
  - policy denies over-limit amount
  - direct API Gateway target invocation is denied
  - LLM output cannot override trusted identity fields
  - every scripted Gateway/tool attempt has an observer event
  - rejected mutating calls have `order_created=false` and an order-store proof
- `make demo-join demo-short-task owner-revoke demo-cutoff` produces the four-beat transcript.
- CloudWatch evidence includes one correlation ID spanning Runtime, Gateway/interceptor, policy, and Order API.
- `make verify-browser` uses Browser Console Bridge against the default deployed-resource UI mode and proves:
  - Org A chat UI loads without console errors
  - Org B observer UI loads separately without console errors
  - submitting the join prompt through the chat UI invokes the deployed Runtime and appends an accepted observer row
  - submitting the low-risk order prompt creates an order and appends an accepted `place_order` row
  - owner revoke is visible in the observer UI
  - submitting the post-revoke order prompt appends a highlighted `revoked identity denied` row
  - the denial row shows owner revoke time, revoked `su` status, unexpired token, and `order_created=false`
  - the browser-visible DOM and network-visible responses do not expose bearer tokens, signing keys, raw private status payloads, or presigned storage URLs

Manual acceptance:

- A new builder can stand the demo up from the recipe README plus AWS credentials, DNSid lab credentials, and the shared SDK.
- No AWS service change or private AWS feature is required.
- Public-facing docs do not claim unvalidated DNSid or AWS behavior.
- The final dev-loop implementation includes a browser-console walkthrough transcript or screenshots for the deployed Bedrock/AgentCore path. The walkthrough must cover Org A chat prompt, Org B observer UI, accepted path, owner revoke, revoked-identity denial highlight, and proof that the denied order was not created.

## Dry-run checklist

Before the live run:

- `aws sts get-caller-identity` returns the expected account.
- `agentcore --version` and `aws --version` are recorded.
- DNSid CLI/shared SDK can mint a token for `agent.bank-a.example`.
- `_dnsid.agent.bank-a.example` resolves and contains `ku` and `su`.
- JWKS fetch from `ku` succeeds.
- `su` status returns active.
- `make probe-oidc` confirms issuer and JWKS.
- `make deploy` completes and writes `.artifacts/gateway/orders-state.json`.
- `make verify` passes.
- `make ui` starts the Org A chat and Org B observer browser surfaces in deployed-resource mode.
- Browser Console Bridge health reports the extension connected before `make verify-browser`.
- `make demo-join` and `make demo-short-task` pass once.
- `make owner-revoke --dry-run` shows the target status endpoint without changing it.
- `make verify-browser --dry-run` confirms both UI routes and selectors are present without mutating DNSid status.
- A cleanup command is ready but not run until after the demo.

## Failure and backout plan

Failure modes:

- Gateway token validation fails: use `make probe-oidc`, inspect `allowedAudience`, and re-fetch protected resource metadata.
- DNSid proof verification fails: run `make verify-proof-local` with the same canonical payload and key ID.
- Live status check times out: fail closed for the sensitive action; use the direct fixture backup for the presentation.
- Policy denies unexpectedly: switch policy engine to `LOG_ONLY` only during dry-run diagnosis, not during the trust demo; fix the policy before presenting.
- API Gateway target is directly callable: stop and fix the resource policy before running the demo.
- Runtime agent fails: use `make demo-*-direct` commands to call Gateway MCP directly while preserving the trust path.
- Org A chat UI fails but deployed Runtime works: use `agentcore invoke` for backup and keep the observer UI open; do not count this as browser acceptance.
- Org B observer UI misses an event: stop and fix the audit ingestion/correlation path before claiming full demo coverage.
- Browser Console Bridge is unavailable: follow the browser-console skill recovery steps. If the Chrome extension cannot connect, escalate instead of substituting Playwright for the required walkthrough.

Backout:

- `make teardown` removes recipe-owned Gateway targets, Gateway, interceptor Lambda, Order API, API Gateway REST API, IAM roles, logs if configured, and local `.artifacts/` state.
- `make owner-restore` restores `agent.bank-a.example` to active if the demo used a mutable lab status endpoint.
- Do not delete or mutate DNS records outside the pre-baked demo identity.

## Gaps and risks

- The exact shared SDK/API for creating an accountable-entity proof over an MCP tool call must be confirmed. The cookbook has examples for DNSid token validation and signature verification concepts, but not this exact MCP action-proof envelope.
- The exact demo-safe owner revoke command must be confirmed. The local docs define `su` as the status URI and live checks as the mechanism, but they do not expose a status mutation command.
- If DNSid OIDC tokens for this issuer do not support stable `scope`, configure Gateway with `allowedAudience` plus `customClaims` and move scope-like checks into the signed proof and policy input.
- AWS documentation validates Gateway interceptors and Policy in AgentCore, but the implementation must confirm their runtime ordering. The recipe must fail closed even if the order is not what the plan assumes.
- Policy in AgentCore may not receive interceptor-injected status context. If so, the policy gate covers token principal and tool input, while the interceptor and Order API enforce DNSid proof/status.
- The current source set validates Runtime invocation and Recipe 07's local browser UI pattern, but not an AWS-hosted AgentCore Runtime chat UI. Until confirmed, the plan should use a recipe-owned Runtime-backed chat UI and describe it that way.
- The current source set does not validate a complete AgentCore Gateway per-request log event for requests rejected before the request interceptor. The implementation must confirm the Gateway logging surface or limit "every call" claims to attempts the deployed demo can record through its audit/probe path.
- The optional Supplier B DNSid response-signing extension should not be included in the base recipe unless the scope explicitly expands.
