# DNSid Cookbook — Index

Recipes for verifying who you're talking to, and proving who you are, using DNS-anchored identity.

Organized by where DNSid actually shows up in a system: **Publish → Verify → Federate → Operate**. Plus **Standards map** and **Anti-recipes**.

Flagship recipes (recommended starting set) marked ⭐.

---

## Standards map

DNSid is a thin layer easily composable with existing standards. Recipes name the standard they implement.

| Standard | Role in DNSid | Recipes |
|---|---|---|
| **RFC 9421** — HTTP Message Signatures | Wire format for signed HTTP requests | 6, 6b, 9, 10, 12, 31 |
| **RFC 7515** — JWS | Signature envelope | 1 |
| **RFC 7517** — JWK / JWKS | Public key publication at `/.well-known/jwks.json`; OIDC verification keys | 1, 4, 6b, 29 |
| **RFC 9530** — Digest Fields | Signed request-body integrity | 6b |
| **RFC 8037** — Ed25519 in JOSE | Algorithm binding | 1 |
| **RFC 8615** — Well-known URIs | JWKS hosting path | 1 |
| **RFC 7519** — JWT | OIDC token format | 7b, 15, 29 |
| **OIDC Core** | Federation to AWS / GCP / Azure; DNSid bearer-token service auth | 7b, 15, 28, 29 |
| **Cedar / AWS Verified Permissions** | Authorization policy for DNSid principals and room resources | 29 |
| **W3C Verifiable Credentials** | Capability assertions | 14 |
| **W3C DID** | Comparable identifier model (interop / contrast) | A6 |
| **SPIFFE / SPIRE** | Trust-domain federation bootstrap | 16 |
| **Sigstore / cosign** | Artifact signing chain | 19 |
| **DKIM (RFC 6376)** | Per-agent provenance for AI-generated email; prior art for DNS-anchored signing | 27 |
| **Envoy / Istio / Linkerd** | Service mesh sidecar WASM filter for ingress-edge identity | 26 |
| **MCP (Anthropic)** | Tool / context protocol | 7, 7b, 8 |
| **gRPC** | `CallCredentials` / `ChannelCredentials` extension point | 13 |
| **A2A (Google)** | Agent interaction protocol | 12, 31 |
| **LangGraph** | Agent framework — verified ingress, signed tool-call egress, caller-gated tools | 31 |
| **Cloud OIDC federation** | GitHub Actions OIDC, AWS IAM Roles Anywhere, GCP Workload Identity Federation, Azure Federated Credentials | 15, 19 |
| **Edge runtimes** | Cloudflare Workers, Lambda@Edge, CloudFront Functions, Fastly Compute, Akamai EdgeWorkers, Vercel Edge, Netlify Edge | 10, 10a–10g |
| **Cloudflare Web Bot Auth** | Verified bot/agent traffic; DNSid as additional issuer | 24 |
| **Agent discovery manifests** | A2A `/.well-known/agent.json`, OpenAI `/.well-known/ai-plugin.json`, MCP descriptors | 23 |
| **C2PA** | Content provenance signing — DNSid-anchored issuer (experimental) | 25 |
| **OID4VC** | OpenID for Verifiable Credentials presentation flow | 14 |
| **in-toto / SLSA** | Supply-chain attestation format and provenance levels | 19 |
| **Vendor webhook signatures** | Stripe, GitHub, Slack — composes with RFC 9421 path | 9 |
| **ENS / Handshake** | Alt-root naming systems (different trust root) | A8 |

---

## Publish — provision identity

### 1. Publish `_dnsid` + JWKS for a domain ⭐
Provision a domain identity on the local DNSid registry — Ed25519 keypair (RFC 8037), registration, signed challenge, published `_dnsid` TXT record, countersigned transparency-log entry — then take it apart by hand: `dig` the record and read every tag, serve and `curl` the JWKS (RFC 7517, at `/.well-known/jwks.json` per RFC 8615), match the served key to the local keypair, check live status. End state: any RFC 9421-aware verifier can authenticate signed messages from your domain. See [recipes/01-publish-jwks/](recipes/01-publish-jwks/).

### 2. Per-agent subdomains
`agent-billing.corp.com`, `agent-mail.corp.com`, each with own key. Independent revocation scope, least-privilege blast radius.

### 3. Dev-tier under `*.dev.dnsid.ai`
Fast provisioning, KMS-isolated signing key. Verifiers reject by default; opt in with `AllowDevTier: true`. For prototypes and CI.

### 4. Key rotation playbook
JWKS multi-key overlap, TXT TTL ordering, cache invalidation. Rotate without downtime.

### 5. Revocation drill
Revoke a compromised agent. Cached verifiers re-check within TTL (≤5 min); live-check verifiers reject immediately. Rehearse before you need it.

### 23. Sign your agent / plugin discovery manifest
Existing agent-discovery surfaces — Google A2A's `/.well-known/agent.json`, OpenAI GPT Actions' `/.well-known/ai-plugin.json`, MCP server descriptors — are unsigned today. Compose with DNSid by attaching a detached JWS over the manifest, keyed by the agent's domain. Discovery and identity bootstrap in one resolution: fetch manifest, verify signature against `_dnsid.<domain>` JWKS, then talk to the agent on the endpoint the manifest declares. No change to the consuming protocol; verifier-side is opt-in.

---

## Verify — relying-party patterns

### 6. HTTP server middleware (RFC 9421) ⭐
Express / Fastify / Hono / FastAPI. Verify inbound HTTP Message Signatures per RFC 9421 — `Signature-Input` + `Signature` headers, covered components — with the signing key resolved via DNSid. The middleware returns one of `verified | unregistered | revoked | unverifiable`; the route handler enforces its own authorization on top. **Result:** any caller with a `_dnsid` binding can authenticate on first contact, no shared secret distribution, and revocation propagates through DNS without redeploys at every endpoint.

### 6b. Go HTTP API verifies DNSid callers (fake-Stripe)
Recipe 6 in Go, end-to-end. A `fake-stripe` ledger exposes `GET /v1/balance` and `POST /v1/balance/credit` behind `dnsid-go` RFC 9421 verification; a worker serves its live JWKS and signs requests with its locally provisioned identity. The server verifies the complete DNSid binding, status, transparency-log lifecycle, and HTTP signature before applying a separate writer allowlist. Runs entirely on the DNSid CLI local registry. See [recipes/06b-go-http-stripe/](recipes/06b-go-http-stripe/).

### 7. AgentCore Gateway MCP image tool with DNSid auth ⭐
Deploy an Amazon Bedrock AgentCore Gateway MCP target that accepts DNSid-issued JWTs, exposes an image-generation tool, and verifies the target receives only Gateway-injected trusted context. Includes a local browser UI backed by a local server that mints DNSid tokens server-side and calls Gateway MCP; the browser receives only local artifact URLs and non-secret metadata. This is a lab deploy-only PoC for the configured DNSid lab agent and AWS account, not a generic hosted UI or DNSid provisioning flow. See [recipes/07-agentcore-gateway-mcp-image-poc/](recipes/07-agentcore-gateway-mcp-image-poc/).

### 7b. Minimal AgentCore Gateway OIDC image tool
Deploy the smaller version of Recipe 7: AgentCore Gateway validates DNSid-issued OIDC JWTs with `CUSTOM_JWT` and invokes a direct Lambda MCP target that generates a Bedrock image. It removes the request/response interceptor, API Gateway bridge, S3 audit/artifact store, and local browser UI, so the recipe shows the minimum AWS customization needed for the OIDC-adapter path. See [recipes/07b-agentcore-gateway-oidc-image/](recipes/07b-agentcore-gateway-oidc-image/).

### 8. MCP client verifying servers
Before connecting to a tool server, resolve its `_dnsid`. Refuse `unverifiable`. Pin acceptable issuer domains per-tool. **Result:** an MCP client cannot be tricked into connecting to a tool server impersonating a known one — DNS hijack alone isn't enough, the attacker would need to compromise the target domain itself.

### 9. Webhook signature verification (RFC 9421)
Webhook sender signs the request with RFC 9421 HTTP Message Signatures; the receiver resolves `_dnsid.<sender-domain>` to fetch the verification key. The same verifier code path covers any RFC 9421-signed webhook, including Stripe's announced RFC 9421 signatures — DNSid composes with that direction of travel by being the issuer behind the key id. Sender identity = sender domain; no per-partner shared secret.

### 29. DNSid-authenticated message board
A runnable Go message board on the real DNSid local registry. The CLI mints a short-lived OIDC token per command; `dnsid-go/oidc` verifies the issuer, audience, time claims, and the token subject's signed DNS record, keys, active status, and lifecycle log before room authorization. Includes arbitrary validated room IDs, future DNSid subjects in allowlists, bounded reads/watch, an in-memory backend, and optional DynamoDB plus AVP/Cedar adapters. See [recipes/29-dnsid-message-board/](recipes/29-dnsid-message-board/).

### 30. Verify a DNSid-signed order in AgentCore Gateway
Accept one AgentCore Gateway order from a DNS identity without exchanging a signing key or shared secret. The interceptor verifies the caller's DNS-published operational key and lifecycle state, then rejects modified or replayed actions. See [recipes/30-agentcore-gateway-dnsid-oidc-orders/](recipes/30-agentcore-gateway-dnsid-oidc-orders/).

### 10. Edge verification — overview
Verify at PoP. Reject before origin. Cache JWKS per-PoP. Cuts origin load and abuse surface. Each platform below differs in runtime, crypto primitives, network access, and cache surface — pick the one that matches your CDN.

### 10a. Cloudflare Workers
V8 isolate. `crypto.subtle` does Ed25519 natively. JWKS cached in Workers KV or Cache API; DNS resolution via DoH (`1.1.1.1`) from inside the Worker. Verify in `fetch` handler; reject with 401 before `fetch(origin)`.

### 10b. AWS Lambda@Edge (CloudFront)
Node.js runtime at Regional Edge. Full `fetch` to JWKS endpoints. Verify in `viewer-request` trigger; reject before origin. Use CloudFront cache-key normalization so verified requests don't revalidate per-viewer.

### 10c. CloudFront Functions
Restricted JS runtime — **no network, no full crypto**. Cannot fetch JWKS at runtime. Pattern: pre-stage JWKS + revocation set in CloudFront KeyValueStore via a control-plane sync job; CF Function reads KV and verifies signatures with the staged keys. Trades revocation freshness for sub-millisecond latency.

### 10d. Fastly Compute (WASM)
Rust / Go / JS / AssemblyScript compiled to WASM. JWKS in Edge Dictionaries or Config Store, refreshed via background sync. Per-PoP JWKS cache via `fastly::cache::core`. Native Ed25519 via `ring` (Rust) or `@noble/ed25519` (JS).

### 10e. Akamai EdgeWorkers
V8 with ~512KB code budget. EdgeKV for JWKS and revocation list. Subrequests via `httpRequest` API are counted — prefer pre-staged keys over per-request fetch. Verify in `onClientRequest`.

### 10f. Vercel Edge Functions / Middleware
V8 isolate, Web-standard `fetch` and `crypto.subtle`. JWKS cache via `unstable_cache` or in-memory module scope (per-isolate). Run in `middleware.ts`; redirect or 401 before the route handler.

### 10g. Netlify Edge Functions (Deno)
Deno runtime, full standard library plus Web Crypto. JWKS cache in Deno KV. Call `Context.next()` only on verify; otherwise return 401.

### 27. AI-generated email provenance (DKIM + DNSid)
DKIM proves a message left an authorized SMTP server for the sending domain — it doesn't say *which agent* on the sender side composed it. Compose with DNSid by adding a signed `X-Agent-Identity` header (or equivalent in the DKIM-signed header set) carrying the DNSid binding for the agent that produced the message. Recipients verify DKIM as today, then verify the agent identity against `_dnsid.<agent-domain>`. **Result:** receivers can distinguish "this came from the corp.com mail server" from "this was composed by `agent-billing.corp.com`," and apply different trust / filtering / archival policy per agent. Composes with: DKIM, ARC, BIMI; replaces ad-hoc `User-Agent`-string trust for AI-sent mail.

### 24. Verified agent identity for Cloudflare Web Bot Auth
Cloudflare Web Bot Auth signs bot/agent traffic with HTTP Message Signatures (RFC 9421) keyed against a public directory of bot operators. Compose with DNSid by adding the bot operator's `_dnsid`-published JWKS as an additional resolution path: a verifier can accept either the Cloudflare-directory key or the DNSid-resolved key, validating the same RFC 9421 signature either way. Useful when a bot operator runs across surfaces where Cloudflare isn't in path, or when a property wants to anchor trust in domain ownership rather than directory listing. Same wire format end-to-end.

---

## Federate — cross-party

### 12. A2A protocol + DNSid ⭐
A2A standardizes agent interaction but punts on the trust-bootstrap step — both sides need to know who they're talking to before the conversation can start. DNSid fills that step: each side resolves the other's `_dnsid` record and verifies signed handshake messages. **Result:** two A2A agents from different organizations can begin a session on first contact, with no shared API keys, no manual key exchange, and no out-of-band introduction. Runs two Python agents (Alice and Bob) on the live DNSid local registry, exchanging a2a-sdk JSON-RPC messages signed with RFC 9421 HTTP Message Signatures. See [recipes/12-a2a-dnsid/](recipes/12-a2a-dnsid/).

### 31. LangGraph agent with a DNSid identity
Agent frameworks standardize the loop — model decides, tools execute — but say nothing about who the agent is on the network, so tool calls authenticate with provisioned API keys and inbound callers are whoever holds the URL. This recipe gives a LangGraph agent a complete DNSid identity story: it is a verifiable A2A endpoint (ingress), its tool calls to a plain HTTP API travel as RFC 9421-signed requests (egress), and its sensitive tool exists only for verified callers on an allowlist (authorization — absent from the tool set, not merely refused). **Result:** the agent framework's tool calls become attributable to a domain; the tool server needs no API-key onboarding, and a new caller works the moment its `_dnsid` record is live. Runs without an LLM key by default (deterministic scripted model); `ANTHROPIC_API_KEY` swaps in a real Claude model — the LLM is never in the trust path either way. See [recipes/31-langgraph-dnsid-agent/](recipes/31-langgraph-dnsid-agent/).

### 13. gRPC channel auth with DNSid
Plug DNSid into gRPC's `CallCredentials` / `ChannelCredentials` extension point. Client attaches a DNSid signature in call metadata; server-side interceptor resolves `_dnsid.<caller-domain>` and verifies before dispatching the RPC. **Result:** gRPC services across organizational or cluster boundaries authenticate without pre-shared mTLS certs, API keys, or a service-mesh sidecar. Same identity model as the HTTP recipes, applied at gRPC's metadata channel.

### 14. Capability advertisement (W3C Verifiable Credentials, OID4VC)
Domain owner issues a VC declaring agent scope (e.g. `can-quote`, `can-pay≤$10k`); agent presents it on call. Counterparty verifies VC signature against DNSid key + checks claims. Standard VC verifier libraries apply. Composes with **OpenID for Verifiable Credentials (OID4VC)** when the presentation flow goes through an OIDC provider — DNSid is the issuer's identity key. **Result:** any domain owner becomes a credential issuer without negotiating into a closed trust list; counterparties decide which issuer domains to trust based on their own risk model, not a registry's gatekeeper.

### 15. OIDC federation to AWS / GCP / Azure ⭐
DNSid-signed assertion → 5-minute OIDC JWT. Wire into AWS IAM Roles Anywhere / IAM OIDC, GCP Workload Identity Federation, Azure Federated Credentials. Same trust pattern GitHub Actions OIDC uses today; DNSid is the OIDC issuer. **Result:** workloads outside any specific cloud (on-prem, other-cloud, edge) get short-lived cloud credentials without static keys to rotate or store. The cloud's IAM trust config points at DNSid; the workload signs an assertion with its DNSid key.

### 26. Service mesh sidecar (Envoy / Istio WASM filter)
Run a WASM filter in the Envoy sidecar (Istio, Linkerd, standalone Envoy) that verifies DNSid-signed traffic on the mesh's *ingress* edge — requests crossing into the mesh from outside. Inside the mesh, existing mTLS still handles in-cluster hops; DNSid only authenticates the boundary. **Result:** a service mesh becomes reachable by external partners with cryptographic identity at the application layer, without provisioning external certs into the mesh's CA, and without standing up a separate API gateway just for partner traffic. Composes with: Envoy filter chain, Istio `RequestAuthentication`, Linkerd policy.

### 28. GitHub code review bot on Amazon Bedrock AgentCore
A Strands agent deployed to AgentCore Runtime that reviews GitHub PRs. The agent uses `dnsid-py` and its server-side operational key to mint a DNSid OIDC token when calling the `ReviewGateway` audit tool; Gateway validates that identity before invoking the audit Lambda. Runtime caller identity is outside this recipe's scope. See [recipes/28-bedrock-agentcore-github-review/](recipes/28-bedrock-agentcore-github-review/). **Status:** deploy-only.

### 16. SPIFFE trust-domain federation anchored in DNSid
SPIFFE federation lets one trust domain accept SVIDs from another, but each side has to bootstrap trust in the other's bundle endpoint somehow — usually a manually-configured URL + key. Compose with DNSid by publishing the SPIFFE bundle's verification key as a DNSid binding on the trust domain's parent domain. Federating side fetches `_dnsid.<trust-domain>`, resolves the JWKS, and uses it to verify the SPIFFE bundle. **Result:** trust-domain federation between two organizations becomes a DNS publication step, not a manual key-exchange ceremony coordinated over email. Inside each cluster nothing changes; SPIFFE/SPIRE keep operating exactly as today.

---

## Operate — production

### 17. Co-signed witness for high-stakes transaction ⭐
Financial / regulated op. Both parties' status checked live, no cache. DNSid co-signs a timestamped witness statement. **Result:** the audit record is a third-party-signed assertion that *both* parties were in good standing at the moment of the transaction — provable to a regulator without trusting either party's logs, and without either party retaining the other's keys.

### 18. Audit log consumption
Pull witness statements for a transaction window. Each witness is independently verifiable against DNSid keys at the time of signing — a regulator can validate provenance years later without trusting your storage layer. Covers format, retention, query patterns, and key-rotation handling for old witnesses.

### 19. CI/CD machine identity (Sigstore + GitHub Actions OIDC, in-toto, SLSA)
Runner uses GitHub Actions OIDC token to obtain a DNSid identity for the building org's domain. Sign artifacts and attestations through cosign / Sigstore with that identity. Composes with **in-toto** attestation format (the predicate carries DNSid-signed claims) and **SLSA** provenance levels (DNSid identity satisfies the "non-falsifiable" requirement at SLSA L3+). Provenance chains to a domain owner instead of a workflow file.

### 20. Caching and revocation tradeoffs
JWKS cache TTL, registry status cache TTL, negative-cache for `unverifiable`. Tuning for latency vs. revocation freshness.

### 21. Failure modes ⭐
DNS outage. JWKS 404. Registry down. Stale cache. What does your verifier do? Fail-open vs. fail-closed per route.

### 22. Observability
Metrics: verify rate, `revoked` hit rate, `unverifiable` spikes (attack signal). Logs: which domain, which key id, which result. Dashboards.

### 25. C2PA content provenance with DNSid-anchored issuer (experimental)
C2PA assertions today reference identity via X.509 certs from the C2PA Trust List. Compose with DNSid by signing C2PA assertions with a DNSid key — the manifest carries an issuer identifier resolvable via `_dnsid.<domain>`. Useful for AI-generated content provenance: "this image was produced by an agent at `agent.nytimes.com`." **Status:** experimental — DNSid is not yet on the C2PA Trust List, so consumers must verify out-of-band or trust the assertion explicitly. Demonstrates the composition pattern; production adoption requires Trust List inclusion.

---

## Anti-recipes — don't do this

### A1. DNSid for end-user authentication
DNSid is machine / agent / service identity. Users don't own domains. Use OIDC, passkeys, etc., for humans.

### A2. DNSid wrapping model API calls
Calling `api.openai.com` or `api.anthropic.com` is an inference call. DNSid has no boundary to defend there. Wrong layer.

### A3. DNSid as browser TLS replacement
Different trust anchor (domain owner key, not CA). Not for HTTPS PKI. Complementary, not substitute.

### A4. DNSid without revocation plan
A signed binding with no revocation strategy is a long-lived credential waiting to be stolen. Recipe 5 is not optional.

### A5. Dev-tier in production
`*.dev.dnsid.ai` bindings in a prod verifier path means anyone with a dev account can spoof. Default reject; opt in only for prototypes.

### A6. Treating DNSid as a W3C DID method
DID resolution and DNSid resolution serve overlapping needs but aren't the same. DNSid is not a registered DID method and doesn't aim to be — the trust root is DNS ownership, not a self-asserted controller document. Use DID for identifier portability across resolution networks; use DNSid when DNS ownership is the trust signal you actually want. Don't shim one as the other.

### A7. CloudFront Functions for revocation-sensitive paths
CloudFront Functions can't make network calls, so JWKS and revocation state are only as fresh as your control-plane sync job. If revocation latency matters (≤ minutes), use Lambda@Edge instead. CF Functions are right for static-key, high-traffic paths where staleness is acceptable.

### A8. Treating DNSid as a substitute for ENS / Handshake / alt-root naming
Different trust roots, different audiences. DNSid's authority is ICANN DNS ownership; ENS and Handshake anchor identity in their own naming systems. They solve overlapping problems for non-overlapping populations. If your application's users live in an ENS-rooted ecosystem, use ENS; if your trust signal is "this party owns this domain in the ICANN DNS hierarchy," use DNSid. They can coexist on the same agent (one identity per trust root) but neither subsumes the other.
