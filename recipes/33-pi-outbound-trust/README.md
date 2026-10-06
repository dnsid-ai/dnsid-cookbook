# Recipe 33 — Guard a personal agent's outbound calls in Pi

> Let a Pi agent compose tools in JavaScript, while TypeScript verifies the counterparty and enforces your policy inside each outbound tool.

**Spec version:** `dnsid-draft-01`

**Status:** runnable (scripted verification; local Clef Flash for interactive use)

**Standards used:** RFC 7517 (JSON Web Key Sets), DNSid C2SP lifecycle log

**Estimated time:** ~15 minutes

---

## What you'll build

An all-TypeScript [Pi](https://pi.dev) extension with three tools: inspect a counterparty, read its public catalog, and simulate a payment. Pi's **codemode**, a JavaScript interpreter for composing tool calls, can call these tools directly. Each action verifies its destination itself; a previous inspection or a saved session cannot authorize it. Catalog reads use real HTTPS. Payments never send money or contact a payment processor.

## Why this matters

A personal agent can discover an unfamiliar service without knowing who operates it. DNSid, DNS-anchored cryptographic identity, establishes the domain/key binding and the accountable entity before the agent sends an application request. Pi supplies composition and Clef Flash supplies fallible naming signals; your code controls permission. The result is a catalog tool that refuses unverifiable or suspicious destinations and a payment tool that requires a user-approved entity, an amount limit and explicit human confirmation—not a model saying “looks safe.”

## Prerequisites

- [Docker](https://docs.docker.com/get-started/get-docker/) 24+ installed and running, Git, `make`, `curl`, and `dig` for inspecting DNS. On Linux, `dig` is usually in `dnsutils` or `bind-utils`.
- The [`dnsid` CLI](https://docs.dnsid.ai/cli-installation) with `dnsid local` support. On macOS with Homebrew: `brew install dnsid-ai/tap/dnsid`.
- [Node.js](https://nodejs.org/en/download) 22.19+ and npm. Tested with Node 22.23.2; [`package.json`](package.json) and [`package-lock.json`](package-lock.json) pin the published npm packages DNSid SDK/transport 0.24.1 and Pi 0.99.2. Bootstrap installs them with `npm ci`; no local SDK checkout is required.
- A clone of this repository; the commands in Step 1 create it. No Python, model download, or account is needed for `make run` or `make verify`. Pi is installed by bootstrap; do not install it globally.
- Optional live naming checks: [llama.cpp](https://llama.app) with the `/v1/systemone` decision API and Clef Flash Q4_K_M weights. Tested with `llama` 0.5.0-dev, build 11379 (`1537a0a8b`). `make serve` downloads/caches the weights; no vendor account or Python runtime is needed.
- Optional interactive use also needs your usual Pi chat-model login. Clef Flash supplies naming scores, not the conversation.

For the optional local model, install the **`llama` CLI from [llama.app](https://llama.app)**, not just an older `llama-server` binary. Follow its installer, open a new terminal, and check `llama version`. The build must support `/v1/systemone`; ordinary chat-completion support is not enough. Allow roughly 6 GB of disk/download space for Q4_K_M weights, plus free memory to load the model. The first `make serve` needs internet access; subsequent starts reuse the cache.

Check the basic tools before proceeding:

```bash
docker info                         # Must reach the running Docker daemon
node --version                      # 22.19 or newer
npm --version
dnsid local --help
```

Pi 0.99.2's upstream npm shrinkwrap currently pins `brace-expansion` 5.0.9 with a reported denial-of-service vulnerability (`npm audit`). Do not treat this recipe as a hardened runtime for untrusted projects; upgrade Pi when its dependency is patched.

## Concepts

- **DNSid binding** — a signed `_dnsid.<domain>` DNS TXT record connecting the domain, accountable entity (`gi`), keys (`ku=`), status (`su=`), and lifecycle log (`lr=`). The SDK verifies those relationships rather than trusting a tool argument's claim about its operator.
- **JWKS** — JSON Web Key Set, a standard public-key document ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)); here it is available at `/.well-known/jwks.json`.
- **Fresh non-revocation evidence** — proof from an append-only lifecycle log that the identity has not been revoked or retired within the configured freshness boundary. The log's C2SP trust policy comes only from independently configured `DNSID_LOG_POLICY_URL`, never from the identity's log reference. It is separate from the operation policy in `src/policy.ts`.
- **Naming classifier** — a model answering fixed yes/no naming questions with numeric scores; here, local Clef Flash or optionally hosted Jev. These are fallible opinions, not verified brand affiliation or calibrated safety probabilities. They can restrict actions; they cannot establish payment authority.
- **Guarded tool** — trusted code that verifies and authorizes inside the operation that executes the action. Agent-written codemode scripts can compose tools but cannot supply `approved: true`, change their policy, or reuse an inspection as permission.

## Running system

| Process | Where | Role |
|---|---|---|
| DNS server | local registry, `127.0.0.1:7753` | Live `_dnsid` TXT records |
| Registry and lifecycle log | local registry, `127.0.0.1:7755` | Issuance, status and fresh log evidence |
| TLS proxy | local registry, `:443` | Routes `.test` HTTPS to local upstreams |
| Merchant | host `0.0.0.0:3133` | Public `/catalog` endpoint |
| Pi extension | host Node process | DNSid verification, naming checks and operation enforcement |
| Naming replies | in-process fixture for verification; optional host `127.0.0.1:8080` | Local Clef Flash serves the System One decision API, a JSON question/answer endpoint |

The CLI owns the containers. `dnsid local run shopper -- ...` injects DNS routing, TLS trust and the independent log-policy location. The extension builds a verification-only manager; it does not load signing keys or use the registry API credential.

## Step 1 — Provision and inspect the identities

Clone into your home directory, then bootstrap from the recipe directory. Until this recipe is merged, use its feature branch:

```bash
git clone --branch feat/pi-outbound-trust https://github.com/dnsid-ai/dnsid-cookbook.git ~/dnsid-cookbook
cd ~/dnsid-cookbook/recipes/33-pi-outbound-trust
make bootstrap
dig @127.0.0.1 -p 7753 _dnsid.merchant.test TXT +short
curl --resolve merchant.test:443:127.0.0.1 \
  --cacert ~/.dnsid-local/certs/root-ca.pem \
  https://merchant.test/.well-known/jwks.json
```

Bootstrap runs `dnsid local up --zone test` and idempotently provisions `shopper.test`, `merchant.test` and `paypal-payments.test` using `dnsid local agent ensure ... -- dnsid log issue`. The merchant's live record contains these fields, with cryptographic fields omitted:

```text
v=dnsid-draft-01;gi=merchant.test;ku=https://merchant.test/.well-known/jwks.json;su=https://registry.test/v1/status/merchant.test
```

The record is one semicolon-separated value; `dig` may split it into quoted chunks. `paypal-payments.test` is a valid self-accounted DNSid identity, but its accountable entity is **not** `paypal.com`. The scripted classifier flags that distinction; it does not prove a real model will recognize every impersonator. For custom registry state, use the CA path supplied as `DNSID_CA_BUNDLE`.

## Step 2 — Check and execute inside the same tool

From [`src/guard.ts`](src/guard.ts):

```ts
const verified = await manager.verifyDomain(validateDomain(domain), undefined, { signal });
const evidence = await verified.verifyNonRevocation(); // Required even without fl=logchk.
```

Invalid bindings, inactive status or unavailable fresh log evidence stop before the classifier or the catalog request. The recipe disables identity-result caching; SDK log checkpoints remain in memory. Verification traffic itself still contacts the published key/status/log endpoints—it is the **application request** that waits for authorization.

The catalog tool checks naming restrictions and then requests only the checked hostname's `/catalog` endpoint. It uses the SDK transport's `createSsrfSafeFetch`, which blocks unsafe network addresses (SSRF, server-side request forgery) and returns redirects instead of following them. Trusted `.test` private-address exceptions come from the harness environment. Catalog responses are capped at 64 KiB and a 15-second request deadline. HTTPS authenticates the connection; catalog JSON is not a DNSid-signed response and remains untrusted content.

## Step 3 — Keep policy and approval outside the model

[`src/policy.ts`](src/policy.ts) fixes three naming questions and these operation constraints:

```ts
export const policy = {
  version: 'personal-outbound/2',
  impersonationThreshold: 0.3,
  paymentEntities: ['merchant.test'], // Exact verified gi match, not a model opinion.
  maxPaymentCents: 5000,
} as const;
```

The extension invokes Pi's native `ctx.modelRegistry.classify()` with only verified naming facts. Its default `local-clef` provider reuses Pi's System One client against llama.cpp's `/v1/systemone` endpoint. Clef is a decision model, not a chat model; Pi's generic llama.cpp chat-token classifier is not compatible with these weights. Missing, malformed or unavailable answers refuse the operation. Code combines `names_org AND acts_for AND NOT same_org` as a thresholded minimum score; a low score does not prove a domain safe.

The payment tool independently requires an exact approved `gi`, positive integer USD cents within the limit, and `ctx.ui.confirm()` showing the exact domain, entity and amount. No interactive UI means refusal. After confirmation it repeats verification and policy evaluation before producing the simulated receipt. Every payment requires its own confirmation; session entries and codemode's `store()` values never count as approval.

## Run it

**All commands below run from `~/dnsid-cookbook/recipes/33-pi-outbound-trust`.** Open that directory in every new terminal. If you cloned elsewhere, substitute your clone's path.

Start with the account-free, scripted demo:

```bash
make run
```

The short-lived demo starts the merchant, checks the guards, runs real Pi direct and codemode tool calls using scripted model proposals, restores the same session branch, and exits. It needs no model account.

For real naming scores, use two terminals. **Terminal 1 — model server:**

```bash
cd ~/dnsid-cookbook/recipes/33-pi-outbound-trust
make serve
```

This runs `llama serve` with `ggml-org/Clef-Flash-GGUF:Q4_K_M`, the alias `clef-flash`, a 4096-token context and no image projector. It binds only to `127.0.0.1:8080`. Leave this terminal running.

**Terminal 2 — wait for readiness, then run the live demo:**

```bash
cd ~/dnsid-cookbook/recipes/33-pi-outbound-trust
curl --fail http://127.0.0.1:8080/health   # Retry after loading if not ready
make eval
```

The health response should be `{"status":"ok"}`. `make eval` starts and stops its own merchant and needs no chat-model account.

For interactive use, keep Terminal 1 running. After `make eval` finishes, start the merchant in **Terminal 2**:

```bash
npm run merchant
```

**Terminal 3 — Pi:**

```bash
cd ~/dnsid-cookbook/recipes/33-pi-outbound-trust
make pi
```

If this is your first Pi session, run `/login`, select a chat provider you have access to, and complete its login. Then run `/model` to select a conversational model. Existing Pi logins are reused. Clef Flash only answers naming questions; it cannot replace this chat model.

Ask Pi: “Compare catalogs at merchant.test and paypal-payments.test using codemode. Then simulate paying merchant.test USD 42.” The merchant read should succeed, the impersonator should be refused, and the simulated payment should prompt for confirmation. The local classifier receives counterparty naming facts, never payment amounts, customer payloads or the conversation.

`LLAMA_BASE_URL` changes the server root URL; `LLAMA_API_KEY` supplies an optional server credential. `DNSID_JEV_MODEL` changes the request's model label, not a single-model server's weights. Other classifier providers remain selectable with `DNSID_JEV_PROVIDER` and `DNSID_JEV_MODEL`.

If the live run reports `Naming classifier unavailable`, check Terminal 1 and `/health`. A 404 at `/v1/systemone` usually means the wrong llama build; a port-bind error means another process owns port 8080. Stop it or configure an existing compatible server with `LLAMA_BASE_URL`. Do not start a separate merchant while `make eval` is running: both would need port 3133. The local registry also needs ports 443, 7753 and 7755 available.

`make pi` loads only this extension and built-in codemode, with no bash, file-writing or MCP tools. This narrows the demo's tool set; it is **not an operating-system sandbox**. Loading other tools or executable extensions can create bypass paths. This recipe does not gate arbitrary MCP connections or all Pi network traffic.

## Verify

```bash
make verify
```

Expected transcript:

```text
ok    unverifiable domain stops before classifier and catalog
ok    inspection grants no call permission
ok    malformed/unavailable classifier fails closed
ok    redirects refused and response size bounded
ok    payment pins entity and amount; explicit approval only; no money sent
ok    Pi direct and codemode calls enforce policy; resumed approval is refused
verify passed (scripted naming replies; real DNSid TS SDK and Pi codemode)
```

The single assert-based [`src/demo.ts`](src/demo.ts) uses live DNSid verification and real HTTPS, counts catalog requests to detect unauthorized calls, and exercises Pi's actual JavaScript interpreter. It proves wiring and enforcement, **not** a real classifier's naming accuracy. The approved-payment check supplies an explicit test confirmation callback; real Pi uses its human dialog. Failures exit nonzero and dump registry-container logs. `npm run check` typechecks every source file.

With `make serve` running, check the live classifier:

```bash
make eval
```

This reuses the scripted guard checks but substitutes real model replies in Pi's direct, codemode and resumed-session calls. It asserts a successful merchant catalog, refusal of the brand lookalike before any catalog request, and refusal of payments without interactive approval. Success ends with:

```text
verify passed (live naming replies in Pi calls; real DNSid TS SDK and Pi codemode)
```

Clef Flash Q4_K_M passed these checks with the shipped questions and threshold. The original vague “acts for” question missed the lookalike; the questions now distinguish an organization's own service from an independent integration, and name resemblance from an official domain. The threshold was not lowered. These two names are a demo, not an accuracy benchmark or proof of brand affiliation.

## What to try next

- Edit approved entities or the amount ceiling in `src/policy.ts`, bump its version, restart Pi and rerun verification. The default transcript assumes the shipped policy.
- Compare with hosted Jev: set `TYPESAFE_API_KEY`, `DNSID_JEV_PROVIDER=typesafe` and `DNSID_JEV_MODEL=jev-latest`, then run `make eval` or `make pi`. Hosted providers receive the naming facts. Never treat absence of a warning as verified brand affiliation.
- [Recipe 32](../32-jev-trust-policy/) explores age and key-rotation restrictions on inbound callers. This recipe deliberately skips tiers, history-based reputation, MCP discovery and a generic policy language.
- To stop the demo, exit Pi and press Ctrl-C in the merchant and model terminals, then run `make clean` from the recipe directory to stop the local registry. This retains registry state and cached model weights for the next run. On disposable registry state only, `dnsid local reset --hard && make verify` repeats first-time provisioning.

Before moving real money, add a separate credential-holding payment broker that enforces recipient/invoice binding and idempotency, protection against executing one payment twice. A verified domain does not authorize an arbitrary wallet or bank account from its catalog. Production also needs durable log checkpoints to detect rollback across restarts, and a DNSSEC-aware resolver to report validated DNS signatures: the SDK's Node resolver reports `UNKNOWN`. Unicode names are decoded for the classifier but this is not a complete Unicode lookalike detector.
