# Recipe 32 — Decide how far to trust an agent you have never met

> Open a service to any DNSid-verified agent, then use a written trust policy to decide how far to trust it; use the same policy before your agent calls an unfamiliar service.

**Spec version:** `dnsid-draft-01`

**Status:** runnable (scripted model replies for `make verify`; optional local Clef Flash for real-model evaluation)

**Standards used:** RFC 9421 (HTTP Message Signatures), RFC 7517 (JSON Web Key Sets), DNSid C2SP lifecycle log

**Estimated time:** ~20 minutes, plus optional model download

---

## What you'll build

A Python API that uses DNSid, DNS-anchored cryptographic identity, to verify unfamiliar callers before allowing a catalog read or a demonstration refund. A client applies the same policy before it would send data to an unfamiliar service. The central flow is **verify identity → build facts → apply `policy.toml` → check the operation's required trust tier**. A tier is an application permission level: `untrusted`, `limited` or `trusted`.

## Why this matters

DNSid proves the domain/key binding and the accountable entity, the domain taking responsibility for that identity (`gi`). An HTTP signature proves that key signed this request. Neither proves that an agent named “PayPal refunds” actually represents PayPal. This recipe lets a service authenticate new callers without shared secrets or a partner allowlist, then use its own policy to restrict their access. The same distinction helps an outbound agent decide whether to share customer data.

## Prerequisites

- Docker 24+ running, `make`, and the [`dnsid` CLI](https://docs.dnsid.ai/cli-installation) with `dnsid local` support.
- [`uv`](https://docs.astral.sh/uv/) and Python 3.11+. Tested with Python 3.12.14; dependencies are pinned in [`pyproject.toml`](pyproject.toml), including dnsid-py 0.23.1.
- A clone of this repository. The standard demo needs no model or vendor account.
- Optional live naming checks: llama.cpp **build 11379 (`1537a0a8b`)**, using either its `llama serve` CLI or its standalone `llama-server`. The recipe pins this tested build because build 11429 gave worse Clef results with identical weights and requests. Clef Flash Q4_K_M needs roughly 6 GB of disk/download space, plus memory to load the weights. Setup is under **Verify**; no Python model runtime or vendor account is needed.

## Concepts

- **DNSid binding** — a signed `_dnsid.<domain>` TXT record connecting an identity, accountable entity (`gi`), public-key URL (`ku=`), status URL (`su=`) and lifecycle log reference (`lr=`). The verifier follows those references rather than trusting a caller's claimed identity.
- **JWKS** — JSON Web Key Set, a standard list of public keys ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)), published at `/.well-known/jwks.json`.
- **HTTP Message Signatures** — [RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421) signs selected request components: here the method, authority, target URI and, for a body, its content digest. A digest is a hash binding the signature to those body bytes.
- **Two different policies** — `DNSID_LOG_POLICY_URL` is independently trusted configuration for checking the C2SP lifecycle log, the append-only record of issuance, rotation and revocation. It must never come from `DNSID_LOG_REF` or log-provided data. [`policy.toml`](policy.toml), by contrast, is this application's permission policy; changing it cannot waive identity verification.
- **Trust judgments** — code checks age and rotation, and the model estimates three naming signals. Model opinions about brand affiliation are fallible, not verified delegation or permission grants. Code alone combines the signals and enforces operation requirements.

## Running system

| Process | Where | Role |
|---|---|---|
| DNS server | local registry, `127.0.0.1:7753` | Serves live `_dnsid` TXT records |
| Registry and log | local registry, `127.0.0.1:7755` | Issues identities and records lifecycle events |
| TLS proxy | local registry, `:443` | Routes `https://<identity>.test` to local upstreams |
| API | host `0.0.0.0:3120` | Verifies signed requests and checks permissions |
| Model endpoint | host `127.0.0.1:8791` scripted replies, `127.0.0.1:8080` Clef Flash | System One, a JSON question/answer API, answers only naming questions |
| Client | short-lived process | Signs calls or checks outbound permissions |

The CLI owns the Docker services. `dnsid local run` injects DNS routing, TLS trust, credentials, identity keys and the independently trusted log-policy location into recipe processes.

## Step 1 — Provision identities and inspect their records

```bash
make bootstrap
dig @127.0.0.1 -p 7753 _dnsid.acme-billing.test TXT +short
curl --resolve acme-billing.test:443:127.0.0.1 \
  --cacert ~/.dnsid-local/certs/root-ca.pem \
  https://acme-billing.test/.well-known/jwks.json
```

The Makefile starts `dnsid local up --zone test` and provisions `api.test`, `acme-billing.test` and `paypal-refunds.test` idempotently with `dnsid local agent ensure ... -- dnsid log issue`. An excerpt of the live catalog caller's record, with cryptographic fields omitted:

```text
v=dnsid-draft-01;
gi=acme-billing.test;
ku=https://acme-billing.test/.well-known/jwks.json;
su=https://registry.test/v1/status/acme-billing.test
```

The real TXT value is one semicolon-separated record; `dig` may split it into quoted chunks. `gi` names the accountable domain, `ku` supplies the public keys for verifying requests, and `su` supplies live status. The brand lookalike's `gi` is `paypal-refunds.test`, **not** `paypal.com`: self-accountability does not establish brand affiliation. `--resolve` routes curl through the local TLS proxy. With custom registry state, use the CA path injected as `DNSID_CA_BUNDLE`.

## Step 2 — Verify identity before asking about trust

From [`src/app.py`](src/app.py):

```python
verified = await asyncio.to_thread(
    profile.verify_signed_http_request, signed, HttpVerificationOptions(required_components=components))
await asyncio.to_thread(manager.verify_log_evidence, verified)
```

The SDK checks the DNSid binding, key, lifecycle, live status and request signature; the second call requires fresh non-revocation evidence. The API bounds the body and uses a configured public URL, not a caller-controlled forwarded-host header. Invalid identity or signature stops before any model call. The outbound [`src/client.py`](src/client.py) similarly calls `verify_domain` and `verify_log_evidence` before checking a service's permissions.

## Step 3 — Configure trust and operation requirements

[`src/facts.py`](src/facts.py) reads the verified lifecycle into raw identity age, key age and key-event kind. [`src/trust.py`](src/trust.py) applies the configured windows to those facts on every request—there is no decision cache. These excerpts from [`policy.toml`](policy.toml) are actual configuration, not instructions interpreted by an LLM:

```toml
[rules.unproven]
new_agent_days = 30
effect = "limit"
```

```toml
[requires]
catalog = "limited"
refund = "trusted"
order-lookup = "limited"
customer-pii = "trusted"
```

A new identity without established entity history triggers `unproven`. A recent **key rotation**, not issuance or log migration, before a sensitive operation triggers `takeover_risk`. Code defines each operation's real impact; the caller cannot label a refund harmless. Matching rules apply `limit` or `deny`; the most restrictive result wins. Missing lifecycle history never gets full trust. Entity-level history is unavailable in the live registry; two offline cases illustrate that possible future evidence.

Only verified counterparty naming facts reach the model. Code also supplies a Unicode lookalike spelling (`name_skeleton`) and a mixed-writing-system flag; these are diagnostic signals, not complete Unicode security checks. The three configured questions ask whether the name references an organization, whether `gi` is its official domain, and whether the name claims to act for it. The model receives no lifecycle history, operation descriptions or customer payloads. From `src/trust.py`:

```python
impersonation = min(answers["names_org"], answers["acts_for"], 1 - answers["same_org"])
```

Comparing this score with the configured threshold implements an AND, **not** a calibrated joint probability. Missing, malformed or unreachable model answers fail closed. The route calls `evaluate(verified, "catalog")`, then `permits(decision, "catalog")`; the latter reads the minimum tier from TOML.

## Run it

```bash
make run
```

This runs the signed inbound calls and outbound checks using scripted model replies for the three demo identities. It uses real DNSid verification, but the scripted replies are **not** a naming classifier. For a fresh registry:

| Request/check | Identity verified? | Tier | Result |
|---|---|---|---|
| Unsigned catalog read | No | Not evaluated | 401 |
| `acme-billing.test` catalog read | Yes | Limited | 200 |
| Same agent's refund | Yes | Limited | 403 |
| `paypal-refunds.test` catalog read | Yes | Untrusted | 403 |
| Outbound order lookup at `api.test` | Yes | Limited | Allow |
| Outbound customer-data sharing at `api.test` | Yes | Limited | Refuse |

To keep the API running for a policy-edit experiment, start the scripted model in one terminal—no weights needed:

```bash
uv run python src/fixture_model.py
```

In a second terminal:

```bash
make bootstrap
JEV_ENDPOINT=http://127.0.0.1:8791/v1/systemone \
  DNSID_PUBLIC_URL=https://api.test dnsid local run api -- \
  uv run uvicorn app:app --app-dir src --host 0.0.0.0 --port 3120
```

The API binds to all host interfaces so the Docker TLS proxy can reach it on Linux. Signed requests are still required; the scripted and real model endpoints remain loopback-only.

In a third, send a signed request:

```bash
dnsid local run acme-billing -- uv run python src/client.py call GET /v1/catalog 200
```

For real model judgments, run `make serve` instead of the scripted server and omit `JEV_ENDPOINT` in both API and client commands. The default is `http://127.0.0.1:8080/v1/systemone` with model label `clef-flash`. Setup is below.

**Try one policy edit:** change `rules.unproven.effect` from `"limit"` to `"deny"`, bump `version`, and restart the API in the second terminal. For a fresh identity, repeat the client command with expected status `403`: verification still succeeds, but the policy now denies even catalog reads. Restore the effect and version afterward. Alternatively, set `requires.catalog = "trusted"` to deny limited callers without changing their tier. Policy is loaded at process startup, not hot-reloaded.

## Verify

```bash
make verify
```

The one-shot check asserts the table above, rejects the brand lookalike outbound, rejects signed non-object JSON with 400, and returns 503 when the model endpoint is unavailable. It also proves that unsigned requests never reached the model. `verify passed` means the plumbing and fail-closed behavior work, **not** that a model understands every name.

Optional real-model check: `make eval EVAL_FLAGS=--strict`. The 16 offline cases store raw domains, ages and key-event kinds; the same code applies policy windows live and offline. No registry is needed. Their expected results target the default policy. Changing the policy may intentionally change those results. Strict evaluation returns nonzero for any missed tier or rule, or for scripted replies.

In this recipe directory, start the local Clef Flash decision server in **Terminal 1**. `make serve` checks the runtime commit before loading weights. If your `llama` CLI is already build 11379, use `make serve`. Otherwise, get the matching archive from the [build 11379 release](https://github.com/ggml-org/llama.cpp/releases/tag/b11379); keep its executable and libraries together. For the tested Apple Silicon Mac:

```bash
mkdir -p ~/llama-b11379
curl --fail --location \
  https://github.com/ggml-org/llama.cpp/releases/download/b11379/llama-b11379-bin-macos-arm64.tar.gz \
  --output /tmp/llama-b11379.tar.gz
tar -xzf /tmp/llama-b11379.tar.gz -C ~/llama-b11379
make serve LLAMA_SERVE="$HOME/llama-b11379/llama-b11379/llama-server"
```

On Linux or Intel macOS, select the archive for your platform from the same release and set `LLAMA_SERVE` to its `llama-server` path. This does not replace your installed `llama` CLI.

The server loads `ggml-org/Clef-Flash-GGUF:Q4_K_M` with alias `clef-flash`, a 4096-token context and no image projector. The first start downloads weights; later starts reuse the cache. It binds only to `127.0.0.1:8080`. Leave it running.

In **Terminal 2**, in the same recipe directory:

```bash
curl --fail http://127.0.0.1:8080/health   # Retry while weights are loading
make eval
make eval EVAL_FLAGS=--strict
```

Readiness returns `{"status":"ok"}`. Clef is a decision model, not a chat model; the recipe sends the existing System One yes/no questions, not chat completions. `MODEL_PORT` changes the server port and `make eval`'s default endpoint. When using a different port for the API or client, also set `JEV_ENDPOINT` explicitly.

`MODEL` changes the server alias and evaluation request label, not the weights. Other compatible servers work with `JEV_ENDPOINT=https://your-server/v1/systemone make eval MODEL=your-model`. For the API and client, use `JEV_MODEL` to change the label. `JEV_API_KEY` supplies an optional Bearer credential. Hosted endpoints receive counterparty naming facts, never lifecycle history or customer payloads.

Tested on Apple Silicon with Clef Flash Q4_K_M and unchanged policy `/3`. Build 11379 (`1537a0a8b`, 0.5.0-dev) gets **46/48 rule matches and 14/16 tiers**, in 6.3 seconds on a warm server. Build 11429 (`d81235049`, 0.6.0-dev), using the same weights and requests, gets 39/48 and 8/16. Disabling flash attention did not fix that result. The weights, naming questions and threshold remain unchanged; upgrade the pinned runtime only after comparing these checks.

Two original cases still fail: the Stripe integration is falsely denied, and the Google-calendar lookalike is not denied. Strict evaluation therefore still fails. Clearer prompts improved the original set to 15/16, but regressed the additional cases below, so those prompt changes were not kept.

Six additional cases in [`cases/holdout/`](cases/holdout/) check another brand, government services and neutral names. They were not used to tune the shipped questions. Run them separately:

```bash
uv run python src/eval.py cases/holdout --strict
```

Build 11379 gets **5/6 tiers and 17/18 rule matches**, compared with 3/6 tiers on build 11429. The remaining miss is `canada-tax-refunds.test`: the model does not give its naming claim enough weight, so it permits the catalog read. Keep that failure visible; do not treat an absent warning as verified affiliation. These small hand-labelled sets are smoke tests, not independent calibration or a production safety guarantee.

If `/v1/systemone` returns 404, check that you launched the pinned build. If port 8080 is occupied, stop the other server or use `MODEL_PORT`. Stop the foreground server with Ctrl-C; `make clean` stops only the registry.

### Usage warning and potential improvements

**This recipe demonstrates a policy mechanism, not production-ready authorization.** A `trusted` tier means the configured checks found no reason to restrict access; it does not prove brand affiliation, honest intent or permission to receive sensitive data. An old identity can still impersonate an organization. Unavailable or malformed model answers fail closed, but valid, incorrect answers can permit access.

Domain names alone cannot reliably distinguish an independent product integration from an official service. The Stripe and Google cases expose that ambiguity. Do not use model naming scores as the sole authorization check for real refunds, credentials or customer data. Require independently verified permission or delegation, checked in code. Keep identity and signature verification mandatory.

Potential improvements, not implemented here:

- **Expand and review the labelled cases.** Apply consistent rules to integrations and impersonation claims. Include more brands, government services and neutral names. Reserve unseen organizations for final evaluation, and report missed impersonators separately from false denials. The current sets have already been examined during development.
- **Use explicit affiliation evidence.** Maintain an application-owned reference of official domains and check the verified accountable entity against it in code. A mismatch alone does not establish impersonation; unknown affiliations still need a policy decision.
- **Compare questions and models under controlled conditions.** Test a direct impersonation question alongside the three-signal rule, higher-precision weights or another compatible model. Keep inputs and runtime fixed when comparing models, and record latency and memory use. These changes are experiments, not demonstrated improvements.
- **Calibrate and restrict uncertain outcomes.** Select thresholds on separate labelled data using the cost of missed impersonators and false denials. Consider limiting ambiguous cases rather than granting full trust. Report how often the system declines to decide; restriction improves safety but does not itself prove better classification accuracy.

## What to try next

- Edit an effect, age window, naming question or operation requirement in `policy.toml`, bump the version, and restart. Add a labelled case explaining the intended result. The three rules are explicit Python, not a generic policy language.
- Run `make clean` to stop the local registry. Stop a foreground API or model with Ctrl-C. `dnsid local reset --hard && make verify` repeats first-time provisioning.
- See [Recipe 12](../12-a2a-dnsid/) for another signed agent-to-agent flow.

The refund does **not** move money. Real side effects need replay and idempotency protection beyond signature freshness. A long-running verifier also needs durable log checkpoints, records that detect log rollback across restarts, instead of the SDK's in-memory default.
