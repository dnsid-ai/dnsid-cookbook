# Recipe 32 — Decide how far to trust an agent you have never met

> Open a service to any DNSid-verified agent, then use a written trust policy to decide how far to trust it; use the same policy before your agent calls an unfamiliar service.

**Spec version:** `dnsid-draft-01`

**Status:** runnable (scripted model replies for `make verify`; optional Decider for real-model evaluation)

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
- A clone of this repository. The standard demo needs no model or vendor account. Optional Decider setup is described under **Verify**; the default 12B model was tested on a 48 GB Apple Silicon Mac.

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
| API | host `127.0.0.1:3120` | Verifies signed requests and checks permissions |
| Model endpoint | host `:8791` scripted replies, `:8792` Decider | Answers only naming questions |
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
  uv run uvicorn app:app --app-dir src --host 127.0.0.1 --port 3120
```

In a third, send a signed request:

```bash
dnsid local run acme-billing -- uv run python src/client.py call GET /v1/catalog 200
```

For real model judgments, run `make serve` instead of the scripted server and set `JEV_ENDPOINT` to `http://127.0.0.1:8792/v1/systemone` (the default when unset). Setup is below.

**Try one policy edit:** change `rules.unproven.effect` from `"limit"` to `"deny"`, bump `version`, and restart the API in the second terminal. For a fresh identity, repeat the client command with expected status `403`: verification still succeeds, but the policy now denies even catalog reads. Restore the effect and version afterward. Alternatively, set `requires.catalog = "trusted"` to deny limited callers without changing their tier. Policy is loaded at process startup, not hot-reloaded.

## Verify

```bash
make verify
```

The one-shot check asserts the table above, rejects the brand lookalike outbound, rejects signed non-object JSON with 400, and returns 503 when the model endpoint is unavailable. It also proves that unsigned requests never reached the model. `verify passed` means the plumbing and fail-closed behavior work, **not** that a model understands every name.

Optional real-model check: `make eval EVAL_FLAGS=--strict`. The 16 offline cases store raw domains, ages and key-event kinds; the same code applies policy windows live and offline. Their expected results target the default policy. Changing the policy may intentionally change those results. Decider 12B still gets **15/16 tiers** right: it wrongly denies the Stripe integration case, so strict evaluation fails. Do not lower thresholds just to fit these cases.

<details>
<summary>Optional Decider setup and evaluation details</summary>

In this recipe directory, start the local [Decider](https://github.com/Mapika/decider) server:

```bash
make serve                       # default: 12B, ~24 GB weights; tested on a 48 GB Mac
# Wait for "Application startup complete"; leave it running.
# In another terminal:
make eval
make eval EVAL_FLAGS=--strict
```

The optional `model` dependency group pins decider-ai 1.8.1. The server binds to `127.0.0.1:8792`, reports readiness at `/health`, and chooses CUDA, Apple's MPS GPU backend, or CPU. CPU uses float32 and needs more memory. Tested runtime: torch 2.14.1, transformers 5.18.0, MLX 0.32.3; macOS excludes CUDA-only dependencies. GGUF quantized weights are not supported by this server.

Stop the server before switching weights: `make serve MODEL=decider-4b` downloads ~8.4 GB instead. `make eval MODEL=decider-4b` is only a request label; it cannot switch a running server's weights. `DECIDER_MODEL` can point to a model directory; `MODEL_PORT` changes the port. Other compatible endpoints work with `JEV_ENDPOINT=http://127.0.0.1:8080/v1/systemone make eval MODEL=your-model`; `JEV_API_KEY` is optional. Hosted endpoints receive counterparty naming facts.

Current 12B v2 results with policy `/3`: 47/48 rule matches, 15/16 tiers, 9.9 seconds for a warm server. The earlier 4B v2.1 run with policy `/2` got 13/16 tiers, missing three impersonators. The three naming questions and their threshold are unchanged. 12B's stored yes/no temperature of 0.05 produces near-binary answers, not evidence of certainty. These small hand-labelled cases are a smoke test, not independent calibration. Tested weight revisions: 12B `8ac1efa708b71b86ae33b01d2a8d7a3ddcb48e66`; 4B `eb5fbdfc9448473ec25e399882912863afbdb70e`.

</details>

## What to try next

- Edit an effect, age window, naming question or operation requirement in `policy.toml`, bump the version, and restart. Add a labelled case explaining the intended result. The three rules are explicit Python, not a generic policy language.
- Run `make clean` to stop the local registry. Stop a foreground API or model with Ctrl-C. `dnsid local reset --hard && make verify` repeats first-time provisioning.
- See [Recipe 12](../12-a2a-dnsid/) for another signed agent-to-agent flow.

The refund does **not** move money. Real side effects need replay and idempotency protection beyond signature freshness. A long-running verifier also needs durable log checkpoints, records that detect log rollback across restarts, instead of the SDK's in-memory default.
