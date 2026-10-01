# Recipe 32 — Decide how far to trust an agent you have never met

> Open a service to any DNSid-verified agent, then use a written trust policy to decide how far to trust it; use the same policy before your agent calls an unfamiliar service.

**Spec version:** `dnsid-draft-01`  
**Status:** runnable (fixture for `make verify`; real decision model required for semantic evaluation)
**Standards used:** RFC 9421 (HTTP Message Signatures), RFC 7517 (JWKS), DNSid C2SP lifecycle log  
**Estimated time:** ~20 minutes, plus model setup for `make eval`

---

## What you'll build

A Python API that verifies signed requests before allowing a catalog read, quote request or demonstration refund, and a client that checks a service's identity before sending data to it. [`src/facts.py`](src/facts.py) turns verified DNSid evidence into a fact sheet; [`policy.toml`](policy.toml) separates mechanical rules from three short naming questions for a Jev-compatible decision server, an HTTP service that returns yes/no probabilities. [`src/trust.py`](src/trust.py) evaluates the rules and combines the answers into `trusted`, `limited` or `untrusted`. Each operation sets its own minimum tier in code. The fixture server exercises the wiring, **not** the accuracy of a real model.

## Why this matters

DNSid can prove *who* controls an agent's operational key and which domain is accountable (`gi`); RFC 9421 proves that key signed this HTTP request. Neither tells you whether to share customer data with a newly encountered agent. Here a service can authenticate unfamiliar callers without a shared secret or partner allowlist, then limit what each one may do. The same check can stop an outbound agent from sending data to an impersonator.

## Prerequisites

- Docker 24+ running, `make`, and the [`dnsid` CLI](https://docs.dnsid.ai/cli-installation) with `dnsid local` support.
- [`uv`](https://docs.astral.sh/uv/) and Python 3.11+. Tested with Python 3.12.14, dnsid-py 0.23.1, FastAPI 0.141.1, httpx 0.28.1, confusable-homoglyphs 3.3.1 and uvicorn 0.52.4; versions are pinned in [`pyproject.toml`](pyproject.toml).
- A clone of this repository. For `make serve` / `make eval` only: hardware for a local model (tested on a 48 GB Apple Silicon Mac), or an existing Jev-compatible `/v1/systemone` endpoint. Decider's runtime is optional and pinned to decider-ai 1.8.1 in the `model` dependency group. No model or API key is needed for `make verify`.

## Concepts

- **DNSid binding** — a signed `_dnsid.<domain>` DNS TXT record linking an identity to an accountable entity (`gi`), a public-key URL (`ku=`), status (`su=`) and a lifecycle log reference. The verifier uses the keys in a JWKS (JSON Web Key Set, [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) at `/.well-known/jwks.json`.
- **HTTP Message Signatures ([RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421))** — request headers signed with the identity's operational key. Covered components are the method, authority, target URI and, for a body, its content digest. This proves possession of the key on this particular request.
- **C2SP lifecycle log** — the append-only record of issuance, rotation and revocation used by DNSid verification. Its trust policy URL comes **only** from independently supplied `DNSID_LOG_POLICY_URL`, never `DNSID_LOG_REF` or data supplied by a log.
- **Trust tier** — an application-level limit, not a cryptographic verdict. The model estimates three naming signals; code evaluates age and rotation rules, combines the signals, and chooses the tier. Model failure denies access.
- **Local registry** — `dnsid local` starts disposable DNS, registry, log and TLS services in Docker and injects DNS routing, keys, CA and log-policy configuration into `dnsid local run` processes.

## Running system

| Process | Where | Role |
|---|---|---|
| DNS server | local registry, `127.0.0.1:7753` | Serves live `_dnsid` TXT records |
| Registry and log | local registry, `127.0.0.1:7755` | Issues identities and records lifecycle events |
| TLS proxy | local registry, `:443` | Routes `https://*.dev.dnsid.test` to local upstreams |
| API | host `127.0.0.1:3120` | Verifies inbound signatures and gates operations |
| Decision endpoint | host `127.0.0.1:8791` fixture, `:8792` Decider | Answers only naming questions; the fixture is never an accuracy benchmark |
| Client | short-lived process | Signs inbound calls or gates outbound calls |

## Step 1 — Provision identities and inspect their records

```bash
make bootstrap
dig @127.0.0.1 -p 7753 _dnsid.acme-billing.test TXT +short
curl --resolve acme-billing.test:443:127.0.0.1 \
  --cacert ~/.dnsid-local/certs/root-ca.pem \
  https://acme-billing.test/.well-known/jwks.json
```

`make bootstrap` starts `dnsid local up --zone test` and uses `dnsid local agent ensure ... -- dnsid log issue` for `api`, `acme-billing` and `paypal-refunds`. The latter has a valid identity but its accountable entity is the local registry, **not** PayPal. The TXT record has one semicolon-separated value starting with `v=`, including `ku=` and `su=`. `--resolve` routes the host-only curl through the local TLS proxy; if using `--state`, use the CA path supplied by `DNSID_CA_BUNDLE` under `dnsid local run` instead.

## Step 2 — Verify identity before asking about trust

[`src/app.py`](src/app.py) bounds the request body, builds an `HttpRequest` using a deployment-configured public URL (never a forwarded-host header), and verifies it before calling the decision endpoint:

```python
verified = await asyncio.to_thread(
    profile.verify_signed_http_request, signed, HttpVerificationOptions(required_components=components))
await asyncio.to_thread(manager.verify_log_evidence, verified)
```

The SDK checks the binding, key, live status, lifecycle log and signed request; the second call asks for fresh non-revocation evidence. DNSid verification runs off the async server thread. A bad signature or unavailable verification stops here: the model cannot waive it. For a bodyless GET, the SDK receives `body=None` rather than an empty body, since the signing client does not cover `content-digest` on GET.

The outbound [`src/client.py`](src/client.py) calls `verify_domain` and `verify_log_evidence` before evaluating an unfamiliar service with the **same** trust policy. No model decision is reused as authentication.

## Step 3 — Apply the written policy

[`policy.toml`](policy.toml) marks `unproven` and `takeover_risk` as `evaluated_by = "code"`. Code bins verified ages without rounding at the boundary, checks for a recent **rotation** (not issuance or migration), and takes impact from our own operation table. A new identity with unknown or new entity history is limited; a recent rotation before moving money, exposing credentials or sharing personal data is denied. Editing these rules' prose alone does not change their implementation.

Only the `counterparty` section goes to the model: the verified name, `gi`, their domain relationship, DNSSEC state and code-built Unicode signals. `mixed_script` says the name mixes writing systems; `name_skeleton` substitutes known ASCII lookalikes, for example Cyrillic `а` → Latin `a`. Unmapped characters are preserved; this is a useful signal, not a complete Unicode security check or an automatic denial. Evaluation rebuilds the same signals from each case's DNS wire name. The model receives no lifecycle history, operation descriptions, customer payloads or counterparty-authored descriptions.

The three questions in `policy.toml` ask whether the name references an organization (`names_org`), whether `gi` is its official domain (`same_org`), and whether the name claims to act for it rather than use its product (`acts_for`). Code combines them as quoted from [`src/trust.py`](src/trust.py):

```python
impersonation = min(answers["names_org"], answers["acts_for"], 1 - answers["same_org"])
```

This is a thresholded AND, **not** a calibrated joint probability. [`src/trust.py`](src/trust.py) starts at `trusted`; a clause score at or above its threshold applies `limit` or `deny`, and the most restrictive wins. Missing lifecycle history caps trust at `limited`. Missing, malformed or unreachable model answers fail closed. Decisions are cached briefly by identity, entity, policy version, operation and lifecycle fingerprint; bump the policy version when rules or questions change.

The demo refund endpoint does **not** move money. Real side effects need replay and idempotency protection beyond RFC 9421 freshness. The SDK's default checkpoint store is in-memory; for a long-running verifier, use a durable checkpoint store so log rollback protection survives restarts.

## Run it

```bash
make run
```

This runs the same flow as verification without making transcript assertions. It starts a hard-coded fixture at `:8791`, serves the API behind the local registry's TLS proxy, and exercises both inbound and outbound gates. The fixture's simplistic substring rules are deliberately **not** a trust model.

To keep the API running against Decider instead, start `make serve` as described below, then in another terminal:

```bash
make bootstrap
DNSID_PUBLIC_URL=https://api.test dnsid local run api -- \
  uv run uvicorn app:app --app-dir src --host 127.0.0.1 --port 3120
```

A third terminal can send a signed catalog request:

```bash
dnsid local run acme-billing -- uv run python src/client.py call GET /v1/catalog 200
```

The API and outbound client default to Decider at `:8792`; `make verify` explicitly uses the separate fixture at `:8791`.

## Verify

```bash
make verify
```

Expected: unsigned catalog read → 401 without contacting the decision server; signed `acme-billing` catalog read → 200 (`limited`); its refund → 403; signed `paypal-refunds` catalog read → 403; outbound lookup of `api` → allow, sharing customer data with it → refuse; outbound lookup of `paypal-refunds` → refuse; with the fixture stopped, a signed quote request → 503. `verify passed` checks the fixture plumbing and fail-closed behavior, **not** real-world trust accuracy.

To serve [Decider](https://github.com/Mapika/decider) locally, open a second terminal in this recipe:

```bash
make serve MODEL=decider-4b       # first run downloads ~8.4 GB of weights
# Wait for "Application startup complete"; leave this terminal running.
```

Then evaluate in the first terminal:

```bash
make eval MODEL=decider-4b
make eval MODEL=decider-4b EVAL_FLAGS=--strict
```

The server binds only to `127.0.0.1:8792` and exposes `/health`. It automatically chooses CUDA, Apple's MPS (Metal Performance Shaders GPU backend), or CPU; override with `DECIDER_DEVICE=mps make serve`. The optional Metal kernel is included on Apple Silicon; CUDA-only Triton dependencies are excluded on macOS. Tested runtime: torch 2.14.1, transformers 5.18.0, MLX 0.32.3. CPU uses float32 and needs more memory than the weights' quoted 16-bit size. GGUF quantized weights do **not** work with this HTTP server.

On the tested 48 GB Mac, 12B is the default (`make serve` / `make eval` without `MODEL`). Stop the 4B server with Ctrl-C before trying it:

```bash
make serve MODEL=decider-12b      # ~24 GB of 16-bit weights plus runtime
# In the other terminal:
make eval MODEL=decider-12b EVAL_FLAGS=--strict
```

`make serve` selects the actual weights; `make eval MODEL=...` sets only a request label, not a remote model switch. Evaluation prints the server-reported model, each naming probability, clause scores, tier accuracy and elapsed time. `DECIDER_MODEL` can select a downloaded model directory; `MODEL_PORT` changes the port. Other compatible servers work with `JEV_ENDPOINT=http://127.0.0.1:8080/v1/systemone make eval MODEL=your-model`; `JEV_API_KEY` is optional. Hosted servers receive only counterparty identity facts.

[`cases/`](cases/) contains 16 labelled fact sheets, including an internationalized-name lookalike, delegated contractor, partner mention, rotations and entity-history examples. Hypothetical hosted names use reserved `.invalid` domains; live identities use distinct `.test` domains. Strict evaluation returns nonzero on any labelled clause or tier mismatch and always rejects fixture results. These small, hand-labelled cases are a smoke test, **not** independent calibration or a production safety claim.

| Server / weights | Correct clauses | Correct tiers | Time for 16 cases |
|---|---:|---:|---:|
| Decider 4B v2.1, MPS | 43/46 | 13/16 | 4.6 s |
| Decider 12B v2, MPS (default) | 45/46 | 15/16 | 10.6 s |

4B missed `outbound_gov_lookalike`, `squat_platform_hosted` and `testnet_brand_squat`, all false-negative impersonation decisions. 12B caught every labelled impersonator but wrongly denied `partner_mention` (a Stripe integration); **both strict runs fail**. The 12B checkpoint's stored yes/no temperature is 0.05, producing near-binary answers, not evidence of perfect certainty. Results use policy `counterparty-trust/2` without lowering the inherited impersonation threshold or overriding checkpoint calibration to fit these cases. These are single warm-server runs, excluding download/load time. Tested weights revisions: 4B `eb5fbdfc9448473ec25e399882912863afbdb70e`; 12B `8ac1efa708b71b86ae33b01d2a8d7a3ddcb48e66`.

The six authenticated inbound/outbound demo checks also passed against the real 12B server: neutral agent reads allowed, its refund and customer-data sharing refused, and the brand impersonator refused in both directions.

The live registry has no entity-level history index yet, so that field is `unknown` live; two cases show future entity-history evidence. Age and rotation checks pass all labelled mechanical rules without a model. Model accuracy, thresholds and false positives still need independent calibration before deployment.

## What to try next

- Edit a naming question or threshold in `policy.toml` (or a mechanical rule in `src/trust.py`), bump `version`, add a labelled case, and rerun `make eval` against a real model. Code, not the model, owns operation tiers.
- Run `make clean` to stop the local registry. Use `dnsid local reset --hard && make verify` to watch first-time provisioning again.
- See [Recipe 12](../12-a2a-dnsid/) for another signed agent-to-agent request flow.
