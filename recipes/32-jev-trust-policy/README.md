# Recipe 32 — Decide how far to trust an agent you have never met

> Open a service to any DNSid-verified agent, then use a written trust policy to decide how far to trust it; use the same policy before your agent calls an unfamiliar service.

**Spec version:** `dnsid-draft-01`  
**Status:** runnable (fixture for `make verify`; real decision model required for semantic evaluation)
**Standards used:** RFC 9421 (HTTP Message Signatures), RFC 7517 (JWKS), DNSid C2SP lifecycle log  
**Estimated time:** ~20 minutes, plus model setup for `make eval`

---

## What you'll build

A Python API that verifies signed requests before allowing a catalog read, quote request or demonstration refund, and a client that checks a service's identity before sending data to it. [`src/facts.py`](src/facts.py) turns verified DNSid evidence into a fact sheet; [`policy.toml`](policy.toml) supplies human-written clauses to a Jev-compatible decision server; [`src/trust.py`](src/trust.py) combines its answers into `trusted`, `limited` or `untrusted`. Each operation sets its own minimum tier in code. The fixture server exercises the wiring, **not** the accuracy of a real model.

## Why this matters

DNSid can prove *who* controls an agent's operational key and which domain is accountable (`gi`); RFC 9421 proves that key signed this HTTP request. Neither tells you whether to share customer data with a newly encountered agent. Here a service can authenticate unfamiliar callers without a shared secret or partner allowlist, then limit what each one may do. The same check can stop an outbound agent from sending data to an impersonator.

## Prerequisites

- Docker 24+ running, `make`, and the [`dnsid` CLI](https://docs.dnsid.ai/cli-installation) with `dnsid local` support.
- [`uv`](https://docs.astral.sh/uv/) and Python 3.11+. Tested with Python 3.14.7, dnsid-py 0.23.1, FastAPI 0.141.1, httpx 0.28.1 and uvicorn 0.52.4; versions are pinned in [`pyproject.toml`](pyproject.toml).
- A clone of this repository. For `make eval` only: a separately running Jev-compatible `/v1/systemone` model endpoint. No model or API key is needed for `make verify`.

## Concepts

- **DNSid binding** — a signed `_dnsid.<domain>` DNS TXT record linking an identity to an accountable entity (`gi`), a public-key URL (`ku=`), status (`su=`) and a lifecycle log reference. The verifier uses the keys in a JWKS (JSON Web Key Set, [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) at `/.well-known/jwks.json`.
- **HTTP Message Signatures ([RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421))** — request headers signed with the identity's operational key. Covered components are the method, authority, target URI and, for a body, its content digest. This proves possession of the key on this particular request.
- **C2SP lifecycle log** — the append-only record of issuance, rotation and revocation used by DNSid verification. Its trust policy URL comes **only** from independently supplied `DNSID_LOG_POLICY_URL`, never `DNSID_LOG_REF` or data supplied by a log.
- **Trust tier** — an application-level limit, not a cryptographic verdict. A Jev-style decision server estimates the probability that each written clause applies; code combines those estimates, and model failure denies access.
- **Local registry** — `dnsid local` starts disposable DNS, registry, log and TLS services in Docker and injects DNS routing, keys, CA and log-policy configuration into `dnsid local run` processes.

## Running system

| Process | Where | Role |
|---|---|---|
| DNS server | local registry, `127.0.0.1:7753` | Serves live `_dnsid` TXT records |
| Registry and log | local registry, `127.0.0.1:7755` | Issues identities and records lifecycle events |
| TLS proxy | local registry, `:443` | Routes `https://*.dev.dnsid.test` to local upstreams |
| API | host `127.0.0.1:3120` | Verifies inbound signatures and gates operations |
| Decision endpoint | host `127.0.0.1:8791` for the fixture | Answers policy questions; replace with a real model for evaluation |
| Client | short-lived process | Signs inbound calls or gates outbound calls |

## Step 1 — Provision identities and inspect their records

```bash
make bootstrap
dig @127.0.0.1 -p 7753 _dnsid.acme-billing.dev.dnsid.test TXT +short
curl --resolve acme-billing.dev.dnsid.test:443:127.0.0.1 \
  --cacert ~/.dnsid-local/certs/root-ca.pem \
  https://acme-billing.dev.dnsid.test/.well-known/jwks.json
```

`make bootstrap` uses `dnsid local agent ensure ... -- dnsid log issue` for `api`, `acme-billing` and `paypal-refunds`. The latter has a valid identity but its accountable entity is the local registry, **not** PayPal. The TXT record has one semicolon-separated value starting with `v=`, including `ku=` and `su=`. `--resolve` routes the host-only curl through the local TLS proxy; if using `--state`, use the CA path supplied by `DNSID_CA_BUNDLE` under `dnsid local run` instead.

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

[`policy.toml`](policy.toml) asks whether a verified identity impersonates another organization, lacks a track record, or recently rotated its key before a sensitive interaction. The model sees only code-built facts: the verified name and `gi`, how they relate, DNSSEC state, lifecycle age and rotation summary, plus an operation description from our own table. It never sees customer payloads or counterparty-authored descriptions.

[`src/trust.py`](src/trust.py) starts at `trusted`. A clause above its threshold applies its own effect (`limit` or `deny`); the most restrictive wins. If lifecycle history cannot be read, code caps trust at `limited`. Missing, malformed or unreachable model answers fail closed. Decisions are cached briefly by identity, entity, policy version, operation and lifecycle fingerprint; change the policy version when changing clauses.

The demo refund endpoint does **not** move money. Real side effects need replay and idempotency protection beyond RFC 9421 freshness. The SDK's default checkpoint store is in-memory; for a long-running verifier, use a durable checkpoint store so log rollback protection survives restarts.

## Run it

```bash
make run
```

This runs the same flow as verification without making transcript assertions. It starts a hard-coded fixture at `:8791`, serves the API behind the local registry's TLS proxy, and exercises both inbound and outbound gates. The fixture's simplistic substring rules are deliberately **not** a trust model.

## Verify

```bash
make verify
```

Expected: unsigned catalog read → 401 without contacting the decision server; signed `acme-billing` catalog read → 200 (`limited`); its refund → 403; signed `paypal-refunds` catalog read → 403; outbound lookup of `api` → allow, sharing customer data with it → refuse; outbound lookup of `paypal-refunds` → refuse; with the fixture stopped, a signed quote request → 503. `verify passed` checks the fixture plumbing and fail-closed behavior, **not** real-world trust accuracy.

To measure a real model rather than the fixture:

```bash
JEV_ENDPOINT=http://127.0.0.1:8080/v1/systemone make eval
```

[`cases/`](cases/) contains 16 labelled fact sheets, including an internationalized-name homoglyph, delegated contractor, partner mention, rotations and entity-history examples. The included fixture gets only 11/16 tiers right, so `--strict` against it must fail. Use a real [OpenJev](https://github.com/razorback16/openjev) or compatible `/v1/systemone` server; `JEV_MODEL` defaults to `jev-latest`, and `JEV_API_KEY` is optional. OpenJev's larger model needs significant GPU memory; test any smaller model against the cases before relying on it. Hosted endpoints receive identity facts and your operation descriptions. The live registry has no entity-level history index yet, so that field is `unknown` live; two cases demonstrate what future entity history might enable. Model accuracy, thresholds and false positives need independent calibration before deployment.

## What to try next

- Edit a clause in `policy.toml`, bump `version`, add a labelled case, and rerun `make eval` against a real model. Code, not the model, owns operation tiers.
- Run `make clean` to stop the local registry. Use `dnsid local reset --hard && make verify` to watch first-time provisioning again.
- See [Recipe 12](../12-a2a-dnsid/) for another signed agent-to-agent request flow.
