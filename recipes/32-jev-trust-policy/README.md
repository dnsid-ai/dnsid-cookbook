# Recipe 32 — Evaluate counterparty trust with DNSid and a written policy

> Verify a request's counterparty with DNSid first; only then ask a Jev-compatible model if the verified evidence and request context satisfy your trust policy.

**Spec version:** `dnsid-draft-01`  
**Status:** runnable (fixture decision server for `make verify`; real model optional)  
**Standards used:** RFC 9421 (HTTP Message Signatures), RFC 7517 (JWKS), DNSid C2SP lifecycle log  
**Estimated time:** ~20 minutes, plus model setup for real semantic decisions

---

## What you'll build

A generic `/evaluate` gate for an incoming signed request. The `dnsid-py` SDK establishes **who sent it** and checks the identity record, operational key, lifecycle log, live status and request signature. The application then sends only verified identity evidence, caller-provided request context, and an operator-written [`policy.txt`](policy.txt) to a separate Jev-compatible decision endpoint. The result is `proceed` or a denial; this example does **not** perform the requested operation.

## Why this matters

DNSid says who is accountable for an agent, not whether you should trust that agent for a particular interaction. Signing the HTTP request additionally proves this caller holds the identity's operational key. Only after those checks pass can the relying party consider its own policy and the request's purpose; a verified but unrecognized counterparty may still be denied without confusing authentication with trust.

## Prerequisites

- Docker 24+ running, `make`, and the [`dnsid` CLI](https://docs.dnsid.ai/cli-installation) with `dnsid local` support
- [`uv`](https://docs.astral.sh/uv/) and Python 3.11+
- For *real semantic decisions*: a separate Jev-compatible `/v1/systemone` decision server. No model/API key is needed for the fixture-only wiring check.

`pyproject.toml` pins dnsid-py v0.22.0, FastAPI 0.141.1 and uvicorn 0.52.4 (tested with Python 3.14.7).

## Concepts

- **DNSid** — an identity publishes a signed `_dnsid.<domain>` DNS TXT record pointing at public keys (a JWKS, or JSON Web Key Set), live status and lifecycle log. `dnsid-py` verifies these; the recipe does not implement its own parser, cryptography or DNS fetcher.
- **HTTP Message Signatures (RFC 9421)** — headers prove possession of the operational key and cover the method, URL and request-body digest. DNSid verification alone would not prove that the current HTTP caller is that agent. RFC 9421 is an optional application profile layered on top of DNSid.
- **C2SP log** — an append-only lifecycle log that binds the published key to issuance and supports a fresh non-revocation check. Its trust policy location comes only from independently supplied `DNSID_LOG_POLICY_URL`, never the incoming record.
- **Jev-style decision** — a model service returns probabilities for yes/no questions about the written policy, verified evidence and caller-provided context. These are fallible estimates, not cryptographic proofs; uncertain or unavailable answers fail closed.
- **Local registry** — `dnsid local` runs disposable DNS, registry, log and TLS services in Docker, and supplies DNS, TLS, keys and trusted log-policy configuration via `dnsid local run`.

## Running system

| Process | Where | Role |
|---|---|---|
| DNS, registry, log and TLS proxy | CLI-managed local containers | Issue and serve `.dev.dnsid.test` identities |
| Trust gate | host `:3120` behind `https://api.dev.dnsid.test` | Verify each caller before asking the decision server |
| Decision server | host `127.0.0.1:8791` | A fixture for the smoke test, or your own local model |
| Peer and outsider | short-lived clients | Send SDK-signed requests with different contexts |

## Step 1 — Provision the counterparty identities

```bash
make bootstrap
dig @127.0.0.1 -p 7753 _dnsid.peer.dev.dnsid.test TXT +short
```

The Makefile uses `dnsid local agent ensure ... -- dnsid log issue` to provision `api`, `peer` and `outsider`. Both counterparties have real, verifiable local DNSid records. In this example policy, only `peer` may ask for a routine read-only health check; `outsider` remains **authenticated but not trusted**. The example names can be changed in `policy.txt`; they are not coded into the gate.

## Step 2 — Verify before asking the model

[`src/app.py`](src/app.py) builds an SDK `HttpRequest` from the bounded inbound body and a server-configured public URL (not a caller-controlled forwarded-host header):

```python
verified = await asyncio.to_thread(profile.verify_signed_http_request, signed, VERIFY)
log_state = await asyncio.to_thread(manager.verify_log_evidence, verified)
```

`verify_signed_http_request` calls the SDK's `verify_domain` internally: DNS TXT record, signed key binding, log issuance, current status and signature/digest are all verified before returning. The second call obtains fresh operation-level non-revocation evidence. A bad or missing signature, invalid domain evidence, or unavailable status/log stops here: **Jev is never called**. Verification is synchronous in the SDK, so the async web server calls it on a worker thread.

The server constructs an `evidence` object only from this SDK result: verified domain, accountable entity (`gi`), DNSSEC state, status, DNSid flags, log state and freshness, and proof of possession. The signed JSON body is still *untrusted context*, even when its signature checks out: a caller can sign lies about its intent.

## Step 3 — Evaluate the human trust policy

[`src/policy.py`](src/policy.py) submits `{policy, evidence, context}` to the decision endpoint. It asks whether to trust **this verified counterparty for this particular request**, plus a separate question about attempted instruction/policy injection. Proceed requires a permit probability ≥0.85 and injection probability <0.5. Uncertain or malformed replies deny; endpoint errors return 503. The model cannot create identity evidence or waive failed SDK checks. A real model can still make mistakes; tune thresholds with labelled requests and keep consequential actions behind additional deterministic or human controls.

By default the API calls `http://127.0.0.1:8791/v1/systemone`. For a compatible local model, see the [Open-Jev server instructions](https://github.com/Zefan-Cai/Open-Jev); model weights are not included here. Override `JEV_ENDPOINT` and optionally `JEV_MODEL` / `JEV_API_KEY` for other backends. **Hosted endpoints receive the trust policy, verified evidence and the caller's request context**: choose one only if that disclosure is acceptable.

## Run it

```bash
make run
```

The run script starts [`src/mock_jev.py`](src/mock_jev.py), a **fixture** that returns preselected probabilities based on the test domain and context. It exercises the request flow but does **not** understand natural language or establish that the policy is effective. Never use it for real trust decisions.

To try a real local model, start its decision server separately, then run the API after `make bootstrap`:

```bash
DNSID_PUBLIC_URL=https://api.dev.dnsid.test \
JEV_ENDPOINT=http://127.0.0.1:8791/v1/systemone \
dnsid local run api --upstream http://localhost:3120 -- \
  uv run uvicorn app:app --app-dir src --host 127.0.0.1 --port 3120
# From another terminal:
dnsid local run peer --upstream http://localhost:3121 -- \
  uv run python src/client.py routine 200
```

The client signs `POST /evaluate` with its provisioned key. The returned `proceed` means only that the gate approved this particular signed request; an application must bind the decision to that same request before doing anything else. RFC 9421 freshness checks do not themselves make requests one-time: add shared replay/idempotency enforcement for side-effecting operations.

## Verify

```bash
make verify
```

Expected: unsigned → 401 **without calling the model**; signed routine peer → 200; signed sensitive/injected peer and signed outsider → 403; signed peer with the model offline → 503. The fixture asserts it received SDK-verified evidence and that only the four authenticated requests reached it. `verify passed (stub only; real model not evaluated)` confirms **wiring and fail-closed behavior**, not Jev accuracy.

## What to try next

- Edit [`policy.txt`](policy.txt) for your actual counterparties and contexts, then benchmark a real decision model on labelled cases. An agent's domain or `gi` is evidence of accountability, not automatic permission.
- See [Recipe 12](../12-a2a-dnsid/) for a fully signed agent-to-agent request flow.
- `make clean` stops the CLI-managed local registry.
