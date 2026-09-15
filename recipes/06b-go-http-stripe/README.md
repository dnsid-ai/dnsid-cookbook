# Recipe 06b — Go HTTP API verifies DNSid callers (fake-Stripe)

> A Go ledger rejects unsigned HTTP requests and accepts RFC 9421 requests signed by a caller whose complete DNSid identity verifies.

**Spec version:** `dnsid-draft-01`
**Status:** runnable
**Standards used:** RFC 9421 (HTTP Message Signatures), RFC 9530 (Content-Digest), RFC 7517 (JWKS)
**Estimated time:** ~10 minutes

---

## What you'll build

A small Go service with `GET /v1/balance` and `POST /v1/balance/credit` endpoints. A worker calls both endpoints through the local DNSid testnet. The worker signs each request with `dnsid-go`; the server uses the same SDK to resolve and verify the caller's signed `_dnsid` record, accountable-entity endorsement, operational JWKS, status, transparency-log lifecycle, and RFC 9421 signature before a route runs. An unsigned request receives `401`.

## Why this matters

RFC 9421 standardizes how to sign an HTTP request, but a relying party still needs a trustworthy way to find the signer's key and determine whether it remains valid. DNSid supplies that lifecycle from the caller's domain, so this server does not need a shared API key, partner-specific certificate, or copied JWKS. After this recipe, a newly published caller can authenticate on first contact, while authorization remains a separate local decision.

## Prerequisites

- Docker 24+ (running)
- `make`, `dig`, and `curl`
- Go 1.26.5 or newer
- The `dnsid` CLI — download it from the [dnsid-ai/dnsid releases](https://github.com/dnsid-ai/dnsid/releases) and put it on `PATH`
- Git credentials that can read the current `dnsid-ai/dnsid-go` repository
- A clone of this repository

The recipe pins `dnsid-go` v0.33.1 in [`go.mod`](go.mod).

## Concepts

- **DNSid binding** — a signed `_dnsid.<domain>` TXT record that names the operational key endpoint (`ku=`), accountable-entity key endpoint (`ek=`), live status endpoint (`su=`), governance identity (`gi=`), and transparency-log reference (`lr=`). Verifying the complete binding is stronger than merely following `ku=`.
- **JWKS** — JSON Web Key Set ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)), a standard list of public keys. Each DNSid identity serves its current operational public key at the binding's `ku=` URL.
- **RFC 9421 HTTP Message Signatures** — detached request signatures carried in `Signature-Input` and `Signature` headers. Covered components are the request fields protected by the signature; this SDK covers the method, authority, target URI, and a body digest when a body exists.
- **Content-Digest** — an RFC 9530 header containing a digest of the request body. Covering it with the HTTP signature makes a changed credit amount fail verification.
- **The DNSid testnet** — a disposable local DNS server, registry, C2SP transparency log, and TLS proxy managed by `dnsid testnet`. It publishes real records and lifecycle evidence under `.test` domains without requiring an external account.

## Running system

The recipe owns no Docker Compose file; the CLI manages the testnet containers.

| Process | Where | Role |
|---|---|---|
| DNS server | testnet container, `127.0.0.1:7753` | Serves `_dnsid.stripe.dev.dnsid.test` and `_dnsid.writer.dev.dnsid.test` |
| Registry + C2SP log | testnet container, `127.0.0.1:7755` | Provisions identities, serves status, and records lifecycle events |
| TLS proxy | testnet container, `127.0.0.1:443` | Routes each `https://*.dev.dnsid.test` name to its local process |
| fake-Stripe server | host process, `:3301` | Verifies signed requests and maintains an in-memory balance |
| writer agent | host process, `:3302` | Serves its JWKS and sends the signed read-credit-read flow |

## Step 1 — Provision both identities

```bash
make bootstrap
```

[`Makefile`](Makefile) downloads the Go modules, builds both binaries, starts the testnet, provisions `stripe.dev.dnsid.test` and `writer.dev.dnsid.test`, and issues their transparency-log entries. Provisioning is idempotent, so re-running it keeps the existing identities.

Every recipe process later starts under `dnsid testnet run`. That command injects its private identity directory, testnet DNS server, local CA bundle, and independently trusted C2SP policy URL as `DNSID_*` environment variables.

[`src/internal/testnet`](src/internal/testnet) is testnet-only harness glue: it teaches the SDK to use the injected private DNS server and local CA. Production applications keep the SDK's public-network protections and do not copy this package. The application integration taught below is the signer, verifier middleware, and authorization check.

### Inspect the live caller identity

In one terminal, serve the writer's real operational JWKS through the testnet proxy:

```bash
dnsid testnet run writer --upstream http://localhost:3302 -- ./bin/agent --serve
```

In a second terminal, inspect the TXT binding and follow its `ku=` endpoint with `curl`:

```bash
dnsid testnet run stripe -- sh -c '
  host=${DNSID_DNS_SERVER%:*}
  port=${DNSID_DNS_SERVER##*:}
  dig @"$host" -p "$port" _dnsid.writer.dev.dnsid.test TXT +short
  curl --fail --silent --show-error \
    --resolve writer.dev.dnsid.test:443:127.0.0.1 \
    --cacert "$DNSID_CA_BUNDLE" \
    https://writer.dev.dnsid.test/.well-known/jwks.json
'
```

The TXT output is the signed DNSid binding; its `ku=` URL returns the writer's current public key. Press Ctrl-C in the first terminal when finished.

## Step 2 — Verify before dispatch

The server creates the SDK's HTTP Message Signatures profile from its testnet-configured identity manager. [`src/server/main.go`](src/server/main.go) verifies the request before placing the resulting domain in out-of-band request context:

```go
caller, err := profile.VerifyHTTPRequest(r.Context(), publicRequest)
if err != nil {
    http.Error(w, "valid DNSid HTTP signature required", http.StatusUnauthorized)
    return
}
next.ServeHTTP(w, publicRequest.WithContext(
    context.WithValue(publicRequest.Context(), callerContextKey{}, caller),
))
```

`VerifyHTTPRequest` delegates identity verification to `dnsid-go`: it checks the signed record, entity endorsement, operational key, status, and C2SP lifecycle before using the selected key to verify the HTTP signature. The verified domain reaches the route only through context set by this middleware; request input cannot supply it.

The testnet terminates TLS before forwarding to the local HTTP server, so the middleware restores the external HTTPS scheme before verification. This is required because `@target-uri` commits to the public URL the worker signed.

## Step 3 — Sign with the worker identity

[`src/agent/main.go`](src/agent/main.go) loads the identity injected by `dnsid testnet run` and asks the SDK to sign each request:

```go
profile := httpsig.NewFromIdentityManagerKeyProvider(identity, httpsig.Config{})
signed, err := profile.CreateSignedHTTPRequest(req, httpsig.SigningOptions{
    ExpiresIn: time.Minute,
})
```

For the credit POST, the SDK reads the body, adds `Content-Digest`, covers that digest, and restores the body before sending. It also adds a creation time, expiry, random nonce, algorithm, and `<domain>#<kid>` key identifier.

The worker runs a small JWKS endpoint while making its calls. The fake-Stripe verifier follows the live `ku=https://writer.dev.dnsid.test/.well-known/jwks.json` URL through the testnet TLS proxy to that endpoint.

## Step 4 — Authorize the verified domain

Authentication proves the caller is `writer.dev.dnsid.test`; it does not grant permission by itself. The credit handler separately checks the verified domain against `WRITER_DOMAINS` before changing the ledger:

```go
caller := r.Context().Value(callerContextKey{}).(*dnsid.VerifiedDomain)
if !writers[caller.Domain()] {
    http.Error(w, "verified caller is not authorized to credit", http.StatusForbidden)
    return
}
```

The Make flow sets that allowlist to the writer identity. Reads accept any successfully verified caller.

## Run it

```bash
make run
```

This starts fake-Stripe, rejects an unsigned request and a signed request whose body was changed after signing, then runs the valid signed read-credit-read flow. Set `AMOUNT` or `ACCOUNT` to change the demo:

```bash
make run AMOUNT=500 ACCOUNT=acct_demo
```

## Verify

```bash
make verify
```

The one-shot check provisions both identities, starts both binaries under `dnsid testnet run`, and asserts that unsigned and tampered requests fail while valid signed calls carry the expected verified domain and balance.

Expected output:

```
verified identity: writer.dev.dnsid.test
unsigned GET -> 401 Unauthorized
tampered POST -> 401 Unauthorized
GET balance -> 1000 (verified as writer.dev.dnsid.test)
POST credit -> 1250 (verified as writer.dev.dnsid.test)
GET balance -> 1250 (verified as writer.dev.dnsid.test)
✓ verify passed
```

Failures include testnet container logs. `make clean` stops the testnet and removes the two built binaries.

## What to try next

- Inspect the worker's `Signature-Input` and `Content-Digest` headers before they are sent.
- Provision a second caller and run it without adding its domain to `WRITER_DOMAINS`; signed reads pass but credits return `403`.
- Run `dnsid testnet reset --hard && make verify` to watch both identities complete first-time issuance.
- [Recipe 31](../31-langgraph-dnsid-agent/) applies the same verified ingress and signed egress pattern around an agent's tools.

## Glossary

- **Accountable entity** — the governing organization that endorses the agent identity. Its independently published `ek=` key verifies the DNS record signature.
- **Authorization** — the route's local decision about what an already authenticated domain may do. DNSid identifies the caller; it does not invent application permissions.
- **Covered components** — request fields included in an RFC 9421 signature base. Changing a covered field invalidates the signature.
- **C2SP transparency log** — an append-only log whose witnessed checkpoints let verifiers audit identity issuance and later lifecycle events.
- **JWKS** — JSON Web Key Set, the standard JSON document containing public keys and their key IDs.
- **Verifier** — code that resolves a claimed domain's DNSid evidence and accepts the request only if both the identity lifecycle and message signature verify.
