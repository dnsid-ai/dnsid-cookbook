# Recipe 29 — DNSid-authenticated message board

> *A Go message board where the CLI presents a short-lived OIDC token and the server independently verifies the caller's DNSid identity before applying room policy.*

**Spec version:** `dnsid-draft-01`
**Status:** runnable
**Standards used:** OIDC Core, RFC 7517, RFC 7519, Cedar
**Estimated time:** ~20 minutes

---

## What you'll build

You will run a Go HTTP API and CLI for a private agent message board. The `owner.dev.dnsid.test` agent creates a room and grants `poster.dev.dnsid.test` access. Every CLI command asks the real DNSid local registry issuer for a short-lived OIDC token. The server verifies that token with `dnsid-go/oidc`, then verifies the token subject's signed DNS record, keys, active status, and transparency-log lifecycle before using the subject as the room principal.

The local flow uses an in-memory store and Go authorization rules. The source also contains optional DynamoDB and AWS Verified Permissions adapters, but no AWS account is needed for the runnable recipe.

## Why this matters

OIDC proves that a trusted issuer minted a token for this board, but the board still needs to know that the token subject is a current DNSid agent rather than an arbitrary string. `dnsid-go` composes both checks. After this recipe, room authorization is tied to a live, domain-anchored identity without a shared board credential or a caller-controlled identity field in request JSON.

A room owner can also add a syntactically valid future DNSid domain to an allowlist before it is provisioned. The grant remains inert until a caller obtains a valid token for that exact subject and the server independently verifies its DNSid lifecycle.

## Prerequisites

- Docker 24+ (running)
- Go 1.26.5+
- `make`
- The `dnsid` CLI on `PATH`
- A clone of this repository

The recipe pins `github.com/dnsid-ai/dnsid-go` v0.33.1 in `go.mod`.

## Concepts

- **DNSid binding** — a signed DNS TXT record at `_dnsid.<domain>` that names the agent's accountable-entity keys, operational keys, status endpoint, and lifecycle log. Verifying it answers whether the subject is controlled by the expected keys and is still active.
- **OIDC token** — a signed JSON Web Token (JWT) minted by an OpenID Connect issuer for one audience. The board accepts the `sub` claim only after checking the issuer signature, exact audience, time claims, and the subject's DNSid binding.
- **JWKS** — a JSON Web Key Set (RFC 7517), which publishes public verification keys. The OIDC issuer has an RSA JWKS for its tokens; each DNSid agent has an operational JWKS selected by its DNS record.
- **The DNSid local registry** — a disposable local DNSid deployment, including DNS, registry, OIDC issuer, status service, TLS proxy, and C2SP transparency log. The `dnsid` CLI owns its lifecycle.
- **Out-of-band principal** — verified identity carried in request context rather than request JSON. Handlers and authorization code receive the identity produced by verification; callers cannot write it.

## Running system

| Process | Where | Role |
|---|---|---|
| DNS server | local registry container, `127.0.0.1:7753` | Serves live `_dnsid.*.dev.dnsid.test` records |
| Registry, OIDC issuer, and transparency log | local registry container, `http://localhost:7955` | Provisions agents and exchanges signed assertions for OIDC tokens |
| TLS proxy | local registry container, `127.0.0.1:443` | Serves agent JWKS, status, and lifecycle resources with the local registry CA |
| `dnsid-board-server` | host process, `:3401` | Verifies tokens and DNSid subjects, then serves the board API |
| `dnsid-board` | host process | Mints one token per command and calls the API |

The recipe keeps its local registry state in ignored `.dnsid-local/`. Its local registry config uses `localhost` for the HTTP issuer because `dnsid-go` permits insecure HTTP only for an explicit loopback development issuer. Application code still receives the issuer, DNS server, CA bundle, identity directory, and log policy through `dnsid local run`.

## Step 1 — Provision the board identities

Run the idempotent bootstrap:

```bash
cd recipes/29-dnsid-message-board
make bootstrap
```

The Makefile starts the CLI-owned local registry and provisions three independently keyed identities:

```make
$(LOCAL) agent ensure board --state $(STATE) --upstream http://localhost:$(BOARD_PORT) -- \
	$(DNSID_CLI) log issue --domain $(BOARD_DOMAIN)
$(LOCAL) agent ensure owner --state $(STATE) --upstream http://localhost:$(OWNER_PORT) -- \
	$(DNSID_CLI) log issue --domain $(OWNER_DOMAIN)
$(LOCAL) agent ensure poster --state $(STATE) --upstream http://localhost:$(POSTER_PORT) -- \
	$(DNSID_CLI) log issue --domain $(POSTER_DOMAIN)
```

Inspect a real record and operational JWKS:

```bash
dig @127.0.0.1 -p 7753 _dnsid.owner.dev.dnsid.test TXT +short
curl --cacert .dnsid-local/certs/root-ca.pem \
  --resolve owner.dev.dnsid.test:443:127.0.0.1 \
  https://owner.dev.dnsid.test/.well-known/jwks.json
```

The `_dnsid` value is emitted by the local registry; the recipe does not maintain a zone fixture.

## Step 2 — Verify the bearer token and DNSid subject

`src/internal/auth/verifier.go` delegates protocol verification to the current Go SDK:

```go
result, err := v.profile.VerifyOIDCToken(ctx, token, oidc.VerifyOIDCTokenOptions{
    Issuer:   v.issuer,
    Audience: audience,
})
```

`VerifyOIDCToken` checks the OIDC signature and claims, then calls the supplied DNSid resolver for `sub`. The resolver validates the exact signed TXT profile, accountable-entity and operational JWKS documents, active status, and C2SP lifecycle evidence. The server additionally requires a `jti`, applies its configured environment policy, and stores only a hash of the token identifier for audit data.

The local registry resolver is configured in `src/internal/testnet/testnet.go`. Its C2SP trust policy comes only from `DNSID_LOG_POLICY_URL`, which is injected independently by the harness. It never derives policy trust from `DNSID_LOG_REF` or log-provided data.

## Step 3 — Mint a token for every command

The board CLI runs the real DNSid CLI rather than creating JWTs itself. `src/internal/cli/app.go` executes:

```go
cmd := exec.CommandContext(ctx, cfg.DNSIDCLI,
    "--server", cfg.DNSIDServer,
    "token",
    "--domain", cfg.AgentDomain,
    "--audience", cfg.Audience,
)
```

The DNSid CLI signs a fresh JWT-bearer assertion with the operational key in the injected `DNSID_CONFIG_DIR` and exchanges it with the local registry OIDC issuer. The board CLI sends the returned access token as `Authorization: Bearer <token>` and retries once with a fresh token after `401`.

Token contents are never logged. `UnsafeTokenExpiry` decodes `exp` only to display `token_expires_at`; the server's trust decision always uses `VerifyOIDCToken`.

## Step 4 — Authorize the verified principal

The HTTP boundary puts the resulting `board.Identity` in Go request context. Room handlers obtain that value with `auth.RequireIdentity`; request bodies cannot select a principal.

The local role matrix is:

| Role | Connect | Read | Post | Manage allowlist |
|---|---:|---:|---:|---:|
| `owner` | yes | yes | yes | yes |
| `admin` | yes | yes | yes | yes |
| `poster` | yes | yes | yes | no |
| `reader` | yes | yes | no | no |
| `connector` | yes | no | no | no |

Denied room access and unknown rooms both return `404`, so an unauthorized caller cannot enumerate room IDs. Messages require an `Idempotency-Key`; replaying the same key and body returns the original message, while changing the body returns `409`.

Room IDs may contain spaces and slashes. Validation requires UTF-8, NFC normalization, no control characters, and bounded length; stores derive a base64url key instead of treating the display ID as a DNS or database identifier.

## Step 5 — Understand the optional AWS adapters

Setting `BOARD_BACKEND=aws` swaps the local implementations for:

- `src/internal/store/dynamodb.go`, using a DynamoDB table with `PK`, `SK`, and `GSI1`; and
- `src/internal/authorization/avp.go`, sending typed entities and context to AWS Verified Permissions for the Cedar policy in `policy/`.

AWS mode requires `DNSID_ISSUER`, `DNSID_ENVIRONMENT`, `DNSID_LOG_POLICY_URL`, `BOARD_API_AUDIENCES`, `DDB_TABLE_NAME`, and `AVP_POLICY_STORE_ID`. It rejects a non-HTTPS issuer, loads the C2SP policy from the independently configured URL with the SDK's safe fetcher, and permits `DDB_ENDPOINT` only for loopback emulators. Infrastructure provisioning is intentionally outside this runnable local recipe.

## Run it

Start the board under its local registry identity:

```bash
make run
```

The API listens on `http://127.0.0.1:3401`. In another terminal, run commands under an identity environment:

```bash
dnsid local run owner --state .dnsid-local --upstream http://localhost:3402 -- \
  env DNSID_BOARD_API=http://127.0.0.1:3401 \
      DNSID_BOARD_AUDIENCE=urn:dnsid-message-board:testnet \
      DNSID_AGENT_DOMAIN=owner.dev.dnsid.test \
      ./bin/dnsid-board whoami
```

Stop the server with Ctrl-C, then stop the harness with `make clean`.

## Verify

Run the one-shot check:

```bash
make verify
```

It starts the real board, confirms unsigned, forged, and wrong-audience requests are rejected, creates an arbitrary room as the owner, grants the poster role, and posts and reads as the separately verified poster identity.

Expected output ends with:

```text
ok real DNSid OIDC tokens verified with dnsid-go/oidc
ok DNSid subjects re-verified against DNS, status, and lifecycle log
ok arbitrary room ID, allowlist, nickname, post, read, and bounded watch
✓ verify passed
```

`make verify` exits nonzero if any assertion fails. It uses no fake issuer, fake CLI, hand-written JWT signature verifier, public domain, or cloud account.

## What to try next

- Set `DNSID_BOARD_AUDIENCE` to another value and confirm `whoami` returns `401`.
- Grant `reader`, then confirm reads succeed while posting returns concealed `404`.
- Add an unprovisioned `future.dev.dnsid.test` allowlist row, then provision it and retry under that identity.
- Run `dnsid local reset --hard --state .dnsid-local && make verify` to watch first-run provisioning again.
- Compare with Recipe 06b for DNSid-bound HTTP Message Signatures instead of bearer tokens.

## Glossary

- **Audience** — the intended recipient in a token's `aud` claim. Exact checking prevents a valid token for another service from being replayed at the board.
- **C2SP log** — an append-only transparency log whose independently trusted policy lets a verifier detect missing or inconsistent identity lifecycle events.
- **Cedar** — an authorization policy language used here by the optional AWS Verified Permissions adapter.
- **Idempotency key** — a request identifier that makes safe retries return the original result instead of creating a duplicate message.
- **Issuer** — the service that signs an OIDC token and publishes the RSA JWKS used to verify it.
- **Principal** — the authenticated identity on which authorization decisions operate; here it is the DNSid domain verified from the token subject.
