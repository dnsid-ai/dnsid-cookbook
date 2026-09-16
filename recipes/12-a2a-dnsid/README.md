# Recipe 12 — A2A protocol + DNSid

> Two A2A agents from different organizations begin a session on first contact, with no shared API keys, no manual key exchange, and no out-of-band introduction.

**Spec version:** `dnsid-draft-01`
**Status:** runnable
**Standards used:** A2A 1.0 (JSON-RPC binding), RFC 9421 (HTTP Message Signatures), RFC 7517 (JWKS), RFC 8037 (Ed25519 in JOSE), C2SP tlog (transparency log)
**Estimated time:** ~20 minutes

---

## What you'll build

Two A2A agents, Alice and Bob, each with its own cryptographic identity anchored in DNS. Bob runs as a server; Alice sends him one signed message. Before that message is accepted, both sides verify each other with nothing but DNS lookups: Alice resolves Bob's identity record to check who she's talking to, and Bob verifies the RFC 9421 signature on Alice's request against keys published at Alice's domain. Neither agent has ever seen the other before, and no secret was exchanged between them at any point. You'll also watch the whole identity lifecycle that makes this possible — registration, a signed challenge, publication to DNS, and a transparency-log entry — because the recipe runs against a real (local) DNSid testnet, not a mock.

## Why this matters

A2A (Google's Agent2Agent protocol) standardizes how agents talk — agent cards, JSON-RPC messages, task lifecycles — but punts on the trust-bootstrap step: both sides need to know who they're talking to before the conversation can start, and the spec leaves that to "security schemes" you still have to provision. In practice that means API keys, mTLS certificates, or a partner-onboarding meeting. DNSid fills exactly that step: each side resolves the other's `_dnsid` DNS record and verifies signed messages against the keys it finds there. After this recipe: two A2A agents from different organizations can begin a session on first contact — the sender is identified by its domain name, the proof is a per-request cryptographic signature, and revocation propagates through DNS instead of through credential rotation at every counterparty.

## Prerequisites

- Docker 24+ (running)
- `make`
- The `dnsid` CLI — `brew install dnsid-ai/tap/dnsid`, or download a binary per the [installation docs](https://docs.dnsid.ai/cli-installation) and put it on `PATH`
- [`uv`](https://docs.astral.sh/uv/) 0.12+ (manages Python and the recipe's dependencies; installs a compatible Python 3.11+ automatically)
- A clone of this repo

Dependency versions this recipe was tested against are pinned in [`pyproject.toml`](pyproject.toml) (dnsid-py v0.19.1, a2a-sdk 1.1.2, Python 3.13).

## Concepts

- **DNSid binding** — a small record published in DNS that says "this domain owns this public key." A verifier resolves `_dnsid.<domain>` (a DNS TXT record) to find the binding, then follows the record's `ku=` tag to fetch the public keys at `/.well-known/jwks.json`. This is what lets us trust a signature without a certificate authority or a pre-shared secret.
- **JWKS** — JSON Web Key Set, a list of public keys in a standard JSON format ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)). Each agent serves its own at `/.well-known/jwks.json`.
- **RFC 9421 — HTTP Message Signatures** — an IETF standard for signing HTTP requests with detached signatures carried in headers ([RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421)). A signature commits to a chosen set of *covered components* — here the method, target URI, content type, a SHA-256 digest of the body, and the A2A negotiation headers — so none of them can be altered in transit.
- **A2A** — the [Agent2Agent protocol](https://a2a-protocol.org/), which standardizes agent-to-agent interaction. Each agent publishes an *agent card* (a machine-readable capability document at `/.well-known/agent-card.json`) and accepts JSON-RPC messages. This recipe uses the official `a2a-sdk` and declares DNSid signing as a required A2A extension in the card.
- **The DNSid testnet** — a disposable, fully local DNSid deployment (DNS server, registry, transparency log, TLS proxy) that the `dnsid` CLI runs in Docker. It behaves like the real system — agents register, answer challenges, publish records, get countersigned log entries — so everything you learn here transfers, and everything the agents "trust" is provisioned live in front of you.
- **Transparency log (C2SP tlog)** — an append-only, publicly auditable log of identity issuance events, in the [C2SP](https://c2sp.org/) checkpoint format. When an identity is published, the log's countersigned ISSUANCE entry is what makes a quietly swapped key detectable. Which logs to trust is defined by a *policy file* fetched from an independently configured URL — a point this recipe makes twice, because getting it wrong quietly destroys the guarantee.

## Running system

`dnsid testnet up` manages its own containers — the recipe owns no compose file. What's running when the recipe is up:

| Process | Where | Role |
|---|---|---|
| DNS server | testnet container, `127.0.0.1:7753` | Serves live `_dnsid.*.dev.dnsid.test` TXT records — the records your agents publish |
| Registry + transparency log | testnet container, `127.0.0.1:7755` | Registration, challenge verification, record publication, C2SP log |
| TLS proxy | testnet container | Terminates `https://*.dev.dnsid.test` with a local CA and routes to each agent's upstream port |
| Bob (this recipe) | host process, `:3002` | A2A echo agent — stays running, verifies every inbound request |
| Alice (this recipe) | host process, `:3001` | A2A agent — sends Bob one signed message, then exits |

## Step 1 — Bootstrap the testnet and two identities

```bash
make bootstrap
```

This runs three idempotent things (see [`Makefile`](Makefile)): `dnsid testnet up` starts the containers; `dnsid testnet agent ensure <name>` provisions each agent — a keypair on disk, a registered upstream, a published `_dnsid` record; and `dnsid log issue` submits each identity's countersigned ISSUANCE entry to the transparency log. Safe to re-run at any time.

Because this is a real DNS server, you can inspect what was just published — this TXT record is the entire public anchor of Bob's identity:

```bash
dig @127.0.0.1 -p 7753 _dnsid.bob.dev.dnsid.test TXT +short
```

```
"v=dnsid-draft-01;cu=https://bob.dev.dnsid.test/.well-known/agent-card.json;...;ku=https://bob.dev.dnsid.test/.well-known/jwks.json;lr=c2sp-tlog:testnet:...;sg=...;su=https://registry.dev.dnsid.test/v1/status/bob.dev.dnsid.test"
```

One semicolon-separated value: `v` (spec version) first, then `cu=` pointing at the agent card, `ku=` at the key set, `lr=` naming the transparency log, `sg=` a signature over the record, and `su=` the live status endpoint. A verifier that resolves this record has everything it needs to fetch Bob's keys and check he's in good standing — and once Bob's agent is running, `curl http://localhost:3002/.well-known/jwks.json` shows the Ed25519 public key the `ku=` URL serves.

## Step 2 — Identity from the environment

Recipe processes never configure DNS servers, CA bundles, or registry credentials in code. They launch under `dnsid testnet run <name> -- <cmd>`, which injects the full `DNSID_*` environment: DNS routing (`DNSID_DNS_SERVER`), TLS trust (`DNSID_CA_BUNDLE`), the registry credential (`DNSID_API_KEY`), the provisioned identity directory (`DNSID_CONFIG_DIR`), and the independently trusted policy location (`DNSID_LOG_POLICY_URL`).

[`src/identity.py`](src/identity.py) turns that environment into a usable identity. The one rule in it worth memorizing:

```python
def required_log_policy_url(environment: Mapping[str, str]) -> str:
    """Return the independently supplied testnet C2SP policy URL."""
    policy_url = environment.get("DNSID_LOG_POLICY_URL", "").strip()
    if not policy_url:
        raise RuntimeError("DNSID_LOG_POLICY_URL is required; run with `dnsid testnet run`")
    return policy_url
```

**The policy trust rule:** which transparency logs to trust comes *only* from `DNSID_LOG_POLICY_URL` — configuration you control. It is never derived from `DNSID_LOG_REF`, the log prefix, or anything else the log itself hands you. A log that could name its own trust policy could vouch for itself, and the transparency guarantee would be circular. (See [What goes wrong](#what-goes-wrong) for what this looks like when violated.)

The rest of the module wires the SDK: `config_from_environment` parses the env into a `DnsidConfig` (identity, verification, transport) plus registry config, `LocalKeyProvider.from_cli_directory` loads the provisioned key (its `private.jwk` carries the RFC 7638 thumbprint `kid` the registry requires), and `make_log_registry` fetches the policy file and registers a C2SP log reader for issuance verification.

One testnet-only wrinkle: the SDK's HTTPS fetcher refuses any host that resolves to a private address (an SSRF guard), and on the testnet *every* name under the governance domain resolves to the loopback proxy. Bob can't list his callers in advance, so `load_identity` allows the whole zone with one leading-dot entry — `private_address_hosts = {"." + governance_id}`. Production verifiers leave that set empty.

## Step 3 — Register, prove key possession, publish

Bootstrap already published both identities, so on the testnet this step is a fast no-op — but [`src/identity.py`](src/identity.py) carries the full flow because in any real deployment your agent code drives it. `register_and_publish` walks the registry state machine:

```python
if not status.published and not status.ready_for_publication:
    await _verify_with_challenge(key_provider, registry, domain, status)
    status = await asyncio.to_thread(registry.get_agent_status, domain)

if status is not None and status.ready_for_publication:
    published = await asyncio.to_thread(idm.publish_to_registry, registry)
    print(f"{domain} published {published.owner_name}")
else:
    print(f"{domain} already published ({status.registry_status if status else 'unknown'})")
```

Registration alone proves nothing — anyone can claim a domain name. The challenge step is where trust enters: the registry issues a random nonce, and `_verify_with_challenge` signs it with the agent's private key and submits the signature. Only after the registry confirms the agent actually *holds* the key does the identity become publishable; `publish_to_registry` then makes the `_dnsid` record live in DNS. The flow is idempotent — an already-published identity logs `already published (READY)` and moves on, which is exactly what you'll see in this recipe's transcripts.

## Step 4 — The agent card declares the contract

An A2A agent card tells callers what an agent can do and what it requires. [`src/agent_card.py`](src/agent_card.py) builds a card that declares the DNSid signature extension as **required**:

```python
ext = card.capabilities.extensions.add()
ext.uri = DNSID_A2A_EXTENSION_URI
ext.description = (
    "Requires DNSid validation, RFC 9421 HTTP Message Signatures, "
    "and mTLS for inbound requests."
)
ext.required = True
```

The extension's params spell out the whole verification contract machine-readably: which headers carry the signature, how the `keyid` is formed (`<caller-dnsid-subject>#<jwks-kid>`), that keys resolve via the DNSid `ku=` JWKS, and which covered components a signature must include. A compliant caller can read the card and know exactly how to authenticate before sending its first message. The card itself is signed (`sign_agent_card` attaches a detached JWS — a JSON Web Signature over the card's canonical form), so a tampered card is detectable too.

## Step 5 — Ingress: verify every inbound request

[`src/middleware.py`](src/middleware.py) is the trust boundary. It wraps the whole server as ASGI middleware (the interface Python web servers use to compose request handling), so no unverified POST can reach the A2A handlers:

```python
dnsid_req = DnsidRequest(method=scope["method"], url=url, headers=headers_raw, body=body)
try:
    verified = await asyncio.to_thread(
        self._http_sig.verify_signed_http_request, dnsid_req, VERIFY_OPTS
    )
    scope = {**scope, "_dnsid_sender": VerifiedSenderUser(verified.domain)}
except Exception as exc:
    response = JSONResponse({"error": str(exc)}, status_code=401)
```

That one `verify_signed_http_request` call does the whole DNSid dance: parse the signature headers, resolve `_dnsid.<sender>` in DNS, follow `ku=` to the sender's JWKS, check live status via `su=`, and validate the signature over the required covered components — rejecting anything missing `content-digest` (so the body can't be swapped) or the A2A negotiation headers (so the protocol version can't be downgraded). Before any of that, the middleware also rejects requests whose `A2A-Version` or `A2A-Extensions` headers don't match the card's declared contract.

The verified sender domain rides in the ASGI scope to the a2a-sdk call context. It is *not* a header the caller controls — it exists only because verification succeeded.

## Step 6 — Egress: sign every outbound request

The mirror image, in [`src/client.py`](src/client.py). Signing lives at the transport layer, not in per-call code:

```python
self._http_client = http_sig.create_signed_async_http_client(
    base_headers={
        "content-type": "application/json",
        "a2a-version": A2A_VERSION,
        "a2a-extensions": DNSID_A2A_EXTENSION_URI,
    },
    opts=signing_opts,
)
self._factory = ClientFactory(ClientConfig(httpx_client=self._http_client, streaming=False))
```

`create_signed_async_http_client` returns an httpx client that signs everything it sends — including the SHA-256 `content-digest` of the exact body bytes. The a2a-sdk's `ClientFactory` is simply handed that client, so the protocol code never thinks about signatures at all. One client, one choke point, no way to accidentally send an unsigned A2A message.

## Step 7 — The agent behind the boundary

With identity handled at the edges, the agent itself ([`src/executor.py`](src/executor.py)) is deliberately trivial — it echoes the message back, prefixed with who it verifiably came from:

```python
text = context.get_user_input()
sender_id = context.call_context.user.user_name
reply_text = f"[from: {agent_id}; verified sender: {sender_id}] {text}"
```

`sender_id` here is the cryptographically verified domain from Step 5. [`src/main.py`](src/main.py) ties everything together: load identity → start the server → register/publish → wait until the agent's own record resolves — then either stay running (Bob) or verify a peer and send one message (Alice). Alice's side of first contact is two lines: `idm.verify_domain(peer_fqdn)` resolves and verifies Bob's record before she talks to him, then the signed client sends the message.

## Run it

```bash
make run
```

Bob starts under `dnsid testnet run` and publishes; Alice then verifies him, sends one signed hello, and exits. Expected output (abridged):

```
==> starting Bob on :3002
    waiting for Bob to publish his identity.. done
==> starting Alice on :3001 — sending hello to Bob
alice -> https://alice.dev.dnsid.test
alice.dev.dnsid.test already published (READY)
verified: alice.dev.dnsid.test -> bob.dev.dnsid.test

reply: "[from: bob.dev.dnsid.test; verified sender: alice.dev.dnsid.test] hello from alice.dev.dnsid.test"

--- Bob transcript ---
bob -> https://bob.dev.dnsid.test
bob.dev.dnsid.test already published (READY)
[bob.dev.dnsid.test] verified signed POST / from alice.dev.dnsid.test
[bob.dev.dnsid.test] handling message from verified sender alice.dev.dnsid.test: "hello from alice.dev.dnsid.test"
```

Both identities appear in the reply, and both were established cryptographically: Alice's by her request signature, Bob's by the DNS record Alice verified before sending.

## Verify

```bash
make verify
```

Runs the same flow one-shot and asserts the transcript ([`verify/verify.sh`](verify/verify.sh)): Bob's identity published, Bob logged a verified signed POST from Alice, Alice verified Bob on first contact, and the reply carries both verified identities. Exits nonzero on any miss.

```
==> asserting transcript
  ok: Bob's identity published
  ok: Bob verified Alice's signature
  ok: Alice verified Bob's identity on first contact
  ok: reply carries both verified identities

✓ verify passed
```

Re-running `make verify` without a reset exercises the idempotent path — both agents log `already published (READY)` instead of re-registering. `make clean` tears the testnet down; `dnsid testnet reset --hard` also wipes all identity state for a truly fresh start.

## What goes wrong

Two failure modes worth seeing on purpose:

**An unsigned request is a 401, not a protocol error.** With Bob running, send a well-formed A2A request without a signature:

```bash
curl -s -X POST http://localhost:3002/ \
  -H 'content-type: application/json' -H 'a2a-version: 1.0' \
  -H "a2a-extensions: https://example-provider.example/a2a/extensions/dnsid-http-message-signatures/v1" \
  -d '{"jsonrpc":"2.0","method":"message/send","id":1}'
```

```
{"error":"[SIGNATURE_INVALID] missing Signature or Signature-Input headers"}   ← HTTP 401
```

The request never reached the A2A handlers — identity is enforced before protocol. (Omit the `a2a-extensions` header instead and you get a 400: the extension negotiation is checked even earlier.)

**Deriving the policy URL from the log reference.** The `lr=` tag in the DNS record names the transparency log, and it's tempting to fetch the trust policy from the same host — one less thing to configure. But the record (and the `DNSID_LOG_REF` env var derived from it) is exactly what an attacker who compromised publication controls. If the verifier fetches its policy from a URL derived from `lr=`, a forged record can point at a forged log *and* a forged policy that blesses it — the log vouches for itself, and transparency detects nothing. That's why `required_log_policy_url` in Step 2 hard-fails rather than falling back: the policy URL must arrive out-of-band (`DNSID_LOG_POLICY_URL`), from configuration the record can't influence.

## What to try next

- **Cross-language interop** — the same agents exist in TypeScript ([dnsid-ts/examples/a2a](https://github.com/dnsid-ai/dnsid-ts/tree/main/examples/a2a)). Run TypeScript Bob against this recipe's Python Alice (or vice versa): the wire format is standard RFC 9421 + A2A, so nothing changes.
- **Watch a true first run** — `dnsid testnet reset --hard && make verify` wipes all state, so you see fresh registration and challenge-signing instead of the idempotent path.
- **Inspect the transparency log** — the testnet serves a stream explorer at `http://127.0.0.1:7755/streams/bob.dev.dnsid.test` showing Bob's countersigned ISSUANCE entry.
- **Recipe 1 — Publish `_dnsid` + JWKS** — the anatomy of the record and key set this recipe's agents published automatically.
- **Recipes 7 / 7b / 8** — DNSid composed with MCP instead of A2A, for tool-calling rather than agent-messaging trust.

## Glossary

- **Agent card** — A2A's machine-readable capability document, served at `/.well-known/agent-card.json`. Declares interfaces, skills, and required extensions; this recipe's card is signed with a detached JWS.
- **Binding** — a signed assertion that a specific public key belongs to a specific domain. In DNSid, the binding is what `_dnsid.<domain>` resolution returns.
- **Covered components** — the parts of an HTTP request an RFC 9421 signature commits to (method, target URI, body digest, chosen headers). Anything outside the covered components is not protected by the signature.
- **Challenge** — a random nonce the registry issues at registration; the agent signs it to prove possession of the private key before the identity can be published.
- **C2SP tlog** — a transparency log in the C2SP checkpoint format: an append-only log of issuance events that makes silent key substitution detectable. Trust in specific logs comes from a policy file at an independently configured URL.
- **Ed25519** — a fast, modern public-key signature algorithm. Small keys (32 bytes), small signatures (64 bytes), no parameter choices to get wrong.
- **JWKS** — JSON Web Key Set. A JSON document listing one or more public keys with metadata (key id, algorithm, use). Served at `/.well-known/jwks.json` on the agent's domain.
- **JWS** — JSON Web Signature. A signed-payload format used here to sign the agent card, so the signature can travel with (or detached from) the JSON it protects.
- **Testnet** — the local, disposable DNSid deployment managed by `dnsid testnet up/down/reset`. Real DNS, real registry, real transparency log; nothing leaves your machine.
