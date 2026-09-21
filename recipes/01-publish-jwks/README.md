# Recipe 1 — Publish `_dnsid` + JWKS for a domain

> Provision a domain's cryptographic identity and inspect every artifact it publishes: the `_dnsid` DNS record, the JWKS it points at, and the live status endpoint — the three things any verifier resolves on first contact.

**Spec version:** `dnsid-draft-01`
**Status:** runnable
**Standards used:** RFC 7517 (JWKS), RFC 8037 (Ed25519 in JOSE), RFC 8615 (Well-known URIs)
**Estimated time:** ~10 minutes

---

## What you'll build

A published DNSid identity for `publish.dev.dnsid.test` on a local DNSid registry, with your own process serving its public keys. One `make bootstrap` runs the whole provisioning lifecycle — keypair generation, registration, a signed challenge, publication to DNS, and a countersigned transparency-log entry. Then you take it apart by hand: `dig` the `_dnsid` TXT record and read every tag, `curl` the JWKS the record points at, watch that the key served over HTTPS is byte-for-byte the keypair on your disk, and hit the live status endpoint. At the end, any DNSid verifier can authenticate messages signed by this domain — and you'll know exactly which three lookups make that possible.

## Why this matters

Every other recipe in this cookbook depends on a published identity; this is the one that creates it and shows you its anatomy. DNSid's whole trust model is: a domain publishes a small DNS record pointing at its public keys, and anyone can verify a signature from that domain with nothing but DNS and HTTPS — no certificate authority, no pre-shared secret, no partner onboarding. After this recipe: your domain has a cryptographic identity any counterparty can verify on first contact, you can rotate the key without coordinating with consumers, and revocation propagates through DNS instead of through redeploys at every consumer.

## Prerequisites

- Docker 24+ (running)
- `make`
- The `dnsid` CLI — `brew install dnsid-ai/tap/dnsid`, or download a binary per the [installation docs](https://docs.dnsid.ai/cli-installation) and put it on `PATH`
- Python 3.9+ (`python3` — standard library only, no packages to install)
- `dig` and `curl` (preinstalled on macOS and most Linux; `dnsutils`/`bind-utils` package otherwise)
- A clone of this repo

## Concepts

- **DNSid binding** — a record in DNS that says "this domain owns this public key." A verifier resolves `_dnsid.<domain>` (a DNS TXT record) to find where the key lives, then follows the record's `ku=` tag to fetch and verify it. No CA involved — the trust signal is domain ownership.
- **JWKS** — JSON Web Key Set ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)): a JSON document listing one or more public keys. DNSid serves this at `/.well-known/jwks.json` on the identity's domain. Each key has a `kid` (key id) that signed messages reference so verifiers select the right key.
- **Ed25519** — the signature algorithm DNSid uses by default ([RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037)). Small keys (32 bytes), small signatures (64 bytes), fast to verify, no algorithm parameters to misconfigure.
- **The DNSid local registry** — a disposable, fully local DNSid deployment (DNS server, registry, transparency log, TLS proxy) run by the `dnsid` CLI in Docker. It behaves like the real system — the record you'll dig was published through a real registration lifecycle seconds earlier — so everything transfers, and nothing leaves your machine.
- **Transparency log** — an append-only, publicly auditable log of identity issuance events. Publication submits a countersigned ISSUANCE entry, which is what makes a quietly swapped key detectable later.

## Running system

`dnsid local up` manages its own containers — the recipe owns no compose file. What's running when the recipe is up:

| Process | Where | Role |
|---|---|---|
| DNS server | local registry container, `127.0.0.1:7753` | Serves the live `_dnsid.publish.dev.dnsid.test` TXT record you'll dig |
| Registry + transparency log | local registry container, `127.0.0.1:7755` | Registration, challenge verification, publication, C2SP log, live status |
| TLS proxy | local registry container, `127.0.0.1:443` | Terminates `https://*.dev.dnsid.test` with a local CA and routes to your upstream |
| JWKS server (this recipe) | host process, `:3201` | `src/serve.py` — answers the record's `ku=` URL with the public key |

## Step 1 — Provision and publish the identity

```bash
make bootstrap
```

Two idempotent commands ([`Makefile`](Makefile)): `dnsid local up` starts the containers, and `dnsid local agent ensure publish ... -- dnsid log issue --domain publish.dev.dnsid.test` does everything an identity needs to exist: it generates an Ed25519 keypair (kept in a local identity directory — the private key never goes anywhere), registers the domain with the registry, answers the registry's challenge by signing a nonce (proving key possession — anyone can *claim* a domain name), publishes the `_dnsid` record to DNS, and submits the countersigned ISSUANCE entry to the transparency log.

That's the entire lifecycle the rest of this recipe inspects. Nothing below creates anything — it's all reading back what this step published.

## Step 2 — Read the record

The local registry's DNS server is a real DNS server on `127.0.0.1:7753`, so the record is one `dig` away:

```bash
dig @127.0.0.1 -p 7753 _dnsid.publish.dev.dnsid.test TXT +short
```

```
"v=dnsid-draft-01;ek=https://dnsid.dnsid.test/.well-known/dnsid-ek.json;gi=dnsid.test;ku=https://publish.dev.dnsid.test/.well-known/jwks.json;lr=c2sp-tlog:testnet:https://registry.dev.dnsid.test#ag-...;sg=...;su=https://registry.dev.dnsid.test/v1/status/publish.dev.dnsid.test"
```

One semicolon-separated value — this is the identity's entire public anchor. Tag by tag:

| Tag | Meaning |
|---|---|
| `v=` | Spec version, always first. A verifier that doesn't recognize it stops here. |
| `ku=` | Key URL — where the domain's JWKS lives. The tag a verifier follows to fetch keys. |
| `su=` | Status URL — live standing (ACTIVE, revoked, …). Checked per verification, so revocation takes effect without touching DNS consumers. |
| `lr=` | Log reference — which transparency log carries this identity's ISSUANCE entry. |
| `sg=` | A signature over the record itself, so tampering with any tag is detectable. |
| `gi=` | Governance id — the namespace operator this identity is provisioned under. |
| `ek=` | The governance operator's endorsement key location. |

Everything a verifier needs, in one DNS answer.

## Step 3 — Serve the keys

The record's `ku=` points at `https://publish.dev.dnsid.test/.well-known/jwks.json`, and answering that URL is *your* job — the domain owner hosts its own keys. [`src/serve.py`](src/serve.py) is the smallest honest version: a standard-library HTTP server that reads the provisioned public key and serves it as a JWKS:

```python
def load_jwks() -> dict:
    config_dir = os.environ.get("DNSID_CONFIG_DIR", "").strip()
    ...
    public_jwk = json.loads((Path(config_dir) / "public.jwk").read_text())
    return {"keys": [public_jwk]}
```

It runs under `dnsid local run publish -- ...`, which injects `DNSID_CONFIG_DIR` (the identity directory from step 1). Serving any other key here would break verification — the record's `sg=` signature and the challenge from step 1 bind this domain to exactly this keypair. The local registry's TLS proxy terminates `https://publish.dev.dnsid.test` and forwards to this server's port, exactly the role your web server or CDN plays in production.

Start it (foreground; leave it running and inspect from a second terminal):

```bash
make run
```

## Step 4 — Follow the record like a verifier

With the server up, do what any verifier does on first contact: resolve the domain with the local registry's DNS, then fetch the `ku=` URL over TLS (the local registry's CA bundle plays the role of the public web PKI):

```bash
curl --cacert ~/.dnsid-local/certs/root-ca.pem \
     --resolve publish.dev.dnsid.test:443:127.0.0.1 \
     https://publish.dev.dnsid.test/.well-known/jwks.json
```

```json
{"keys": [{"alg": "EdDSA", "crv": "Ed25519", "kid": "L6rgyZbQpknTUv...", "kty": "OKP", "use": "sig", "x": "9khC_JnqP..."}]}
```

`kty: "OKP"` is the JOSE key type for octet key pairs (which Ed25519 uses); `x` is the base64url-encoded 32-byte public key; `kid` is the key id signed messages will reference. Compare that `kid` with `public.jwk` in your identity directory — same key, which is the point: DNS told a stranger where to look, and what they found is provably yours.

The record's `su=` tag completes the picture — live status from the registry:

```bash
curl --cacert ~/.dnsid-local/certs/root-ca.pem \
     --resolve registry.dev.dnsid.test:443:127.0.0.1 \
     https://registry.dev.dnsid.test/v1/status/publish.dev.dnsid.test
```

```json
{"state": "ACTIVE", "lastTransitionAt": "2026-..."}
```

## Run it

```bash
make run
```

Starts the JWKS server in the foreground under the local registry (Ctrl-C to stop):

```
serving JWKS (kid L6rgyZbQpknTUv-yOwqoXTEhOIhpUjeJaKHw5aQagC4) on :3201
```

While it runs, steps 2 and 4's `dig` and `curl` commands work from any other terminal.

## Verify

```bash
make verify
```

One shot: starts the JWKS server, then performs the verifier's walk from [`verify/verify.sh`](verify/verify.sh) — resolve the TXT binding, check the `v=` tag, follow `ku=` over HTTPS, match the served `kid` against the local keypair, follow `su=` for live status. Exits nonzero on any miss.

Expected output (abridged):

```
--- TXT record ---
v=dnsid-draft-01;...;ku=https://publish.dev.dnsid.test/.well-known/jwks.json;...

--- JWKS (from https://publish.dev.dnsid.test/.well-known/jwks.json) ---
{
    "keys": [ { "kty": "OKP", "crv": "Ed25519", "kid": "L6rgyZ...", ... } ]
}

✓ binding resolved
✓ JWKS reachable at https://publish.dev.dnsid.test/.well-known/jwks.json
✓ kid matches local keypair: L6rgyZbQpknTUv-yOwqoXTEhOIhpUjeJaKHw5aQagC4
✓ status: ACTIVE
```

`make clean` tears the local registry down. `dnsid local reset --hard` also wipes all identity state — re-running `make verify` after that provisions a brand-new keypair and record, worth watching once.

## What goes wrong

**Stop the JWKS server and the identity goes dark.** Kill `make run` and re-try step 4's first `curl`: the record still resolves in DNS, but the `ku=` fetch fails — and with it, every verification of this domain. The record is a pointer; *you* keep the keys reachable. In production this means your JWKS endpoint deserves the same availability as the service it authenticates.

**`.test` domains don't resolve in normal DNS — by design.** `dig _dnsid.publish.dev.dnsid.test TXT` without `@127.0.0.1 -p 7753` returns nothing: RFC 2606 reserves `.test` so it can never resolve publicly, which is exactly why the local registry uses it. Real deployments publish under real domains and step 2 becomes a plain `dig`.

## What to try next

- **Recipe 12 — A2A protocol + DNSid** — two agents use identities exactly like this one to trust each other on first contact and exchange signed messages.
- **Recipe 31 — LangGraph agent with a DNSid identity** — an agent framework's tool calls made attributable to a domain published this same way.
- **Watch the transparency log** — the local registry serves a stream explorer at `http://127.0.0.1:7755/streams/publish.dev.dnsid.test` showing this identity's countersigned ISSUANCE entry.
- **Provision a second identity** — `dnsid local agent ensure second --upstream http://localhost:3202 -- dnsid log issue --domain second.dev.dnsid.test`, then dig its record. Per-agent subdomains with independent keys and revocation scope is the pattern recipes build on.

## Glossary

- **Binding** — a signed assertion that a specific public key belongs to a specific domain. In DNSid, the binding is what `_dnsid.<domain>` resolution returns.
- **Challenge** — a random nonce the registry issues at registration; signing it proves possession of the private key before the identity can be published.
- **Identity directory** — the local directory (`DNSID_CONFIG_DIR`) holding the keypair and config the CLI provisioned. The private key lives here and only here.
- **kid** — key id. A string that uniquely identifies one key within a JWKS. Signed messages name the `kid` so a verifier that fetches a multi-key JWKS knows which key applies.
- **ku / su** — the record's key URL and status URL tags: where the keys live, and where live standing is checked.
- **Local registry** — the disposable, fully local DNSid deployment managed by `dnsid local up/down/reset`. Real DNS, real registry, real transparency log; nothing leaves your machine.
