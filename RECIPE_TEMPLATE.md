# Recipe README Template

Every recipe in `recipes/NN-slug/` ships a `README.md` following this structure. The structure is non-negotiable — readers should be able to land on any recipe and find the same sections in the same order. Substance is yours; layout is shared.

**Write progressively.** Assume the reader has not read any other recipe and may be encountering DNSid for the first time on this page. Introduce concepts before using them. Define jargon (`JWKS`, `binding`, `covered components`, `Ed25519`, `_dnsid` TXT) inline on first use, in one short clause — not by linking away mid-step. A reader should be able to land on this page cold and finish without opening five other tabs to figure out what a word means. If the recipe introduces enough new terms that inline definitions would clutter the prose, add a **Glossary** section (see structure below) and reference it.

Copy this file to `recipes/NN-slug/README.md` and fill in. Delete the commentary in italics; keep the section headers.

---

# Recipe NN — Title

> *One-sentence tagline. Same line that appears in `INDEX.md`.*

**Spec version:** `dnsid-draft-NN`
**Status:** runnable | deploy-only
**Standards used:** RFC 9421, RFC 7517, …
**Estimated time:** ~N minutes

---

## What you'll build

*One paragraph. What the reader will have at the end. Be concrete: "an Express server that rejects unsigned requests and accepts requests signed with a `_dnsid`-published Ed25519 key" beats "a server with DNSid auth."*

## Why this matters

*Make the affirmative case for DNSid in this specific scenario, in two to four sentences. Name what DNSid composes with (the protocol / standard) and what it replaces (the credential or trust mechanism). Then — most importantly — say what changes about the **result**. Not "DNSid slots in here," but "after this recipe, the system can do X that it couldn't before, or stops being exposed to Y."*

*Example: "RFC 9421 already standardizes how to sign HTTP requests; what's missing is a public, agent-scoped way to publish the signing key. DNSid fills that with a TXT record + JWKS at the agent's domain. After this recipe: any service can verify any other service's identity on first contact without a pre-shared secret, partner onboarding meeting, or CA dependency. Revocation propagates through DNS, not through redeploys at every consumer."*

*If the affirmative case is hard to write, the recipe is probably plumbing nobody asked for. Reconsider whether to ship it.*

## Prerequisites

*Bullet list. Versions matter — pin them.*

- Docker 24+ (running)
- `make`
- The `dnsid` CLI — `brew install dnsid-ai/tap/dnsid`, or download a binary per the [installation docs](https://docs.dnsid.ai/cli-installation) and put it on `PATH`
- *The language toolchain — for Python recipes, [`uv`](https://docs.astral.sh/uv/) (which installs Python 3.11+ itself)*
- A clone of this repo
- *Anything else the reader must have installed before step 1*

For deploy-only recipes, also list the platform account / CLI tools required (e.g. `wrangler`, `fastly`, `aws`).

## Concepts

*This is where the reader gets the mental model they need before the steps make sense. Keep it short, but don't skip it: assume zero prior knowledge of DNSid and partial knowledge of the standards involved.*

*For each concept the recipe uses, give a one-to-three-sentence plain-language definition before naming it formally. Tell the reader **why** the concept is in this recipe, not the full spec. Link out to the standard for depth.*

- **DNSid binding** — a small record published in DNS that says "this domain owns this public key." A verifier resolves `_dnsid.<domain>` (a TXT record) to find the binding, then follows the record's `ku=` tag to fetch the public keys at `/.well-known/jwks.json`. This is what lets us trust a signature without a CA.
- **JWKS** — JSON Web Key Set, a list of public keys in a standard JSON format ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)). DNSid hosts these at the `/.well-known/jwks.json` URL on the agent's domain.
- **RFC 9421** — IETF standard for signing HTTP requests with detached signatures in headers. We use covered components `@method`, `@target-uri`, `content-digest`. The covered components are the parts of the request the signature commits to.
- **The DNSid local registry** — a disposable, fully local DNSid deployment (DNS server, registry, transparency log, TLS proxy) that the `dnsid` CLI runs in Docker via `dnsid local`. Every runnable recipe uses it as the harness.
- *…one bullet per concept the recipe touches. If you find yourself with more than five, consider whether the recipe is doing too much, or move some into the Glossary.*

If a concept is non-obvious or contested, say so honestly. Don't fake confidence.

## Running system

*What's up when the recipe runs. The local registry's containers are CLI-managed — the recipe owns no compose file — so this table describes the running system, not a Docker stack the reader maintains. One row per process: local registry services first, then the recipe's own processes.*

| Process | Where | Role |
|---|---|---|
| DNS server | local registry container, `127.0.0.1:7753` | Serves live `_dnsid.*.dev.dnsid.test` TXT records |
| Registry + transparency log | local registry container, `127.0.0.1:7755` | Registration, challenge verification, publication, C2SP log |
| TLS proxy | local registry container | Terminates `https://*.dev.dnsid.test` with a local CA, routes to agent upstreams |
| *your-process* | host process, `:PORT` | *what it does* |

## Step 1 — *Short imperative title*

*Narrate what the reader is doing and why. Then show the code. Either:*
- *Inline code block the reader types (small things), or*
- *Reference to `src/path/file.py` with the relevant lines quoted.*

```python
# example
```

*Explain anything non-obvious in the snippet. Don't paraphrase the code; explain decisions the code can't.*

## Step 2 — *…*

*Same pattern. Each step should be runnable in isolation if possible — the reader should be able to stop after step 2 and have something working, even if partial.*

## Step N — *…*

## Run it

```bash
make run
```

*What ports come up. What the reader should see in the logs.*

## Verify

*What success looks like. Concrete commands and expected output.*

```bash
make verify
```

Expected output:

```
✓ binding resolved
✓ signature verified
✓ status: verified
```

For deploy-only recipes: how to confirm the recipe is working in the vendor's edge / cloud. Console screenshot paths, log queries, CLI commands.

## What to try next

*Links to related recipes. Concrete next experiments the reader can run with the same setup.*

- Recipe X — *what it adds*
- Recipe Y — *what it adds*
- `dnsid local reset --hard && make verify` — watch the full first-run lifecycle instead of the idempotent path.

## Glossary

*Optional. Include only if the recipe introduces enough terms that inline definitions would clutter the steps. Alphabetical order. Each entry one to three sentences in plain language; standards links allowed but the entry must stand on its own without clicking through.*

- **Binding** — a signed assertion that a specific public key belongs to a specific domain. In DNSid, the binding is what `_dnsid.<domain>` resolution returns.
- **Covered components** — the parts of an HTTP request that an RFC 9421 signature commits to (e.g. method, target URI, body digest). Anything not in the covered components is not protected by the signature.
- **Ed25519** — a fast, modern public-key signature algorithm. Small keys (32 bytes), small signatures (64 bytes), no parameter choices to get wrong.
- **JWKS** — JSON Web Key Set. A JSON document listing one or more public keys with metadata (key id, algorithm, use). DNSid publishes the JWKS at `/.well-known/jwks.json` on the agent's domain.
- **JWS** — JSON Web Signature. A signed-payload format used when the data being signed is JSON or when a signature needs to travel separately from a request.
- **Verifier** — code on the receiving side that decides whether to trust an incoming signed message. Returns one of `verified | unregistered | revoked | unverifiable`.

*Add or remove entries to match the recipe. Don't dump the whole DNSid vocabulary into every recipe.*

---

## Notes for recipe authors

*Delete this section before committing. It's guidance for you, not the reader.*

- **One harness: the DNSid local registry.** Every runnable recipe runs against the real DNSid local registry (`dnsid local`), driven by the `dnsid` CLI (from `dnsid-ai/dnsid`). `dnsid testnet` is the deprecated former name of the same command — don't write it. Do not add CoreDNS zone files, docker-compose DNS services, or mock registries — that earlier convention is retired. The local registry pulls `ghcr.io/identity-digital/dnsid-local-registry:main` (anonymously pullable; override with `DNSID_LOCAL_IMAGE`).

- **The harness contract.** Follow it exactly — recipe 12 (`recipes/12-a2a-dnsid/`) is the reference implementation:
  1. `dnsid local up` / `down` / `reset --hard` own the local registry lifecycle. Recipes own no DNS or registry containers.
  2. Identities are provisioned idempotently with `dnsid local agent ensure <name> --upstream <url> -- dnsid log issue --domain <fqdn>`.
  3. Recipe processes launch under `dnsid local run <name> -- <cmd>`, which injects the full `DNSID_*` environment: DNS routing (`DNSID_DNS_SERVER`), TLS trust (`DNSID_CA_BUNDLE`), the registry credential (`DNSID_API_KEY`), the identity directory (`DNSID_CONFIG_DIR`), and the independently trusted policy location (`DNSID_LOG_POLICY_URL`). Application code reads config from that environment; it never hardcodes local registry endpoints.

- **Policy trust rule (normative).** The C2SP policy URL comes only from `DNSID_LOG_POLICY_URL`. Never derive it from `DNSID_LOG_REF`, the log prefix, or any log-provided data — a log that can name its own trust policy can vouch for itself.

- **Make contract.** Four targets, no exceptions: `make bootstrap` (local registry up + identities ensured; idempotent), `make run` (the flow, human-watchable), `make verify` (one-shot; asserts the expected transcript; exits nonzero on failure), `make clean` (local registry down). `verify` may depend on `bootstrap` — provisioning is idempotent. On failure, the verify script should dump the local registry container logs (`docker ps --filter name=dnsid-local` + `docker logs`); a red CI job without them is undebuggable.

- **Teach against the live local registry.** Readers inspect real state, not fixtures: `dig @127.0.0.1 -p 7753 _dnsid.<domain> TXT +short` for records, `curl` for `/.well-known/jwks.json` and status. Quote real transcripts in the README.

- **Scaffolding.** `make new N=<number> SLUG=<slug>` scaffolds the local-registry layout: Makefile (`bootstrap`/`run`/`verify`/`clean`), `pyproject.toml`, `src/`, `verify/verify.sh`, and a README skeleton. Recipes 12 and 31 are the reference implementations to crib from.

- **Use `.test`, not `.local`.** Local registry identities live under `*.dev.dnsid.test`. `.local` is reserved for Multicast DNS (RFC 6762); RFC 2606 reserves `.test` for testing, and it will never resolve in public DNS. `python3 scripts/scan-hardcoded-identities.py` must pass.
- **Use the canonical TXT shape.** One semicolon-separated `_dnsid` TXT value with `v` first, `ku=` for the JWKS endpoint, and `su=` for status. Do not emit the legacy space-separated `kid` / `jwks` / `registry` shape. (The local registry emits the canonical shape; this rule mainly constrains prose and hand-written examples.)

- **Python recipes:** Python 3.11+, managed with `uv`. Pin dependencies in the recipe's own `pyproject.toml` and record the versions actually tested against. Launch with `uv run python -u …` — the `-u` matters, because verify scripts grep the process output and Python buffers stdout when piped.

- **Progressive structure is the rule.** A reader who has never heard of DNSid should be able to land on this recipe and finish it. Don't assume they've read recipe 1, the spec draft, or any other page in this repo. If the recipe depends on state from another recipe, give the reader the shortest path to that prerequisite — either a one-paragraph inline summary plus a link, or a working `make bootstrap` that does it for them. Never just say "see recipe 1" and move on.
- **Define jargon on first use.** Every standard, every term-of-art, every protocol acronym gets a one-clause plain-language gloss the first time it appears in the prose. Don't make readers chase footnotes to get past sentence two. If the recipe introduces more than a handful of terms, lean on the Glossary section instead of bloating every paragraph.
- **Runnable means runnable.** Don't merge until `make bootstrap && make run && make verify` succeeds on a clean clone, and add the recipe to the CI matrix in `.github/workflows/verify-recipes.yml` in the same PR.
- **Spec version.** Pin the spec draft you tested against. Breaking spec changes get a recipe-update PR, not silent rot.
- **Code in `src/`.** Don't put real code only in README fences. Code goes in `src/`; README quotes from it. That way the source compiles and the README stays a tutorial.
- **Honest scope.** If the recipe needs a vendor account, mark it deploy-only at the top and adjust Verify accordingly. Don't pretend a CloudFront Function runs in Docker.
- **Anti-patterns are welcome.** A "what goes wrong" subsection is more useful than glossing over the rough edges.
- **`INDEX.md` is part of the change.** Adding or renumbering a recipe updates its entry and any standards-map rows in the same PR.
