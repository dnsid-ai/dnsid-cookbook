# DNSid Cookbook

Recipes that teach DNSid — DNS-anchored cryptographic identity for agents and
services — by building small, runnable systems. The audience is a reader who has
never seen DNSid before landing on a recipe page.

## One harness: the DNSid testnet

This repo has exactly **one** recipe harness: the real DNSid testnet, driven by the
`dnsid` CLI (from the `dnsid-ai/dnsid` repo). Do not build or propose recipes
on CoreDNS zone files, docker-compose DNS services, or mock registries — that earlier
convention is retired. If you find template text, scaffold output, or a recipe still
describing it, that is migration debt, not a pattern to copy.

The harness contract every runnable recipe follows:

- `dnsid testnet up` / `down` / `reset --hard` own the testnet lifecycle.
- Identities are provisioned with
  `dnsid testnet agent ensure <name> --upstream <url> -- dnsid log issue --domain <fqdn>`
  (idempotent; safe to re-run).
- Recipe processes launch under `dnsid testnet run <name> -- <cmd>`, which injects the
  full `DNSID_*` environment: DNS routing (`DNSID_DNS_SERVER`), TLS trust
  (`DNSID_CA_BUNDLE`), the registry credential (`DNSID_API_KEY`), the identity
  directory (`DNSID_CONFIG_DIR`), and the independently trusted C2SP policy location
  (`DNSID_LOG_POLICY_URL`).
- **Policy trust rule (normative):** the C2SP policy URL comes only from
  `DNSID_LOG_POLICY_URL`. Never derive it from `DNSID_LOG_REF`, the log prefix, or any
  log-provided data.
- Testnet image: `ghcr.io/identity-digital/dnsid-testnet-registry:main`
  (anonymously pullable; override with `DNSID_TESTNET_IMAGE`).
- Readers inspect live records with `dig @$DNSID_DNS_SERVER _dnsid.<domain> TXT` and
  `curl` against `/.well-known/jwks.json` — teach against the real testnet, not
  hand-written fixtures.

## Recipe conventions

- **Structure is non-negotiable.** Every recipe README follows `RECIPE_TEMPLATE.md`,
  section for section. Write progressively: define every term of art in one plain
  clause on first use; assume the reader has read no other page in this repo.
- **Make contract:** `make bootstrap` (testnet up + identities), `make run`,
  `make verify` (one-shot, asserts expected transcript, nonzero on failure),
  `make clean` (testnet down). "Runnable means runnable": don't merge until these pass
  on a clean clone.
- **Code lives in `src/`**, not only in README fences. The README quotes from source
  files so the code compiles and the tutorial can't silently drift.
- **Domains:** use `.test` names (typically `*.dev.dnsid.test`), never `.local`.
  `python3 scripts/scan-hardcoded-identities.py` must pass.
- **TXT shape:** one semicolon-separated `_dnsid` value with `v` first, `ku=` for the
  JWKS endpoint, `su=` for status. Never emit the legacy space-separated shape.
- **Python recipes:** Python 3.11+, managed with `uv`; pin dependencies in the
  recipe's own `pyproject.toml` and record the versions actually tested against.
- **Honest scope:** if a recipe needs a vendor account, mark it deploy-only up top. If
  the affirmative "Why this matters" case is hard to write, reconsider the recipe.
- **`INDEX.md` is part of the change.** Adding or renumbering a recipe updates its
  entry and any standards-map rows in the same PR.

## Security posture in agent recipes

An LLM is never in the trust path. It may choose tool arguments; identity,
verification, signing, and tool exposure are code. Verified caller identity travels in
out-of-band config (e.g. LangGraph `config["configurable"]`), never in model-writable
state, and nothing inherits trust across a resumed session or checkpoint — every
inbound request is re-verified.

## Plans

`plans/` holds planning artifacts for future recipes. They record intent at the time
of writing and do not override the template, this file, or shipped recipe code —
verify against the repo before treating a plan's claims as current.
