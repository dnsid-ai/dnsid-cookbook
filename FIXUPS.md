# Cookbook fixups

The cookbook migration to the current `dnsid` CLI and SDKs is incomplete. This document records the gaps found by comparing this repository with the local checkouts at `~/dnsid`, `~/dnsid-py`, `~/dnsid-ts`, and `~/dnsid-go`.

## Current state

| Measure | Result |
|---|---:|
| Recipe directories | 9 |
| Recipes marked runnable | 5 |
| Runnable recipes using `dnsid testnet` | 5 (`01`, `06b`, `12`, `29`, `31`) |
| Recipes importing an SDK | 7 (`06b` and `29` Go; `07`, `07b`, `12`, `28`, and `31` Python) |
| Recipes using `dnsid-go` | 2 (`06b`, `29`) |
| Recipes using `dnsid-ts` | 0 |

Recipes 06b and 29 pin `dnsid-go` v0.33.1; Python recipes 07, 07b, 12, 28, 30, and 31 pin `dnsid-py` v0.19.1. The remaining recipes and examples still contain older conventions.

## Completed — Go SDK/testnet migrations

### Recipe 06b

Recipe 06b now uses `dnsid-go/httpsig` for signing and complete DNSid verification, provisions both identities through the CLI testnet, launches both processes under `dnsid testnet run`, and has a one-shot CI verification. Its removed `dnsid keygen` call, hand-written protocol package, public DNS dependency, and manual private-JWK conversion have been deleted.

### Recipe 29

Recipe 29 now uses `dnsid-go/oidc` for OIDC and DNSid subject verification, provisions its identities through the CLI testnet, launches processes under `dnsid testnet run`, and has a one-shot CI verification. Its fake issuer, fake CLI mode, and hand-written JWT verifier have been deleted.

## P1 — Correct protocol documentation

### Rewrite `WHAT_DNSID_IS.md` against the current SDK contract — completed

`WHAT_DNSID_IS.md` now shows the current testnet record shape, distinguishes the accountable-entity and operational keys, covers owner-signature and C2SP lifecycle verification, documents the independent `DNSID_LOG_POLICY_URL` trust rule, and links the CLI testnet and all three SDKs.

### Update the root README — completed

`README.md` now documents the required `make bootstrap`, `make run`, `make verify`, and `make clean` lifecycle, the CLI-owned DNSid testnet used by every locally runnable recipe, and the real vendor infrastructure required by deploy-only recipes.

## Completed — Recipe 30 DNSid proof and token integration

Recipe 30 now uses `dnsid-py`'s JOSE profile to sign canonical action payloads with the agent's operational key and to verify the caller's complete DNSid identity and current lifecycle state in the interceptor. Replay and freshness checks remain enforced. Server-side token minting uses `OIDCProfile`, operator commands default to `dnsid` on `PATH`, and the recipe remains honestly deploy-only.

## Completed — Use `dnsid-py` inside deploy-only Python applications

Recipes 07, 07b, and 28 now load their server-side identity with public SDK APIs and mint outbound tokens with `OIDCProfile` / `OIDCTokenExchangeOptions`. Their application paths no longer depend on a CLI executable or subprocess output format; Gateway `CUSTOM_JWT` remains the managed relying-party boundary.

## P2 — Add TypeScript SDK coverage

There is currently no TypeScript recipe despite `dnsid-ts` providing current Node helpers, OIDC, JOSE, RFC 9421, C2SP, and testnet-compatible A2A examples.

Prefer the smallest useful addition rather than a new speculative scenario:

- either make Recipe 12 cross-language, with one Python agent and one TypeScript agent; or
- implement the already-listed Recipe 6 HTTP middleware in TypeScript.

Use current public APIs from `@identity-digital/dnsid`, `@identity-digital/dnsid/node`, `@identity-digital/dnsid-http-signatures`, and `@identity-digital/dnsid-log-c2sp-tlog`. The recipe must use `dnsid testnet`, include a lockfile, and run in CI.

## Completed — Remove Python SDK private-API dependencies

Recipes 12 and 31 now pin `dnsid-py` commit `843a8f0` and use its public environment loader, inherited HTTP transport configuration, safe testnet-aware C2SP fetcher, and JWK/JWKS serialization. Private imports and attributes have been removed. Recipe 31 also deleted its cookbook-local `httpx.Auth` signer in favor of the SDK's signed async client. Both recipes pass their full testnet `make verify` checks.

## Completed — Align the testnet image with `~/dnsid`

The cookbook, recipe template, plans, and CI now use the CLI's authoritative `ghcr.io/identity-digital/dnsid-testnet-registry:main` image tag.

## Completed — Repair Recipe 28

Recipe 28 is consistently marked deploy-only, has one top-level application/config tree, and uses matching paths in its README, Makefile, AgentCore config, and architecture document. `make clean` now destroys only stacks from the recipe's CDK app and does not redeploy.

## P3 — Finish repository convention migration

### Make and README contracts

Several older README files do not follow `RECIPE_TEMPLATE.md` section-for-section. Normalize every shipped recipe against the template and use only supported statuses.

### Scaffold

`scripts/new-recipe.sh` is Python-specific and tells authors to copy substantial lifecycle code from recipes 12 and 31. Once the Python SDK exposes the required public loader, simplify the scaffold to consume it. Do not add multi-language scaffold machinery until a second recipe in that language needs it.

### CI

- Add the first TypeScript SDK recipe.
- Keep cloud-account recipes out of the hermetic matrix, but give each a local unit/package check.
- Remove private-internal SDK assumptions from CI comments when dependencies change.

On 2026-08-27, all four recipe jobs failed before verification because the newest `dnsid` release had no binary assets. The workflow now selects the newest release containing `dnsid_linux_amd64.tar.gz`. The upstream `dnsid` release workflow should still stop publishing assetless releases; until that is fixed, cookbook CI may exercise an older CLI than the latest source release.

### `examples/plumbing-store`

This example contains an 832-line mock-DNS/manual-JWT implementation and explicitly defers SDK usage. That is retired cookbook behavior.

Either:

1. migrate it to `dnsid-go` and the CLI testnet, then promote it to a proper recipe; or
2. delete it.

Do not preserve a second mock harness merely because its unit tests pass.

### Index

`INDEX.md` mixes shipped recipes with proposed recipe summaries while the root README says it lists every recipe. Clearly label unimplemented entries as proposals, or move them to `plans/`. Keep shipped recipe status synchronized with each recipe README.

## Validation performed during review

The following checks were run:

- `python3 scripts/test_scan_hardcoded_identities.py` — passed.
- `python3 scripts/scan-hardcoded-identities.py` — passed.
- Go tests for recipes 06b and 29 and `examples/plumbing-store` — passed.
- `make -C recipes/06b-go-http-stripe verify` — passed against `dnsid-go` v0.29.0 and the current CLI testnet.
- `make -C recipes/29-dnsid-message-board verify` — passed with real testnet OIDC tokens and `dnsid-go` subject verification.
- Python bytecode compilation for recipes 07, 07b, and 30 — passed.
- Shell syntax checks — passed.
- `make -C recipes/01-publish-jwks verify` — passed against the current local CLI and testnet.
- `make -C recipes/12-a2a-dnsid verify` — passed with `dnsid-py` commit `843a8f0` and no private SDK access.
- `make -C recipes/31-langgraph-dnsid-agent verify` — passed with the SDK-signed tool client and full caller-gated flow.

## Suggested delivery order

1. **TypeScript PR:** add one real `dnsid-ts` testnet flow.
2. **Cleanup PR:** simplify the scaffold and CI/index conventions, and remove or migrate plumbing-store.

Each functional PR should leave one runnable `make verify` check that fails when the SDK integration is removed or bypassed.
