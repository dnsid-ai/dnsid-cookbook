# Contributing to dnsid-cookbook

Recipes are the product here. A good recipe is runnable, honest about what it verifies, and cites
the spec or SDK behavior it relies on.

## Adding a recipe

1. `make new N=<number> SLUG=<slug>` — scaffolds `recipes/NN-slug/` from `RECIPE_TEMPLATE.md`.
2. Fill in the README. Runnable recipes must pass `make bootstrap`, `make run`, `make verify`, and
   `make clean` on a clean clone. Deploy-only recipes say so and document their platform steps.
3. Add the recipe to `INDEX.md` and to the `verify` matrix in `.github/workflows/verify-recipes.yml`
   in the same PR. A recipe whose verify never runs in CI silently rots.
4. Run `make scan-hardcoded-identities`. Recipes use local registry identities under `*.dev.dnsid.test`;
   never check in a real domain, AWS account ID, key, or token.

## Pull requests

- Branch off `main`; PRs require one approving review from a code owner and signed commits.
- Keep recipes self-contained; do not add shared frameworks or Docker DNS stacks — the `dnsid` CLI
  local registry is the only harness.
- Pin SDK versions in each recipe's manifest; Dependabot proposes bumps.

## Licensing of contributions

This project does not use a CLA or DCO (inbound = outbound). By contributing you agree that your sample code is licensed under the Apache License 2.0
(`LICENSE.txt`) and your documentation and recipe prose under CC BY 4.0 (`LICENSE-docs.txt`),
matching the rest of the repository. Do not copy code or text from sources under other licenses.

## Security

Recipes are examples, not production deployments. Still, if you find something in a recipe that
would lead a reader into an insecure setup, report it per `SECURITY.md` rather than in a public issue.
