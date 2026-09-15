# dnsid-cookbook

Practical recipes for building with DNSid — DNS-anchored identity for agents and services. New to DNSid? See [WHAT_DNSID_IS.md](WHAT_DNSID_IS.md).

## Browse

[INDEX.md](INDEX.md) lists every recipe, organized by where DNSid shows up: **Publish → Verify → Federate → Operate**, plus a Standards map and Anti-recipes.

## Recipe structure

Every recipe lives in `recipes/NN-slug/` with a `README.md` that follows [RECIPE_TEMPLATE.md](RECIPE_TEMPLATE.md). Every locally runnable recipe uses the [`dnsid` CLI testnet](https://github.com/dnsid-ai/dnsid#local-testnet) as its harness; the CLI owns the testnet containers, DNS, registry, transparency log, and TLS lifecycle. Recipes do not ship their own Docker Compose DNS stacks.

```bash
cd recipes/NN-slug/
make bootstrap  # start the testnet and provision identities
make run        # launch the recipe processes
make verify     # assert the expected result; exit nonzero on failure
make clean      # stop the testnet
```

Deploy-only recipes require real vendor infrastructure, such as CloudFront, Fastly Compute, or Akamai EdgeWorkers, and document their platform-specific deploy-and-verify steps instead of claiming local runnability.

## Contributing

1. Fork.
2. Copy `RECIPE_TEMPLATE.md` into `recipes/NN-slug/README.md` and fill in.
3. Add the entry to [INDEX.md](INDEX.md) under the right section.
4. Open a PR.

Runnable recipes must pass the `make bootstrap`, `make run`, `make verify`, and `make clean` lifecycle on a clean clone before merge.
Run `make scan-hardcoded-identities` before opening a PR to catch checked-in AWS account IDs and concrete DNSid identities.
