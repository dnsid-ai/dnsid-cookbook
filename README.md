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

See [CONTRIBUTING.md](CONTRIBUTING.md). Runnable recipes must pass `make bootstrap` / `run` / `verify` / `clean`
on a clean clone and be in the CI verify matrix.

## Security & trust

Recipes are examples for the DNSid SDKs, not production deployments. Every runnable recipe targets the
local `dnsid` CLI testnet under `*.dev.dnsid.test`; nothing here contains real identities, keys, or
credentials. Report problems per [SECURITY.md](SECURITY.md). For what the SDKs themselves do on the
network and why software is not identity, see the "Security & trust" section in each SDK README
([go](https://github.com/dnsid-ai/dnsid-go), [ts](https://github.com/dnsid-ai/dnsid-ts), [py](https://github.com/dnsid-ai/dnsid-py)).

## License

Sample code (everything under `recipes/*/` and `examples/*/` that is not a Markdown file) is licensed
under the [Apache License 2.0](LICENSE.txt). Documentation and recipe prose (Markdown files) are
licensed under [CC BY 4.0](LICENSE-docs.txt). Code blocks embedded in Markdown are Apache-2.0.
