# Local integration tests

Run `npm run test:e2e` from this recipe’s root directory. Tests and their support code live in `test/e2e/`. These tests are separate from `npm test`, which runs the fast Worker tests. `npm run typecheck` checks both suites. Optional public-service checks run separately with `npm run test:live`; see [test commands](../README.md).

## Prerequisites

- Node.js 24 or later and dependencies installed with `npm ci`.
- Docker running and accessible to the current user.
- A `dnsid` CLI supporting `local up`, `local agent ensure`, and custom local ports.
- The DNSid Local registry image available locally or network access to pull it.

Set `DNSID_CLI` to a different CLI executable if needed. Set `DNSID_LOCAL_IMAGE` to a pinned registry image for reproducible CI runs; otherwise the CLI's default image is used. CI needs Docker and the DNSid CLI installed before invoking the command. No Cloudflare account or deployment is required.

## What the suite owns

The suite builds both Workers, then starts a separate DNSid Local environment in a newly created temporary directory with dynamically selected registry, DNS, and HTTPS ports. It issues three test identities and revokes only its own revoked-identity fixture. It never uses or resets the user's default local state directory or existing identities.

The Worker bundles run in Miniflare. A network adapter routes test DNS and HTTPS requests to the isolated services. The origin is a test-only Node HTTP server from `origin.ts`, started on a free loopback port, and DNSSEC is reported as unsigned by the local DNS adapter. This exercises real identity issuance, log evidence, status checks, request signatures, and replay protection; it does not test public DNSSEC, Cloudflare edge networking, or production load.

CoreDNS readiness is checked before requests are sent. Tests assert:

- Direct origin requests without its shared secret are denied.
- Cold and warm requests reach the origin with verified agent and accountable-entity headers.
- A fixed origin denial preserves its status, headers, and body.
- Revoked identities and unsigned requests never reach the origin.
- The signed method, path, query, and body reach the origin intact.
- Replayed requests are rejected before reaching the origin a second time.

Normal completion and assertion failures run teardown: dispose Miniflare, close network clients, stop the suite's registry, and remove its temporary state. If registry teardown fails, the suite fails and retains the state path for diagnosis. Force-killing the process can interrupt cleanup; remove only the test environment identified by that run, never reset the default registry.

## Test origin

The fixture checks the shared secret before echoing the method, path, body, and verified identity headers. Its `/denied` endpoint returns a fixed 403 to test response forwarding; it has no application access policy.

The cookbook Make targets keep a recipe-owned registry between runs: `make bootstrap` provisions it, `make run` exercises the flow, `make verify` also runs fast checks, and `make clean` removes it. The ignored `.recipe-state.json` records only the local paths and endpoints. Worker processes run under `dnsid local run` to receive the independently supplied policy URL.
