# Tests

| Command | Scope | Prerequisites |
| --- | --- | --- |
| `npm test` | Fast Worker tests: authentication, signing, verification, replay, configuration, malformed inputs, and forwarding | Installed dependencies |
| `npm run test:e2e` | Built Workers + isolated DNSid Local + test-only HTTP origin | Docker and DNSid CLI; [setup details](e2e/README.md) |
| `npm run test:live` | Optional checks against public DNS, npm, and the DNSid development log | Internet access and available external services |
| `npm run typecheck` | Workers and tests | Installed dependencies |

The default run uses local fixtures and does not include live-service tests. Keep protocol failure cases in the fast suite; use end-to-end tests for service integration.

`fixture.ts` supplies identity evidence; `signing-fixture.ts` supplies token hashing and a real egress signer with an injected destination. `xreq.worker.ts` is a manual cross-request cancellation experiment, separate from the automated suites.

Live checks are optional diagnostics, not a replacement for deployed Cloudflare validation. Their external endpoints and trust keys may need updating independently of the integration code.

Optional live log checks require `DNSID_LOG_POLICY_URL`, `DNSID_CHECKPOINT_URL`, and `DNSID_CHECKPOINT_KEY` in your shell. These are explicitly trusted inputs, not learned from the log. The default suite and cookbook CI do not run live checks.
