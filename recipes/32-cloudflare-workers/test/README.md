# Tests

| Command | Scope | Prerequisites |
| --- | --- | --- |
| `npm test` | Fast Worker tests: authentication, signing, verification, replay, configuration, malformed inputs, and forwarding | Installed dependencies |
| `npm run test:e2e` | Built Workers + isolated DNSid Local + test-only HTTP origin | Docker and DNSid CLI; [setup details](e2e/README.md) |
| `npm run typecheck` | Workers and tests | Installed dependencies |

The default run uses local fixtures. Keep protocol failure cases in the fast suite; use end-to-end tests for service integration.

`fixture.ts` supplies identity evidence; `signing-fixture.ts` supplies token hashing and a real egress signer with an injected destination.
