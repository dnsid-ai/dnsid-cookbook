# Draft issues (not filed)

These were found while prototyping `dnsid-cloudflare` (2026-10-29). Issues 1–5 are for `dnsid-ts` (v0.34.0). Issue 6 is for the `dnsid` CLI and DNSid Local (`2026.10.02-8e8404f`).

The prototype works around every item, so none of them blocks it. Each lists the workaround it would remove.

---

## 1. Log verification loads Node networking even with a custom fetcher

**Repo:** dnsid-ts · **Package:** `@dnsid-ai/log-c2sp-tlog`

**Problem:** `stream-source.ts` statically imports `@dnsid-ai/transport`, which loads `undici` and crashes in Cloudflare Workers—even with `nodejs_compat` and a custom `resourceFetcher`. The dependency loads before the application can supply its fetcher.

**Reproduce:** Import and use the log-registry factory in a Worker without our transport alias. Loading fails in `undici/lib/mock/pending-interceptors-formatter.js`:

```text
TypeError: Cannot destructure property 'Console' of 'require(...)' as it is undefined
```

**Proposed fix:** Load the Node transport only when the default downloader is needed, or move it to a `/node` entry point. Custom-fetcher users should not load Node networking dependencies.

**Current workaround:** Alias the transport to a shim that throws if called, and supply a Workers-based fetcher. The fix would remove `src/shims/transport.ts` and the Wrangler/Vitest aliases.

## 2. Request verification does not identify the accepted signature

**Repo:** dnsid-ts · **Package:** `@dnsid-ai/http-signatures`

**Problem:** `verifySignedHttpRequest` returns the verified identity, but not the signature parameters it accepted. HTTP requests can carry multiple signatures, each with its own nonce and creation time—for example, during a key transition.

Replay protection must record the accepted signature's nonce. The verified domain alone does not identify that signature; choosing the wrong entry can undermine replay protection.

**Proposed fix:** Return the accepted parameters alongside the identity, for example `{ verified: VerifiedDomain, signature: SignatureParams }`. Alternatively, invoke a nonce-claim callback with those parameters after verification succeeds.

**Current workaround:** Ingress accepts exactly one signature and records its nonce only after verification. Returning the accepted parameters would let us support multiple signatures without guessing which nonce to record.

## 3. JSON fetchers must provide certificate details that Workers cannot expose

### Reviewed

**Repo:** dnsid-ts · **Package:** `@dnsid-ai/protocol`

**Problem:** `JsonFetcher` must return TLS certificate details, including an expiration date used to limit identity-evidence caching. Workers validates HTTPS certificates but does not expose those details, so it cannot supply the actual expiry.

**Proposed fix:** Allow fetchers to supply an explicit evidence-cache lifetime instead of certificate metadata. Keep real peer-certificate requirements for mutual TLS (`fl=mtls`) separate.

**Current workaround:** `src/shared/fetch-json.ts` returns synthetic certificate metadata with a one-hour expiry. That is a cache deadline, not the certificate's actual expiration, and could permit caching beyond it. An explicit cache-lifetime option would remove this workaround.

## 4. Request signing buffers the body without a size limit

**Repo:** dnsid-ts · **Package:** `@dnsid-ai/http-signatures`

**Problem:** When `responseSignature` is unset, `signRequest` reads the entire body with `req.clone().arrayBuffer()`. A large or unbounded streaming body can exhaust memory. Verification and response-signing mode already use a bounded reader.

**Proposed fix:** Use `readBoundedBody` with the existing eight-megabyte limit (`MAX_HTTP_CONTENT_BYTES`) in the request-only signing path too. Reject oversized bodies before buffering them in full.

**Current workaround:** Egress reads the body with an eight-megabyte cap before passing it to the SDK. Enforcing the limit inside the signer would remove this extra pre-read.

## 5. (Optional) Use Web Crypto for log verification

**Repo:** dnsid-ts · **Package:** `@dnsid-ai/log-c2sp-tlog`

**Problem:** Log verification uses `node:crypto` for hashing and signature checks. It works in Workers with `nodejs_compat`, but limits portability to runtimes without Node APIs.

**Proposed change:** Replace those operations with Web Crypto. Its asynchronous API would also require changes to the surrounding code.

**Current workaround:** Enable Workers' Node compatibility mode. This change is optional for our integration.

---

## 6. Local agent registration does not complete the issuance promised by its help text

**Repo:** dnsid (CLI / Local)

**Problem:** `dnsid local agent add --help` says the command issues the identity and publishes its `_dnsid` record. In our test, the agent remained `CONFIGURED`, with only an A record. The TXT record appeared after a separate `dnsid log issue` step.

**Proposed fix:** Either complete issuance during `add`, or update the help text to explain the required issuance step.

**Current workaround:** Explicitly issue each registered local agent through `dnsid local agent ensure <fqdn> -- dnsid log issue --domain <fqdn>`. Our end-to-end suite performs this step during setup.
