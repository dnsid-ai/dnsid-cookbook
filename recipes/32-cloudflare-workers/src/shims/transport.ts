// Build-time alias for @dnsid-ai/transport (Node-only: undici, node:dns, node:tls).
// @dnsid-ai/log-c2sp-tlog imports it for its default fetcher; Workers inject
// createFetchBackedC2spResourceFetcher(fetch, ...) instead, so this must never run.
// ponytail: delete once log-c2sp-tlog loads the Node transport lazily.
export function createSsrfSafeFetch(): never {
  throw new Error('@dnsid-ai/transport is not available in Workers; inject a resourceFetcher');
}
