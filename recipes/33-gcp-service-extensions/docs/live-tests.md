# The live tests

`scripts/test-live.sh` runs these cases against a deployment (`DEPLOY_OUT`), signing as `DNSID_AGENT_ID` with the
private key at `DNSID_AGENT_KEY_FILE`; `OTHER_AGENT_ID` is a second agent, for `deny-other-identity` and
`app-account-policy`. Each case's
result goes to `LIVE_OUT/report.json` with the criterion it is evidence for (`edge`), what was expected, what the edge
answered and whether it passed.

| Case | Criterion | Expected |
|---|---|---|
| `allow-trusted` | EDGE-01 | 200 from Demo Bank for a signed GET by a trusted, ACTIVE agent |
| `app-account-policy` | EDGE-01 | Demo Bank's own authorization behind the edge: the agent reads its own account (200); another agent's account is refused by Demo Bank (403 `account_not_permitted`), not by the verifier |
| `deny-unsigned`, `deny-malformed-signature`, `deny-tampered` | EDGE-02 | 403 from the verifier, and Demo Bank's request log shows nothing for them |
| `deny-other-identity` | EDGE-03 | 403: signed with one agent's key while claiming another identity |
| `deny-untrusted-governance` | EDGE-04 | 403 `governance_not_trusted` while the trusted list excludes the agent's governance, then allowed again (changes the deployment for a moment) |
| `deny-revoked` (`MODE=revoked`) | EDGE-05 | 403 with a revocation reason **and** the source behind it shows REVOKED: the status document for `identity_inactive`, the agent's authenticated log history for `identity_invalid` or `lifecycle_not_established` |
| `evidence-freshness` | EDGE-06 | the verifier's own record of each of 3 served requests: evidence age within -5..300 s, completeness mode, material-cache use, elapsed time within 2,500 ms |
| `deny-verifier-down` | EDGE-07 | the load balancer's 500 while the verifier is scaled to zero, nothing reaches Demo Bank, then restored (changes the deployment) |
| `deny-expired-signature` | EDGE-08 | 403 for `created` an hour old and an hour ahead |
| `deny-cache-reuse`, `deny-bypass-run-app`, `deny-bypass-http`, `deny-bypass-uncovered-rule`, `deny-bypass-dotdot`, `deny-bypass-verifier`, `deny-bypass-rewrite` | EDGE-09 | no cached answer; the `run.app` URLs, plain HTTP, an uncovered forwarding rule, `..` paths, the verifier itself and URL-map rewrites give no way around the check |
| `fidelity-http1`, `fidelity-http2`, `fidelity-escaped-path`, `fidelity-query-order`, `fidelity-duplicate-headers`, `deny-body-on-get`, `deny-body-on-get-chunked`, `deny-body-on-get-h2` | ADD-02 | signatures verify after the load balancer; an escaped unreserved character reaches the verifier and Demo Bank as the same path; reordered or duplicated signature fields are refused; requests with content are refused before Demo Bank (the load balancer's own 400, or the verifier's 403) |
| `strip-spoofed-identity-headers` | ADD-04 | Demo Bank sees only the verifier's identity headers |
| `deny-forged-identity` | ADD-04 | with Demo Bank's own `run.app` URL opened for a moment (as when a front end forwards a request without the authorization policy), forged identity headers are refused by Demo Bank itself: 403 `identity_attestation_required` without an attestation, 403 `identity_attestation_invalid` with a forged one; the URL closed again (changes the deployment for a moment) |
| `replay-within-window` | ADD-07 | the same request twice within 300 s is allowed both times (documented limitation) |
| `deny-method` | ADD-08 | POST, PUT and DELETE refused with 403 |
| `verification-timing` | ADD-05 | the verifier's records of 5 requests as deployed (cold or warm), then with `DNSID_LOG_EVIDENCE=full-scan` (a new revision) the record of its first request, which must be a cold `miss`, and of 3 more (every record must say `full-scan`), each within 2,500 ms; the setting removed afterwards (changes the deployment for a moment) |

`MODE=live` (the default) runs every case but `deny-revoked`; `MODE=allow` only `allow-trusted`; `MODE=revoked` only
`deny-revoked`, against an agent that has already been revoked (nothing here revokes one).

How the results are judged:

- A case passes only on its full evidence: the edge's answer and, where the table says so, Demo Bank's own request log
  (read from Cloud Logging). After the other cases, one more signed request is sent as a control, and the log windows
  are judged only once that request's record appears (waiting up to two minutes for a slow log).
- `deny-revoked` needs a refusal with a revocation reason and, read independently of the edge, the source behind that
  reason showing the revocation: the agent's status document reading REVOKED for `identity_inactive` (the verifier
  gives the same answer for a retired agent); its log history, verified under its accountable-entity key and the log's
  witnessed checkpoint, ending in a REVOCATION for `identity_invalid` or `lifecycle_not_established` (when the log
  already holds the revocation, the verifier's log read refuses first, and the SDK says only that the log check
  failed, as it would for a tampered or unreachable log). RETIRED in either source never passes.
- `deny-untrusted-governance`, `deny-verifier-down`, `verification-timing` and `deny-forged-identity` change the
  deployment for a moment (the trusted governance list; the verifier's scaling; its log mode; Demo Bank's ingress and
  default URL) and restore it. The change is recorded in `LIVE_OUT/pending-restore.json` first, and the record is
  removed only once the restoration reads back in the changed service's configuration and shows at the edge. Exit 4
  means a change may still be in place: run `scripts/test-live.sh` again (it restores first) or tear down.
- These, the EDGE-02 denials and `evidence-freshness` need the deployment's login (Cloud Logging and the changes);
  without it they fail and say so.
- `evidence-freshness` and `verification-timing` are judged from the verifier's own record of each request it let
  through, not from the client's round trip: exactly one complete record per served request, waited for up to
  `LIVE_LOG_WAIT_S` (default 120 s); missing, extra or incomplete records fail the case. With
  `DNSID_LOG_EVIDENCE=full-scan` the verifier never reads a stream bundle, so every lifecycle read is the complete raw
  scan of the log the SDK otherwise falls back to, with the same trust and checks.

## Finding: requests forwarded without the authorization policy (eighth deployment, 2026-11-14)

`allow-trusted` got one 403 among seven signed requests (`200,200,200,403,200,200,200`). From the project's Cloud
Logging:

- The verifier logged no denial in that case: only `continue_submitted` for each of the other requests.
- Load balancer log, 2026-11-14T05:12:24.550Z: status 403, statusDetails `response_sent_by_backend`, latency 0.13 s,
  and no `authzPolicyInfo` at all. Every other request in the case has `authzPolicyInfo`
  `{policies: [dnsid-gse-d47cbfdd-authz-policy: ALLOWED], result: ALLOWED}` (or `DENIED` for the unsigned ones).
- Demo Bank's log, 05:12:24.622Z: `{"event":"origin_request","method":"GET","outcome":"identity_missing","route":"accounts","status":403}`.

About 12 minutes after the policy was created, and after the deployment's two-minute readiness hold, one of Google's
front ends still forwarded a request to Demo Bank without evaluating the authorization policy. The verifier never saw
it. Demo Bank refused it only because the identity headers were missing; it then trusted those headers by their
presence alone, so a caller who sent forged `x-dnsid-*` headers in that window would have been served as that identity.
The deployment's own readiness log shows the same window: Demo Bank answered two of its unsigned probes (at 435 s and
502 s) before its single probes held for 120 s.

What changed:

- **Attestation.** Demo Bank accepts an identity only with the verifier's `x-dnsid-attestation`, an HMAC-SHA256 over the
  verified domain, the governance ID and the time, under a key Terraform generates for each deployment and gives to
  those two services only. A request that reaches Demo Bank without the verifier is refused whatever headers it
  carries. `deny-forged-identity` checks it live.
- **Readiness.** Probes go out eight at a time on new connections; Demo Bank answering any of them means the policy is
  not yet in force, and it must then hold for ten minutes in a row (three minutes otherwise).

**Open risk.** Google can forward requests without the authorization policy for some minutes after the policy is
created. No readiness wait can prove the window has closed; the attestation is what keeps it closed. Any origin behind
this pattern must authenticate what the edge tells it, not trust headers by their presence.
