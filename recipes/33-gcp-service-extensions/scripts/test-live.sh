#!/usr/bin/env bash
# The live tests against a deployment scripts/deploy.sh made (scripts/live/test-live.ts; the cases are in
# scripts/live/cases.ts, one per live case described in docs/live-tests.md).
#
#   DEPLOY_OUT=<deploy-out.json> LIVE_OUT=<dir> DNSID_AGENT_ID=<agent> DNSID_AGENT_KEY_FILE=<key> \
#     [OTHER_AGENT_ID=<another agent>] [MODE=live|allow|revoked] scripts/test-live.sh
#
# DEPLOY_OUT     what deploy.sh wrote (default: the one in deploy.sh's default STATE_DIR for GOOGLE_CLOUD_PROJECT)
# LIVE_OUT       where report.json goes (default: live-out/ beside DEPLOY_OUT)
# DNSID_AGENT_ID, DNSID_AGENT_KEY_FILE   the agent to sign as, and its private key as the portal exports it
# OTHER_AGENT_ID a second real identity, which the agent's key claims to be (deny-other-identity)
# MODE           live (default): every live case but deny-revoked; allow: allow-trusted only; revoked: deny-revoked only
# LIVE_LOG_WAIT_S how long to wait for Cloud Logging to show records that should be there (default 120)
#
# deny-untrusted-governance, deny-verifier-down and verification-timing change the deployment for a moment (the trusted
# governance list, the verifier's scaling, its log mode) and put it back; they need the platform login (as for
# deploy.sh) and fail without one. So do the EDGE-02 denials and the outage case, whose evidence that Demo Bank was not
# invoked is Demo Bank's own request log, and evidence-freshness and verification-timing, whose evidence is the
# verifier's own record of each served request (elapsed time, completeness mode, material-cache use, evidence age).
# Every gcloud command is bounded. A change is recorded in LIVE_OUT/pending-restore.json before it is made and the
# record removed once it is undone; SIGINT or SIGTERM restores a change in progress before exiting, and a record left by
# an earlier run is restored first. After a restoration fails no further change is made. deny-revoked passes only when
# the verifier refuses the agent with a revocation reason AND the source behind that reason, read here, identifies the
# revocation: the agent's status document says REVOKED (identity_inactive), or its authenticated log history ends in a
# REVOCATION (identity_invalid, lifecycle_not_established). Nothing here revokes an identity. The key is never printed.
#
# Exit codes: 0 every case passed; 1 a case failed; 2 an input is missing; 4 the deployment could not be restored
# (or an earlier run's change can't be); 130 interrupted, with any change in progress restored.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [[ -z "${DEPLOY_OUT:-}" && -n "${GOOGLE_CLOUD_PROJECT:-}" ]]; then
  DEPLOY_OUT="${STATE_DIR:-$HOME/.local/state/dnsid-gcp-service-extensions/$GOOGLE_CLOUD_PROJECT}/deploy-out.json"
fi
[[ -n "${DEPLOY_OUT:-}" ]] || { echo "error: DEPLOY_OUT is required (or GOOGLE_CLOUD_PROJECT, to find deploy.sh's default)" >&2; exit 2; }
export DEPLOY_OUT
export LIVE_OUT="${LIVE_OUT:-$(dirname "$DEPLOY_OUT")/live-out}"

# The signer and the cases use the pinned SDK: install exactly the lockfile's tree when it isn't installed yet.
stamp="node_modules/.package-lock.json"
if [[ ! -f "$stamp" || package-lock.json -nt "$stamp" ]]; then
  echo "== installing the pinned dependencies (npm ci)"
  npm ci --no-audit --no-fund --loglevel=error > /dev/null
fi

exec node scripts/live/test-live.ts
