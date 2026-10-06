#!/usr/bin/env bash
# Recipe 32 wiring and fail-closed checks, using the fixture decision server.
# Proves the plumbing, not the policy: measure a real model with `make eval`.
set -euo pipefail
cd "$(dirname "$0")/.."

DNSID_CLI=${DNSID_CLI:-dnsid}
API_PORT=${API_PORT:-3120}
export DNSID_RECIPE_ASSERT=${DNSID_RECIPE_ASSERT:-1}
export JEV_ENDPOINT=http://127.0.0.1:8791/v1/systemone
export FIXTURE_LOG; FIXTURE_LOG=$(mktemp)
pids=()
api_log=$(mktemp)
cleanup() {
  status=$?
  server_pid=$(awk '/Started server process \[/{gsub(/[^0-9]/, "", $NF); print $NF; exit}' "$api_log" 2>/dev/null || true)
  [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
  kill "${pids[@]}" 2>/dev/null || true
  wait "${pids[@]}" 2>/dev/null || true
  if [ "$status" != 0 ]; then
    tail -60 "$api_log"
    docker ps --filter name=dnsid-local
    for c in $(docker ps -q --filter name=dnsid-local); do docker logs --tail 50 "$c"; done
  fi
  rm -f "$FIXTURE_LOG" "$api_log"
}
trap cleanup EXIT

check() {  # check LABEL CONDITION...
  local label=$1; shift
  if "$@"; then echo "ok    $label"; else echo "FAIL  $label"; [ "$DNSID_RECIPE_ASSERT" = 0 ] || exit 1; fi
}
wait_for() { for _ in $(seq 60); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; "$@"; }
as() {  # as IDENTITY client-args...
  local who=$1; shift
  local port; case $who in acme-billing) port=3121 ;; paypal-refunds) port=3122 ;; esac
  "$DNSID_CLI" local run "$who" --upstream "http://localhost:$port" -- uv run python src/client.py "$@"
}

uv run python -m unittest discover -s tests

uv run python src/fixture_model.py & fixture=$!; pids+=("$fixture")
wait_for curl -s -o /dev/null http://127.0.0.1:8791/

# Docker's TLS proxy reaches the host gateway, not host loopback, on Linux.
DNSID_PUBLIC_URL=https://api.test \
  "$DNSID_CLI" local run api --upstream "http://localhost:$API_PORT" -- \
  uv run uvicorn app:app --app-dir src --host 0.0.0.0 --port "$API_PORT" >"$api_log" 2>&1 & pids+=($!)
wait_for curl -fsS "http://127.0.0.1:$API_PORT/healthz"
kill -0 "${pids[1]}" || { echo 'API exited before ready'; exit 1; }

# Unsigned: rejected by DNSid verification; the decision server is never asked.
before=$(wc -l < "$FIXTURE_LOG")
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$API_PORT/v1/catalog")
check "unsigned GET /v1/catalog -> 401" [ "$code" = 401 ]
check "unsigned request never reached the decision server" [ "$(wc -l < "$FIXTURE_LOG")" = "$before" ]

# Inbound. Every local identity is minutes old, so the best tier here is "limited".
as acme-billing   call GET  /v1/catalog 200     # new, neutral name: limited, reads allowed
as acme-billing   call POST /v1/refunds 403     # limited is not enough to move money
as paypal-refunds call GET  /v1/catalog 403     # valid self-accounted name, not PayPal: untrusted

# Outbound: the same policy, run by acme-billing before it calls a service.
as acme-billing guard api.test            order-lookup allow
as acme-billing guard api.test            customer-pii refuse
as acme-billing guard paypal-refunds.test order-lookup refuse
check "six authenticated decisions reached the fixture" [ "$(wc -l < "$FIXTURE_LOG")" -eq 6 ]

# A signed body must still be a JSON object, not an array.
"$DNSID_CLI" local run acme-billing -- uv run python - <<'PY'
import asyncio
from dnsid import HttpSignatureProfile, identity_manager_from_environment
async def check():
    profile = HttpSignatureProfile.from_identity_manager(identity_manager_from_environment())
    async with profile.create_signed_async_http_client() as client:
        response = await client.request("GET", "https://api.test/v1/catalog", json=[])
        assert response.status_code == 400, response.text
    print("ok    signed non-object JSON -> 400")
asyncio.run(check())
PY

# Decision server down: fail closed.
kill "$fixture"; wait "$fixture" 2>/dev/null || true
as acme-billing call GET /v1/catalog 503

echo "verify passed (fixture decision server; real model not evaluated, see make eval)"
