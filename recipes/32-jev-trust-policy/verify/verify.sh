#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
CLI=${DNSID_CLI:-dnsid}
PORT=${API_PORT:-3120}
TMP=$(mktemp -d)
cleanup() {
  # dnsid local run / uv run are wrappers; terminate the server child too.
  server_pid=$(awk '/Started server process \[/{gsub(/[^0-9]/, "", $NF); print $NF; exit}' "$TMP/api" 2>/dev/null || true)
  [[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null || true
  kill "${API_PID:-}" "${MODEL_PID:-}" 2>/dev/null || true
  wait "${API_PID:-}" "${MODEL_PID:-}" 2>/dev/null || true
  echo '--- API log ---'; tail -40 "$TMP/api" 2>/dev/null || true
  echo '--- decision stub log ---'; tail -20 "$TMP/model" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  docker ps --filter name=dnsid-local >&2 || true
  for c in $(docker ps -q --filter name=dnsid-local); do docker logs --tail 50 "$c" >&2 || true; done
  exit 1
}

# The fixture is ONLY a protocol/banding smoke test, not a Jev model or policy benchmark.
uv run python -u src/mock_jev.py >"$TMP/model" 2>&1 & MODEL_PID=$!
DNSID_PUBLIC_URL=https://api.dev.dnsid.test \
  JEV_ENDPOINT=http://127.0.0.1:8791/v1/systemone \
  "$CLI" local run api --upstream "http://localhost:$PORT" -- \
  uv run uvicorn app:app --app-dir src --host 127.0.0.1 --port "$PORT" >"$TMP/api" 2>&1 & API_PID=$!
for _ in $(seq 1 90); do
  if grep -q 'Uvicorn running' "$TMP/api" && curl -fsS "http://127.0.0.1:$PORT/openapi.json" >/dev/null 2>&1; then break; fi
  if grep -q 'address already in use' "$TMP/api"; then fail 'API port already in use'; fi
  kill -0 "$API_PID" 2>/dev/null || fail 'API exited before ready'
  sleep 1
done
curl -fsS "http://127.0.0.1:$PORT/openapi.json" >/dev/null || fail 'API not ready'
status=$(curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
  -d '{"purpose":"check service health"}' "http://127.0.0.1:$PORT/evaluate")
[[ "$status" == 401 ]] || fail "unsigned request: expected 401, got $status"
[[ $(grep -c 'POST /v1/systemone' "$TMP/model" || true) == 0 ]] || fail 'model called before identity verification'
echo 'unsigned: 401 (no model call)'
for spec in 'peer routine 200' 'peer sensitive 403' 'peer injection 403' 'outsider routine 403'; do
  read -r agent mode expected <<<"$spec"
  "$CLI" local run "$agent" --upstream "http://localhost:$([[ $agent == peer ]] && echo 3121 || echo 3122)" -- \
    uv run python -u src/client.py "$mode" "$expected" || fail "$spec"
done
[[ $(grep -c 'POST /v1/systemone' "$TMP/model" || true) == 4 ]] || fail 'expected four evaluated, signed requests'
# Even a valid signed request must fail closed without the model.
kill "$MODEL_PID"
wait "$MODEL_PID" 2>/dev/null || true
"$CLI" local run peer --upstream http://localhost:3121 -- \
  uv run python -u src/client.py routine 503 || fail 'decision outage must return 503'
[[ "${DNSID_RECIPE_ASSERT:-1}" == 0 ]] || echo 'verify passed (stub only; real model not evaluated)'
