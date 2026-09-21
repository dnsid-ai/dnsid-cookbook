#!/usr/bin/env bash
# One-shot message-board flow using the real DNSid local registry and Go SDK.
set -euo pipefail
cd "$(dirname "$0")/.."

DNSID_CLI="${DNSID_CLI:-dnsid}"
STATE="${STATE:-$PWD/.dnsid-local}"
REGISTRY_PORT="${REGISTRY_PORT:-7955}"
DNS_PORT="${DNS_PORT:-7753}"
PROXY_PORT="${PROXY_PORT:-443}"
BOARD_PORT="${BOARD_PORT:-3401}"
OWNER_PORT="${OWNER_PORT:-3402}"
POSTER_PORT="${POSTER_PORT:-3403}"
ZONE="${ZONE:-dev.dnsid.test}"
AUDIENCE="${AUDIENCE:-urn:dnsid-message-board:testnet}"
TOKEN_ENVIRONMENT="${TOKEN_ENVIRONMENT:-production}"
BOARD_DOMAIN="board.${ZONE}"
OWNER_DOMAIN="owner.${ZONE}"
POSTER_DOMAIN="poster.${ZONE}"
API="http://127.0.0.1:${BOARD_PORT}"
LOCAL_ENV=(env "DNSID_LOCAL_REGISTRY_PORT=${REGISTRY_PORT}" "DNSID_LOCAL_DNS_PORT=${DNS_PORT}" "DNSID_LOCAL_PROXY_PORT=${PROXY_PORT}")
SERVER_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe29-server.XXXXXX")
OWNER_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe29-owner.XXXXXX")
POSTER_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe29-poster.XXXXXX")
SERVER_PID=""

fail() {
    echo "FAIL: $1" >&2
    docker ps --filter name=dnsid-local >&2 || true
    docker ps -q --filter name=dnsid-local | while read -r container; do
        echo "--- docker logs ${container} (tail) ---" >&2
        docker logs --tail 50 "${container}" >&2 || true
    done
    exit 1
}

cleanup() {
    if [[ -n "${SERVER_PID}" ]]; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    pkill -f "${PWD}/bin/dnsid-board-server" 2>/dev/null || true
    echo ""
    echo "--- board server transcript ---"
    cat "${SERVER_LOG}"
    rm -f "${SERVER_LOG}" "${OWNER_LOG}" "${POSTER_LOG}"
}
trap cleanup EXIT
pkill -f "${PWD}/bin/dnsid-board-server" 2>/dev/null || true

run_agent() {
    local name=$1 port=$2 domain=$3
    shift 3
    "${LOCAL_ENV[@]}" "${DNSID_CLI}" local run "${name}" --state "${STATE}" \
        --upstream "http://localhost:${port}" -- \
        env "DNSID_BOARD_API=${API}" "DNSID_BOARD_AUDIENCE=${AUDIENCE}" \
        "DNSID_AGENT_DOMAIN=${domain}" "$@"
}

# A freshly published record takes a couple of seconds to appear (the local
# registry DNS reloads its zone periodically). The board verifies every token
# subject against DNS, so wait for all three records before the flow starts.
for domain in "${BOARD_DOMAIN}" "${OWNER_DOMAIN}" "${POSTER_DOMAIN}"; do
    echo -n "==> waiting for _dnsid.${domain} to resolve"
    resolved=""
    for _ in $(seq 1 30); do
        if dig @127.0.0.1 -p "${DNS_PORT}" "_dnsid.${domain}" TXT +short 2>/dev/null | grep -q 'v=dnsid'; then
            resolved=1
            break
        fi
        echo -n "."
        sleep 1
    done
    echo ""
    [[ -n "${resolved}" ]] || fail "_dnsid.${domain} TXT did not resolve within 30s"
done

echo "==> starting board as ${BOARD_DOMAIN}"
"${LOCAL_ENV[@]}" "${DNSID_CLI}" local run board --state "${STATE}" \
    --upstream "http://localhost:${BOARD_PORT}" -- \
    env BOARD_BACKEND=local "ADDR=:${BOARD_PORT}" "BOARD_API_AUDIENCES=${AUDIENCE}" \
    "DNSID_ENVIRONMENT=${TOKEN_ENVIRONMENT}" "${PWD}/bin/dnsid-board-server" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        cat "${SERVER_LOG}" >&2
        fail "board server exited early"
    fi
    curl -fsS "${API}/healthz" >/dev/null 2>&1 && break
    sleep 1
done
curl -fsS "${API}/healthz" >/dev/null || fail "board server did not become ready"

status=$(curl -sS -o /dev/null -w '%{http_code}' "${API}/v1/whoami")
[[ "${status}" == "401" ]] || fail "unsigned request returned HTTP ${status}, want 401"
echo "ok unsigned request rejected"

echo "==> owner creates the room and grants poster access"
run_agent owner "${OWNER_PORT}" "${OWNER_DOMAIN}" bash -euo pipefail -c '
    board=$1
    room=$2
    poster=$3
    api=$4
    "$board" whoami
    token=$(dnsid token --domain "$DNSID_AGENT_DOMAIN" --audience "$DNSID_BOARD_AUDIENCE")
    status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${token%.*}.invalid" "$api/v1/whoami")
    [[ "$status" == 401 ]]
    echo "ok forged token rejected"
    if DNSID_BOARD_AUDIENCE=urn:dnsid-message-board:wrong "$board" whoami >/dev/null 2>&1; then
        echo "wrong-audience token was accepted" >&2
        exit 1
    fi
    echo "ok wrong-audience token rejected"
    "$board" room create "$room" --name Security
    "$board" allowlist grant "$room" --agent "$poster" --role poster
' _ "${PWD}/bin/dnsid-board" "security/risk brainstorm" "${POSTER_DOMAIN}" "${API}" 2>&1 | tee "${OWNER_LOG}"

echo "==> poster writes and reads as a separately verified DNSid subject"
run_agent poster "${POSTER_PORT}" "${POSTER_DOMAIN}" bash -euo pipefail -c '
    board=$1
    room=$2
    "$board" nickname set "$room" --nickname future-agent
    "$board" post "$room" --body "hello from a DNSid subject" --idempotency-key verify-local-1
    "$board" read "$room" --limit 500
    "$board" watch "$room" --limit 25 --wait 0
' _ "${PWD}/bin/dnsid-board" "security/risk brainstorm" 2>&1 | tee "${POSTER_LOG}"

grep -q "agent: ${OWNER_DOMAIN}" "${OWNER_LOG}" || fail "owner token subject was not verified"
grep -q 'ok forged token rejected' "${OWNER_LOG}" || fail "forged token was accepted"
grep -q 'ok wrong-audience token rejected' "${OWNER_LOG}" || fail "wrong audience was accepted"
grep -q '"author_nickname": "future-agent"' "${POSTER_LOG}" || fail "poster message was not returned"

echo "ok real DNSid OIDC tokens verified with dnsid-go/oidc"
echo "ok DNSid subjects re-verified against DNS, status, and lifecycle log"
echo "ok arbitrary room ID, allowlist, nickname, post, read, and bounded watch"
echo "✓ verify passed"
