#!/usr/bin/env bash
# One-shot run of the recipe, with transcript assertions.
#
# Starts the tools API and the graph agent under `dnsid local run`, then:
# The agent runs on a real model (DNSID_RECIPE_MODEL), so every check below
# reads what the code logged, never the model's wording.
#
#   1. peer (allowlisted) asks the graph to order 3 widgets: place_order runs,
#      as a signed request the tools API verifies as graph.<zone>.
#   2. outsider (verified, not allowlisted) asks the same: place_order is
#      absent, no order happens.
#   3. peer asks the graph to fetch from rogue.<zone>, which has no DNSid
#      identity: the graph's client refuses before sending anything.
#   4. a signed request sent twice: the copy is rejected (replay protection).
#   5. an unsigned request to the graph gets a 401.
#
# DNSID_RECIPE_ASSERT=0 skips the assertions (used by `make run`).
# Assumes `make bootstrap` has run.

set -euo pipefail
cd "$(dirname "$0")/.."

DNSID_CLI="${DNSID_CLI:-dnsid}"
ZONE="${ZONE:-test}"
GRAPH_PORT="${GRAPH_PORT:-3101}"
PEER_PORT="${PEER_PORT:-3102}"
TOOLS_PORT="${TOOLS_PORT:-3103}"
OUTSIDER_PORT="${OUTSIDER_PORT:-3104}"
ASSERT="${DNSID_RECIPE_ASSERT:-1}"

LOGS=$(mktemp -d "${TMPDIR:-/tmp}/dnsid-recipe31.XXXXXX")
PIDS=()

fail() {
    echo "" >&2
    echo "FAIL: $1" >&2
    echo "--- local registry containers ---" >&2
    docker ps --filter "name=dnsid-local" >&2 || true
    docker ps -q --filter "name=dnsid-local" | while read -r c; do
        echo "--- docker logs ${c} (tail) ---" >&2
        docker logs --tail 30 "${c}" >&2 || true
    done
    exit 1
}

kill_our_agents() {
    # `dnsid local run` wraps the python process; kill by command line too.
    # uvicorn finishes in-flight requests on SIGTERM, and with a slow model an
    # in-flight request can still place an order. Give it 5s, then SIGKILL.
    local pattern="python -u src/main.py (tools|graph)"
    pkill -f "${pattern}" 2>/dev/null || true
    for _ in $(seq 1 10); do
        pgrep -f "${pattern}" >/dev/null || return 0
        sleep 0.5
    done
    pkill -9 -f "${pattern}" 2>/dev/null || true
}

cleanup() {
    for pid in "${PIDS[@]}"; do kill "${pid}" 2>/dev/null || true; done
    kill_our_agents
    for role in tools graph; do
        echo ""
        echo "--- ${role} transcript ---"
        cat "${LOGS}/${role}.log"
    done
    rm -rf "${LOGS}"
}
trap cleanup EXIT
kill_our_agents

start() {
    local name="$1" port="$2"
    echo "==> starting ${name} on :${port}"
    "${DNSID_CLI}" local run "${name}" --upstream "http://localhost:${port}" -- \
        uv run python -u src/main.py "${name}" >"${LOGS}/${name}.log" 2>&1 &
    PIDS+=($!)
    for _ in $(seq 1 60); do
        grep -q "listening" "${LOGS}/${name}.log" && return 0
        kill -0 "${PIDS[-1]}" 2>/dev/null || { cat "${LOGS}/${name}.log" >&2; fail "${name} exited early"; }
        sleep 0.5
    done
    fail "${name} did not start"
}

ask() {
    local who="$1" port="$2" text="$3"
    echo "==> ${who}: ${text}"
    "${DNSID_CLI}" local run "${who}" --upstream "http://localhost:${port}" -- \
        uv run python -u src/main.py ask "graph.${ZONE}" "${text}" 2>&1 | tee "${LOGS}/${who}.$4.log"
}

start tools "${TOOLS_PORT}"
start graph "${GRAPH_PORT}"

ask peer "${PEER_PORT}" "Please order 3 widgets" order
ask outsider "${OUTSIDER_PORT}" "Please order 3 widgets" order
ask peer "${PEER_PORT}" "Use the fetch tool to GET https://rogue.${ZONE}/catalog and tell me what it returns." rogue

echo "==> peer sends one signed request twice"
"${DNSID_CLI}" local run peer --upstream "http://localhost:${PEER_PORT}" -- \
    uv run python -u verify/replay.py "https://graph.${ZONE}/ask" 2>&1 | tee "${LOGS}/replay.log"

echo "==> unsigned request to the graph"
CA_BUNDLE=$("${DNSID_CLI}" local agent ensure peer --upstream "http://localhost:${PEER_PORT}" --format dotenv \
    | sed -n 's/^DNSID_CA_BUNDLE="\(.*\)"$/\1/p')
UNSIGNED=$(curl -s -w ' %{http_code}' --cacert "${CA_BUNDLE}" --resolve "graph.${ZONE}:443:127.0.0.1" \
    -H 'content-type: application/json' -d '{"text":"Please order 500 widgets"}' "https://graph.${ZONE}/ask")
echo "${UNSIGNED}"

if [[ "${ASSERT}" == "1" ]]; then
    echo ""
    echo "==> asserting transcript"
    G="${LOGS}/graph.log" T="${LOGS}/tools.log"

    grep -q "\[graph.${ZONE}\] verified POST /ask from peer.${ZONE}" "${G}" || fail "graph did not verify peer"
    grep -q "\[peer.${ZONE}\] verified peer graph.${ZONE}" "${LOGS}/peer.order.log" || fail "peer did not verify graph"
    echo "  ok: peer and graph verified each other"

    grep -q "\[tools.${ZONE}\] verified POST /order from graph.${ZONE}" "${T}" || fail "tools did not verify graph"
    grep -q "^200 " "${LOGS}/peer.order.log" || fail "peer's request failed"
    echo "  ok: graph's signed tool call verified by tools"

    grep -q "\[graph.${ZONE}\] verified POST /ask from outsider.${ZONE}" "${G}" || fail "graph did not verify outsider"
    grep -q "\[policy\] hid place_order from outsider.${ZONE}" "${G}" || fail "place_order was not hidden from outsider"
    grep -q "\[policy\] hid place_order from peer.${ZONE}" "${G}" && fail "place_order was hidden from peer"
    echo "  ok: outsider verified, but place_order absent"

    # The model must choose to call fetch; a refusal proves the client stopped it.
    grep -q "\[graph.${ZONE}\] refused peer rogue.${ZONE}" "${G}" || fail "graph did not refuse the unverified peer"
    grep -q "verified peer rogue.${ZONE}" "${G}" && fail "graph contacted rogue.${ZONE}"
    echo "  ok: graph refused to call an unverified peer"

    [[ "${UNSIGNED}" == *"SIGNATURE_INVALID"*" 401" ]] || fail "unsigned request was not rejected: ${UNSIGNED}"
    echo "  ok: unsigned request rejected with 401"

    grep -q "^first: 200" "${LOGS}/replay.log" || fail "first copy of the signed request was not accepted"
    grep -q "^replay: 401.*nonce already used" "${LOGS}/replay.log" || fail "replayed request was not rejected"
    echo "  ok: replayed signed request rejected with 401"

    orders=$(grep -c "verified POST /order" "${T}" || true)
    [[ "${orders}" == "1" ]] || fail "expected exactly 1 order, saw ${orders}"
    echo "  ok: exactly one order reached the tools API"

    echo ""
    echo "✓ verify passed"
fi
