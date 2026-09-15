#!/usr/bin/env bash
# One-shot run of the full LangGraph + DNSid flow, with transcript assertions.
#
# Starts the tools API and the graph agent under `dnsid testnet run`, waits
# for both identities to publish, then:
#   1. peer (allowlisted) asks the graph to place an order — the graph's
#      scripted model calls place_order, which travels to the tools API as a
#      signed HTTP request attributable to graph.<zone>.
#   2. outsider (verified but NOT allowlisted) asks the same — place_order is
#      absent from its tool set, so no order happens.
#
# Assertions:
#   - graph verified the signed A2A POST from peer.<zone> (ingress)
#   - tools verified the signed POST /order from graph.<zone> (egress)
#   - peer's reply carries both identities and the accepted order
#   - outsider's request verified, but its reply shows place_order unavailable
#   - the tools log contains exactly one verified /order call
#
# DNSID_RECIPE_ASSERT=0 skips the assertions (used by `make run`).
# Assumes `make bootstrap` has run (testnet up, identities ensured).

set -euo pipefail
cd "$(dirname "$0")/.."

DNSID_CLI="${DNSID_CLI:-dnsid}"
ZONE="${ZONE:-dev.dnsid.test}"
GRAPH_PORT="${GRAPH_PORT:-3101}"
PEER_PORT="${PEER_PORT:-3102}"
TOOLS_PORT="${TOOLS_PORT:-3103}"
OUTSIDER_PORT="${OUTSIDER_PORT:-3104}"
ASSERT="${DNSID_RECIPE_ASSERT:-1}"

GRAPH_CU="https://graph.${ZONE}/.well-known/agent-card.json"

# Portable across BSD and GNU mktemp: an explicit XXXXXX template.
TOOLS_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe31-tools.XXXXXX")
GRAPH_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe31-graph.XXXXXX")
PEER_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe31-peer.XXXXXX")
OUTSIDER_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe31-outsider.XXXXXX")
TOOLS_PID=""
GRAPH_PID=""

fail() {
    echo "" >&2
    echo "FAIL: $1" >&2
    # Emit the testnet container logs — without them a red CI job is undebuggable.
    echo "--- testnet containers ---" >&2
    docker ps --filter "name=dnsid-testnet" >&2 || true
    docker ps -q --filter "name=dnsid-testnet" | while read -r c; do
        echo "--- docker logs ${c} (tail) ---" >&2
        docker logs --tail 50 "${c}" >&2 || true
    done
    exit 1
}

kill_our_agents() {
    # `dnsid testnet run` wraps the python process; killing the wrapper alone
    # can leave the agent holding its port. Kill by command line instead.
    pkill -f "python -u src/main.py" 2>/dev/null || true
}

cleanup() {
    for pid in "${GRAPH_PID}" "${TOOLS_PID}"; do
        if [[ -n "${pid}" ]]; then
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
        fi
    done
    kill_our_agents
    echo ""
    echo "--- tools transcript ---"
    cat "${TOOLS_LOG}"
    echo ""
    echo "--- graph transcript ---"
    cat "${GRAPH_LOG}"
    rm -f "${TOOLS_LOG}" "${GRAPH_LOG}" "${PEER_LOG}" "${OUTSIDER_LOG}"
}
trap cleanup EXIT

# Kill any leftover agent processes from a previous run.
kill_our_agents

wait_for() {
    local pattern="$1" log="$2" pid="$3" what="$4"
    echo -n "    waiting for ${what}"
    for _ in $(seq 1 90); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            echo ""
            cat "${log}" >&2
            fail "${what}: process exited early"
        fi
        if grep -qE "${pattern}" "${log}" 2>/dev/null; then
            echo " done"
            return 0
        fi
        echo -n "."
        sleep 1
    done
    echo ""
    cat "${log}" >&2
    fail "${what}: timed out after 90s"
}

# ---------------------------------------------------------------------------
# 1. Start the tools API and the graph agent
# ---------------------------------------------------------------------------
echo "==> starting tools API on :${TOOLS_PORT}"
"${DNSID_CLI}" testnet run tools --upstream "http://localhost:${TOOLS_PORT}" -- \
    uv run python -u src/main.py tools \
    >"${TOOLS_LOG}" 2>&1 &
TOOLS_PID=$!
wait_for "published" "${TOOLS_LOG}" "${TOOLS_PID}" "tools identity to publish"

echo "==> starting graph agent on :${GRAPH_PORT}"
"${DNSID_CLI}" testnet run graph --upstream "http://localhost:${GRAPH_PORT}" --cu "${GRAPH_CU}" -- \
    uv run python -u src/main.py graph \
    >"${GRAPH_LOG}" 2>&1 &
GRAPH_PID=$!
wait_for "verified: graph.${ZONE} -> tools.${ZONE}" "${GRAPH_LOG}" "${GRAPH_PID}" "graph to publish and verify the tools API"

# ---------------------------------------------------------------------------
# 2. The allowlisted peer places an order through the graph
# ---------------------------------------------------------------------------
echo "==> peer asks the graph to order 3 widgets"
"${DNSID_CLI}" testnet run peer --upstream "http://localhost:${PEER_PORT}" -- \
    uv run python -u src/main.py send "graph.${ZONE}" "Please order 3 widgets" \
    2>&1 | tee "${PEER_LOG}"

# ---------------------------------------------------------------------------
# 3. The outsider (verified, not allowlisted) tries the same
# ---------------------------------------------------------------------------
echo "==> outsider asks the graph to order 3 widgets"
"${DNSID_CLI}" testnet run outsider --upstream "http://localhost:${OUTSIDER_PORT}" -- \
    uv run python -u src/main.py send "graph.${ZONE}" "Please order 3 widgets" \
    2>&1 | tee "${OUTSIDER_LOG}"

# ---------------------------------------------------------------------------
# 4. Assert the transcript
# ---------------------------------------------------------------------------
if [[ "${ASSERT}" == "1" ]]; then
    echo ""
    echo "==> asserting transcript"

    grep -q "verified signed POST / from peer.${ZONE}" "${GRAPH_LOG}" \
        || fail "graph never verified the signed A2A POST from peer.${ZONE}"
    echo "  ok: peer->graph ingress verified"

    grep -q "verified signed POST /order from graph.${ZONE}" "${TOOLS_LOG}" \
        || fail "tools never verified a signed /order call from graph.${ZONE}"
    echo "  ok: graph->tools egress verified as graph.${ZONE}"

    grep -q "reply: \"\[from: graph.${ZONE}; verified caller: peer.${ZONE}\]" "${PEER_LOG}" \
        || fail "peer's reply is missing the two verified identities"
    grep -q '\\?"status\\?": \\?"accepted\\?"' "${PEER_LOG}" \
        || grep -q "accepted" "${PEER_LOG}" \
        || fail "peer's reply is missing the accepted order"
    echo "  ok: reply carries both identities and the accepted order"

    grep -q "verified signed POST / from outsider.${ZONE}" "${GRAPH_LOG}" \
        || fail "graph never verified the signed A2A POST from outsider.${ZONE}"
    grep -q "place_order tool is not available" "${OUTSIDER_LOG}" \
        || fail "outsider's reply does not show place_order as unavailable"
    echo "  ok: outsider verified, but the sensitive tool is absent"

    order_calls=$(grep -c "verified signed POST /order" "${TOOLS_LOG}" || true)
    [[ "${order_calls}" == "1" ]] \
        || fail "expected exactly 1 verified /order call, saw ${order_calls}"
    echo "  ok: exactly one order reached the tools API"

    echo ""
    echo "✓ verify passed"
fi

echo ""
echo "==> done"
