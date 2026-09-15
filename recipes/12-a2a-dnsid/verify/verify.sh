#!/usr/bin/env bash
# One-shot run of the full A2A + DNSid flow, with transcript assertions.
#
# Starts Bob under `dnsid testnet run`, waits for his identity to publish,
# runs Alice (sends one signed message, exits), then asserts the transcript:
#   - Bob's identity published (or `already published (READY)` on re-runs)
#   - Bob logged a verified signed POST from alice.<zone>
#   - Alice's reply text carries both verified identities
#
# DNSID_RECIPE_ASSERT=0 skips the assertions (used by `make run`).
# Assumes `make bootstrap` has run (testnet up, identities ensured).

set -euo pipefail
cd "$(dirname "$0")/.."

DNSID_CLI="${DNSID_CLI:-dnsid}"
ZONE="${ZONE:-dev.dnsid.test}"
ALICE_PORT="${ALICE_PORT:-3001}"
BOB_PORT="${BOB_PORT:-3002}"
ASSERT="${DNSID_RECIPE_ASSERT:-1}"

ALICE_CU="https://alice.${ZONE}/.well-known/agent-card.json"
BOB_CU="https://bob.${ZONE}/.well-known/agent-card.json"

# Portable across BSD and GNU mktemp: an explicit XXXXXX template.
BOB_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe12-bob.XXXXXX")
ALICE_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe12-alice.XXXXXX")
BOB_PID=""

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
    if [[ -n "${BOB_PID}" ]]; then
        kill "${BOB_PID}" 2>/dev/null || true
        wait "${BOB_PID}" 2>/dev/null || true
    fi
    kill_our_agents
    echo ""
    echo "--- Bob transcript ---"
    cat "${BOB_LOG}"
    rm -f "${BOB_LOG}" "${ALICE_LOG}"
}
trap cleanup EXIT

# Kill any leftover agent processes from a previous run.
kill_our_agents

# ---------------------------------------------------------------------------
# 1. Start Bob in the background
# ---------------------------------------------------------------------------
echo "==> starting Bob on :${BOB_PORT}"
"${DNSID_CLI}" testnet run bob --upstream "http://localhost:${BOB_PORT}" --cu "${BOB_CU}" -- \
    uv run python -u src/main.py \
    >"${BOB_LOG}" 2>&1 &
BOB_PID=$!

echo -n "    waiting for Bob to publish his identity"
for _ in $(seq 1 90); do
    if ! kill -0 "${BOB_PID}" 2>/dev/null; then
        echo ""
        cat "${BOB_LOG}" >&2
        fail "Bob exited early"
    fi
    if grep -qE "published|already published" "${BOB_LOG}" 2>/dev/null; then
        break
    fi
    echo -n "."
    sleep 1
done
grep -qE "published|already published" "${BOB_LOG}" || {
    cat "${BOB_LOG}" >&2
    fail "Bob never published within 90s"
}
echo " done"

# ---------------------------------------------------------------------------
# 2. Run Alice — sends one signed message to Bob then exits
# ---------------------------------------------------------------------------
echo "==> starting Alice on :${ALICE_PORT} — sending hello to Bob"
"${DNSID_CLI}" testnet run alice --upstream "http://localhost:${ALICE_PORT}" --cu "${ALICE_CU}" -- \
    uv run python -u src/main.py "bob.${ZONE}" \
    2>&1 | tee "${ALICE_LOG}"

# ---------------------------------------------------------------------------
# 3. Assert the transcript
# ---------------------------------------------------------------------------
if [[ "${ASSERT}" == "1" ]]; then
    echo ""
    echo "==> asserting transcript"

    grep -qE "published|already published" "${BOB_LOG}" \
        || fail "Bob's transcript is missing the published line"
    echo "  ok: Bob's identity published"

    grep -q "verified signed POST / from alice.${ZONE}" "${BOB_LOG}" \
        || fail "Bob never logged a verified signed POST from alice.${ZONE}"
    echo "  ok: Bob verified Alice's signature"

    grep -q "verified: alice.${ZONE} -> bob.${ZONE}" "${ALICE_LOG}" \
        || fail "Alice never verified Bob's identity"
    echo "  ok: Alice verified Bob's identity on first contact"

    grep -q "reply: \"\[from: bob.${ZONE}; verified sender: alice.${ZONE}\] hello from alice.${ZONE}\"" "${ALICE_LOG}" \
        || fail "Alice's reply is missing both verified identities"
    echo "  ok: reply carries both verified identities"

    echo ""
    echo "✓ verify passed"
fi

echo ""
echo "==> done"
