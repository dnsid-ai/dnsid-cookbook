#!/usr/bin/env bash
# One-shot fake-Stripe flow using the real DNSid testnet and Go SDK.
set -euo pipefail
cd "$(dirname "$0")/.."

DNSID_CLI="${DNSID_CLI:-dnsid}"
ZONE="${ZONE:-dev.dnsid.test}"
STRIPE_PORT="${STRIPE_PORT:-3301}"
WRITER_PORT="${WRITER_PORT:-3302}"
ACCOUNT="${ACCOUNT:-acct_demo}"
AMOUNT="${AMOUNT:-250}"
ASSERT="${DNSID_RECIPE_ASSERT:-1}"
STRIPE_DOMAIN="stripe.${ZONE}"
WRITER_DOMAIN="writer.${ZONE}"

STRIPE_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe06b-stripe.XXXXXX")
WRITER_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe06b-writer.XXXXXX")
STRIPE_PID=""

fail() {
    echo "FAIL: $1" >&2
    docker ps --filter "name=dnsid-testnet" >&2 || true
    docker ps -q --filter "name=dnsid-testnet" | while read -r container; do
        echo "--- docker logs ${container} (tail) ---" >&2
        docker logs --tail 50 "${container}" >&2 || true
    done
    exit 1
}

kill_our_processes() {
    pkill -f "${PWD}/bin/server" 2>/dev/null || true
    pkill -f "${PWD}/bin/agent" 2>/dev/null || true
}

cleanup() {
    if [[ -n "${STRIPE_PID}" ]]; then
        kill "${STRIPE_PID}" 2>/dev/null || true
        wait "${STRIPE_PID}" 2>/dev/null || true
    fi
    kill_our_processes
    echo ""
    echo "--- fake-Stripe transcript ---"
    cat "${STRIPE_LOG}"
    rm -f "${STRIPE_LOG}" "${WRITER_LOG}"
}
trap cleanup EXIT
kill_our_processes

echo "==> starting fake-Stripe as ${STRIPE_DOMAIN}"
"${DNSID_CLI}" testnet run stripe --upstream "http://localhost:${STRIPE_PORT}" -- \
    env WRITER_DOMAINS="${WRITER_DOMAIN}" "${PWD}/bin/server" >"${STRIPE_LOG}" 2>&1 &
STRIPE_PID=$!

for _ in $(seq 1 30); do
    if ! kill -0 "${STRIPE_PID}" 2>/dev/null; then
        cat "${STRIPE_LOG}" >&2
        fail "fake-Stripe exited early"
    fi
    grep -q "fake-stripe ready" "${STRIPE_LOG}" 2>/dev/null && break
    sleep 1
done
grep -q "fake-stripe ready" "${STRIPE_LOG}" || fail "fake-Stripe did not become ready"

echo "==> running ${WRITER_DOMAIN}"
"${DNSID_CLI}" testnet run writer --upstream "http://localhost:${WRITER_PORT}" -- \
    "${PWD}/bin/agent" \
        --server "https://${STRIPE_DOMAIN}" \
        --account "${ACCOUNT}" \
        --amount "${AMOUNT}" \
    2>&1 | tee "${WRITER_LOG}"

if [[ "${ASSERT}" == "1" ]]; then
    echo "==> asserting transcript"
    grep -q "unsigned GET -> 401 Unauthorized" "${WRITER_LOG}" || fail "server accepted an unsigned request"
    grep -q "tampered POST -> 401 Unauthorized" "${WRITER_LOG}" || fail "server accepted a tampered signed body"
    grep -q "GET balance -> 1000 (verified as ${WRITER_DOMAIN})" "${WRITER_LOG}" || fail "initial signed read failed"
    grep -q "POST credit -> $((1000 + AMOUNT)) (verified as ${WRITER_DOMAIN})" "${WRITER_LOG}" || fail "signed credit failed"
    grep -q "GET balance -> $((1000 + AMOUNT)) (verified as ${WRITER_DOMAIN})" "${WRITER_LOG}" || fail "final signed read failed"
    grep -q "verified POST /v1/balance/credit from ${WRITER_DOMAIN}" "${STRIPE_LOG}" || fail "server did not verify the writer domain"
    echo "✓ verify passed"
fi
