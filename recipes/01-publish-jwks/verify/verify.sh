#!/usr/bin/env bash
# One-shot check of the published identity, exactly the way a verifier sees it.
#
# Runs UNDER `dnsid local run publish` (the Makefile does this), so the
# DNSID_* environment is present: DNSID_DNS_SERVER for lookups,
# DNSID_CA_BUNDLE for TLS trust, DNSID_CONFIG_DIR for the local keypair.
#
# Checks:
#   1. `_dnsid.<domain>` TXT resolves and starts with the v= version tag
#   2. the ku= JWKS URL from the record serves a key over HTTPS
#   3. the served public JWK matches the local public JWK on disk
#   4. the su= status URL reports the identity as ACTIVE
#
# Exits nonzero on any miss.

set -euo pipefail
cd "$(dirname "$0")/.."

: "${DNSID_DNS_SERVER:?run via 'make verify' (dnsid local run injects DNSID_DNS_SERVER)}"
: "${DNSID_CA_BUNDLE:?run via 'make verify' (dnsid local run injects DNSID_CA_BUNDLE)}"
: "${DNSID_CONFIG_DIR:?run via 'make verify' (dnsid local run injects DNSID_CONFIG_DIR)}"

DOMAIN="${DNSID_DOMAIN:-publish.test}"
DNS_HOST="${DNSID_DNS_SERVER%:*}"
DNS_PORT="${DNSID_DNS_SERVER#*:}"
PORT="${DNSID_AGENT_UPSTREAM##*:}"
PORT="${PORT:-3201}"

SERVE_LOG=$(mktemp "${TMPDIR:-/tmp}/dnsid-recipe01-serve.XXXXXX")
SERVE_PID=""

fail() {
    echo "" >&2
    echo "FAIL: $1" >&2
    echo "--- local registry containers ---" >&2
    docker ps --filter "name=dnsid-local" >&2 || true
    exit 1
}

cleanup() {
    if [[ -n "${SERVE_PID}" ]]; then
        kill "${SERVE_PID}" 2>/dev/null || true
        wait "${SERVE_PID}" 2>/dev/null || true
    fi
    rm -f "${SERVE_LOG}"
}
trap cleanup EXIT

# Resolve a URL's host with the local registry DNS and fetch it over TLS, the same
# two steps any DNSid verifier performs.
fetch() {
    local url="$1"
    local host ip
    host=$(python3 -c "from urllib.parse import urlparse; import sys; print(urlparse(sys.argv[1]).hostname)" "${url}")
    ip=$(dig "@${DNS_HOST}" -p "${DNS_PORT}" A "${host}" +short | head -n 1)
    [[ -n "${ip}" ]] || return 1
    curl -sf --cacert "${DNSID_CA_BUNDLE}" --resolve "${host}:443:${ip}" "${url}"
}

# ---------------------------------------------------------------------------
# 0. Serve our JWKS (the ku= URL routes here through the TLS proxy)
# ---------------------------------------------------------------------------
python3 -u src/serve.py >"${SERVE_LOG}" 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 30); do
    curl -sf "http://localhost:${PORT}/.well-known/jwks.json" >/dev/null 2>&1 && break
    kill -0 "${SERVE_PID}" 2>/dev/null || { cat "${SERVE_LOG}" >&2; fail "JWKS server exited early"; }
    sleep 0.5
done

# ---------------------------------------------------------------------------
# 1. The binding: _dnsid.<domain> TXT
# ---------------------------------------------------------------------------
# A freshly published record takes a couple of seconds to appear (the local registry
# DNS reloads its zone periodically) — retry before declaring failure.
txt=""
for _ in $(seq 1 30); do
    txt=$(dig "@${DNS_HOST}" -p "${DNS_PORT}" "_dnsid.${DOMAIN}" TXT +short | tr -d '" ' )
    [[ -n "${txt}" ]] && break
    sleep 1
done
[[ -n "${txt}" ]] || fail "_dnsid.${DOMAIN} TXT did not resolve within 30s"
echo "--- TXT record ---"
echo "${txt}"
echo ""

case "${txt}" in
    v=dnsid*) ;;
    *) fail "_dnsid TXT record does not start with a v= version tag" ;;
esac

ku=$(printf '%s\n' "${txt}" | tr ';' '\n' | sed -n 's/^ku=//p' | head -n 1)
su=$(printf '%s\n' "${txt}" | tr ';' '\n' | sed -n 's/^su=//p' | head -n 1)
[[ -n "${ku}" ]] || fail "_dnsid TXT record does not contain ku="
[[ -n "${su}" ]] || fail "_dnsid TXT record does not contain su="

# ---------------------------------------------------------------------------
# 2. The keys: follow ku= over HTTPS
# ---------------------------------------------------------------------------
# The A record propagates on the same zone-reload cadence as the TXT record.
jwks=""
for _ in $(seq 1 30); do
    jwks=$(fetch "${ku}" 2>/dev/null) && break
    jwks=""
    sleep 1
done
[[ -n "${jwks}" ]] || fail "could not fetch JWKS from ${ku} within 30s"
echo "--- JWKS (from ${ku}) ---"
printf '%s\n' "${jwks}" | python3 -m json.tool
echo ""

# ---------------------------------------------------------------------------
# 3. The public key in DNS-land matches the public JWK on disk
# ---------------------------------------------------------------------------
served_kid=$(printf '%s' "${jwks}" | python3 -c '
import json, os, sys
from pathlib import Path

served = json.load(sys.stdin)["keys"][0]
local = json.loads((Path(os.environ["DNSID_CONFIG_DIR"]) / "public.jwk").read_text())
if served != local:
    sys.exit("served public JWK does not match local public JWK")
print(served["kid"])
') || fail "JWKS does not contain the expected local public key"

# ---------------------------------------------------------------------------
# 4. Live status: follow su=
# ---------------------------------------------------------------------------
status=$(fetch "${su}") || fail "could not fetch status from ${su}"
printf '%s' "${status}" | grep -q '"state":"ACTIVE"' \
    || fail "status document does not report ACTIVE: ${status}"

echo ""
echo "✓ binding resolved"
echo "✓ JWKS reachable at ${ku}"
echo "✓ public JWK matches local keypair (kid ${served_kid})"
echo "✓ status: ACTIVE"
