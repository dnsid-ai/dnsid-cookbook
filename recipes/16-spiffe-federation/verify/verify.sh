#!/usr/bin/env bash
# The three acts, end to end, against the running stack (`make bootstrap` first; the Makefile does this).
#
#   make verify   asserts every expected result and exits nonzero on any miss (DNSID_RECIPE_ASSERT=1)
#   make run      same flow, human-watchable, assertions reported but not fatal (DNSID_RECIPE_ASSERT=0)
#
# Act 3 PERMANENTLY revokes the current federation signer identity (a disposable identity under
# rackloria.test, not Rackloria's organization). A revoked signer is never reused or replaced, so a second
# run in the same environment stops at bootstrap (SIGNER UNUSABLE). To repeat the lifecycle, use a fresh
# clone or `make clean CONFIRM=delete-checkpoint-history`.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../scripts/lib.sh
. "$(dirname "$0")/../scripts/lib.sh"
trap 'printf "ERROR unexpected failure at verify/verify.sh:%s\n" "$LINENO" >&2; dump_logs' ERR

ASSERT=${DNSID_RECIPE_ASSERT:-1}
AUDIT="$STATE/controller/data/audit.jsonl"
HELD_SECONDS=${HELD_SECONDS:-12}
FAILED=0

pass() { printf '  PASS %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; FAILED=$((FAILED+1)); }
check() { # check DESCRIPTION CMD... : one assertion
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi
}
# shellcheck disable=SC2329  # invoked through check()
is() { [ "$1" = "$2" ]; }
act() { printf '\n%s\n%s\n' "$*" "------------------------------------------------------------------------------"; }

# pf EXPR : evaluate EXPR over the latest purchasing probe JSON (held in $P)
pf() { printf '%s' "$P" | json "$1"; }
supplier_allow() { curl -sf --max-time 5 "$(url supplier)/status" | json 'd["authz"]["allow"]'; }
supplier_last()  { curl -sf --max-time 5 "$(url supplier)/status" | json 'd["authz"]["last"]'; }
dj() { printf '%s' "$D" | json "$1" 2>/dev/null || echo "?"; }   # field of the latest controller decision

# ------------------------------------------------------------------ starting point (before Act 1)
info "preparing the starting point"
controller_up || die "the controller is not running: run make bootstrap"
st=$(curl -sf "$(url controller)/status" | json 'str(d["checkpoint_store"]["healthy"])')
[ "$st" = True ] || die "the controller's trusted checkpoint store is unhealthy: $(curl -sf "$(url controller)/status" | json 'd["checkpoint_store"]["failure"]')"
if [ -n "$(dc ps -aq rackloria-publisher 2>/dev/null)" ]; then dc rm -sf rackloria-publisher >/dev/null 2>&1; fi
ok "Rackloria is not publishing a federation binding"
admin_post /rebootstrap >/dev/null || die "controller rebootstrap failed"
ok "Acme's controller holds no Rackloria bundle and no trust anchors"
curl -sf -X POST "$(url purchasing)/held/reset" >/dev/null || true
converge fail 45 || die "purchasing still trusts rackloria.test after the reset"
signer=$(id_step "federation signer" ensure-active) || exit 1   # reuse only; never issues or replaces
identity publisher-env "$STATE/dnsid/publisher.env" "$STATE/dnsid/signer" >/dev/null || die "publisher env failed"
ok "federation signer for this run: $signer (ACTIVE)"

# ------------------------------------------------------------------ Act 1
act "Act 1 - SPIFFE works inside Acme; Rackloria is not trusted yet"
P=$(probe) || die "purchasing probe failed"
check "Acme internal mTLS: purchasing -> inventory succeeds (SPIFFE authentication within acme.test)" \
  is "$(pf 'str(d["results"]["inventory"]["new_handshake"]["ok"])')" True
D=$(admin_post /reconcile) || die "controller did not answer"
say "  controller decision: $(printf '%s' "$D" | json 'd["decision"] + " " + d["action"] + " " + d["reason"]')"
check "controller does not ALLOW before Rackloria publishes" \
  sh -c "[ \"$(printf '%s' "$D" | json 'd["decision"]')\" != ALLOW ]"
check "Acme's SPIRE holds no rackloria.test bundle (cross-domain federation unavailable)" \
  is "$(acme_bundle_state)" absent
P=$(probe) || die "purchasing probe failed"
check "new cross-domain connection purchasing -> supplier fails at the SPIFFE layer (handshake)" \
  is "$(pf '"%s/%s" % (d["results"]["supplier"]["new_handshake"]["ok"], d["results"]["supplier"]["new_handshake"].get("layer"))')" "False/SPIFFE"

# ------------------------------------------------------------------ Act 2
act "Act 2 - Rackloria publishes signed federation evidence; Acme verifies it and federates"
mark=$(audit_len)
dc up -d --wait rackloria-publisher || die "binding publisher did not become healthy"
wait_until 60 "Rackloria's binding to be signed" sh -c "curl -sf $(url publisher)/status | grep -q '\"statement\": {'"
PUB=$(curl -sf "$(url publisher)/status")
say "  binding signed by: $(printf '%s' "$PUB" | json 'd["signer"]')"
say "  covers X.509 CA key(s): $(printf '%s' "$PUB" | json '", ".join(d["statement"]["x509_authorities_spki_sha256"])')"
check "Rackloria publishes a binding signed by this run's signer" is "$(printf '%s' "$PUB" | json 'd["signer"]')" "$signer"
say "  waiting for Acme's controller to verify on its own (polls every 5 s; usually 10-40 s)"
if D=$("$PY" -I "$ROOT/scripts/wait_decision.py" "$AUDIT" "$mark" 120 ALLOW DENY); then :; else
  fail "no controller decision within 120 s: $D"; D='{}'
fi
pins=$(tr -d '\n' < "$STATE/dnsid/pins.json")
say "  controller decision: $(dj 'd["decision"] + " " + d["action"] + " " + d["reason"]')"
check "controller ALLOWs and installs the bundle (its own background cycle)" is "$(dj 'd["decision"] + ":" + d["action"]')" "ALLOW:INSTALLED"
check "[DNSid] signer identity verified and allowed by policy (spire-fed-*.rackloria.test)" is "$(dj 'd["evidence"]["signer"]')" "$signer"
check "[DNSid] governance ID is the pinned organization rackloria.test" is "$(dj 'd["evidence"]["governance_id"]')" rackloria.test
check "[DNSid] record-signing entity key matches Acme's pin" \
  is "$(dj "str(d['evidence']['entity_key_thumbprint'] in $pins)")" True
check "[DNSid] registry status ACTIVE (checked live this cycle)" is "$(dj 'd["evidence"]["status_service"]["state"]')" ACTIVE
check "[C2SP] lifecycle log shows ACTIVE" is "$(dj 'd["evidence"]["logged_state"]')" ACTIVE
check "[C2SP] witness-cosigned checkpoint is fresh (age <= 300 s, not in the future beyond skew)" \
  is "$(dj 'str(-60 <= d["evidence"]["evidence_age_s"] <= 300)')" True
check "[coverage] every served CA key is in the signed set" \
  is "$(dj 'str(set(d["installed_spki"]) <= set(d["statement"]["spki"]) and len(d["installed_spki"]) > 0)')" True
check "Acme's SPIRE now holds the rackloria.test bundle" is "$(acme_bundle_state)" present
converge ok 40 || fail "the SPIRE agent did not deliver the bundle to purchasing within 40 s"
a0=$(supplier_allow)
P=$(probe) || die "purchasing probe failed"
check "new cross-domain connection purchasing -> supplier succeeds" is "$(pf 'str(d["results"]["supplier"]["new_handshake"]["ok"])')" True
check "[AuthZ] evaluated separately: supplier's own allow-list admitted spiffe://acme.test/purchasing" \
  sh -c "[ \"$(supplier_last)\" = 'allow spiffe://acme.test/purchasing' ] && [ $(supplier_allow) -gt $a0 ]"
# Open the long-lived connection now, so Act 3 can show what withdrawal does to established sessions.
curl -sf -X POST "$(url purchasing)/held/reset" >/dev/null
probe >/dev/null; P=$(probe) || die "purchasing probe failed"
check "a long-lived TLS connection to the supplier is open and reused" \
  is "$(pf '"%s/%s" % (d["results"]["supplier"]["held_connection"]["ok"], d["results"]["supplier"]["held_connection"].get("reused"))')" "True/True"

# ------------------------------------------------------------------ Act 3
act "Act 3 - Rackloria's federation signer is revoked; Acme withdraws trust on its own"
mark=$(audit_len)
R=$(identity revoke --yes) || die "revocation failed"
say "  revoked federation signer $signer after $(printf '%s' "$R" | json 'd.get("confirmed_after_s", "?")') s (Rackloria's organization and entity key are unchanged)"
check "registry reports the signer REVOKED" is "$(identity state "$signer")" REVOKED
if D=$("$PY" -I "$ROOT/scripts/wait_decision.py" "$AUDIT" "$mark" 90 DENY:WITHDRAWN); then :; else
  fail "controller did not withdraw within 90 s: $D"; D='{}'
fi
say "  controller decision: $(dj 'd["decision"] + " " + d["action"] + " " + d["reason"]') (after $(dj 'd["_waited_s"]') s)"
check "controller detects the lifecycle change and WITHDRAWS (DENY, IDENTITY_NOT_ACTIVE)" \
  is "$(dj 'd["decision"] + ":" + d["action"] + ":" + d["reason"]')" "DENY:WITHDRAWN:IDENTITY_NOT_ACTIVE"
check "Acme's SPIRE no longer holds the rackloria.test bundle" is "$(acme_bundle_state)" absent
converge fail 40 || fail "purchasing kept accepting new handshakes after withdrawal"
P=$(probe) || die "purchasing probe failed"
check "new cross-domain connection fails at the SPIFFE layer" \
  is "$(pf '"%s/%s" % (d["results"]["supplier"]["new_handshake"]["ok"], d["results"]["supplier"]["new_handshake"].get("layer"))')" "False/SPIFFE"
check "Acme internal mTLS still succeeds" is "$(pf 'str(d["results"]["inventory"]["new_handshake"]["ok"])')" True

# The connection opened in Act 2, reported as three separate observations.
say ""
say "  The TLS connection opened in Act 2, before the withdrawal (observed for ${HELD_SECONDS} s):"
a0=$(supplier_allow); n=0; tls_ok=1; app_ok=1; t0=$(date +%s)
while [ $(( $(date +%s) - t0 )) -lt "$HELD_SECONDS" ]; do
  P=$(probe) || die "purchasing probe failed"
  n=$((n+1))
  [ "$(pf 'str(d["results"]["supplier"]["held_connection"].get("reused"))')" = True ] || tls_ok=0
  [ "$(pf '"%s/%s" % (d["results"]["supplier"]["held_connection"]["ok"], d["results"]["supplier"]["held_connection"].get("status"))')" = "True/200" ] || app_ok=0
  sleep 1
done
a1=$(supplier_allow)
check "(1) TLS: the established connection REMAINS ESTABLISHED (single dial, reused on all $n probes)" is "$tls_ok" 1
check "(2) application messages CONTINUE over it (HTTP 200 on all $n requests)" is "$app_ok" 1
check "(3) [AuthZ] the supplier still authorizes each request on it, against the identity presented at handshake" \
  sh -c "[ $a1 -ge $((a0 + n)) ] && [ \"$(supplier_last)\" = 'allow spiffe://acme.test/purchasing' ]"
say "      Withdrawal stops NEW handshakes. Acme's trust decision about Rackloria is made at handshake time;"
say "      DNSid does not terminate established TLS sessions. Ending them is the application's connection policy."
curl -sf -X POST "$(url purchasing)/held/reset" >/dev/null
P=$(probe) || die "purchasing probe failed"
check "control: once that connection is closed, reconnecting fails at the SPIFFE layer" \
  is "$(pf '"%s/%s" % (d["results"]["supplier"]["held_connection"]["ok"], d["results"]["supplier"]["held_connection"].get("layer"))')" "False/SPIFFE"

# ------------------------------------------------------------------ result
say ""
if [ "$FAILED" -eq 0 ]; then
  say "All checks passed."
  exit 0
fi
say "$FAILED check(s) failed."
if [ "$ASSERT" = 1 ]; then die "verify failed"; fi
exit 0
