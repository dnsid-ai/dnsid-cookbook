#!/usr/bin/env bash
# make bootstrap: bring up everything the three acts need. Idempotent; safe to re-run.
#   1. the DNSid local registry, through the dnsid CLI only (isolated --state inside this recipe)
#   2. two SPIRE trust domains (acme.test, rackloria.test), their agents, entries and workloads
#   3. Acme's DNSid federation controller, with its policy, pins, log trust policy and checkpoint store
# Rackloria's binding publisher is NOT started here: publishing is Act 2.
set -euo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(dirname "$0")/lib.sh"
trap 'printf "ERROR unexpected failure at scripts/bootstrap.sh:%s\n" "$LINENO" >&2; dump_logs' ERR

info "Compose project ${PROJECT} (per-checkout; scripts/paths.py)"
legacy_stack_check || die "LEGACY STACK: another Compose project of this recipe is running (see above); nothing was started"
ok "no running containers of the legacy project ${LEGACY_PROJECT} (or it was selected explicitly)"

info "DNSid local registry (dnsid CLI, state: ${DNSID_LOCAL_STATE#"$ROOT"/})"
dnsid local up --zone test --state "$DNSID_LOCAL_STATE" \
  --registry-port "$DNSID_LOCAL_REGISTRY_PORT" --dns-port "$DNSID_LOCAL_DNS_PORT" \
  --proxy-port "$DNSID_LOCAL_PROXY_PORT" >/dev/null || die "dnsid local up failed"
ok "local registry up"

info "Python environment and image inputs"
(cd "$ROOT" && uv sync --frozen -q) || die "uv sync failed"
mkdir -p "$STATE/acme/bootstrap" "$STATE/rackloria/bootstrap" "$STATE/dnsid" "$STATE/controller/data" "$STATE/build"
chmod 750 "$STATE" "$STATE/dnsid" "$STATE/controller"
chmod 2770 "$STATE/controller/data"   # the controller (uid 1000, in the host user's group) writes here
set_env_var HOST_GID "$(id -g)"
(cd "$ROOT" && uv export --frozen --no-dev --group image-build --no-emit-project --format requirements-txt \
  -q -o "$STATE/build/requirements.txt") || die "uv export failed"
ok "dependencies exported from uv.lock (hash-pinned; dnsid at its locked commit)"

info "building images (SPIRE 1.15.5, go-spiffe v2.9.0, dnsidfed)"
dc build -q || die "image build failed"

info "SPIRE servers: two independent trust domains"
dc up -d --wait acme-server rackloria-server || die "SPIRE servers did not become healthy"
for org in acme rackloria; do
  spire_server $org bundle show > "$STATE/$org/bootstrap/bundle.crt" || die "bundle show ($org) failed"
done
ok "agent bootstrap bundles written (each agent trusts only its own server)"
if ! spire_server rackloria bundle list -id spiffe://acme.test >/dev/null 2>&1; then
  spire_server acme bundle show -format spiffe | spire_server rackloria bundle set -format spiffe -id spiffe://acme.test >/dev/null \
    || die "seeding Acme's bundle into Rackloria failed"
fi
ok "Rackloria trusts Acme through standard SPIFFE federation (not DNSid-gated)"

info "SPIRE agents (join-token node attestation)"
for org in acme rackloria; do
  cid=$(dc ps -q "$org-agent" 2>/dev/null || true)
  if [ -n "$cid" ] && [ "$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid" 2>/dev/null)" = healthy ]; then
    ok "$org agent already attested"
  else
    tok=$(spire_server $org token generate -spiffeID "spiffe://$org.test/node/agent" -ttl 600 | awk '{print $2}')
    [ -n "$tok" ] || die "join token generation failed ($org)"
    set_env_var "$(printf '%s' "$org" | tr '[:lower:]' '[:upper:]')_JOIN_TOKEN" "$tok"
    ok "$org join token minted (stored in .state/compose.env)"
  fi
done
dc up -d --wait acme-agent rackloria-agent || die "SPIRE agents did not become healthy"

# ensure_entry (scripts/lib.sh): verified-idempotent; never overwrites or deletes a registration.
ensure_entry acme spiffe://acme.test/inventory 10002
ensure_entry acme spiffe://acme.test/purchasing 10001
ensure_entry rackloria spiffe://rackloria.test/supplier-api 10003 spiffe://acme.test

info "workloads"
dc up -d --wait acme-inventory rackloria-supplier-api acme-purchasing || die "workloads did not become healthy"
wait_until 60 "purchasing to receive its SVID" sh -c "curl -sf $(url purchasing)/status | grep -q spiffe://acme.test/purchasing"
ok "purchasing holds spiffe://acme.test/purchasing"

info "DNSid layer: Acme's federation controller"
nd=$(dnsid_local_network) || die "could not find a unique in-network resolver for this recipe's local registry"
set_env_var DNSID_LOCAL_NETWORK "${nd%% *}"
set_env_var DNSID_COMPOSE_DNS "${nd#* }:53"
ca=$(id_step "local registry environment" local-env DNSID_CA_BUNDLE) || exit 1
[ -s "$ca" ] || die "local registry root CA missing: $ca"
set_env_var DNSID_ROOT_CA "$ca"
# Reuses the existing signer only once it is verified ACTIVE; never replaces one. --first-enrollment lets a
# first install (no signer, pin, checkpoint store or registry signer yet) issue the first one.
signer=$(id_step "federation signer" ensure-active --first-enrollment) || exit 1
ok "Rackloria federation signer: $signer (ACTIVE)"
# Setup-time trust captures for Acme. Pinned once; never refetched per cycle. In this recipe both come from
# the local registry (trust on first use); production obtains them out of band.
[ -s "$STATE/dnsid/log-policy.txt" ] || id_step "log policy capture" log-policy "$STATE/dnsid/log-policy.txt" >/dev/null
if [ -s "$STATE/dnsid/pins.json" ]; then
  # Restart: reuse the preserved pin, and refuse if the local registry's state was replaced underneath it.
  id_step "preserved entity-key pin check" pin --check "$STATE/dnsid/pins.json" >/dev/null
else
  id_step "entity-key pin capture" pin "$STATE/dnsid/pins.json" >/dev/null
fi
chmod 644 "$STATE/dnsid/log-policy.txt"
ok "pinned Rackloria entity key: $(tr -d '[]" \n' < "$STATE/dnsid/pins.json")"
sed -e "s|__PINS__|$(tr -d '\n' < "$STATE/dnsid/pins.json")|" -e "s|__DNS__|${nd#* }:53|" \
  "$ROOT/config/federation-policy.template.toml" > "$STATE/controller/policy.toml"
chmod 644 "$STATE/controller/policy.toml"
if [ ! -s "$STATE/controller/admin-token" ]; then
  "$PY" -I -c 'import secrets; print(secrets.token_urlsafe(32))' > "$STATE/controller/admin-token"
fi
chmod 640 "$STATE/controller/admin-token"

# Trusted C2SP checkpoints: initialized ONCE, explicitly, on first install only. The controller never creates
# its own store. If the store is missing but its journal shows an earlier initialization, that is a loss,
# not a first start, and bootstrap stops (see README, "Recovering the checkpoint store").
out=$(dc run --rm --no-deps acme-dnsid-controller dnsidfed.checkpoints ensure-initialized \
      --state-dir /var/lib/dnsidfed) \
  || die "CHECKPOINT STORE: the trusted checkpoint store is missing, damaged or could not be checked; refusing to continue (see message above and README, \"Recovering the checkpoint store\")"
case "$out" in
  *'"initialized"'*) ok "trusted checkpoint store initialized (first install)" ;;
  *)                 ok "trusted checkpoint store preserved (history kept across restarts)" ;;
esac
start_controller   # scripts/lib.sh: keeps / starts / recreates only on a stale DNSid Local network
ok "controller enforcing"
info "bootstrap complete"
