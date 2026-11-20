# Shared helpers for scripts/bootstrap.sh and verify/verify.sh. Sourced, not executed. bash 3.2 compatible.
#
# Required environment (exported by the Makefile): DNSID_LOCAL_STATE, DNSID_LOCAL_REGISTRY_PORT,
# DNSID_LOCAL_DNS_PORT, DNSID_LOCAL_PROXY_PORT.

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STATE="$ROOT/.state"
PY="$ROOT/.venv/bin/python"
export RECIPE_STATE="$STATE"
# This checkout's Compose project (scripts/paths.py: derived from the canonical recipe path, or the validated
# RECIPE16_COMPOSE_PROJECT override). Exported for compose.yaml, which names the project and images after it.
PROJECT=$(python3 -I "$ROOT/scripts/paths.py" project "${RECIPE16_COMPOSE_PROJECT:-}") || exit 2
export RECIPE16_COMPOSE_PROJECT="$PROJECT"
LEGACY_PROJECT=dnsid-recipe16
: "${DNSID_LOCAL_STATE:?run through make}" "${DNSID_LOCAL_REGISTRY_PORT:?run through make}" \
  "${DNSID_LOCAL_DNS_PORT:?run through make}"
# Only this recipe's own local registry state, by its canonical path, never a symlink or another instance.
python3 -I "$ROOT/scripts/paths.py" check-state "$DNSID_LOCAL_STATE" || exit 2

say()  { printf '%s\n' "$*"; }
info() { printf '\n==> %s\n' "$*"; }
ok()   { printf '  ok   %s\n' "$*"; }
warn() { printf '  WARN %s\n' "$*" >&2; }
die()  { printf 'ERROR %s\n' "$*" >&2; dump_logs; exit 1; }

# identity_reason CODE : the failure category for an identity.py exit code (EXIT_* in scripts/identity.py).
# identity.py has already printed the specific cause on stderr; this names the class of problem.
identity_reason() {
  case $1 in
    2)  echo "CONFIGURATION: invalid recipe configuration or input" ;;
    3)  echo "REFUSED: the operation was deliberately refused" ;;
    10) echo "RESOLVER: this recipe's own DNS resolver could not be established (mismatch, wrong instance or unavailable)" ;;
    11) echo "REGISTRY UNCERTAIN: no definite answer from this recipe's local registry (timeout or unreachable); nothing was created or replaced" ;;
    12) echo "SIGNER UNUSABLE: the federation signer is revoked, retired, missing or not reusable; signers are never replaced automatically" ;;
    13) echo "MALFORMED RECORD: the signer's _dnsid record or the entity-key document is missing or malformed" ;;
    14) echo "GOVERNANCE MISMATCH: the published gi= is not the configured governance identity" ;;
    15) echo "ENTITY-KEY MISMATCH: the served entity key does not match the preserved pin" ;;
    *)  echo "unexpected failure (exit $1)" ;;
  esac
}

# id_step WHAT ARGS... : run `identity.py ARGS` (stdout passes through); on failure, die with the named category.
id_step() {
  local what=$1 rc=0
  shift
  identity "$@" || rc=$?
  [ "$rc" = 0 ] || die "$what - $(identity_reason "$rc")"
}

# Container state and logs for a failed run (the CLI-managed local registry and this recipe's stack).
dump_logs() {
  [ "${DUMPED:-0}" = 1 ] && return 0
  DUMPED=1
  command -v docker >/dev/null 2>&1 || return 0
  {
    say "--- local registry containers"
    docker ps -a --filter "label=com.docker.compose.project.working_dir=$DNSID_LOCAL_STATE" 2>&1 || true
    docker ps -a --filter name=dnsid-local 2>&1 || true
    say "--- recipe containers"
    docker compose -p "$PROJECT" ps -a 2>&1 || true
    local c
    for c in $(docker ps -aq --filter "label=com.docker.compose.project.working_dir=$DNSID_LOCAL_STATE" 2>/dev/null) \
             $(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null); do
      say "=== docker logs $c"
      docker logs --tail 80 "$c" 2>&1 || true
    done
  } >&2
}

# docker compose, scoped to THIS recipe's project only.
dc() {
  if [ -f "$STATE/compose.env" ]; then
    docker compose -p "$PROJECT" --project-directory "$ROOT" -f "$ROOT/compose.yaml" --env-file "$STATE/compose.env" "$@"
  else
    docker compose -p "$PROJECT" --project-directory "$ROOT" -f "$ROOT/compose.yaml" "$@"
  fi
}

spire_server() { # spire_server ORG ARGS... : spire-server CLI against ORG's own admin socket
  local org=$1; shift
  dc exec -T "$org-server" /opt/spire/bin/spire-server "$@" -socketPath /run/spire/server/api.sock
}

identity() { "$PY" -I "$ROOT/scripts/identity.py" "$@"; }

# entry_check ORG SPIFFE_ID UID [FEDERATES_WITH] : compare ORG's registration for SPIFFE_ID with the expected one.
# Returns spire_entry.py's code (0 match, 10 confirmed missing, 20 mismatch, 21 ambiguous, 22 unreadable), or 30
# if the lookup itself failed. The whole lookup is captured first and handed over without a pipeline, so an
# early-exiting reader (grep -q under pipefail) can never turn a present entry into an "absent" one.
entry_check() {
  local org=$1 id=$2 uid=$3 fed=${4:-} out rc=0
  out=$(spire_server "$org" entry show -spiffeID "$id" -output json 2>/dev/null) || rc=$?
  if [ "$rc" != 0 ]; then
    printf '  SPIRE entry lookup for %s failed (exit %s)\n' "$id" "$rc" >&2
    return 30
  fi
  set -- check --spiffe-id "$id" --parent "spiffe://$org.test/node/agent" --selector "unix:uid:$uid"
  if [ -n "$fed" ]; then set -- "$@" --federates-with "$fed"; fi
  python3 -I "$ROOT/scripts/spire_entry.py" "$@" <<<"$out" >/dev/null || return $?
}

# ensure_entry ORG SPIFFE_ID UID [FEDERATES_WITH] : idempotent registration. Creates the entry only when its
# absence is confirmed; accepts an existing entry only when every security-relevant field matches. Never
# overwrites or deletes an entry.
ensure_entry() {
  local org=$1 id=$2 uid=$3 fed=${4:-} rc=0 out
  entry_check "$org" "$id" "$uid" "$fed" || rc=$?
  case $rc in
    0)  ok "entry $id (existing registration verified)"; return 0 ;;
    10) ;;
    *)  die "SPIRE REGISTRATION: could not confirm the registration for $id (code $rc, see above); nothing was changed" ;;
  esac
  set -- entry create -parentID "spiffe://$org.test/node/agent" -spiffeID "$id" -selector "unix:uid:$uid"
  if [ -n "$fed" ]; then set -- "$@" -federatesWith "$fed"; fi
  rc=0
  out=$(spire_server "$org" "$@" 2>&1) || rc=$?
  if [ "$rc" = 0 ]; then ok "entry $id -> unix:uid:$uid (created)"; return 0; fi
  case $out in
    *AlreadyExists*) ;;
    *) die "SPIRE REGISTRATION: failed to create entry $id (exit $rc): $(printf '%s' "$out" | tail -n 1)" ;;
  esac
  # It appeared between the lookup and the create (or the lookup was wrong): look again, accept only an exact match.
  rc=0
  entry_check "$org" "$id" "$uid" "$fed" || rc=$?
  [ "$rc" = 0 ] || die "SPIRE REGISTRATION: $id already exists but does not match the expected registration (code $rc, see above); it was not modified"
  ok "entry $id (already present; verified matching)"
}

# json EXPR : evaluate a Python expression over the JSON document on stdin (`d`); print the result.
json() { "$PY" -I -c "import json,sys; d=json.load(sys.stdin); r=($1); print(r if isinstance(r,str) else json.dumps(r))"; }

set_env_var() { # set_env_var NAME VALUE : in .state/compose.env (mode 600, never printed)
  local f="$STATE/compose.env"
  touch "$f"; chmod 600 "$f"
  grep -v "^$1=" "$f" > "$f.tmp" 2>/dev/null || true
  printf '%s=%s\n' "$1" "$2" >> "$f.tmp"; mv "$f.tmp" "$f"; chmod 600 "$f"
}

wait_until() { # wait_until SECONDS DESCRIPTION CMD...
  local secs=$1 desc=$2 i=0; shift 2
  while [ $i -lt "$secs" ]; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1; i=$((i+1))
  done
  die "timed out after ${secs}s waiting for: $desc"
}

url() { # url SERVICE : host-side status endpoint
  case $1 in
    purchasing) echo "http://127.0.0.1:${RECIPE16_PURCHASING_PORT:-18080}" ;;
    inventory)  echo "http://127.0.0.1:${RECIPE16_INVENTORY_PORT:-18081}" ;;
    supplier)   echo "http://127.0.0.1:${RECIPE16_SUPPLIER_PORT:-18082}" ;;
    controller) echo "http://127.0.0.1:${RECIPE16_CONTROLLER_PORT:-18085}" ;;
    publisher)  echo "http://127.0.0.1:${RECIPE16_PUBLISHER_PORT:-18090}" ;;
  esac
}

# legacy_stack_check : refuse to start this checkout's project while containers of the LEGACY project
# (`dnsid-recipe16`, used by every checkout before per-checkout names) are running: they hold the same host
# ports. Never stops, modifies or removes them; it says how to manage them explicitly. Read-only.
legacy_stack_check() {
  local running
  [ "$PROJECT" = "$LEGACY_PROJECT" ] && return 0
  running=$(docker ps -q --filter "label=com.docker.compose.project=$LEGACY_PROJECT") \
    || { printf '  could not list containers of the legacy project %s\n' "$LEGACY_PROJECT" >&2; return 1; }
  [ -z "$running" ] && return 0
  printf '  %s container(s) of the legacy Compose project %s are running and hold the same host ports.\n' \
    "$(printf '%s\n' "$running" | grep -c .)" "$LEGACY_PROJECT" >&2
  printf '  This checkout now uses its own project, %s. Manage the legacy stack explicitly, for example:\n' "$PROJECT" >&2
  printf '    RECIPE16_COMPOSE_PROJECT=%s make stop      (non-destructive; keeps its volumes and state)\n' "$LEGACY_PROJECT" >&2
  return 1
}

# dnsid_local_network : print "NETWORK IP" for the in-network resolver of THIS recipe's local registry.
# The CLI runs the local registry as a Compose project whose working-dir label is the --state directory.
# Never guesses by name: exactly one running DNS container with that label, on exactly one network that
# belongs to the same Compose project.
dnsid_local_network() {
  local ids proj nets net ip nproj
  ids=$(docker ps -q --filter status=running \
        --filter "label=com.docker.compose.project.working_dir=$DNSID_LOCAL_STATE" \
        --filter label=com.docker.compose.service=dns-compose)
  [ -n "$ids" ] && [ "$(printf '%s\n' "$ids" | grep -c .)" = 1 ] || return 1
  proj=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$ids") || return 1
  nets=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{$v.IPAddress}}{{"\n"}}{{end}}' "$ids" | grep .)
  [ "$(printf '%s\n' "$nets" | grep -c .)" = 1 ] || return 1
  net=${nets%% *}; ip=${nets#* }
  nproj=$(docker network inspect -f '{{index .Labels "com.docker.compose.project"}}' "$net") || return 1
  [ "$nproj" = "$proj" ] && [ -n "$ip" ] || return 1
  printf '%s %s\n' "$net" "$ip"
}

# dnsid_local_project : Compose project of THIS recipe's running DNSid Local (from its dns-compose container).
dnsid_local_project() {
  local ids
  ids=$(docker ps -q --filter status=running \
        --filter "label=com.docker.compose.project.working_dir=$DNSID_LOCAL_STATE" \
        --filter label=com.docker.compose.service=dns-compose) || return 1
  [ -n "$ids" ] && [ "$(printf '%s\n' "$ids" | grep -c .)" = 1 ] || return 1
  docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$ids"
}

# service_inspection SERVICE : sets SVC_NET, SVC_LPROJ, NET_JSON, CTR_JSON for THIS recipe's SERVICE container
# (non-one-off) and its DNSid Local network. Returns nonzero if anything cannot be inspected.
service_inspection() {
  local svc=$1 nd ids
  nd=$(dnsid_local_network) || { printf '  cannot identify this recipe DNSid Local network\n' >&2; return 1; }
  SVC_NET=${nd%% *}
  SVC_LPROJ=$(dnsid_local_project) && [ -n "$SVC_LPROJ" ] \
    || { printf '  cannot identify this recipe DNSid Local Compose project\n' >&2; return 1; }
  NET_JSON=$(docker network inspect "$SVC_NET") || { printf '  network inspection failed: %s\n' "$SVC_NET" >&2; return 1; }
  ids=$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" \
        --filter "label=com.docker.compose.service=$svc" --filter label=com.docker.compose.oneoff=False) \
    || { printf '  container listing failed for %s\n' "$svc" >&2; return 1; }
  if [ -z "$ids" ]; then
    CTR_JSON='[]'
  else
    # shellcheck disable=SC2086  # one ID per line
    CTR_JSON=$(docker inspect $ids) || { printf '  container inspection failed for %s\n' "$svc" >&2; return 1; }
  fi
}

# service_plan SERVICE : prints keep | start | recreate (reason on stderr); nonzero when uncertain.
service_plan() {
  service_inspection "$1" || return 1
  NET_JSON=$NET_JSON CTR_JSON=$CTR_JSON python3 -I "$ROOT/scripts/dnsid_service.py" plan --service "$1" \
    --project "$PROJECT" --working-dir "$ROOT" --network "$SVC_NET" --local-project "$SVC_LPROJ"
}

# start_controller : start Acme's controller on the CURRENT DNSid Local network. Keeps a running healthy
# controller untouched; recreates ONLY a stopped controller that references a previous network (its state is
# bind-mounted under .state/); fails closed on any uncertainty. Then verifies the resulting container.
start_controller() {
  local action ca summary
  action=$(service_plan acme-dnsid-controller) \
    || die "CONTROLLER CONTAINER: ownership, state or network could not be established (see above); nothing was changed"
  case $action in
    keep)
      ok "controller already running and healthy on the current DNSid Local network (not restarted)" ;;
    start)
      dc up -d --wait acme-dnsid-controller || die "controller did not become healthy" ;;
    recreate)
      say "  NOTE recreating the stopped controller container: DNSid Local recreated its Docker network, and the old container still references the previous one. State is bind-mounted and kept."
      dc up -d --wait --force-recreate --no-deps acme-dnsid-controller \
        || die "CONTROLLER CONTAINER: recreation failed (see above); state under .state/ is untouched" ;;
    *)
      die "CONTROLLER CONTAINER: unexpected plan '$action'" ;;
  esac
  ca=$(grep '^DNSID_ROOT_CA=' "$STATE/compose.env" | cut -d= -f2-) || die "DNSID_ROOT_CA missing from .state/compose.env"
  service_inspection acme-dnsid-controller || die "CONTROLLER CONTAINER: post-start inspection failed"
  summary=$(NET_JSON=$NET_JSON CTR_JSON=$CTR_JSON python3 -I "$ROOT/scripts/dnsid_service.py" verify-controller \
    --project "$PROJECT" --working-dir "$ROOT" --network "$SVC_NET" --local-project "$SVC_LPROJ" --root-ca "$ca") \
    || die "CONTROLLER CONTAINER: the running controller does not match the expected configuration (see above)"
  ok "controller container verified: $summary"
}

controller_up() { curl -sf -o /dev/null --max-time 3 "$(url controller)/healthz"; }
admin_post() { # admin_post PATH : the controller's POST endpoints need the admin token
  curl -sf --max-time 60 -X POST -H "X-Admin-Token: $(cat "$STATE/controller/admin-token")" "$(url controller)$1"
}
probe() { curl -sf --max-time 20 -X POST "$(url purchasing)/probe"; }
audit_len() { local f="$STATE/controller/data/audit.jsonl"; if [ -f "$f" ]; then wc -l < "$f" | tr -d ' '; else echo 0; fi; }

# acme_bundle_state : present | absent | error for Acme's rackloria.test bundle (read-only). An inspection
# failure is never mistaken for "absent".
acme_bundle_state() {
  local err
  if err=$(spire_server acme bundle list -id spiffe://rackloria.test 2>&1 >/dev/null); then echo present; return; fi
  case "$err" in *NotFound*|*"not found"*) echo absent ;; *) echo error ;; esac
}

# converge ok|fail SECONDS : wait until purchasing's NEW handshakes to the supplier match. The SPIRE agent
# pushes bundle changes to workloads asynchronously (typically 3-10 s).
converge() {
  local want=$1 secs=${2:-40} t0; t0=$(date +%s)
  while [ $(( $(date +%s) - t0 )) -lt "$secs" ]; do
    if probe | "$PY" -I -c "import json,sys
r=json.load(sys.stdin)['results']['supplier']['new_handshake']
sys.exit(0 if (r['ok'] if '$want'=='ok' else (not r['ok'] and r.get('layer')=='SPIFFE')) else 1)" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}
