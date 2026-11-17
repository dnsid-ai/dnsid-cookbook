# shellcheck shell=bash
# What scripts/deploy.sh and scripts/teardown.sh share: input checks, the state directory, the lock, authentication,
# and Terraform and gcloud run the same way every time. Sourced, never run.
#
# Authentication is the platform's ordinary login, never a key file:
#   - Application Default Credentials (`gcloud auth application-default login`): Terraform reads them itself. gcloud
#     keeps separate credentials (`gcloud auth login`), which a reader may not have; instead it is given a short-lived
#     access token minted from the same Application Default Credentials, in a private file
#     (CLOUDSDK_AUTH_ACCESS_TOKEN_FILE), refreshed before each long step.
#   - Or a short-lived token supplied by automation: GOOGLE_OAUTH_ACCESS_TOKEN (Terraform) and/or
#     CLOUDSDK_AUTH_ACCESS_TOKEN_FILE (gcloud). Either one is enough: the other is derived from it.
# A token is never printed, never put in a command's arguments, and never written outside a private temporary directory
# that is removed on exit.

# A deployment's unique name: every resource it creates is named from it.
dg_check_name() { [[ "$1" =~ ^dnsid-gse-[0-9a-f]{8}$ ]]; }
dg_new_name() { printf 'dnsid-gse-%s\n' "$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"; }

dg_say() { printf '%s\n' "$*"; }
dg_warn() { printf 'warning: %s\n' "$*" >&2; }
dg_die() {
  printf 'error: %s\n' "$1" >&2
  exit "${2:-1}"
}
dg_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
dg_seconds() { date +%s; }

# ---------- inputs ----------

dg_check_project() {
  [[ "$1" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || dg_die "GOOGLE_CLOUD_PROJECT is not a Google Cloud project ID (6 to 30 lowercase letters, digits or hyphens, starting with a letter)" 2
}

dg_check_region() {
  [[ "$1" =~ ^[a-z]+-[a-z]+[0-9]+$ ]] || dg_die "GOOGLE_CLOUD_REGION is not a Google Cloud region name (for example us-central1)" 2
}

# The same shape the verifier accepts for each governance ID: a domain name with at least two labels whose last label
# isn't all digits, at most 253 characters. The verifier checks it again at startup.
dg_check_governance() {
  local value="$1" item label='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
  [[ -n "${value//[[:space:],]/}" ]] || dg_die "DNSID_TRUSTED_GOVERNANCE is empty: leave it unset for the default, or name at least one governance ID" 2
  local IFS=','
  for item in $value; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    item="$(printf '%s' "$item" | tr '[:upper:]' '[:lower:]')"
    if ((${#item} > 253)) || ! [[ "$item" =~ ^($label\.)+$label$ ]] || [[ "${item##*.}" =~ ^[0-9]+$ ]]; then
      dg_die "DNSID_TRUSTED_GOVERNANCE has an entry that isn't a governance ID (a domain name such as dnsid-sandbox.io)" 2
    fi
  done
}

# ---------- the state directory ----------

# The default keeps a deployment's state with the person who made it, outside the repository, one directory per project.
dg_default_state_dir() { printf '%s/.local/state/dnsid-gcp-service-extensions/%s\n' "$HOME" "$1"; }

# dg_prepare_state_dir DIR ROOT: creates DIR (private) and refuses a location inside the integration's own tree, so
# state, the certificate's key and tokens can never be committed or uploaded with the build.
dg_prepare_state_dir() {
  local dir="$1" root="$2" existing rest="" resolved
  # Resolved through its nearest existing ancestor, so nothing is created before the location is checked.
  [[ "$dir" == /* ]] || dir="$PWD/$dir"
  existing="$dir"
  while [[ ! -d "$existing" ]]; do
    rest="/$(basename "$existing")$rest"
    existing="$(dirname "$existing")"
  done
  resolved="$(cd "$existing" && pwd -P)$rest"
  case "$resolved/" in
    "$(cd "$root" && pwd -P)/"*) dg_die "STATE_DIR must be outside the integration's directory: Terraform state holds the certificate's private key" 2 ;;
  esac
  mkdir -p "$dir" || dg_die "cannot create STATE_DIR"
  chmod 700 "$dir" || dg_die "cannot make STATE_DIR private"
  mkdir -p "$dir/bootstrap" "$dir/service" "$dir/builds" && chmod 700 "$dir/bootstrap" "$dir/service" "$dir/builds"
}

# A JSON value from a state file (node: no jq needed). Prints nothing for a missing key.
dg_json_get() {
  node -e '
    const [file, key] = process.argv.slice(1);
    let value;
    try { value = JSON.parse(require("node:fs").readFileSync(file, "utf8"))[key]; } catch { process.exit(1); }
    if (value !== undefined && value !== null) process.stdout.write(typeof value === "string" ? value : JSON.stringify(value));
  ' "$1" "$2"
}

# dg_write_record FILE KEY=VALUE…: writes a flat JSON object atomically (temporary file, then rename).
dg_write_record() {
  local file="$1"
  shift
  node -e '
    const fs = require("node:fs");
    const [file, ...pairs] = process.argv.slice(1);
    const record = {};
    for (const pair of pairs) { const at = pair.indexOf("="); record[pair.slice(0, at)] = pair.slice(at + 1); }
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(record, null, 2) + "\n", { mode: 0o600 });
    fs.renameSync(tmp, file);
  ' "$file" "$@"
}

# ---------- one command at a time per STATE_DIR ----------

dg_lock() {
  local dir="$1/.lock" holder
  if mkdir "$dir" 2> /dev/null; then
    printf '%s\n' "$$" > "$dir/pid"
    DG_LOCK_DIR="$dir"
    return 0
  fi
  holder="$(cat "$dir/pid" 2> /dev/null || true)"
  if [[ "$holder" =~ ^[0-9]+$ ]] && kill -0 "$holder" 2> /dev/null; then
    dg_die "another deploy or teardown (process $holder) is using this STATE_DIR; wait for it, or stop it first" 3
  fi
  dg_warn "taking over a lock left by a process that is no longer running"
  printf '%s\n' "$$" > "$dir/pid"
  DG_LOCK_DIR="$dir"
}

dg_unlock() {
  [[ -z "${DG_LOCK_DIR:-}" ]] || rm -rf "$DG_LOCK_DIR"
  DG_LOCK_DIR=""
}

# ---------- authentication ----------

# dg_auth_setup: decides how Terraform and gcloud authenticate, without a key file and without a second login.
dg_auth_setup() {
  local flags="$-"
  set +x
  DG_AUTH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dnsid-gse-auth.XXXXXX")" || dg_die "cannot create a private temporary directory"
  chmod 700 "$DG_AUTH_DIR"
  export CLOUDSDK_CORE_DISABLE_PROMPTS=1
  if [[ -n "${CLOUDSDK_AUTH_ACCESS_TOKEN_FILE:-}" ]]; then
    [[ -r "$CLOUDSDK_AUTH_ACCESS_TOKEN_FILE" ]] || dg_die "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE names a file that can't be read" 2
    if [[ -z "${GOOGLE_OAUTH_ACCESS_TOKEN:-}" ]]; then
      local token=""
      IFS= read -r token < "$CLOUDSDK_AUTH_ACCESS_TOKEN_FILE" || true
      [[ -n "$token" ]] || dg_die "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE is empty" 2
      export GOOGLE_OAUTH_ACCESS_TOKEN="$token"
      unset token
    fi
    DG_AUTH_MODE=token
  elif [[ -n "${GOOGLE_OAUTH_ACCESS_TOKEN:-}" ]]; then
    (umask 077 && printf '%s' "$GOOGLE_OAUTH_ACCESS_TOKEN" > "$DG_AUTH_DIR/token")
    export CLOUDSDK_AUTH_ACCESS_TOKEN_FILE="$DG_AUTH_DIR/token"
    DG_AUTH_MODE=token
  else
    DG_AUTH_MODE=adc
    dg_auth_refresh || dg_die "no Google Cloud login: run \`gcloud auth application-default login\` (or supply a short-lived token in GOOGLE_OAUTH_ACCESS_TOKEN or CLOUDSDK_AUTH_ACCESS_TOKEN_FILE)" 2
    export CLOUDSDK_AUTH_ACCESS_TOKEN_FILE="$DG_AUTH_DIR/token"
  fi
  [[ "$flags" != *x* ]] || set -x
}

# With Application Default Credentials, mints a fresh token for gcloud (they last an hour). A no-op for a supplied token.
dg_auth_refresh() {
  [[ "${DG_AUTH_MODE:-}" == adc ]] || return 0
  local flags="$-"
  set +x
  (umask 077 && env -u CLOUDSDK_AUTH_ACCESS_TOKEN_FILE gcloud auth application-default print-access-token > "$DG_AUTH_DIR/token.next" 2> /dev/null) \
    && [[ -s "$DG_AUTH_DIR/token.next" ]] && mv -f "$DG_AUTH_DIR/token.next" "$DG_AUTH_DIR/token"
  local rc=$?
  rm -f "$DG_AUTH_DIR/token.next"
  [[ "$flags" != *x* ]] || set -x
  return "$rc"
}

dg_auth_description() {
  if [[ "${DG_AUTH_MODE:-}" == adc ]]; then echo "Application Default Credentials"; else echo "a short-lived access token"; fi
}

dg_auth_cleanup() {
  [[ -z "${DG_AUTH_DIR:-}" ]] || rm -rf "$DG_AUTH_DIR"
  DG_AUTH_DIR=""
}

# ---------- Terraform ----------

# dg_tf STAGE ARGS…: Terraform on infra/STAGE, with its working data under STATE_DIR (nothing is written in the tree).
dg_tf() {
  local stage="$1"
  shift
  TF_DATA_DIR="$DG_STATE_DIR/$stage/tfdata" TF_IN_AUTOMATION=1 TF_INPUT=0 terraform -chdir="$DG_ROOT/infra/$stage" "$@"
}

# dg_tf_init STAGE: the stage's local backend at its own explicit path under STATE_DIR, providers exactly as locked.
dg_tf_init() {
  dg_tf "$1" init -input=false -no-color -lockfile=readonly -reconfigure \
    -backend-config="path=$DG_STATE_DIR/$1/terraform.tfstate" > "$DG_STATE_DIR/$1/init.log" 2>&1 || {
    tail -20 "$DG_STATE_DIR/$1/init.log" >&2
    return 1
  }
}

# The resources in a stage's state, one address per line; nothing when there is no state yet.
# Fails (non-zero) when the state exists but can't be read.
dg_tf_resources() {
  [[ -s "$DG_STATE_DIR/$1/terraform.tfstate" ]] || return 0
  local listed
  listed="$(dg_tf "$1" state list -no-color)" || return 1
  grep -v '^data\.' <<< "$listed" || true
}

# ---------- gcloud ----------

dg_gcloud() { gcloud --quiet --verbosity=error "$@"; }
