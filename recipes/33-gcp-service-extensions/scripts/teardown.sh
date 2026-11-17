#!/usr/bin/env bash
# One command down: removes everything scripts/deploy.sh created, from the state it kept, after a complete deployment,
# an interrupted one or one that failed partway, and says what it removed.
#
#   GOOGLE_CLOUD_PROJECT=<project> scripts/teardown.sh
#
# The same inputs, login and STATE_DIR as the deploy (STATE_DIR defaults to
# ~/.local/state/dnsid-gcp-service-extensions/<project>; when STATE_DIR is given, GOOGLE_CLOUD_PROJECT may be omitted).
#
# Order:
#   1. builds: every image build of this deployment that is still queued or running is cancelled and seen to stop, so
#      none can publish into the repository while it is being removed
#   2. the service stage (load balancer, policy, extension, certificate, Cloud Run services, NEGs, runtime identities)
#   3. the bootstrap stage (address, repository with its images, the build bucket with its sources and logs, the build
#      identity and its grants)
#   4. a final inventory: nothing named after the deployment may remain
# Before 2, the same inventory (and the grants on the repository and bucket) is listed and printed, so the record of
# every teardown, after a complete or a partial deployment, shows what was there as well as that nothing is left.
# Only then is the state removed. Anything that couldn't be removed or confirmed leaves the state in place, says what
# went wrong, and exits non-zero; running it again is safe and continues where it stopped.
#
# Kept on purpose: the APIs the deployment enabled stay enabled (they cost nothing and may be in use by other work).
# Not deployed resources, but history Google Cloud keeps: build records, Cloud Logging entries, and deleted service
# accounts (undeletable for 30 days). Nothing else in the project is touched: only resources in this deployment's state,
# and builds tagged with its name.
#
# Exit codes: 0 everything removed and confirmed (or nothing was deployed); 1 something remains or couldn't be confirmed
# (state kept: run it again); 2 an input, a tool or the login is missing; 3 another deploy or teardown holds STATE_DIR;
# 130/143 interrupted (state kept).
set -euo pipefail
umask 077
# The terminal's stderr, kept: an interruption can run the exit trap while a command's own redirection (such as
# `2> /dev/null`) is still in effect, and the report of what was interrupted must not go there.
exec 9>&2

DG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$DG_ROOT/scripts/lib/common.sh"

project="${GOOGLE_CLOUD_PROJECT:-}"
if [[ -n "${STATE_DIR:-}" ]]; then
  DG_STATE_DIR="$STATE_DIR"
elif [[ -n "$project" ]]; then
  dg_check_project "$project"
  DG_STATE_DIR="$(dg_default_state_dir "$project")"
else
  dg_die "GOOGLE_CLOUD_PROJECT is required (the same project you deployed to), or STATE_DIR if you set one for the deploy" 2
fi

record="$DG_STATE_DIR/deployment.json"
has_state() { [[ -s "$record" || -s "$DG_STATE_DIR/bootstrap/terraform.tfstate" || -s "$DG_STATE_DIR/service/terraform.tfstate" ]]; }
if [[ ! -d "$DG_STATE_DIR" ]] || ! has_state; then
  echo "Nothing to tear down: no deployment state in $DG_STATE_DIR."
  exit 0
fi

for tool in terraform gcloud node; do
  command -v "$tool" > /dev/null 2>&1 || dg_die "$tool is not installed (see README.md, Prerequisites)" 2
done

phase="starting"
on_exit() {
  local rc=$?
  set +e
  trap - EXIT INT TERM
  dg_auth_cleanup
  dg_unlock
  if ((rc != 0)) && [[ "$phase" != "starting" ]]; then
    echo >&9
    echo "TEARDOWN NOT COMPLETE (during: $phase, exit $rc). The state is kept in $DG_STATE_DIR." >&9
    echo "Fix what is reported above if anything is, then run scripts/teardown.sh again; it continues where it stopped." >&9
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

dg_lock "$DG_STATE_DIR"

# The deployment's name, project and region, from the record (or the stages' own variables if the record is missing).
name="" region=""
if [[ -s "$record" ]]; then
  name="$(dg_json_get "$record" name)"
  recorded_project="$(dg_json_get "$record" project)"
  region="$(dg_json_get "$record" region)"
else
  vars="$DG_STATE_DIR/bootstrap/terraform.tfvars.json"
  [[ -s "$vars" ]] || vars="$DG_STATE_DIR/service/terraform.tfvars.json"
  [[ -s "$vars" ]] || dg_die "the state in $DG_STATE_DIR has no deployment record and no stage variables; it can't be torn down safely by this script" 1
  name="$(dg_json_get "$vars" deployment_name)"
  recorded_project="$(dg_json_get "$vars" project_id)"
  region="$(dg_json_get "$vars" region)"
fi
dg_check_name "$name" || dg_die "the deployment record in $DG_STATE_DIR is damaged (no valid deployment name)" 1
if [[ -n "$project" && "$project" != "$recorded_project" ]]; then
  dg_die "STATE_DIR holds deployment $name in another project than GOOGLE_CLOUD_PROJECT; refusing" 2
fi
project="$recorded_project"
dg_check_project "$project"
dg_check_region "$region"
echo "Tearing down deployment $name in project $project, region $region (state in $DG_STATE_DIR)"

phase="authenticating"
dg_auth_setup
echo "Login: $(dg_auth_description)"

removed=()

# ---------- 1. builds ----------
phase="stopping image builds"
ledger="$DG_STATE_DIR/builds/builds.tsv"
bootstrap_resources="$(dg_tf_init bootstrap > /dev/null && dg_tf_resources bootstrap)" \
  || dg_die "the bootstrap stage's state can't be read (see $DG_STATE_DIR/bootstrap/init.log)"
if [[ -n "$bootstrap_resources" || -s "$ledger" ]]; then
  ids=()
  if [[ -s "$ledger" ]]; then
    while IFS=$'\t' read -r id _; do [[ -n "$id" ]] && ids+=("$id"); done < "$ledger"
  fi
  # Builds started for this deployment but not recorded (an interrupted submit) are found by their tag.
  errors="$DG_STATE_DIR/builds/list-errors"
  if listed="$(dg_gcloud builds list --project="$project" --region="$region" --ongoing --filter="tags=$name" --format='value(id)' 2> "$errors")"; then
    while IFS= read -r id; do [[ -n "$id" ]] && ids+=("$id"); done <<< "$listed"
  elif grep -qE 'has not been used|is disabled|SERVICE_DISABLED' "$errors"; then
    echo "Cloud Build was never enabled in this project: no builds to stop"
  else
    dg_die "the project's ongoing builds could not be listed, so a running build can't be ruled out: $(head -3 "$errors" | tr '\n' ' ')"
  fi
  if ((${#ids[@]} > 0)); then
    unconfirmed=()
    for id in $(printf '%s\n' "${ids[@]}" | sort -u); do
      [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || continue
      now="$(dg_seconds)"
      deadline=$((now + 300))
      while :; do
        status="$(dg_gcloud builds describe "$id" --project="$project" --region="$region" --format='value(status)' 2> /dev/null || true)"
        case "$status" in
          SUCCESS | FAILURE | INTERNAL_ERROR | TIMEOUT | CANCELLED | EXPIRED)
            echo "build $id: $status"
            break
            ;;
          QUEUED | PENDING | WORKING)
            dg_gcloud builds cancel "$id" --project="$project" --region="$region" > /dev/null 2>&1 || true
            ;;
        esac
        now="$(dg_seconds)"
        if ((now >= deadline)); then
          unconfirmed+=("$id (${status:-unknown})")
          break
        fi
        sleep 10
      done
    done
    ((${#unconfirmed[@]} == 0)) || dg_die "these builds could not be confirmed stopped, so nothing was removed: ${unconfirmed[*]}"
  fi
fi

# inventory CALLBACK: every kind of resource the deployment creates, listed by the deployment's name from Google's own
# APIs (not from the state), and the project-level IAM bindings naming it (the deployment grants none; this confirms
# it). Calls `CALLBACK KIND LISTING-COMMAND…` for each kind.
inventory() {
  local cb="$1" prefix="name~^$name"
  "$cb" "forwarding rules" dg_gcloud compute forwarding-rules list --project="$project" --filter="$prefix" --format='value(name)'
  "$cb" "target HTTPS proxies" dg_gcloud compute target-https-proxies list --project="$project" --filter="$prefix" --format='value(name)'
  "$cb" "URL maps" dg_gcloud compute url-maps list --project="$project" --filter="$prefix" --format='value(name)'
  "$cb" "backend services" dg_gcloud compute backend-services list --project="$project" --filter="$prefix" --format='value(name)'
  "$cb" "SSL certificates" dg_gcloud compute ssl-certificates list --project="$project" --filter="$prefix" --format='value(name)'
  "$cb" "network endpoint groups" dg_gcloud compute network-endpoint-groups list --project="$project" --filter="$prefix" --format='value(name)'
  "$cb" "addresses" dg_gcloud compute addresses list --project="$project" --filter="$prefix" --format='value(name)'
  "$cb" "authorization policies" dg_gcloud network-security authz-policies list --project="$project" --location=global --filter="name~/$name" --format='value(name)'
  "$cb" "authorization extensions" dg_gcloud service-extensions authz-extensions list --project="$project" --location=global --filter="name~/$name" --format='value(name)'
  "$cb" "Cloud Run services" dg_gcloud run services list --project="$project" --region="$region" --filter="metadata.name~^$name" --format='value(metadata.name)'
  "$cb" "Artifact Registry repositories" dg_gcloud artifacts repositories list --project="$project" --location="$region" --filter="name~/$name\$" --format='value(name)'
  "$cb" "storage buckets" dg_gcloud storage buckets list --project="$project" --filter="name~^$name" --format='value(name)'
  "$cb" "service accounts" dg_gcloud iam service-accounts list --project="$project" --filter="email~^$name" --format='value(email)'
  "$cb" "running builds" dg_gcloud builds list --project="$project" --region="$region" --ongoing --filter="tags=$name" --format='value(id)'
  "$cb" "project IAM bindings" dg_gcloud projects get-iam-policy "$project" --flatten='bindings[].members' --filter="bindings.members~$name" --format='value(bindings.role,bindings.members)'
}

# ---------- before removal: what exists, listed the same way as the final confirmation ----------
# Not a condition for removal (a listing that fails here is reported, not fatal); it makes the record of a teardown,
# after a complete or a partial deployment, show what was there as well as what is left.
phase="listing what exists"
dg_auth_refresh || true
found=()
found_before() {
  local kind="$1" output errors="$DG_STATE_DIR/inventory-errors"
  shift
  if output="$("$@" 2> "$errors")"; then
    [[ -z "$output" ]] || found+=("$kind: ${output//$'\n'/ }")
  elif grep -qE 'has not been used|is disabled|SERVICE_DISABLED' "$errors"; then
    :
  else
    unlisted_before+=("$kind: $(head -1 "$errors")")
  fi
}
unlisted_before=()
inventory found_before
# The grants the bootstrap stage makes are on its repository and bucket, so they go with them; listed here while those
# exist. A repository or bucket that doesn't exist (a partial deployment) has no grants; a policy that can't be read
# for another reason is reported as not listed, never as empty.
found_grants() {
  local kind="$1" output errors="$DG_STATE_DIR/inventory-errors"
  shift
  if output="$("$@" 2> "$errors")"; then
    [[ -z "$output" ]] || found+=("$kind: ${output//$'\n'/ }")
  elif grep -qE 'has not been used|is disabled|SERVICE_DISABLED|NOT_FOUND|not found|does not exist' "$errors"; then
    :
  else
    unlisted_before+=("$kind: $(head -1 "$errors")")
  fi
}
found_grants "grants on the repository" dg_gcloud artifacts repositories get-iam-policy "$name" --project="$project" --location="$region" --flatten='bindings[].members' --format='value(bindings.role,bindings.members)'
found_grants "grants on the build bucket" dg_gcloud storage buckets get-iam-policy "gs://$name-build" --project="$project" --flatten='bindings[].members' --format='value(bindings.role,bindings.members)'
echo "Found in $project before removal, listed by name:"
if ((${#found[@]} > 0)); then printf '  %s\n' "${found[@]}"; else echo "  nothing"; fi
if ((${#unlisted_before[@]} > 0)); then
  echo "Not listed before removal (removal goes ahead; the final confirmation still decides):"
  for entry in "${unlisted_before[@]}"; do echo "  ${entry%%: *}: could not be listed: ${entry#*: }"; done
fi

# destroy STAGE: terraform destroy with the stage's recorded variables, retried once; then the state must be empty.
destroy() {
  local stage="$1" attempt listed
  listed="$(dg_tf_resources "$stage")" || dg_die "the $stage stage's state can't be read"
  if [[ -z "$listed" ]]; then
    echo "$stage stage: nothing in its state"
    return 0
  fi
  [[ -s "$DG_STATE_DIR/$stage/terraform.tfvars.json" ]] \
    || dg_die "the $stage stage has resources in its state but its variables file is missing ($DG_STATE_DIR/$stage/terraform.tfvars.json)"
  echo "$stage stage: removing $(wc -l <<< "$listed" | tr -d ' ') resource(s)"
  for attempt in 1 2; do
    dg_auth_refresh || true
    if dg_tf "$stage" destroy -auto-approve -input=false -no-color -var-file="$DG_STATE_DIR/$stage/terraform.tfvars.json" \
      > "$DG_STATE_DIR/$stage/destroy.log" 2>&1; then
      break
    fi
    tail -25 "$DG_STATE_DIR/$stage/destroy.log" >&2
    if ((attempt == 2)); then
      dg_die "terraform destroy ($stage) failed twice (log: $DG_STATE_DIR/$stage/destroy.log)"
    fi
    echo "terraform destroy ($stage) failed; retrying once in 30 s" >&2
    sleep 30
  done
  local left
  left="$(dg_tf_resources "$stage")" || dg_die "the $stage stage's state can't be read after destroy"
  [[ -z "$left" ]] || dg_die "after destroy, the $stage stage's state still lists: ${left//$'\n'/ }"
  while IFS= read -r address; do removed+=("$stage: $address"); done <<< "$listed"
}

# ---------- 2. service, then 3. bootstrap ----------
phase="removing the service stage"
dg_tf_init service || dg_die "the service stage could not be initialized (see $DG_STATE_DIR/service/init.log)"
destroy service
phase="removing the bootstrap stage"
destroy bootstrap

# ---------- 4. the final inventory ----------
phase="confirming"
dg_auth_refresh || true
problems=()
# check KIND LISTING-COMMAND…: lists resources named after the deployment; anything listed, or a listing that fails for
# any reason but a disabled API, is a problem.
# Only the listing's standard output counts as resources: gcloud writes notes such as "Listed 0 items." to stderr.
check() {
  local kind="$1" output errors="$DG_STATE_DIR/inventory-errors"
  shift
  if output="$("$@" 2> "$errors")"; then
    [[ -z "$output" ]] || problems+=("$kind remaining: ${output//$'\n'/ }")
  elif grep -qE 'has not been used|is disabled|SERVICE_DISABLED' "$errors"; then
    : # the API was never enabled, so none can exist
  elif [[ "$kind" == "project IAM bindings" ]]; then
    # The deployment grants nothing on the project, so this listing confirms rather than finds; a login that may not
    # read the project's IAM policy is told so, and the teardown doesn't fail on it. The category is then recorded as
    # not inspected, and the confirmation doesn't name it.
    echo "Note: project IAM bindings could not be listed (the deployment grants none): $(head -1 "$errors")" >&2
    not_checked+=("$kind: $(head -1 "$errors")")
    return 0
  else
    problems+=("$kind could not be listed: $(head -2 "$errors" | tr '\n' ' ')")
  fi
  checked+=("$kind")
}
checked=() not_checked=()
inventory check
if ((${#problems[@]} > 0)); then
  printf 'NOT CONFIRMED: %s\n' "${problems[@]}" >&2
  dg_die "the deployment could not be confirmed removed"
fi

# ---------- done: the state goes ----------
phase="removing the state"
# Every list goes to node as its length then its entries.
node -e '
  const args = process.argv.slice(4), lists = [];
  while (args.length > 0) { const n = Number(args.shift()); lists.push(args.splice(0, n)); }
  const [found, notListed, removed, checked, notChecked] = lists;
  const reasons = (entries) => entries.map((e) => ({ kind: e.slice(0, e.indexOf(": ")), reason: e.slice(e.indexOf(": ") + 2) }));
  const record = {
    deployment: process.argv[2], project: process.argv[3], torn_down_at: new Date().toISOString(),
    found_before: found, not_listed_before: reasons(notListed), removed,
    checked_after: checked, not_checked_after: reasons(notChecked), remaining_after: [],
  };
  require("node:fs").writeFileSync(process.argv[1], JSON.stringify(record, null, 2) + "\n", { mode: 0o600 });
' "$DG_STATE_DIR/last-teardown.json" "$name" "$project" \
  "${#found[@]}" ${found[@]+"${found[@]}"} "${#unlisted_before[@]}" ${unlisted_before[@]+"${unlisted_before[@]}"} \
  "${#removed[@]}" ${removed[@]+"${removed[@]}"} "${#checked[@]}" ${checked[@]+"${checked[@]}"} \
  "${#not_checked[@]}" ${not_checked[@]+"${not_checked[@]}"}
rm -rf "$DG_STATE_DIR/bootstrap" "$DG_STATE_DIR/service" "$DG_STATE_DIR/builds" "$DG_STATE_DIR/deploy-out.json" "$DG_STATE_DIR/inventory-errors" "$record"
phase="done"

echo
echo "Removed deployment $name:"
if ((${#removed[@]} > 0)); then printf '  %s\n' "${removed[@]}"; else echo "  (nothing had been created)"; fi
echo "Confirmed: nothing named $name remains in $project, in what was listed:"
printf '  %s\n' "${checked[@]}"
if ((${#not_checked[@]} > 0)); then
  echo "Not inspected (recorded in $DG_STATE_DIR/last-teardown.json; this teardown doesn't confirm them):"
  for entry in "${not_checked[@]}"; do echo "  ${entry%%: *}: could not be listed: ${entry#*: }"; done
fi
echo "Kept on purpose: the enabled APIs. Kept by Google Cloud as history, not deployed: build records, logs in Cloud"
echo "Logging, and the deleted service accounts' 30-day undelete window."
