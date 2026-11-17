#!/usr/bin/env bash
# One command up: deploys DNSid verification in front of Demo Bank on a Google Cloud global external Application Load
# Balancer, from nothing.
#
#   GOOGLE_CLOUD_PROJECT=<project> scripts/deploy.sh
#
# Inputs (the quick start's, and nothing else):
#   GOOGLE_CLOUD_PROJECT       required: an existing project with billing enabled
#   GOOGLE_CLOUD_REGION        optional, default us-central1: where Cloud Run, the repository and the build run
#   DNSID_TRUSTED_GOVERNANCE   optional, default dnsid-sandbox.io when unset (set but empty is refused): the governance
#                              IDs the edge trusts, comma-separated
# Login: `gcloud auth application-default login`, or a short-lived token in GOOGLE_OAUTH_ACCESS_TOKEN and/or
# CLOUDSDK_AUTH_ACCESS_TOKEN_FILE (scripts/lib/common.sh). Never a key file.
# Where things go (defaulted, so nobody has to set them):
#   STATE_DIR    default ~/.local/state/dnsid-gcp-service-extensions/<project>: the deployment's name, both Terraform
#                stages' state (which holds the certificate's private key), build records. Private, and refused inside
#                this directory.
#   DEPLOY_OUT   default $STATE_DIR/deploy-out.json: what scripts/test-live.sh needs (lib/deploy-out.ts).
#
# Steps, each recorded in STATE_DIR so a rerun resumes and scripts/teardown.sh can always remove what exists:
#   1. bootstrap (infra/bootstrap): APIs, the reserved address, the image repository, the build's identity and bucket
#   2. images: Cloud Build builds both images, checks them (scripts/container-smoke.sh) and publishes them; their
#      digests go to the next step
#   3. service (infra/service): both Cloud Run services, the load balancer, the self-signed certificate for the address,
#      the authorization extension and its CUSTOM policy
#   4. the inventory of the project's load-balancing configuration, for the live tests
#   5. ready: waits until unsigned GETs of /accounts over TLS pinned to the deployment's certificate, sent in bursts of
#      ready_burst at once, each on its own connection, get the verifier's own 403 on every probe for ready_stable_s in
#      a row (a new load balancer's configuration reaches its front ends over minutes, and until it has, some requests
#      get its 500 or 502). Once Demo Bank itself has answered one (the authorization policy not yet in force on some
#      front end), the policy must hold for ready_after_bypass_s instead. Only then is DEPLOY_OUT written (atomically)
#
# Exit codes: 0 deployed and answering; 1 a step failed (everything created so far is in STATE_DIR: run
# scripts/teardown.sh); 2 an input, a tool or the login is missing; 3 another deploy or teardown holds STATE_DIR;
# 130/143 interrupted.
set -euo pipefail
umask 077
# The terminal's stderr, kept: an interruption can run the exit trap while a command's own redirection (such as
# `2> /dev/null`) is still in effect, and the report of what was interrupted must not go there.
exec 9>&2

DG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$DG_ROOT/scripts/lib/common.sh"
# shellcheck source=scripts/lib/build-context.sh
source "$DG_ROOT/scripts/lib/build-context.sh"

project="${GOOGLE_CLOUD_PROJECT:-}"
region="${GOOGLE_CLOUD_REGION:-us-central1}"
# The default applies only when the variable is absent: a value that is set but empty (or only spaces and commas) is a
# broken configuration, refused by dg_check_governance, never quietly replaced by the sandbox's trust.
governance="${DNSID_TRUSTED_GOVERNANCE-dnsid-sandbox.io}"
[[ -n "$project" ]] || dg_die "GOOGLE_CLOUD_PROJECT is required: the Google Cloud project to deploy into (it must exist, with billing enabled)" 2
dg_check_project "$project"
dg_check_region "$region"
dg_check_governance "$governance"

DG_STATE_DIR="${STATE_DIR:-$(dg_default_state_dir "$project")}"
deploy_out="${DEPLOY_OUT:-$DG_STATE_DIR/deploy-out.json}"

build_timeout_s=2700  # Cloud Build's own timeout is 1,800 s (cloudbuild.yaml); this adds queueing time
ready_timeout_s=1800  # a new global load balancer and certificate usually answer within a few minutes
poll_s=10
# The first denial isn't readiness: the first live deployment to come up (2026-11-14) answered its first probe with the verifier's
# 403, and for about 40 s after that some requests still got the load balancer's 500 or 502 (the authorization policy
# and backends still reaching its front ends). Every probe in this window, each on a new connection, must be the
# verifier's denial; any other answer starts it again.
ready_stable_s=180
ready_stable_poll_s=5
# The authorization policy isn't in force everywhere when it is first seen: on the eighth live deployment (2026-11-14)
# Demo Bank itself answered two readiness probes, the hold of single probes then passed 120 s, and about a minute later
# one of Google's front ends still forwarded a signed request to Demo Bank without the policy (about 12 minutes after
# the policy was created). So each round is a burst of probes on new connections, to reach more front ends, and once
# Demo Bank has answered any probe the policy must hold for ready_after_bypass_s from that answer. The attestation
# (x-dnsid-attestation) keeps such a request from being served as anyone; this wait keeps the live tests from meeting it.
ready_burst=8
ready_after_bypass_s=600

for tool in terraform gcloud node; do
  command -v "$tool" > /dev/null 2>&1 || dg_die "$tool is not installed (see README.md, Prerequisites)" 2
done
node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a > 24 || (a === 24 && b >= 22) ? 0 : 1)' \
  || dg_die "Node.js 24.22 or later is required (found $(node --version))" 2

dg_prepare_state_dir "$DG_STATE_DIR" "$DG_ROOT"
mkdir -p "$(dirname "$deploy_out")"
record="$DG_STATE_DIR/deployment.json"
phase="starting"
started="$(dg_seconds)"

on_exit() {
  local rc=$?
  set +e
  trap - EXIT INT TERM
  dg_auth_cleanup
  dg_unlock
  if ((rc != 0)) && [[ "$phase" != "starting" ]]; then
    echo >&9
    echo "DEPLOY FAILED during: $phase (exit $rc)." >&9
    echo "Everything created so far is recorded in $DG_STATE_DIR." >&9
    echo "  Retry (resumes):  scripts/deploy.sh      Remove it all:  scripts/teardown.sh" >&9
    echo "  (with the same GOOGLE_CLOUD_PROJECT, and STATE_DIR if you set one)" >&9
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

dg_lock "$DG_STATE_DIR"

if [[ -s "$record" ]]; then
  name="$(dg_json_get "$record" name)"
  recorded_project="$(dg_json_get "$record" project)"
  recorded_region="$(dg_json_get "$record" region)"
  dg_check_name "$name" || dg_die "$record is damaged: run scripts/teardown.sh, or use another STATE_DIR" 1
  if [[ "$recorded_project" != "$project" || "$recorded_region" != "$region" ]]; then
    dg_die "STATE_DIR already holds deployment $name in another project or region; tear it down first (scripts/teardown.sh) or use another STATE_DIR" 2
  fi
  created_at="$(dg_json_get "$record" created_at)"
  echo "Resuming deployment $name (state in $DG_STATE_DIR)"
else
  name="$(dg_new_name)"
  dg_check_name "$name" || dg_die "could not generate a deployment name" 1
  created_at="$(dg_now)"
  echo "New deployment $name (state in $DG_STATE_DIR)"
fi
save_phase() {
  phase="$1"
  dg_write_record "$record" name="$name" project="$project" region="$region" governance="$governance" \
    created_at="$created_at" phase="$1" updated_at="$(dg_now)"
}
save_phase "authenticating"
echo "Project $project, region $region, trusted governance $governance"

dg_auth_setup
echo "Login: $(dg_auth_description)"

step_started=0
took_bootstrap=0 took_images=0 took_service=0 took_inventory=0 took_ready=0
begin() {
  save_phase "$1"
  step_started="$(dg_seconds)"
  echo
  echo "== $1"
}
end() {
  local now
  now="$(dg_seconds)"
  printf -v "took_$1" '%s' "$((now - step_started))"
}

# enable_denied LOG: the APIs a failed apply was refused permission to enable, one per line (Terraform names each
# failed resource in a `with` line); fails when there is no such refusal.
enable_denied() {
  grep -q 'serviceusage\.services\.enable' "$1" || return 1
  sed -nE 's/^[[:space:]]*with google_project_service\.required\["([a-z0-9.-]+)"\].*/\1/p' "$1" | sort -u | grep .
}

# apply STAGE: terraform apply, retried once (newly enabled APIs can take a minute to accept requests). A refusal to
# enable an API is not retried: the permission won't appear by itself, and the remedy is printed instead.
apply() {
  local stage="$1" attempt
  dg_tf_init "$stage" || return 1
  for attempt in 1 2; do
    if dg_tf "$stage" apply -auto-approve -input=false -no-color -var-file="$DG_STATE_DIR/$stage/terraform.tfvars.json" \
      > "$DG_STATE_DIR/$stage/apply.log" 2>&1; then
      grep -E '^Apply complete' "$DG_STATE_DIR/$stage/apply.log" || true
      dg_tf "$stage" output -no-color -json > "$DG_STATE_DIR/$stage/outputs.json"
      return 0
    fi
    tail -25 "$DG_STATE_DIR/$stage/apply.log" >&2
    local denied
    if denied="$(enable_denied "$DG_STATE_DIR/$stage/apply.log")"; then
      {
        echo
        echo "The login may not enable these APIs in project $project (permission serviceusage.services.enable):"
        sed 's/^/  /' <<< "$denied"
        echo "Someone who may (the project's Owner, or Service Usage Admin) enables them once:"
        echo "  gcloud services enable $(tr '\n' ' ' <<< "$denied")--project=$project"
        echo "Then run scripts/deploy.sh again; it resumes. (Not retried now: a missing permission doesn't appear by itself.)"
      } >&2
      return 1
    fi
    if ((attempt == 1)); then
      echo "terraform apply ($stage) failed; retrying once in 30 s" >&2
      sleep 30
      dg_auth_refresh || true
    fi
  done
  return 1
}

out() { node "$DG_ROOT/scripts/lib/deploy-tool.ts" output "$DG_STATE_DIR/$1/outputs.json" "$2"; }

# ---------- 1. bootstrap ----------
begin bootstrap
node -e 'process.stdout.write(JSON.stringify({ project_id: process.argv[1], region: process.argv[2], deployment_name: process.argv[3] }, null, 2) + "\n")' \
  "$project" "$region" "$name" > "$DG_STATE_DIR/bootstrap/terraform.tfvars.json"
apply bootstrap || dg_die "the bootstrap stage failed (log: $DG_STATE_DIR/bootstrap/apply.log)"
repository="$(out bootstrap repository_url)"
bucket="$(out bootstrap build_bucket)"
build_account="$(out bootstrap build_service_account)"
end bootstrap

# ---------- 2. images ----------
begin images
dg_auth_refresh || dg_die "the Application Default Credentials no longer give a token: run gcloud auth application-default login" 2
context="$DG_STATE_DIR/builds/context"
rm -rf "$context" && mkdir -p "$context"
assemble_build_context "$DG_ROOT" "$context" || dg_die "the build context could not be assembled"
fingerprint="$(node "$DG_ROOT/scripts/lib/deploy-tool.ts" fingerprint "$context")"
images_file="$DG_STATE_DIR/builds/images.json"
ledger="$DG_STATE_DIR/builds/builds.tsv"
touch "$ledger"

describe_build() {
  dg_gcloud builds describe "$1" --project="$project" --region="$region" --format=json > "$DG_STATE_DIR/builds/$1.json"
}
wait_for_build() {
  local id="$1" deadline status
  now="$(dg_seconds)"
  deadline=$((now + build_timeout_s))
  while :; do
    describe_build "$id" || { echo "could not read build $id" >&2; return 1; }
    status="$(node "$DG_ROOT/scripts/lib/deploy-tool.ts" build-status "$DG_STATE_DIR/builds/$id.json")"
    case "$status" in
      SUCCESS | FAILURE | INTERNAL_ERROR | TIMEOUT | CANCELLED | EXPIRED) break ;;
    esac
    now="$(dg_seconds)"
    if ((now >= deadline)); then
      echo "build $id is still $status after ${build_timeout_s}s; cancelling it" >&2
      dg_gcloud builds cancel "$id" --project="$project" --region="$region" > /dev/null || true
      return 1
    fi
    sleep 15
    dg_auth_refresh || true
  done
  echo "build $id: $status"
  [[ "$status" == SUCCESS ]] && return 0
  echo "The image build did not succeed. Its log: gs://$bucket/logs/log-$id.txt (last lines below)" >&2
  dg_gcloud storage cat "gs://$bucket/logs/log-$id.txt" 2> /dev/null | tail -40 >&2 || true
  return 1
}

images=""
if [[ -s "$images_file" && "$(dg_json_get "$images_file" fingerprint)" == "$fingerprint" ]]; then
  images="$(cat "$images_file")"
  echo "The images for this source were already built and published: reusing them"
else
  # A build recorded for this same source that was interrupted or is still running is waited for, not repeated.
  last="$(awk -F'\t' -v f="$fingerprint" '$2 == f { line = $0 } END { print line }' "$ledger")"
  if [[ -n "$last" ]]; then
    IFS=$'\t' read -r id _ verifier_tagged origin_tagged <<< "$last"
    echo "Waiting for build $id, started earlier for this source"
    if wait_for_build "$id"; then
      images="$(node "$DG_ROOT/scripts/lib/deploy-tool.ts" build-images "$DG_STATE_DIR/builds/$id.json" "$verifier_tagged" "$origin_tagged")"
    fi
  fi
  if [[ -z "$images" ]]; then
    attempt=$(($(wc -l < "$ledger") + 1))
    tag="${fingerprint:0:12}-$attempt"
    verifier_tagged="$repository/verifier:$tag"
    origin_tagged="$repository/origin:$tag"
    echo "Submitting the image build (source ${fingerprint:0:12}, attempt $attempt)"
    id="$(dg_gcloud builds submit "$context" --project="$project" --region="$region" --config="$context/cloudbuild.yaml" \
      --service-account="projects/$project/serviceAccounts/$build_account" \
      --gcs-source-staging-dir="gs://$bucket/source" --gcs-log-dir="gs://$bucket/logs" \
      --substitutions="_VERIFIER_IMAGE=$verifier_tagged,_ORIGIN_IMAGE=$origin_tagged,_DEPLOYMENT=$name" \
      --async --format='value(id)')" || dg_die "the image build could not be submitted"
    [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || dg_die "the image build was submitted but no build id came back"
    printf '%s\t%s\t%s\t%s\n' "$id" "$fingerprint" "$verifier_tagged" "$origin_tagged" >> "$ledger"
    echo "Build $id (log: gs://$bucket/logs/log-$id.txt)"
    wait_for_build "$id" || dg_die "the image build failed"
    images="$(node "$DG_ROOT/scripts/lib/deploy-tool.ts" build-images "$DG_STATE_DIR/builds/$id.json" "$verifier_tagged" "$origin_tagged")" \
      || dg_die "the build's published image digests could not be read"
  fi
  node -e 'const i = JSON.parse(process.argv[1]); process.stdout.write(JSON.stringify({ ...i, fingerprint: process.argv[2] }, null, 2) + "\n")' \
    "$images" "$fingerprint" > "$images_file.tmp" && mv "$images_file.tmp" "$images_file"
fi
verifier_image="$(dg_json_get "$images_file" verifier)"
origin_image="$(dg_json_get "$images_file" origin)"
echo "verifier image: $verifier_image"
echo "origin image:   $origin_image"
rm -rf "$context"
end images

# ---------- 3. service ----------
begin service
node -e '
  const [project_id, region, deployment_name, trusted_governance, address_name, address, verifier_image, origin_image] = process.argv.slice(1);
  process.stdout.write(JSON.stringify({ project_id, region, deployment_name, trusted_governance, address_name, address, verifier_image, origin_image }, null, 2) + "\n");
' "$project" "$region" "$name" "$governance" "$(out bootstrap address_name)" "$(out bootstrap address)" "$verifier_image" "$origin_image" \
  > "$DG_STATE_DIR/service/terraform.tfvars.json"
dg_auth_refresh || true
apply service || dg_die "the service stage failed (log: $DG_STATE_DIR/service/apply.log)"
end service

# ---------- 4. inventory ----------
begin inventory
dg_auth_refresh || true
listings="$DG_STATE_DIR/service/listings"
rm -rf "$listings" && mkdir -p "$listings"
inventory_file="$DG_STATE_DIR/service/inventory.json"
if dg_gcloud compute forwarding-rules list --project="$project" --format=json > "$listings/forwarding-rules.json" \
  && dg_gcloud compute target-https-proxies list --project="$project" --format=json > "$listings/target-https-proxies.json" \
  && dg_gcloud compute target-http-proxies list --project="$project" --format=json > "$listings/target-http-proxies.json" \
  && dg_gcloud compute url-maps list --project="$project" --format=json > "$listings/url-maps.json" \
  && dg_gcloud compute backend-services list --project="$project" --format=json > "$listings/backend-services.json" \
  && dg_gcloud compute network-endpoint-groups list --project="$project" --format=json > "$listings/network-endpoint-groups.json" \
  && dg_gcloud network-security authz-policies list --project="$project" --location=global --format=json > "$listings/authz-policies.json" \
  && node "$DG_ROOT/scripts/lib/deploy-tool.ts" inventory "$listings" deploy.sh > "$inventory_file"; then
  echo "Recorded the project's forwarding rules, proxies, URL maps, backend services and authorization policies"
else
  dg_warn "the load-balancing inventory could not be taken; the live tests will need the platform login to take it themselves"
  node -e 'process.stdout.write(JSON.stringify({ error: "the inventory could not be taken at deployment", takenAt: new Date().toISOString() }))' > "$inventory_file"
fi
end inventory

# ---------- 5. ready ----------
begin ready
endpoint="$(out service endpoint)"
out service certificate_pem > "$DG_STATE_DIR/service/certificate.pem"
pin="$(node "$DG_ROOT/scripts/lib/deploy-tool.ts" cert-fingerprint "$DG_STATE_DIR/service/certificate.pem")"
echo "Endpoint $endpoint, certificate SHA-256 $pin"
echo "Waiting for unsigned GETs of /accounts over pinned TLS, ${ready_burst} at a time, to get the verifier's 403 on every probe for ${ready_stable_s}s in a row (${ready_after_bypass_s}s once Demo Bank has answered one; up to ${ready_timeout_s}s)"
now="$(dg_seconds)"
deadline=$((now + ready_timeout_s))
last_report=0
stable_since=""
stable_probes=0
hold_s="$ready_stable_s"
bypasses=0
while :; do
  code=0
  detail="$(node "$DG_ROOT/scripts/lib/deploy-tool.ts" ready "$endpoint" "$DG_STATE_DIR/service/certificate.pem" "$pin" /accounts 10000 "$ready_burst" 2>&1)" || code=$?
  now="$(dg_seconds)"
  if ((code == 0)); then
    if [[ -z "$stable_since" ]]; then
      stable_since="$now"
      echo "  first denials ($((now - started))s): $detail; now every probe for ${hold_s}s must be one"
    fi
    stable_probes=$((stable_probes + ready_burst))
    if ((now - stable_since >= hold_s)); then
      echo "Ready: $detail ($stable_probes denials in a row over $((now - stable_since))s; Demo Bank answered $bypasses earlier probe round(s))"
      break
    fi
    wait_s="$ready_stable_poll_s"
  else
    if ((code == 3)); then
      bypasses=$((bypasses + 1))
      hold_s="$ready_after_bypass_s"
      echo "  the authorization policy is not in force yet ($((now - started))s): Demo Bank answered an unsigned request: $detail; once it holds, every probe for ${hold_s}s must be the verifier's denial"
      last_report="$now"
    elif [[ -n "$stable_since" ]]; then
      echo "  not steady yet ($((now - started))s): after $stable_probes denial(s) in a row: $detail"
      last_report="$now"
    elif ((now - last_report >= 60)); then
      echo "  not yet ($((now - started))s): $detail"
      last_report="$now"
    fi
    stable_since=""
    stable_probes=0
    wait_s="$poll_s"
  fi
  if ((now >= deadline)); then
    dg_die "the endpoint did not answer unsigned requests with the verifier's denial steadily for ${hold_s}s within ${ready_timeout_s}s (last: $detail)"
  fi
  sleep "$wait_s"
done
end ready

# ---------- DEPLOY_OUT ----------
save_phase "writing DEPLOY_OUT"
now="$(dg_seconds)"
total=$((now - started))
node -e '
  const fs = require("node:fs");
  const [dir, governance, started, total, bootstrap, images, service, inventory, ready] = process.argv.slice(1);
  const read = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
  const imageRecord = read(`${dir}/builds/images.json`);
  const inputs = {
    bootstrap: read(`${dir}/bootstrap/outputs.json`),
    service: read(`${dir}/service/outputs.json`),
    images: { verifier: imageRecord.verifier, origin: imageRecord.origin },
    inventory: read(`${dir}/service/inventory.json`),
    governance,
    timing: { started_at: started, total_s: Number(total), bootstrap_s: Number(bootstrap), images_s: Number(images),
      service_s: Number(service), inventory_s: Number(inventory), ready_s: Number(ready) },
  };
  fs.writeFileSync(`${dir}/deploy-out-inputs.json`, JSON.stringify(inputs), { mode: 0o600 });
' "$DG_STATE_DIR" "$governance" "$(date -u -d "@$started" +%Y-%m-%dT%H:%M:%SZ 2> /dev/null || date -u -r "$started" +%Y-%m-%dT%H:%M:%SZ)" "$total" \
  "$took_bootstrap" "$took_images" "$took_service" "$took_inventory" "$took_ready"
node "$DG_ROOT/scripts/lib/deploy-tool.ts" deploy-out "$DG_STATE_DIR/deploy-out-inputs.json" "$deploy_out" || dg_die "DEPLOY_OUT could not be written"
rm -f "$DG_STATE_DIR/deploy-out-inputs.json"
save_phase "ready"

echo
echo "Deployed $name in ${total}s (bootstrap ${took_bootstrap}s, images ${took_images}s, service ${took_service}s, ready ${took_ready}s)."
echo "  Endpoint:   $endpoint/accounts (self-signed certificate, SHA-256 $pin)"
echo "  DEPLOY_OUT: $deploy_out"
echo "  Live tests: DEPLOY_OUT=$deploy_out DNSID_AGENT_ID=<agent> DNSID_AGENT_KEY_FILE=<key file> scripts/test-live.sh"
echo "  Remove it:  scripts/teardown.sh"
