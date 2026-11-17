#!/usr/bin/env bash
# Local tests: no cloud, no credentials, no portal agents. Exits non-zero on any failure.
#
# Coverage is partial: the ext_proc message decoding, the request preconditions (method and end of stream), the RFC 9421
# signature stage, the identity stage (the real SDK identity verifier on offline test identities and a test C2SP log,
# not DNSid Local or managed-service identities; governance policy; the SDK transports' destination and redirect checks)
# the lifecycle stage (the SDK's non-revocation check and the evidence-freshness limits, on the same offline test log) and
# the shared records-and-keys cache with its warm-path cases, the ext_proc response (the verified continuation with its
# identity-header mutations, and the 403 immediate responses) from serialized request to serialized response, and the
# gRPC service (ExternalProcessor/Process over plaintext HTTP/2 on loopback, with real grpc-js clients: one response per
# stream, deadlines, cancellation, message limits, terminal log records, shutdown, and the executable's startup), Demo
# Bank (the origin: routes, methods, the identity context it requires, no-store, bounded logs, startup and shutdown), and
# the verifier and Demo Bank together through a test forwarding harness (not Google's load balancer or Envoy: signed GET
# and HEAD reach the origin with the verified identity, forged identity headers are replaced, refused requests never
# reach it, and replay within the signature window is served, the documented limitation) are implemented so far. The
# other local cases are added here as they are built (README.md, Testing). The container images are checked
# separately by scripts/container-smoke.sh, which needs a container engine; nothing here does. Only that script's cleanup
# reporting and exit codes are tested here, against a fake `docker` (tests/unit/container-cleanup.test.ts).
#
# The local mode (local/, `make bootstrap`, `run`, `verify`, `clean`) is checked here too, offline: its request path
# (the local edge, the production verifier with the DNSid Local backend, Demo Bank) on the fixture network and on a DNSid
# Local LOOK-ALIKE (real DNS and HTTPS on loopback, offline identities: tests/support/dnsid-local-lookalike.ts), and its
# lifecycle against SIMULATED `dnsid` and `docker` commands (tests/support/fake-dnsid.ts). `make verify` against DNSid
# Local itself needs Docker and the dnsid CLI; nothing here starts either.
#
# The deployment machinery is checked here too, offline: the Terraform stages (formatting, validation against the
# locked providers' schemas with no backend, and `terraform test` with mock providers), the Cloud Build configuration,
# Dockerfiles and upload allowlist (statically), scripts/deploy.sh and scripts/teardown.sh against SIMULATED gcloud and
# Terraform commands (tests/unit/deploy.test.ts), and the live tests' cases against a FIXTURE EDGE and a SIMULATED cloud
# (tests/unit/live.test.ts). None of it builds an image, deploys, or contacts Google Cloud or the DNSid portal; the
# Terraform check downloads the locked providers from the public registry the first time (cached afterwards).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

pinned="$(tr -d '[:space:]' < .nvmrc)"
actual="$(node --version)"
if [[ "$actual" == "v$pinned" ]]; then
  echo "runtime: node $actual (pinned v$pinned), npm $(npm --version)"
else
  echo "runtime: node $actual differs from the pinned v$pinned (npm ci enforces package.json engines)" >&2
fi

# The dependencies are installed here for the run. When there were none before it, they are removed again on exit, so a
# fresh checkout is left as it was (npm ci replaces node_modules on every run anyway).
tf_work=""
installed_here=0
[ -e node_modules ] || installed_here=1
cleanup() {
  [ -z "$tf_work" ] || rm -rf "$tf_work"
  [ "$installed_here" -eq 0 ] || rm -rf node_modules
}
trap cleanup EXIT

echo "== install (npm ci, from package-lock.json)"
npm ci --no-audit --no-fund

echo "== type check"
npx --no-install tsc --noEmit -p tsconfig.json

echo "== unit tests"
node --test "tests/unit/*.test.ts"

echo "== Terraform (offline: no backend, no credentials; mock providers in terraform test)"
command -v terraform > /dev/null || { echo "terraform is not installed: it is needed to validate infra/ (see README.md, Prerequisites)" >&2; exit 1; }
terraform version | head -1
terraform fmt -check -recursive infra
tf_work="$(mktemp -d)"
export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-$HOME/.cache/dnsid-gcp-service-extensions/terraform-plugins}"
mkdir -p "$TF_PLUGIN_CACHE_DIR"
for stage in bootstrap service; do
  echo "-- infra/$stage"
  export TF_DATA_DIR="$tf_work/$stage"
  terraform -chdir="infra/$stage" init -backend=false -input=false -lockfile=readonly -no-color > "$tf_work/$stage-init.log" \
    || { cat "$tf_work/$stage-init.log" >&2; exit 1; }
  terraform -chdir="infra/$stage" validate -no-color
  terraform -chdir="infra/$stage" test -no-color
done
unset TF_DATA_DIR

if command -v shellcheck > /dev/null; then
  echo "== shellcheck (warnings and errors)"
  shellcheck -x -S warning scripts/*.sh scripts/lib/*.sh && echo "shellcheck: clean"
else
  echo "== shellcheck is not installed: the shell scripts were not linted (their behavior is tested above)"
fi

echo "== local tests passed. Coverage is PARTIAL: ext_proc decoding, request preconditions, the signature, identity and"
echo "   lifecycle stages, the shared records-and-keys cache, the ext_proc allow/deny responses, the local gRPC service,"
echo "   Demo Bank, and the two joined by a test forwarding harness (offline test identities and a test log, not DNSid Local"
echo "   or managed-service identities; no Google load balancer; container images not checked here); the local mode's"
echo "   lifecycle (make bootstrap/run/verify/clean) against a simulated dnsid CLI and Docker and a DNSid Local look-alike"
echo "   (not DNSid Local itself; make verify needs Docker and the dnsid CLI); the Terraform stages, build configuration and"
echo "   upload allowlist, deploy/teardown against simulated cloud commands, and the live cases against a fixture edge"
echo "   (nothing deployed, built or sent to Google Cloud)."
