#!/usr/bin/env bash
# Local container smoke test: builds the verifier and Demo Bank images for linux/amd64 (Cloud Run's platform) and runs
# them on this machine, with ports published on 127.0.0.1 only. No cloud, no credentials, no registry push.
#
# Checks, for each image: its platform, the Node.js version inside it, that it runs as a non-root user with the exec-form
# entry point, what it contains (runtime schemas and licenses present; tests, fixtures, plan records, publishing files,
# development dependencies and credentials absent), production startup on the default PORT and on a custom one, its
# behavior (the verifier denies an unsigned request; Demo Bank's routes, methods, identity context and its attestation;
# both refuse to start without an attestation key), and a graceful stop on SIGTERM (`docker stop`). Every container and image it creates is removed at the end, after a failure too, and a
# final inventory confirms it (scripts/lib/container-cleanup.sh).
#
# Exit codes: 0 every check passed and cleanup was confirmed; 1 a check failed, or cleanup could not be confirmed; 2 a
# prerequisite is missing, so NOTHING WAS CHECKED. A missing prerequisite is never reported as a pass. Ordinary source
# tests don't need a container engine: scripts/test-local.sh.
#
# Prerequisites: a running Docker engine that can build and run linux/amd64 images (natively or through emulation), and
# Node.js with this directory's dependencies installed (npm ci) for the host-side probes in tests/container/probe.ts.
#
# The same checks run in the deployment's image build (cloudbuild.yaml), before the images are published, with two
# settings that only that build uses:
#   SMOKE_IMAGES="<verifier image> <origin image>"  check these already-built images instead of building them here. They
#                                                   are not removed at the end: they are the images the build publishes.
#   SMOKE_NETWORK=<docker network>                  run the containers on that network, unpublished, and run the probes
#                                                   in a throwaway container of the verifier image on the same network
#                                                   (it has Node.js and the probes' dependencies), so the host needs
#                                                   neither Node.js nor npm ci. Cloud Build's network is `cloudbuild`.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

PLATFORM=linux/amd64
NODE_VERSION="v$(tr -d '[:space:]' < .nvmrc)"
STOP_TIMEOUT_S=10

not_run() {
  echo "CONTAINER SMOKE NOT RUN: prerequisite missing: $*" >&2
  echo "Nothing was checked. This is not a pass." >&2
  exit 2
}
fail() {
  echo "CONTAINER SMOKE FAILED: $*" >&2
  exit 1
}
pass() { echo "PASS: $*"; }

prebuilt="${SMOKE_IMAGES:-}"
network="${SMOKE_NETWORK:-}"
if [[ -n "$prebuilt" ]]; then
  read -r verifier_given origin_given extra <<< "$prebuilt"
  [[ -n "${origin_given:-}" && -z "${extra:-}" ]] || not_run "SMOKE_IMAGES must name exactly two images: the verifier's, then Demo Bank's"
fi
[[ -z "$network" || "$network" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || not_run "SMOKE_NETWORK is not a docker network name"

command -v docker > /dev/null 2>&1 || not_run "the docker CLI"
docker info > /dev/null 2>&1 || not_run "a running Docker engine ('docker info' failed)"
if [[ -z "$network" ]]; then
  command -v node > /dev/null 2>&1 || not_run "Node.js on the host, for the probes"
  [[ -d node_modules/@grpc/grpc-js ]] || not_run "installed dependencies for the probes (run npm ci here first)"
fi

run_id="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$run_id" =~ ^[0-9a-f]{8}$ ]] || not_run "a random run id (od and /dev/urandom)"
label="dnsid-gcp-smoke=$run_id"
# This run's own attestation key (64 hex characters), shared by the containers and the probes, as a deployment's is by
# the verifier and Demo Bank. Thrown away with the run.
smoke_key="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$smoke_key" =~ ^[0-9a-f]{64}$ ]] || not_run "a random attestation key (od and /dev/urandom)"
export DNSID_ATTESTATION_KEY="$smoke_key"
if [[ -n "$prebuilt" ]]; then
  verifier_image="$verifier_given"
  origin_image="$origin_given"
  removable_images=()
else
  verifier_image="dnsid-gcp-smoke-verifier:$run_id"
  origin_image="dnsid-gcp-smoke-origin:$run_id"
  removable_images=("$verifier_image" "$origin_image")
fi
work="$(mktemp -d)"

# shellcheck source=scripts/lib/container-cleanup.sh
source "$root/scripts/lib/container-cleanup.sh"
cleanup() {
  local status=$? rc=0
  trap - EXIT
  smoke_cleanup "$status" "$label" "$work" ${removable_images[@]+"${removable_images[@]}"} || rc=$?
  exit "$rc"
}
trap cleanup EXIT

echo "== versions"
docker version --format 'docker client {{.Client.Version}}, engine {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})'
echo "host node $(node --version); target platform $PLATFORM; pinned node $NODE_VERSION"

if [[ -n "$prebuilt" ]]; then
  echo "== images built earlier in this build: $verifier_image, $origin_image"
  docker image inspect "$verifier_image" "$origin_image" > /dev/null || fail "an image named in SMOKE_IMAGES does not exist"
else
  echo "== build"
  docker build --platform "$PLATFORM" --label "$label" -t "$verifier_image" . || fail "the verifier image did not build"
  docker build --platform "$PLATFORM" --label "$label" -t "$origin_image" origin || fail "the Demo Bank image did not build"
fi
grep -o 'node:[^ ]*@sha256:[0-9a-f]*' Dockerfile | head -1 | sed 's/^/base image: /'

# Runs a command in a fresh container of the image, with the entry point replaced; the container is removed after.
in_image() {
  local image="$1" program="$2"
  shift 2
  docker run --rm --platform "$PLATFORM" --label "$label" --network none --entrypoint "$program" "$image" "$@" 2>&1
}

check_image() {
  local name="$1" image="$2" entrypoint="$3"
  echo "== $name image"
  docker image inspect -f "id {{.Id}} platform {{.Os}}/{{.Architecture}} user {{.Config.User}} entrypoint {{json .Config.Entrypoint}} cmd {{json .Config.Cmd}}" "$image"
  [[ "$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$image")" == "$PLATFORM" ]] || fail "$name: the image is not $PLATFORM"
  [[ "$(docker image inspect -f '{{json .Config.Entrypoint}}' "$image")" == "$entrypoint" ]] || fail "$name: the entry point is not $entrypoint"
  [[ "$(docker image inspect -f '{{json .Config.Cmd}}' "$image")" == "null" ]] || fail "$name: the image has a CMD as well"
  [[ "$(docker image inspect -f '{{.Config.User}}' "$image")" == "1000:1000" ]] || fail "$name: the configured user is not 1000:1000"
  local version
  version="$(in_image "$image" node --version)" || {
    if [[ "$version" == *"exec format error"* ]]; then not_run "running $PLATFORM images on this engine (no emulation): $version"; fi
    fail "$name: node --version did not run: $version"
  }
  [[ "$version" == "$NODE_VERSION" ]] || fail "$name: node is $version, not $NODE_VERSION"
  pass "$name: runtime node $version"
  local ids
  ids="$(in_image "$image" id -u)"
  [[ "$ids" == "1000" ]] || fail "$name: runs as uid $ids"
  pass "$name: runs as uid $ids (non-root)"
}

check_image verifier "$verifier_image" '["node","src/main.ts"]'
contents="$(in_image "$verifier_image" sh -c '
  set -u
  cd /app
  echo "top: $(ls -A | tr "\n" " ")"
  echo "src: $(ls -A src | tr "\n" " ")"
  test -f proto/envoy/service/ext_proc/v3/external_processor.proto || echo "MISSING the ext_proc schema entry point"
  (cd proto && sha256sum -c --quiet SHA256SUMS) || echo "MISSING or changed vendored schema files"
  echo "schema files: $(find proto -name "*.proto" | wc -l)"
  for license in LICENSE proto/LICENSE.envoy proto/LICENSE.xds proto/LICENSE.protoc-gen-validate; do test -f "$license" || echo "MISSING $license"; done
  for pkg in node_modules/[!@]* node_modules/@*/*; do
    [ -f "$pkg/package.json" ] || continue
    ls "$pkg" | grep -qiE "^(licen[cs]e|copying)" || echo "NO LICENSE FILE in $pkg"
  done
  echo "packages: $(ls -d node_modules/[!@]* node_modules/@*/* | wc -l)"
  for absent in tests docs scripts origin publish infra internal-demos tsconfig.json .nvmrc .npmrc package-lock.json \
      Dockerfile .dockerignore .gitignore node_modules/typescript node_modules/@typescript; do
    [ -e "$absent" ] && echo "PRESENT $absent"
  done
  find /app -path /app/node_modules -prune -o \( -name "*.test.ts" -o -name fixtures -o -name support -o -name "*.pem" \
      -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "*.jwk" -o -name "*private-key*" -o -name "*agent-key*" \
      -o -name ".env" -o -name ".env.*" -o -name "*.tfstate*" -o -name "*.patch" -o -name "*.md" -a -path "*/plan/*" \) -print \
      | sed "s/^/PRESENT /"
  find /app/node_modules \( -name "*.jwk" -o -name "*private-key*" -o -name ".env" -o -name "*.tfstate*" \) -print | sed "s/^/PRESENT /"
  npm ls --omit=dev --all > /dev/null 2>&1 || echo "DEPENDENCY TREE does not match package.json"
  # @types/node is not a development dependency here: protobufjs 7.6.6 declares it as one of its runtime dependencies.
  npm ls --omit=dev --parseable @types/node 2>/dev/null | grep -qx "/app/node_modules/@types/node" && echo "@types/node: from protobufjs"
  echo done
')"
echo "$contents"
grep -qE '^(MISSING|NO LICENSE|PRESENT|DEPENDENCY)' <<< "$contents" && fail "verifier: image contents"
grep -q '^done$' <<< "$contents" || fail "verifier: the contents check did not finish"
pass "verifier: schemas and licenses present; tests, fixtures, docs, plan records, dev dependencies and credentials absent"

check_image origin "$origin_image" '["node","server.ts"]'
origin_files="$(in_image "$origin_image" sh -c 'cd /app && ls -A | tr "\n" " "')"
echo "origin /app: $origin_files"
[[ "$origin_files" == "LICENSE package.json server.ts " ]] || fail "origin: /app holds more or less than LICENSE, package.json and server.ts"
pass "origin: /app holds only LICENSE, package.json, server.ts"

# start <tag> <image> <port> [docker run options]: starts a container; prints the container id. Locally its port is
# published on 127.0.0.1 only; on SMOKE_NETWORK it is published nowhere and reached by its name on that network,
# dnsid-gcp-smoke-<run id>-<tag>. Each caller passes its own tag: start runs in a command substitution, a subshell, so a
# counter kept here would never advance in the caller and every container would get the same name.
start() {
  local tag="$1" image="$2" port="$3"
  shift 3
  if [[ -n "$network" ]]; then
    docker run -d --platform "$PLATFORM" --label "$label" --network "$network" --name "dnsid-gcp-smoke-$run_id-$tag" -e DNSID_ATTESTATION_KEY "$@" "$image"
  else
    docker run -d --platform "$PLATFORM" --label "$label" -p "127.0.0.1::$port" -e DNSID_ATTESTATION_KEY "$@" "$image"
  fi
}
host_port() {
  local binding
  binding="$(docker port "$1" "$2/tcp" | head -1)"
  [[ "$binding" == 127.0.0.1:* ]] || fail "port $2 is published on $binding, not on 127.0.0.1 only"
  echo "${binding##*:}"
}
# probe <verifier|origin> <container> <port>: runs tests/container/probe.ts against the container. Locally from the host
# through the published port; on SMOKE_NETWORK in a throwaway container of the verifier image (Node.js and the probes'
# dependencies are in it) with the probe files copied in, on the same network.
probe() {
  local what="$1" container="$2" port="$3"
  if [[ -z "$network" ]]; then
    node tests/container/probe.ts "$what" "$(host_port "$container" "$port")"
    return
  fi
  local target prober rc=0
  target="$(docker inspect -f '{{.Name}}' "$container")"
  target="${target#/}"
  prober="$(docker create --platform "$PLATFORM" --label "$label" --network "$network" -e DNSID_ATTESTATION_KEY --entrypoint node "$verifier_image" \
    tests/container/probe.ts "$what" "$port" "$target")"
  docker cp "$root/tests/." "$prober:/app/tests" > /dev/null || rc=$?
  ((rc != 0)) || docker start -a "$prober" || rc=$?
  docker rm -f "$prober" > /dev/null || true
  return "$rc"
}
until_logged() {
  local container="$1" text="$2"
  for _ in $(seq 1 150); do
    docker logs "$container" 2>&1 | grep -q "$text" && return 0
    [[ "$(docker inspect -f '{{.State.Running}}' "$container")" == "true" ]] || break
    sleep 0.2
  done
  docker logs "$container" 2>&1 | sed 's/^/  log: /'
  fail "no $text from the container"
}
graceful_stop() {
  local name="$1" container="$2" stopped="$3"
  local begin end code
  begin="$(date +%s%N)"
  docker stop -t "$STOP_TIMEOUT_S" "$container" > /dev/null
  end="$(date +%s%N)"
  code="$(docker inspect -f '{{.State.ExitCode}} oom={{.State.OOMKilled}}' "$container")"
  echo "$name: docker stop took $(((end - begin) / 1000000)) ms; exit $code"
  docker logs "$container" 2>&1 | sed 's/^/  log: /'
  [[ "$code" == "0 oom=false" ]] || fail "$name: exit $code after SIGTERM"
  docker logs "$container" 2>&1 | grep -q "$stopped" || fail "$name: no $stopped record"
  (((end - begin) / 1000000 < STOP_TIMEOUT_S * 1000)) || fail "$name: did not stop before the SIGKILL timeout"
  pass "$name: stopped on SIGTERM with exit 0 and $stopped"
  # Its checks are done: remove it now rather than leave it stopped until the final cleanup.
  docker rm "$container" > /dev/null || fail "$name: the stopped container could not be removed"
}

echo "== verifier: production startup, default PORT"
v1="$(start verifier-8080 "$verifier_image" 8080)"
until_logged "$v1" '"event":"ext_proc_listening","port":8080'
probe verifier "$v1" 8080 || fail "verifier: unsigned request on the default PORT"
pass "verifier: an unsigned request is denied (403 signature_missing) on PORT 8080"
graceful_stop verifier "$v1" ext_proc_stopped

echo "== verifier: custom PORT"
v2="$(start verifier-9090 "$verifier_image" 9090 -e PORT=9090)"
until_logged "$v2" '"event":"ext_proc_listening","port":9090'
probe verifier "$v2" 9090 || fail "verifier: unsigned request on PORT 9090"
pass "verifier: listens on PORT=9090"
graceful_stop verifier "$v2" ext_proc_stopped

echo "== verifier: invalid configuration is refused at startup"
set +e
refused="$(docker run --rm --platform "$PLATFORM" --label "$label" --network none -e DNSID_TRUSTED_GOVERNANCE= "$verifier_image" 2>&1)"
code=$?
set -e
echo "exit $code: $refused"
[[ $code -eq 1 && "$refused" == '{"severity":"ERROR","event":"ext_proc_startup_failed","reason":"invalid configuration: DNSID_TRUSTED_GOVERNANCE is set but empty"}' ]] \
  || fail "verifier: an empty DNSID_TRUSTED_GOVERNANCE was not refused with the fixed diagnostic"
pass "verifier: an empty governance setting exits 1 with a fixed diagnostic"

# no_key <name> <image> <event>: started without DNSID_ATTESTATION_KEY, the service must refuse with its fixed diagnostic.
no_key() {
  local name="$1" image="$2" event="$3" out code
  set +e
  out="$(docker run --rm --platform "$PLATFORM" --label "$label" --network none "$image" 2>&1)"
  code=$?
  set -e
  echo "exit $code: $out"
  [[ $code -eq 1 && "$out" == "{\"severity\":\"ERROR\",\"event\":\"$event\",\"reason\":\""*"DNSID_ATTESTATION_KEY must be set to 32 to 256 characters"*"}" && "$(wc -l <<< "$out")" -eq 1 ]] \
    || fail "$name: starting without DNSID_ATTESTATION_KEY was not refused with the fixed diagnostic"
  pass "$name: no attestation key exits 1 with a fixed diagnostic"
}
no_key verifier "$verifier_image" ext_proc_startup_failed

echo "== origin: default PORT"
o1="$(start origin-8080 "$origin_image" 8080)"
until_logged "$o1" '"event":"origin_listening","port":8080'
probe origin "$o1" 8080 || fail "origin: routes on the default PORT"
pass "origin: routes, methods, identity context, its attestation and no-store on PORT 8080"
graceful_stop origin "$o1" origin_stopped

echo "== origin: custom PORT"
o2="$(start origin-9191 "$origin_image" 9191 -e PORT=9191)"
until_logged "$o2" '"event":"origin_listening","port":9191'
probe origin "$o2" 9191 || fail "origin: routes on PORT 9191"
pass "origin: listens on PORT=9191"
graceful_stop origin "$o2" origin_stopped
no_key origin "$origin_image" origin_startup_failed

echo "== container smoke passed"
