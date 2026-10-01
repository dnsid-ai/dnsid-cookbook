#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
trap 'status=$?; if [ "$status" != 0 ]; then
  docker ps --filter name=dnsid-local
  for c in $(docker ps -q --filter name=dnsid-local); do docker logs --tail 50 "$c"; done
fi' EXIT
"${DNSID_CLI:-dnsid}" local run shopper -- npm run demo
