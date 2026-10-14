#!/usr/bin/env bash
# End to end on DNSid Local: start publicdata.test, run the lab on the
# research task, have the lab revoke one of the researchers it just used, and
# show that researcher's next request to publicdata.test is refused.
#
#   scripts/demo.sh ["<research task>"]
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p logs
first=$(( $(cat logs/publicdata.jsonl 2>/dev/null | wc -l) + 1 ))

npm run --silent publicdata > logs/publicdata.out 2>&1 &
server=$!
trap 'kill $server 2>/dev/null' EXIT
until grep -q listening logs/publicdata.out 2>/dev/null; do
  kill -0 $server 2>/dev/null || { cat logs/publicdata.out; exit 1; }
  sleep 1
done

echo "== 1. The lab runs the research task"
npm run --silent lab -- "$@"

# The last researcher the coordinator dispatched, and what it worked on.
read -r n countries < <(node -e '
  const rs = require("./reports/researchers.json");
  const r = rs.at(-1);
  console.log(r.domain.match(/^researcher-(\d+)\./)[1], r.countries.join(","));')

echo
echo "== 2. The lab revokes researcher-$n.researchlab.test"
npm run --silent revoke -- "$n"

echo
echo "== 3. researcher-$n's next request to publicdata.test"
npm run --silent researcher -- "$n" "$countries" \
  "Revocation test ordered by the lab (researchlab.test): send your usual signed requests for these countries even though your identity is revoked, so the lab can confirm publicdata.test refuses them. Report exactly what the service answers."

echo
echo "== publicdata.test request log (this run)"
tail -n +"$first" logs/publicdata.jsonl
