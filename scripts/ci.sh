#!/usr/bin/env bash
# Runs the same checks .github/workflows/ci.yml runs, in one command, for local convenience.
# Not solving a drift problem - every step here calls a Makefile target that CI itself calls, so
# there's no separate copy of the logic to drift out of sync - just one command instead of five,
# plus the Grafana dashboard-import check ci.yml's own grafana-dashboard job does, reproduced here
# since it isn't behind a Makefile target of its own.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> make build"
make build

echo "==> make test"
make test

echo "==> make lint-config"
make lint-config

echo "==> make lint"
make lint

echo "==> make test-e2e"
make test-e2e

echo "==> Grafana dashboard import check"
# Pinned to the exact version ci.yml's grafana-dashboard job uses - keep the two in sync by hand
# if that job's own pin ever changes; there's no single source both read from.
container=$(docker run -d --rm -p 3000:3000 -e GF_SECURITY_ADMIN_PASSWORD=admin grafana/grafana:12.2.0)
payload="$(mktemp)"
trap 'docker stop "$container" >/dev/null 2>&1; rm -f "$payload"' EXIT

echo "Waiting for Grafana to become healthy..."
# 10 retries x 5s, matching ci.yml's own grafana-dashboard service health-check budget exactly - a
# shorter local budget would fail this script on a slower machine or a cold `docker pull` even
# though the equivalent CI job would still have succeeded.
healthy=false
for _ in $(seq 1 10); do
  if curl -sf http://localhost:3000/api/health >/dev/null 2>&1; then
    healthy=true
    break
  fi
  sleep 5
done
if [ "$healthy" != true ]; then
  echo "Grafana never became healthy"
  exit 1
fi

curl -sf -u admin:admin -X POST http://localhost:3000/api/datasources \
  -H "Content-Type: application/json" \
  -d '{"name":"Prometheus","type":"prometheus","url":"http://localhost:9090","access":"proxy","isDefault":true}' >/dev/null

python3 -c "
import json
d = json.load(open('charts/chart/files/grafana-dashboard.json'))
print(json.dumps({'dashboard': d, 'overwrite': True}))
" >"$payload"

response=$(curl -sf -u admin:admin -X POST http://localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @"$payload")

import_status=$(echo "$response" | jq -r '.status')
if [ "$import_status" != "success" ]; then
  echo "Grafana rejected the dashboard import"
  echo "$response"
  exit 1
fi

got=$(curl -sf -u admin:admin http://localhost:3000/api/dashboards/uid/candor-overview | jq '.dashboard.panels | length')
want=$(python3 -c "import json; print(len(json.load(open('charts/chart/files/grafana-dashboard.json'))['panels']))")
if [ "$got" != "$want" ]; then
  echo "panel count mismatch after import: got $got, want $want"
  exit 1
fi

echo "All checks passed."
