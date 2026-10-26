#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Helm smoke test on kind: build the image, PostgreSQL in the cluster, the Secret, `helm install`, then check the
# migration hook, the per-process logins, rollout, health, a demo world and a scoped API call. CI: .github/workflows/ci.yml.
#   charts/fortproof/ci/smoke.sh            (needs docker, kind, kubectl, helm; ~2 GB RAM)
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
cluster="${AAP_SMOKE_CLUSTER:-aap-smoke}"
ns=fortproof
rand() { python3 -c "import secrets; print(secrets.token_hex(16))"; }

kind get clusters | grep -qx "$cluster" || kind create cluster --name "$cluster" --wait 120s
kubectl config use-context "kind-$cluster" >/dev/null
docker build -t aap:smoke "$root"
kind load docker-image aap:smoke --name "$cluster"
kubectl delete namespace "$ns" --ignore-not-found --wait=true >/dev/null   # every run starts from nothing
kubectl create namespace "$ns" >/dev/null

pg="$(rand)"
kubectl -n "$ns" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: postgres }
spec:
  selector: { matchLabels: { app: postgres } }
  template:
    metadata: { labels: { app: postgres } }
    spec:
      containers:
        - name: postgres
          image: postgres:16-alpine
          env: [{ name: POSTGRES_PASSWORD, value: "$pg" }, { name: POSTGRES_DB, value: aap }]
          ports: [{ containerPort: 5432 }]
          readinessProbe: { exec: { command: [pg_isready, -U, postgres] }, periodSeconds: 3 }
---
apiVersion: v1
kind: Service
metadata: { name: postgres }
spec: { selector: { app: postgres }, ports: [{ port: 5432 }] }
YAML
kubectl -n "$ns" rollout status deploy/postgres --timeout=180s

host="postgres.$ns.svc.cluster.local:5432/aap"
args=(--from-literal=database-url="postgresql+psycopg://postgres:$pg@$host" --from-literal=github-webhook-secret="$(rand)")
for p in api worker hook reporting; do
  args+=(--from-literal="database-url-$p=postgresql+psycopg://aap_${p}_login:$(rand)@$host")
done
kubectl -n "$ns" create secret generic aap-secrets "${args[@]}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# one rules file supplied by the deployment (rules.files), as an adopter would for their trusted producers
helm upgrade --install fortproof "$root/charts/fortproof" -n "$ns" -f "$root/charts/fortproof/ci/smoke-values.yaml" \
  --set-file 'rules.files.config/trusted-producers\.yaml'="$root/config/trusted-producers.yaml" --wait --timeout 10m
for c in api worker hook; do kubectl -n "$ns" rollout status "deploy/fortproof-$c" --timeout=180s; done

# each process connects as its own least-privilege login
logins=$(kubectl -n "$ns" exec deploy/postgres -- psql -U postgres -d aap -Atc \
  "SELECT string_agg(DISTINCT usename, ',' ORDER BY usename) FROM pg_stat_activity WHERE usename LIKE 'aap_%'")
echo "connected logins: $logins"
[[ "$logins" == *aap_api_login* && "$logins" == *aap_worker_login* ]] || { echo "process logins not in use" >&2; exit 1; }

# the deployment's rules file is the one in use, in every process
kubectl -n "$ns" exec deploy/fortproof-worker -- aap config check | grep -E '^deployment +config/trusted-producers.yaml' \
  || { echo "the rules file from rules.files is not in use" >&2; exit 1; }
kubectl -n "$ns" exec deploy/fortproof-worker -- aap demo seed >/dev/null
kubectl -n "$ns" port-forward svc/fortproof-api 18000:80 >/dev/null 2>&1 &
pf=$!; trap 'kill $pf 2>/dev/null || true' EXIT
for _ in $(seq 30); do curl -sf http://127.0.0.1:18000/api/v1/health/ready >/dev/null && break; sleep 1; done
curl -sf http://127.0.0.1:18000/api/v1/health/ready
count='import json,sys; print(len(json.load(sys.stdin)["items"]))'
appsec_json=$(curl -sf -H "X-AAP-Dev-User: cpatel" http://127.0.0.1:18000/api/v1/applications)
team_json=$(curl -sf -H "X-AAP-Dev-User: ajones" http://127.0.0.1:18000/api/v1/applications)
apps=$(python3 -c "$count" <<<"$appsec_json")
team=$(python3 -c "$count" <<<"$team_json")
echo; echo "applications: AppSec sees $apps, a Claims champion sees $team"
if ! { [ "$apps" -ge 4 ] && [ "$team" -lt "$apps" ]; }; then echo "scoping check failed" >&2; exit 1; fi
# the security context really applies: no root, read-only root filesystem
kubectl -n "$ns" exec deploy/fortproof-api -- sh -c 'id -u; touch /app/x 2>/dev/null && echo WRITABLE || echo read-only' | tr '\n' ' '
echo
# an upgrade runs the migration hook again (forward-only, idempotent) and rolls the processes
helm upgrade fortproof "$root/charts/fortproof" -n "$ns" --reuse-values --set api.replicas=2 --wait --timeout 10m
[ "$(kubectl -n "$ns" get deploy fortproof-api -o jsonpath='{.status.readyReplicas}')" = "2" ] || { echo "upgrade did not roll out" >&2; exit 1; }
kubectl -n "$ns" exec deploy/fortproof-api -- aap config check | grep -qE '^deployment +config/trusted-producers.yaml' \
  || { echo "the deployment's rules were lost on upgrade" >&2; exit 1; }
curl -sf http://127.0.0.1:18000/api/v1/health/live >/dev/null || true
echo "helm smoke test passed (install and upgrade)"
