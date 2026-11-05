#!/usr/bin/env bash
# Checks the deployment assets: alerting rules (promtool), Kubernetes manifests
# (kubeconform), compose file, Grafana dashboard, and that every metric they
# reference is exported by the code. Requires promtool, kubeconform, jq and
# docker on the PATH; run it from the repository root.
set -euo pipefail

crds='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'

echo "== Alerting rules"
promtool check rules deployments/prometheus/vaultwarden-alerts.yml
promtool test rules deployments/prometheus/tests/*_test.yml

echo "== Kubernetes manifests"
kubeconform -strict -summary -kubernetes-version 1.30.0 \
  -schema-location default -schema-location "$crds" deployments/kubernetes/*.yaml

echo "== Compose file"
docker compose -f deployments/docker/docker-compose.yml config --quiet

echo "== Grafana dashboard"
jq -e '.panels | length > 0' grafana/vaultwarden.json >/dev/null

echo "== Metric names"
# Every vaultwarden_* name used by the rules and the dashboard must be defined
# in the Go code (Name fields and Desc names, joined from namespace/subsystem)
defined=$(grep -rhoE '"(vaultwarden_[a-z0-9_]+|_[a-z0-9_]+)"|Name: *"[a-z0-9_]+"|Subsystem: *"[a-z]+"' internal cmd \
  | tr -d '"' | sed -E 's/^(Name|Subsystem): *//' | sort -u)
missing=0
for metric in $(grep -rhoE 'vaultwarden_[a-z0-9_]+' deployments/prometheus/vaultwarden-alerts.yml grafana/vaultwarden.json | sort -u); do
  short=${metric#vaultwarden_}
  short_exporter=${short#exporter_}
  if ! grep -qxE "($metric|_$short|$short|$short_exporter)" <<<"$defined"; then
    echo "unknown metric referenced: $metric" >&2
    missing=1
  fi
done
[ "$missing" -eq 0 ]
echo "deployment assets OK"
