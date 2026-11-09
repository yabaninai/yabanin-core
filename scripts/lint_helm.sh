#!/usr/bin/env bash
# Helm chart gate: lint + full template render for every values variant.
# Catches broken templates, invalid k8s object shapes and chart regressions
# BEFORE a cluster sees them (the ENT-06 drill found seven such defects).
set -euo pipefail
cd "$(dirname "$0")/.."

command -v helm >/dev/null 2>&1 || { echo "helm is required for this gate (see scripts/quality/README.md)"; exit 2; }

fail=0
for chart in deploy/helm/*/; do
  [ -f "$chart/Chart.yaml" ] || continue
  name=$(basename "$chart")
  echo "== helm lint: $name"
  helm lint "$chart" || fail=1
  # Render every shipped values variant; --validate-shaped via kube-version.
  for values in "$chart"values*.yaml; do
    [ -f "$values" ] || continue
    echo "== helm template: $name ($(basename "$values"))"
    if ! helm template "gate-check" "$chart" -f "$values" \
        --kube-version 1.25.0 > /dev/null; then
      echo "FAIL: render $name with $(basename "$values")"
      fail=1
    fi
  done
done
python3 scripts/helm_mcp_contract_test.py || fail=1
exit $fail
