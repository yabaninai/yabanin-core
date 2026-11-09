#!/usr/bin/env bash
#
# silently rendered un-appliable manifests for invalid input —
#   --set replicaCount=abc   -> `replicas: abc`
#   --set gateway.replicas=1.5 -> `replicas: 1.5`
#   --set service.port=-1    -> `port: -1`
# and exited 0 (a partial/unknown render was indistinguishable from success;
# the failure only surfaced later at kubectl apply, possibly after other
# resources of the same release had already been applied).
#
# Assertions per chart:
#   S1 every INVALID input (malformed / fractional / zero replicas,
#      negative or out-of-range ports, negative strategy fields) makes
#      `helm template` exit NONZERO with the offending value named;
#   S2 valid boundary inputs (replicas=1, port=1, port=65535) still render;
#   S3 the schema file itself is present in both charts (a deleted schema
#      is exactly mutation M-F this test must catch).
#   S4 (N11-P02-T02) the HA topology guard: ha.enabled=true with
#      replicaCount<2 must fail at render (fake HA), =2 must render;
#      ha enum/key values validate (HA-TOPOLOGY.md knobs).
#
#   M-F delete values.schema.json  -> S1 fails (invalid input renders again).
#
# Usage: bash deploy/helm/values_schema_test.sh   (from repo root; helm required)
set -euo pipefail
cd "$(dirname "$0")/../.."

command -v helm >/dev/null 2>&1 || { echo "FAIL: helm is required" >&2; exit 2; }

fail=0
pass() { echo "PASS: $1"; }
bad() { echo "FAIL: $1" >&2; fail=1; }

# must_fail <chart> <label> <set-args...>: helm template must exit nonzero
# and name the offending value in stderr (no opaque crash, no silent render).
must_fail() {
  local chart="$1" label="$2"; shift 2
  local out rc
  set +e
  out="$(helm template gate-vs "$chart" "$@" 2>&1 >/dev/null)"; rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    bad "$chart: $label rendered successfully with invalid input ($*) — schema guard missing"
  elif printf '%s' "$out" | grep -qiE "want integer|Expected: integer|minimum|maximum|greater than or equal|less than or equal|replicas|replicaCount|port|maxUnavailable|maxSurge|one of|when_unsatisfiable|topology_key|Invalid type"; then
    pass "$chart: $label rejected (exit $rc): $(printf '%s' "$out" | tail -1 | cut -c1-120)"
  else
    bad "$chart: $label failed (exit $rc) but the error does not name the offending value: $out"
  fi
}

# must_pass <chart> <label> <set-args...>: valid boundary input must render.
must_pass() {
  local chart="$1" label="$2"; shift 2
  if helm template gate-vs "$chart" "$@" >/dev/null 2>&1; then
    pass "$chart: $label renders"
  else
    bad "$chart: $label (valid boundary) was rejected: $*"
  fi
}

echo "== R056 values-schema (invalid input) regression test =="

# S3: schema present in both charts.
for chart in deploy/helm/yabanin deploy/helm/yabanin-onprem; do
  if [ -f "$chart/values.schema.json" ]; then
    pass "$chart: values.schema.json present"
  else
    bad "$chart: values.schema.json MISSING — invalid values render silently (R056-03 defect class)"
  fi
done

# --- cloud chart (deploy/helm/yabanin) --------------------------------------
C=deploy/helm/yabanin
must_fail "$C" "malformed replicaCount"          --set replicaCount=abc
must_fail "$C" "zero replicaCount"               --set replicaCount=0
must_fail "$C" "negative replicaCount"           --set replicaCount=-2
must_fail "$C" "negative service.port"           --set service.port=-1
must_fail "$C" "too-large service.port"          --set service.port=70000
must_fail "$C" "malformed service.port"          --set service.port=abc
must_fail "$C" "negative strategy.maxSurge"      --set strategy.rollingUpdate.maxSurge=-1
must_fail "$C" "zero pdb.maxUnavailable"         --set pdb.gateway.maxUnavailable=0
must_fail "$C" "malformed pdb.maxUnavailable"    --set pdb.admin.maxUnavailable=abc
must_fail "$C" "malformed probe port"            --set probes.gateway.liveness.port=abc
# S4: HA topology guard (N11-P02-T02, deploy/helm/yabanin/HA-TOPOLOGY.md).
must_fail "$C" "HA enabled with 1 replica"       --set ha.enabled=true --set replicaCount=1
must_pass "$C" "boundary HA enabled 2 replicas"  --set ha.enabled=true --set replicaCount=2
must_fail "$C" "bogus ha.when_unsatisfiable"     --set ha.when_unsatisfiable=Maybe
must_fail "$C" "empty ha.topology_key"           --set ha.topology_key=
must_pass "$C" "HA degraded fallback ScheduleAnyway" --set ha.enabled=true --set ha.when_unsatisfiable=ScheduleAnyway --set replicaCount=2
must_pass "$C" "boundary replicaCount=1"         --set replicaCount=1
must_pass "$C" "boundary service.port=1"         --set service.port=1
must_pass "$C" "boundary service.port=65535"     --set service.port=65535
must_pass "$C" "percent maxUnavailable"          --set strategy.rollingUpdate.maxUnavailable=25%

# --- onprem chart (deploy/helm/yabanin-onprem) -------------------------------
O=deploy/helm/yabanin-onprem
must_fail "$O" "malformed gateway.replicas"      --set gateway.replicas=abc
must_fail "$O" "fractional gateway.replicas"     --set gateway.replicas=1.5
must_fail "$O" "zero gateway.replicas"           --set gateway.replicas=0
must_fail "$O" "negative admin.replicas"         --set admin.replicas=-1
must_fail "$O" "malformed loggerd.replicas"      --set loggerd.replicas=two
must_fail "$O" "negative strategy.maxUnavailable" --set strategy.rollingUpdate.maxUnavailable=-1
must_pass "$O" "boundary gateway.replicas=1"     --set gateway.replicas=1
must_pass "$O" "boundary admin.replicas=1"       --set admin.replicas=1
must_pass "$O" "percent maxSurge"                --set strategy.rollingUpdate.maxSurge=25%

if [ "$fail" -ne 0 ]; then
  echo "== RESULT: FAIL" >&2
  exit 1
fi
echo "== RESULT: PASS"
