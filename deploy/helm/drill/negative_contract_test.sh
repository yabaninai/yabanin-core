#!/usr/bin/env bash
# N11-P02-T05: contract test — no false HA / replicated-RPO claims for the
# bundled postgres anywhere in the on-prem chart or its documentation.
#
# Stable contract (grep-able, deliberate):
#   1. The bundled postgres StatefulSet ships `replicas: 1` in EVERY
#      shipped profile (default, values-ha, values-airgap) and never gets
#      topology spread constraints (fake HA must stay impossible).
#   2. No PodDisruptionBudget selects the bundled postgres (the PDB
#      template documents why: PDB would add zero durability there).
#   3. values-ha.yaml keeps its explicit negatives: the HA overlay covers
#      STATELESS tiers only; the bundled postgres is NOT an HA database;
#      no external-DB switch through this overlay; no in-flight-stream
#      promises.
#   4. HA-TOPOLOGY.md keeps recovery targets distinct from chart guarantees,
#      retains the accounting/history objectives and their dependencies,
#      plus explicit negatives and the local-fsync limitation.
#   5. The fake-HA render guard works: ha.enabled=true with a single
#      gateway replica must FAIL rendering.
# Exit 0 only if every check holds.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
CHART="$REPO/deploy/helm/yabanin-onprem"
VALUES_HA="$CHART/values-ha.yaml"
VALUES_AIRGAP="$CHART/values-airgap.yaml"
TOPO="$REPO/deploy/helm/yabanin/HA-TOPOLOGY.md"

fail() { echo "FAIL $1"; exit 1; }

echo "== T05 negative_contract_test: no false HA/RPO claims in chart or docs"

command -v helm >/dev/null || { echo "FAIL helm not available"; exit 1; }

render() { helm template gate-check "$CHART" -f "$1" --kube-version 1.25.0; }

# --- 1. bundled postgres stays single-replica, no topology spread
for v in "$CHART/values.yaml" "$VALUES_HA" "$VALUES_AIRGAP"; do
  [ -e "$v" ] || fail "missing shipped values file: $v"
  PG_STS=$(render "$v" | awk -v RS='---' '/kind: StatefulSet/ && /app: postgres/ {print}')
  [ -n "$PG_STS" ] || fail "postgres statefulset not found in render of $v"
  echo "$PG_STS" | grep -q "replicas: 1" \
    || fail "postgres statefulset is not replicas: 1 in $v"
  echo "$PG_STS" | grep -q "topologySpreadConstraints" \
    && fail "postgres statefulset carries topologySpreadConstraints in $v"
done
echo "  PASS statesets: bundled postgres replicas: 1 in default/ha/airgap, no spread"

# --- 2. no PDB selects postgres
for v in "$CHART/values.yaml" "$VALUES_HA"; do
  PG_PDB=$(render "$v" | awk -v RS='---' '/kind: PodDisruptionBudget/ && /app: postgres/ {print}')
  [ -z "$PG_PDB" ] || fail "a PodDisruptionBudget selects postgres in $v (would imply HA)"
done
echo "  PASS pdb: no PodDisruptionBudget selects the bundled postgres"

# --- 3. stable negatives in the HA overlay (stateless-only HA profile)
grep -q "bundled.postgres, so an external-DB endpoint cannot be selected" "$VALUES_HA" \
  || fail "values-ha.yaml lost the 'no template consumes bundled.postgres' negative (external-DB honesty)"
grep -q "Do not read this overlay as an external-DB switch" "$VALUES_HA" \
  || fail "values-ha.yaml lost the external-DB-switch negative"
grep -q "is NOT an HA" "$VALUES_HA" \
  || fail "values-ha.yaml lost the NOT-an-HA-database negative"
grep -q "local fsync is not replication" "$VALUES_HA" \
  || fail "values-ha.yaml lost the fsync-is-not-replication negative"
grep -q "promise that in-flight streams survive node loss" "$VALUES_HA" \
  || fail "values-ha.yaml lost the in-flight-stream negative"
echo "  PASS values-ha.yaml: all explicit negatives intact"

# --- 4. Public recovery objectives retain their limitations.
grep -q "Local fsync is not replicated RPO=0 storage" "$TOPO" \
  || fail "HA-TOPOLOGY.md lost the local-fsync negative sentence"
grep -q "## Recovery objectives and limitations" "$TOPO" \
  || fail "HA-TOPOLOGY.md lost its recovery-objectives section"
grep -q "Accounting / authorization / audit: \*\*RPO=0 target\*\*" "$TOPO" \
  || fail "HA-TOPOLOGY.md lost the accounting RPO=0 target"
grep -q "RPO ≤ 60 s target\*\*" "$TOPO" \
  || fail "HA-TOPOLOGY.md lost the history RPO<=60s target"
grep -q "acceptance criteria, not chart guarantees" "$TOPO" \
  || fail "HA-TOPOLOGY.md presents recovery objectives as chart guarantees"
grep -q "does not configure or prove that bound" "$TOPO" \
  || fail "HA-TOPOLOGY.md lost the asynchronous-history limitation"
grep -q "## Explicit negatives (do not promise)" "$TOPO" \
  || fail "HA-TOPOLOGY.md lost the explicit-negatives heading"
echo "  PASS HA-TOPOLOGY.md: recovery objectives and explicit limitations intact"

# --- 5. fake-HA render guard: ha.enabled with 1 gateway replica must fail
if helm template gate-check "$CHART" -f "$VALUES_HA" \
     --set ha.enabled=true --set gateway.replicas=1 \
     --kube-version 1.25.0 >/dev/null 2>&1; then
  fail "fake-HA guard broken: ha.enabled=true rendered with gateway.replicas=1"
fi
echo "  PASS guard: ha.enabled=true with a single gateway replica refuses to render"

echo "DRILL RESULT: PASS (no false HA/RPO claims; negatives stable)"
exit 0
