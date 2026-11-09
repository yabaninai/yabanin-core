# HA Runbook — Yabanin gateway/admin/mcp

Scope: the Apache-core Helm charts `deploy/helm/yabanin` (cloud/regional) and
`deploy/helm/yabanin-onprem` (air-gap). Negative scenario covered: **pod loss,
leader change, rollout**.

## HA model (read first)

- **gateway / admin / mcp are stateless.** Shared state lives in PostgreSQL
  (`YABANIN_PG_URI`) and Redis. There is **no leader election and none is
  needed**: policy fan-out to all replicas goes through Redis
  (`pkg/adminstore/policystore.go` — `Get/SetPolicyVersion`,
  `bumpPolicyVersion`), so every replica converges on the latest policy
  version without a coordinator. "Leader change" in this deployment model is
  a no-op: killing any gateway pod never requires a re-election, the
  remaining replicas keep serving.
- **HA profile = `replicaCount: 2`** (base `values.yaml` of
  `deploy/helm/yabanin`; onprem `gateway.replicas: 2`). The regional
  overlays (`values-sg/eu/in.yaml`) deliberately pin `replicaCount: 1` — a
  non-HA demo profile (configure the deployment overlays). For a real HA
  install, do not inherit those overlays or override
  `--set replicaCount=2`.
- **Single-instance by design:** `loggerd` (onprem chart) and the Postgres
  statefulset (`postgres-statefulset.yaml`, replicas 1). See
  [Single-node caveats](#single-node-caveats).
- Degraded-state reporting: `/healthz` reports overall degraded when Redis
  is down (`redis.status == "down"`) — usable by probes/LB routing.

## Chart behavior

| Defect | Before | After |
|---|---|---|
| Gateway PDB selector mismatch | PDB selected `app: yabinin` but pods are labeled `app: yabinin-gateway` → matched **zero** pods, gateway unprotected | selector `app: yabinin-gateway` (`templates/serviceaccount.yaml`) |
| Admin PDB blocked all drains | `minAvailable: 1` vs default `replicas: 1` → every voluntary eviction (node drain) blocked forever | `maxUnavailable: 1` — drainable at any replica count |
| Unpinned rollout strategy | no `spec.strategy` → Kubernetes default RollingUpdate 25%/25% could drop all replicas during `helm upgrade` | every Deployment pins `strategy.rollingUpdate` `maxUnavailable: 0, maxSurge: 1` (values `strategy.rollingUpdate.*`) |

PDB semantics with `maxUnavailable: 1`: at `replicaCount: 2` at most one
gateway pod may be voluntarily evicted (≥1 stays Ready); at `replicaCount: 1`
the single pod can always be drained (the non-HA profile accepts a brief
outage during maintenance — that is the overlay's decision, not a PDB bug).

Regression guard: `bash deploy/helm/ha_selector_test.sh` renders both charts
with every values variant and fails if any PDB selects no workload, any PDB
would block all evictions at the rendered replica count, or any Deployment
lacks a pinned `rollingUpdate` strategy.

## Install (HA profile)

```bash
helm upgrade --install yabanin deploy/helm/yabanin \
    --set replicaCount=2 \
    --set image.tag=<version>          # + secrets per values.yaml comments

kubectl rollout status deploy/yabanin-gateway   # 2/2 Ready
kubectl get pdb                                # allowedDisruptions >= 1
```

Soft anti-affinity (`preferredDuringScheduling`, per hostname) spreads
gateway pods across nodes when the cluster allows it.

## Drill 1 — pod loss

```bash
POD=$(kubectl get pod -l app=yabinin-gateway -o jsonpath='{.items[0].metadata.name}')
kubectl delete pod "$POD"
# Service keeps answering on the remaining replica:
watch -n1 'curl -fsS http://<gateway-endpoint>/healthz'
kubectl rollout status deploy/yabanin-gateway   # replacement becomes Ready
```

Expected: zero failed requests from a client that retries/handles
connection resets (readiness + endpoint removal removes the dying pod from
the Service before it stops answering).

## Drill 2 — rollout (zero-downtime upgrade)

```bash
helm upgrade yabanin deploy/helm/yabanin --set image.tag=<new-version> ...
kubectl rollout status deploy/yabanin-gateway
```

With `maxUnavailable: 0, maxSurge: 1` the rollout replaces pods one by one:
a surge pod becomes Ready first, then an old pod is removed. Watch for
5xx windows during the drill; there should be none.

## Drill 3 — node drain (voluntary disruption)

```bash
kubectl drain <node> --ignore-daemonsets --delete-emptydir-data
```

Expected: eviction allowed for gateway/admin pods (PDB
`allowedDisruptions ≥ 1`, `maxUnavailable: 1`); drain completes instead of
hanging. On a `replicaCount: 1` profile the drained service is briefly
unavailable — schedule maintenance accordingly or raise replicas first.

Drain semantics verified live (2026-10-18, docker-desktop k8s 1.25, internal
evidence record): with 2 gateway replicas + a
`maxUnavailable: 1` PDB the FIRST eviction is allowed and the LAST pod's
eviction is refused with `Cannot evict pod as it would violate the pod's
disruption budget` — a drain can never take the service to zero voluntarily.
All three drills above were executed on a live cluster (pod loss: 60/60
healthz checks passed through a pod deletion; rollout: 600/600 in-cluster
requests through a full image rollout; see `integration.md`).

## On-prem chart (air-gap) path

The `yabanin-onprem` chart has no PDBs (single-node-by-design services;
`strategy.rollingUpdate` is pinned the same way). Its install path (migrate
hooks, application role bootstrap, required HEX secrets) is documented in
[../../onprem/install-guide.md](../../onprem/install-guide.md).

## Single-node caveats

- **Postgres** (onprem statefulset) is the availability boundary: gateway
  replicas do not help if the single PG node is down. Backups/upgrade
  safety: `scripts/dr/backup_all.sh`, pre/post-upgrade hooks and
  `rollback-job.yaml` in the chart; migrations are forward-only — rollback
  across a migration means restoring the pre-upgrade backup.
- **loggerd** (onprem) is single-instance: events are published to a Redis
  stream; while loggerd is down the stream buffers and loggerd resumes on
  restart (at-most-once semantics per pending event — verify lag after a
  restart). "Leader change" for loggerd is simply a restart; no state handoff
  exists.
- The migrate initContainer runs per gateway rollout; concurrent replicas
  serialize through golang-migrate's locking (`pkg/migrate`).

## Naming drift note

Chart-internal names/labels say `yabinin` (single-b) in places while the
repository/product is `yabanin`. Renaming breaks Helm upgrade ownership of
existing resources, so account for this drift when updating the chart. Any
label-based policy (mesh, NetworkPolicy peers) must use the labels as
rendered — verify with `helm template` / `kubectl get --show-labels`.
