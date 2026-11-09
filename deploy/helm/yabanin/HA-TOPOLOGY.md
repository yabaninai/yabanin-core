# High-availability topology for the cloud Helm chart

This document describes the placement controls in `deploy/helm/yabanin` and the
external services needed for a deployment that can recover from one cluster-node
failure. The chart does not provision a PostgreSQL or Redis HA cluster. Rendered
Kubernetes resources alone are not evidence of an achieved recovery time or data
loss guarantee; verify the deployed topology with a failure drill.

## Gateway and admin placement

| Component | Resource | Placement |
|---|---|---|
| Gateway | `<release>-gateway` Deployment | Uses `replicaCount`; HA mode requires at least two replicas. |
| Admin | `<release>-admin` Deployment | Uses the same replica count and HA spread controls. |
| MCP | `<release>-mcp` Deployment | One replica; this auxiliary service is not made highly available by the HA flag. |

With `ha.enabled=true`, gateway and admin each receive a topology spread
constraint with `maxSkew: 1`. The default topology key is
`kubernetes.io/hostname`, and the default unsatisfied-placement policy is
`DoNotSchedule`. The selectors match the chart's pod labels
(`app: yabinin-gateway` and `app: yabinin-admin`; these spellings are intentional
compatibility details). HA mode rejects `replicaCount < 2` when rendering.

Spread constraints balance pods across eligible topology domains. They require
enough eligible nodes with capacity, matching labels and compatible scheduling
rules. The chart does not set `minDomains`; therefore the replica count and
spread constraint alone do not prove that pods occupy two distinct nodes.
Check actual pod placement before treating the deployment as node-fault-tolerant.
`ScheduleAnyway` is an optional weaker scheduling policy, not equivalent to the
default hard constraint.

Preferred pod anti-affinity is also present when HA mode is disabled. The region
overlays with one replica provide no replica redundancy. By default, gateway and
admin PodDisruptionBudgets use `maxUnavailable: 1`; these constrain voluntary
disruptions and do not prevent node failures. Rolling updates default to
`maxUnavailable: 0`, `maxSurge: 1` and `minReadySeconds: 5`. Readiness, startup and
liveness probes are configurable. These settings support controlled rollouts;
application readiness and external-service availability still determine whether
requests succeed.

## PostgreSQL

The chart accepts an operator-provided PostgreSQL endpoint through
`secrets.pg_uri`; gateway region configuration can also contain
`gateway.regions.<region>.pg_uri`. Provision database replication, backups,
endpoint failover and fencing separately.

For a deployment that requires no loss of acknowledged accounting,
authorization or audit writes after node loss, evaluate all of these together:

- Synchronous replication to durable storage on another node, with the required
  acknowledgment policy configured for the actual write paths.
- A failover controller that selects a sufficiently current replica and prevents
  the old primary from remaining writable after a partition.
- Client reconnection to the promoted primary and restoration of readiness.
- Failure tests that compare acknowledged records before and after recovery.

The Helm HA flag does not set PostgreSQL replication or `synchronous_commit`.
Local fsync alone does not provide replicated durability. Likewise, asynchronous
replication does not establish a fixed loss bound without additional monitoring
and enforcement. Define request-history retention and replication requirements
explicitly for your deployment rather than inferring them from this chart.

The separate `deploy/helm/yabanin-onprem` chart includes a single-replica
PostgreSQL StatefulSet; that configuration is not a replicated HA database.

## Recovery objectives and limitations

For a deployment adopting these objectives:

- Accounting / authorization / audit: **RPO=0 target**, requiring replicated
  acknowledgment and fenced failover verified on the actual write paths.
- Request history: **RPO ≤ 60 s target** for asynchronous history replication;
  this requires measured lag and a mechanism that enforces the bound. The chart
  does not configure or prove that bound. A zero-loss history requirement needs
  a separately verified synchronous acknowledgment path.
- New requests accepted within 60 seconds of node failure: an operational RTO
  target, not an assertion that the chart achieves it.

Local fsync is not replicated RPO=0 storage. These targets are deployment
acceptance criteria, not chart guarantees. A passing local database scenario
alone does not establish production RTO/RPO.

## Redis and other stateful services

Gateway region configuration can supply
`gateway.regions.<region>.redis_addr`. Redis availability, persistence and
failover are operator responsibilities. Evaluate each enabled feature's use of
Redis, including state that may not be reconstructible from a cache miss.
Do not infer acknowledged-job durability or zero data loss from Sentinel,
clustering or a persistence option alone; validate the complete write and
recovery path against your requirements.

## Configure and inspect

| Value | Default | Effect |
|---|---|---|
| `ha.enabled` | `false` | Enables gateway/admin topology spread and the minimum-replica render guard. |
| `ha.topology_key` | `kubernetes.io/hostname` | Selects the scheduling failure-domain label. |
| `ha.when_unsatisfiable` | `DoNotSchedule` | Controls how the scheduler handles a spread constraint it cannot satisfy. |
| `replicaCount` | `2` | Sets gateway/admin replicas. |

From the repository root, inspect the rendered resources before installation:

```sh
helm template example deploy/helm/yabanin --set ha.enabled=true
```

`deploy/helm/ha_selector_test.sh` checks selector alignment and replica/spread
relationships. `deploy/helm/values_schema_test.sh` checks rendering and schema
constraints, including rejection of a one-replica HA profile. These are chart
checks, not live failover tests. The local database drill is documented in
`deploy/helm/drill/README.md`; a single-host drill does not establish multi-node
or availability-zone resilience.

## Explicit negatives (do not promise)

For deployment acceptance, record the failure timestamp, fencing/promotion
sequence, first successful new request and preservation of acknowledged data.
Measure recovery from the failure itself, not only from its detection. Any
recovery-time target must include database failover, connection recovery,
readiness and service routing. In-flight provider requests and streams can be
interrupted; an unknown outcome does not justify an automatic retry without
appropriate deduplication or proof that the original operation did not execute.
Whole-zone, site or region survival requires a separately designed and tested
topology.
