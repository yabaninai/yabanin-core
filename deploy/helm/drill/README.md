# Local PostgreSQL failover drill

This directory tests a three-member Patroni/PostgreSQL cluster in Docker
Compose. It exercises primary termination, a network partition and the loss of
an unreplicated data volume. It does not deploy the Yabanin gateway or establish
production Kubernetes, multi-host or availability-zone resilience.

## Scenarios and checks

| Script | Checks |
|---|---|
| `failover_drill.sh` | Waits for a physical replication canary on both standbys and a named synchronous standby; seeds records; kills the primary; requires a new acknowledged write within 60 seconds of failure; checks accounting records and the old primary's read-only rejoin. |
| `split_brain_test.sh` | Requires a continuously settled replication state for 20 seconds, partitions the primary, permits up to 240 seconds for survivor election, rejects writes to the isolated old primary, and checks its read-only rejoin after healing (up to 300 seconds). |
| `negative_fsync_test.sh` | Destroys a disposable standalone PostgreSQL volume and verifies that its acknowledged rows do not reappear; local fsync is not replicated storage. |
| `negative_contract_test.sh` | Renders the on-prem Helm profiles and checks that their bundled database remains single-replica, with no misleading HA placement/PDB or durability claims. |

These are executable test conditions, not measured results for your environment.
The scripts report failures instead of treating an unavailable cluster as a
passing drill. The accounting check compares the seeded acknowledged rows after
promotion. The history role uses asynchronous commits; observing its rows after
one run does not establish a general loss bound or zero-loss guarantee.

The partition check samples whether the old primary can acknowledge a write and
whether it becomes a replica after healing. It is not an exhaustive race test
of every possible split-brain window. In-flight transactions, interrupted LLM
streams and loss of all nodes are outside these scenarios.

## Layout and prerequisites

- `Dockerfile` uses the mutable `postgres:16-alpine` base tag, with Patroni
  `4.1.5` and psycopg `3.3.6` version arguments. This is a local drill image,
  not a reproducibly pinned production image.
- `docker-compose.drill.yml` defines project `n11p02-drill`, three nodes,
  named volumes and an internal network without published host ports. The
  nodes start together rather than waiting on one another's health checks.
- `patroni/node-{a,b,c}.yml` configures the raft peers using `partner_addrs`,
  synchronous mode and strict synchronous mode. Trust authentication is for
  this isolated drill only.
- `post_bootstrap.sh` creates `drill_app` and `drill_history`. The history
  role sets `synchronous_commit=off`.

Use a disposable host with Docker, the Compose plugin, Python 3, `flock` and
standard shell utilities. `negative_contract_test.sh` also requires Helm.
Container probes use `psql` and HTTP checks; no database ports need publishing.
The scripts build/start containers and remove their drill resources, including
volumes. Run them sequentially: their lock files are distinct, while the
failover and partition scenarios use the same Compose project. Do not share
that project name or its volumes with other work.

## Run from the repository root

```sh
bash deploy/helm/drill/failover_drill.sh
bash deploy/helm/drill/negative_fsync_test.sh
bash deploy/helm/drill/split_brain_test.sh
bash deploy/helm/drill/negative_contract_test.sh
```

To retain the failover cluster for inspection:

```sh
KEEP_DRILL=1 bash deploy/helm/drill/failover_drill.sh
```

The failover script's advisory lock is
`/tmp/opencode/n11p02-drill.lock`; partition and volume-loss scripts use separate
locks. These literal paths and project names are script interfaces, not release
planning references. Capture the script output, source/image identities,
hardware, failure timestamps and acknowledgment checks with each result.

## Configuration details that matter

A REST role response alone is not sufficient replication evidence: a standby
can answer while cloning. The physical canary and named-sync checks prevent
injecting a failure before the required replication state exists. The partition
scenario additionally requires a settle window before injection.

The bootstrap script waits for PostgreSQL before creating roles. SQL sent through
stdin uses `docker exec -i`; without stdin forwarding, a command can exit without
executing the supplied statements. Commit policy is set on the history role,
not as a table-storage parameter.
