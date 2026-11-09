# Production operations

This runbook describes diagnosis and operating boundaries for a deployment you
have configured. The public repository does not include the maintainer's
production Compose file. Use [deployment preparation](public-stand-deploy.md) or
the [on-premises guide](../onprem/install-guide.md) for installation, and the
[quickstart](../quickstart.md) for a local evaluation stack.

## Service boundaries

| Component | Usual listener | Purpose |
| --- | --- | --- |
| Gateway | 8082, `/healthz` | Authenticated inference and routing |
| Gateway diagnostics | 9090 | Metrics and explicitly enabled diagnostics; keep private |
| Admin | 8086, `/health` | Session authentication and administrative JSON APIs |
| Loggerd | 8085, `/healthz` | Event consumption and persistence |
| PostgreSQL | 5432 | Persistent application state; pgvector where configured |
| Redis | 6379 | Cache, events and coordination; contents are not all disposable |
| Dashboard | Operator-defined static origin | React application; separate from admin API |
| Classifier/embedder | Operator-defined | Optional external services, absent from the default mock quickstart |

Ports are configurable and chart values can differ. In the quickstart, gateway,
admin and loggerd run in one `yabanin` container. A split deployment has separate
service instances. Identify which topology is running before restarting anything.

## Select the correct environment

For the **local quickstart only**, run from its source root:

```bash
QS_COMPOSE=deploy/quickstart/docker-compose.yml
docker compose -f "$QS_COMPOSE" --profile mock ps -a
docker compose -f "$QS_COMPOSE" --profile mock logs --since 10m yabanin
```

Keep the same `COMPOSE_PROJECT_NAME` and port overrides used at installation.
For your production deployment, use its actual manifest, namespace, release and
service names. Do not copy a quickstart reset command into a production incident.
Logs can include sensitive operational context: collect the minimum needed and
redact credentials, cookies, prompts and responses before sharing them.

## Updates and rollback

Before an update, record the current image digest, configuration version and
migration status. Take a verified backup and retain the encryption keys required
by that state. Read migration compatibility before deciding whether the old
binary can run against the new schema.

Use a rollout strategy with healthy replicas and traffic draining when continuous
availability is required. `docker compose restart` stops the selected container;
it is not a zero-downtime rolling update. A single `dev` process restart affects
all three application services. The [HA runbook](../ops/runbooks/ha.md) describes
the Kubernetes drain and rollout controls.

If acceptance fails, stop promotion. Revert the image and configuration only when
compatible with the current database. Never apply an arbitrary `.down.sql` file
as a generic rollback: it can delete data and bypass the migration ledger. A
restore-based rollback needs an explicitly chosen recovery point, an isolated
restore rehearsal and a plan for writes accepted since that point.

## Diagnose an incident

### Gateway is unavailable or requests return 5xx

1. Check the gateway health endpoint through the edge and directly on its private
   listener. A proxy/TLS failure and an application failure need different fixes.
2. Check service status and recent gateway, loggerd and database logs. Preserve
   the first error and request ID before restarting.
3. Test PostgreSQL with `pg_isready` or a read-only `psql` query, not an HTTP client.
   Test Redis with `redis-cli ping`. Use deployment-specific authentication.
4. Inspect [history admission](history-admission.md). A Redis/database failure can
   deliberately reject new requests to protect history; do not assume inference
   continues merely because cache reads can fall back.
5. Check the registered model, upstream health, eligible credential, budget and
   egress policy. A healthy gateway does not establish that its upstream works.
6. Recover the dependency or configuration first, then repeat health and an
   authenticated test request. Verify history persistence after recovery.

For a local quickstart dependency check:

```bash
docker compose -f "$QS_COMPOSE" exec -T postgres pg_isready -U yabanin -d yabanin
docker compose -f "$QS_COMPOSE" exec -T redis redis-cli ping
```

### Latency or provider errors increase

Separate gateway processing, queue wait and provider latency before changing
routing. Inspect the affected organization/model/route and the provider's actual
status/error response. Check concurrent streams, database pool pressure, Redis
latency and optional classifier/embedder timeouts.

Do not switch an organization to `always_cheap` as a generic classifier-outage
fix: it changes model selection and quality. Inspect classifier fallback and the
circuit breaker, then change policy only after evaluating that tradeoff. Optional
ML integration is described in [Classifier service](../classifier-ml.md).

### Database connections or storage are exhausted

Use a privileged **read-only diagnostic session** appropriate to the deployment:

```sql
SELECT state, application_name, count(*)
FROM pg_stat_activity
GROUP BY state, application_name;
SHOW max_connections;
SELECT datname, pg_database_size(datname) FROM pg_database;
```

Correlate active/idle transactions with service pools and rollout replica count.
Do not raise `max_connections` without checking memory and upstream pool limits.
Avoid terminating sessions or deleting history as an unexplained first action.
Use configured retention and a tested archival process; preserve audit/accounting
requirements and investigate why growth exceeded capacity.

### Redis memory pressure

Inspect memory, eviction, persistence and keys by type. Redis contains more than
response cache entries: deleting the database can remove queued events and
coordination state. **Do not use `FLUSHDB` or broad key deletion as routine cache
maintenance.** Use a documented, scoped cache invalidation path or restore
capacity while preserving events. Review eviction policy against the stored data
classes, and alert before the service reaches its limit.

The quickstart Redis service has no durable volume. Production durability depends
on your Redis configuration and storage; AOF is not universally enabled by Yabanin.

### Loggerd backlog increases

For the quickstart's default stream, inspect:

```bash
docker compose -f "$QS_COMPOSE" exec -T redis redis-cli XLEN events:queue
docker compose -f "$QS_COMPOSE" exec -T redis redis-cli XINFO GROUPS events:queue
```

Use the configured stream name elsewhere. Stream length alone is not consumer
lag: compare group lag, pending entries, consumption rate and database failures.
Restore the blocked dependency and verify pending entries are consumed. Do not
trim the stream to make a backlog graph smaller; that can discard unpersisted
history and accounting events. Scaling consumers requires a tested shared-group
configuration, database capacity and unique consumer identities.

## Monitoring and alert delivery

The authoritative shipped expressions are in `deploy/prometheus/alert-rules.yml`.
Use [Alerts](alerts.md) and the [inventory](alerts-inventory.md) for signal meaning,
notification configuration and recovery actions. Tune thresholds against your
measured workload; a historical benchmark is not a deployment SLO.

The gateway diagnostics listener serves `/metrics` when enabled. Configure
`YABANIN_METRICS_BEARER_KEY` when bearer protection is required and mount the
matching scrape credential in Prometheus. Restrict diagnostic listeners at the
network boundary regardless. Metrics can reveal model names, organization IDs
and traffic volumes. Optional profiling is private diagnostic access, not a
public health endpoint; see [Security](../security.md).

The Alertmanager template includes receiver placeholders and no usable receiver
credentials. It does not send notifications merely because the file exists.
Install a rendered, validated configuration and receive both a test notification
and its resolution before relying on it. Generic webhook payloads require a
compatible receiver or adapter; a Slack or PagerDuty URL is not automatically an
Alertmanager-compatible webhook.

Grafana dashboard definitions are available in `deploy/grafana/dashboards`.
Interpret cost panels as estimates/counterfactual comparisons where labeled, not
provider invoices or guaranteed realized savings.

## Backups and recovery

Schedule database backups, encrypt/protect them, copy them off the failure domain
and monitor age and restore success. Retain the encryption keys and deployment
configuration needed to use restored state. A database dump does not capture
Redis pending work, uploaded artifacts, external model files or infrastructure.
Document recovery for each separately.

Run the [backup restore rehearsal](backup-restore-rehearsal.md) against a disposable
PostgreSQL instance. Measure full application recovery, not only `pg_restore`
duration. Set backup frequency from your RPO: a daily snapshot alone can lose
nearly a day of writes. A copied source tree or Git bundle is a source backup,
not an application-data backup.

## Administrative changes

Use the dashboard or the [API contract](../api/CONTRACT.md) for organization,
credential, budget and routing changes. Administrative `/api` mutations normally
require an authenticated admin session, authorized role and CSRF protection.
An organization gateway bearer key does not grant admin access.

`YABANIN_ADMIN_API_KEY` enables a separate read-only internal service API:
`GET /internal/api-keys` and `GET /internal/analytics/savings`, both requiring
`org_id` and `X-Admin-Key`. It is not a general mutation credential. See [CLI](../cli.md)
for supported administrative commands and their authentication.

For each production change, capture the intended scope, prior configuration,
expected result and rollback. After applying it, verify the affected organization
and a negative permission case. Keep one-time keys out of tickets and screenshots.

## On-call reference

| Symptom | First investigation | Recovery evidence |
| --- | --- | --- |
| 5xx increase | Edge versus gateway versus provider; dependency logs | Authorized request succeeds and history persists |
| High latency | Processing/queue/upstream split, concurrency and pools | Percentiles recover under the same workload |
| Cache drop | Cache availability, policy and traffic mix | Scoped behavior matches the chosen cache mode |
| Classifier errors | Optional service health and fallback | Valid classification/fallback without unintended route change |
| Budget rejections | Scope, limits, reservations and settlement | Correctly funded allowed request; exhausted case still rejects |
| Database disk pressure | Growth, retention and backup state | Capacity restored with required data preserved |
| Redis/loggerd backlog | Pending work and downstream database | Consumption resumes and backlog drains without data deletion |
