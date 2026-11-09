# Disaster recovery drill

A disaster recovery drill verifies that a known backup, retained keys and
configuration can restore usable application behavior. Define recovery time (RTO)
and recovery point (RPO) objectives for your service before the drill. This
procedure produces engineering evidence; it does not confer SOC 2, ISO 27001 or
other certification.

Use synthetic data in an isolated environment. Do not destroy a production cluster
to simulate an outage. For a directly executable local database procedure, start
with [Backup restore rehearsal](backup-restore-rehearsal.md).

## Automated database drill

With the repository's required Go toolchain and a reachable Docker daemon:

```bash
go test -count=1 -v -tags=integration \
  -run '^TestDR_BackupWipeRestoreVerify$' ./tests/integration/dr/
```

The test provisions disposable pgvector/PostgreSQL, applies the shipped forward
schema migrations, seeds audit rows through `auditlog.Writer`, dumps the database,
drops/recreates that disposable schema, restores it and verifies table/audit row
counts and the audit hash chain. It cleans up its own test container.

Read the actual output and exit code. The test does not restore production scale,
external services, Redis pending work, keys from an external vault, dashboard
routing or a regional control plane. It does not use a customer's backup. Its
logged restore duration is a local database measurement, not complete service RTO.
Historical millisecond results on a small fixture are not production guarantees.

## Full application drill preparation

Record the intended scope and keep these inputs available outside the failure
domain:

- A selected backup with timestamp, checksum, format and source database version.
- Application image digests, source/release identity and deployment configuration.
- Encryption/signing keys and any license verification material required by the
  chosen deployment, handled through protected recovery access.
- Database roles/grants and region settings, plus Redis/event recovery policy.
- External upstream/collector dependencies and safe mock substitutes for the drill.
- Expected test organizations, keys, history and audit records for validation.
- Recovery owner, test window, communication channel and cleanup plan.

Establish whether the backup's snapshot age can meet the chosen RPO. A daily dump
cannot by itself provide a one-hour recovery point. Include unprocessed events and
writes accepted after the snapshot when calculating possible loss.

## Restore into an explicitly empty target

Provision a new database using the same PostgreSQL major version and required
extensions as the source. Use a new cluster/database/volume with an identity that
cannot be confused with production. Set protected connection credentials through
your approved mechanism; avoid literal passwords in command history.

For an operator-supplied empty target URI and custom-format dump, the essential
host-tool sequence is:

```bash
set -euo pipefail
# Set RESTORE_URI and DUMP_FILE to the disposable target and selected dump first.
: "${RESTORE_URI:?Set the URI of the disposable empty database}"
: "${DUMP_FILE:?Set the path to the selected custom-format dump}"
DR_TABLES=$(psql "$RESTORE_URI" -v ON_ERROR_STOP=1 -Atc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
test "$DR_TABLES" = 0
pg_restore --dbname="$RESTORE_URI" --no-owner --no-acl \
  --exit-on-error "$DUMP_FILE"
```

Use a script or terminal with failure handling enabled so a failed empty-target
check stops execution. The full local rehearsal includes this safeguard. The
`--dbname` option is required: a connection URI as an unflagged `pg_restore`
argument is interpreted as an input filename, not the target database.

The current `scripts/dr/restore.sh` and `restore_all.sh` wrappers omit that option
and must not be treated as a working restore procedure in this version.
`restore_all.sh --backup-ts ...` is also not a supported interface: its declared
arguments are a target URI and dump path. Use the explicit procedure above or the
local rehearsal until the wrappers are corrected and tested.

A custom dump restored with `--no-owner --no-acl` deliberately omits ownership and
grants. Establish the reviewed application role and permissions separately. Keep
migration credentials separate from least-privileged runtime credentials. Apply
only migrations required by the selected target application version.

## Bring up the recovered application

Use the [on-premises installation guide](../onprem/install-guide.md) or your
reviewed deployment manifests. Choose the actual namespace, release name, image
and protected values/Secret references. Do not assume a fixed node port or that
creating a namespace makes Helm use it. Supply the restored database rather than
accidentally provisioning and testing an empty replacement.

Keep external inference and notifications disabled or routed to controlled mocks
until validation is complete. Restore the dashboard separately and check its edge
routes to `/auth` and `/api`. Retain previous deployment configuration for comparison.

## Validate data and behavior

| Check | Required evidence |
| --- | --- |
| Database | Schema, extensions, constraints, migrations, expected snapshot records |
| Privilege | Application role cannot bypass organization/region isolation |
| Encryption | Existing stored credentials can be used through the application |
| Authentication | Known test login/key succeeds; revoked/unauthorized access rejects |
| Inference | Controlled request succeeds and new history persists |
| Audit | Hash-chain verifier succeeds, with any known preexisting gaps identified |
| Lineage | Existing records and keys are usable; signature validity is distinct from the actual processing location |
| Budget | Restored balances/reservations are reconciled before opening paid traffic |
| Event recovery | Pending/duplicate/replayed events handled according to tested policy |
| UI/edge | Login, protected organization view, deep links and logout work |
| Monitoring | Targets scrape and the drill's expected notifications reach receivers |

`auditlog.NewVerifier(...).Verify(ctx)` is a Go API used by the automated drill,
not a shell command named `pkg/auditlog/verifier.Verify()`. For a manual restore,
use an application-integrated verifier or an operator-reviewed harness that targets
the restored database. Merely counting sequence numbers is not hash-chain
verification. Do not claim this check ran if you only inspected rows.

## Record outcome and clean up

Record start of incident simulation, backup snapshot, target provisioning,
database restoration, application acceptance and end of drill in UTC. Report both
database restore duration and full time to accepted service behavior. Measure the
actual recovered-write boundary; backup file creation time alone is insufficient.

| Field | Result |
| --- | --- |
| Deployment/backup identity | Source version, image and backup checksum |
| Recovery time | Full duration and database-only component |
| Recovery point | Snapshot boundary and known missing interval |
| Checks | Passed, failed and unexecuted separately |
| Limitations | Scale, external services and data classes not exercised |
| Follow-up | Exact defect, owner, next verification |

A failed check leaves the drill incomplete. Repair the cause and repeat the
relevant acceptance before treating the backup as recoverable. Delete only the
isolated resources created for this drill, dispose of sensitive temporary dumps
according to policy, and retain sanitized evidence with the deployment record.
