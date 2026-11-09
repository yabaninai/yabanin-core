# Backup and restore rehearsal

A backup is useful only after a restore has been exercised. This procedure takes
a custom-format PostgreSQL dump from a **local quickstart** and restores it into
a new disposable container, without touching the source volume. Adapt the backup
source and credentials explicitly for another deployment. It does not establish
production disaster recovery, Redis recovery, or a fixed recovery-time guarantee.

The public export does not include a production Compose backup sidecar or a
backup schedule. The shipped `scripts/dr/backup_compose.sh` assumes a particular
service hostname, database user and mounted secret; merely having that script does
not mean backups are running. Establish and monitor your own schedule and storage.

## Prerequisites and boundaries

- A running, seeded quickstart from [Quickstart](../quickstart.md).
- Bash, Docker Compose, `openssl`, and adequate local disk space.
- No shell tracing (`set -x`): dump files and database credentials are sensitive.
- The same Compose project name used when creating the quickstart.

Use a dedicated terminal and run from the source root. The commands below retain
variables across steps. The restore container uses the **same local pgvector
image** as the source service, so the vector extension is available. It publishes
no ports and has no connection to the application network.

## 1. Take a protected dump

```bash
set -euo pipefail
umask 077
QS_COMPOSE=deploy/quickstart/docker-compose.yml
DR_DIR=$(mktemp -d "${TMPDIR:-/tmp}/yabanin-restore.XXXXXX")
DR_CONTAINER="yabanin-restore-$(date -u +%Y%m%d%H%M%S)-$$"
DR_IMAGE=$(docker compose -f "$QS_COMPOSE" images -q postgres)
test -n "$DR_IMAGE"
date -u +%Y-%m-%dT%H:%M:%SZ > "$DR_DIR/backup-started.txt"
docker compose -f "$QS_COMPOSE" exec -T postgres \
  pg_dump -U yabanin -d yabanin --no-owner --no-acl --format=custom \
  > "$DR_DIR/database.dump"
test -s "$DR_DIR/database.dump"
date -u +%Y-%m-%dT%H:%M:%SZ > "$DR_DIR/backup-finished.txt"
ls -lh "$DR_DIR/database.dump"
```

The database credentials above are the local quickstart's fixed development
credentials. For production, use a dedicated backup role and protected credential
mechanism with sufficient read access to all required rows, including RLS-protected
state. Check the dump exit status and file readability; file existence alone is
not backup success.

`pg_dump` captures a consistent database snapshot while writes can continue.
Counts collected later from the live database may therefore differ legitimately.
For exact fixture comparisons, stop synthetic writers before the dump and record
expected values. Do not stop production writers merely to copy this example.

## 2. Start a fresh restore target

```bash
printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 32)" > "$DR_DIR/restore.env"
printf 'POSTGRES_DB=yabanin_drill\n' >> "$DR_DIR/restore.env"
docker run -d --name "$DR_CONTAINER" --network none \
  --env-file "$DR_DIR/restore.env" "$DR_IMAGE" > /dev/null

DR_READY=0
for attempt in $(seq 1 60); do
  if docker exec "$DR_CONTAINER" pg_isready -h 127.0.0.1 -U postgres -d yabanin_drill >/dev/null 2>&1; then
    DR_READY=1
    break
  fi
  sleep 1
done
test "$DR_READY" = 1
DR_TABLES=$(docker exec "$DR_CONTAINER" psql -U postgres -d yabanin_drill -Atc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
test "$DR_TABLES" = 0
```

The empty-table assertion addresses the actual `yabanin_drill` target database.
Never substitute a running application database or reused volume here. If startup
fails, inspect this container's logs and clean up only resources named by these
variables.

## 3. Restore with errors enforced

```bash
DR_STARTED=$(date +%s)
docker exec -i "$DR_CONTAINER" pg_restore \
  -U postgres -d yabanin_drill --no-owner --no-acl --exit-on-error \
  < "$DR_DIR/database.dump"
DR_FINISHED=$(date +%s)
printf 'Restore command completed in %s seconds\n' "$((DR_FINISHED - DR_STARTED))"
```

The dump is streamed from the host into the container. There is no assumption that
a decompressed host file also exists inside the container. The reported duration
covers `pg_restore` only; it excludes provisioning, application startup, key
recovery, validation and traffic cutover.

## 4. Validate restored state

```bash
docker exec "$DR_CONTAINER" psql -U postgres -d yabanin_drill -v ON_ERROR_STOP=1 -c \
  "SELECT count(*) AS organizations FROM organizations;
   SELECT count(*) AS api_keys FROM api_keys;
   SELECT count(*) AS request_logs FROM request_logs;
   SELECT extname FROM pg_extension ORDER BY extname;"
```

Check these values against the fixture or snapshot evidence for the backup.
Row counts alone do not establish integrity. Before accepting a production restore:

- Verify required tables, indexes, constraints, extension versions and migration
  ledger against the deployed application's expectations.
- Recreate/review database roles, ownership and grants: `--no-owner --no-acl`
  deliberately does not preserve them, and `pg_dump` does not capture cluster roles.
- Validate RLS using the application role and intended organization/region context,
  not the privileged restore connection used above.
- Restore the required encryption keys and test decryption through the application
  without exporting plaintext secrets into the evidence.
- Verify audit chains with the application's verifier or integration drill.
  Contiguous sequence numbers alone do not verify hashes, signatures or authenticity.
- Start an isolated application against the restore, with upstream egress disabled
  or a controlled mock, and verify authentication, history and an allowed request.
- Account for Redis pending events and any data outside PostgreSQL separately.

The repository's automated database drill is
`go test -tags=integration -run TestDR_BackupWipeRestoreVerify ./tests/integration/dr/`.
It requires its own integration-test prerequisites and is not implicitly executed
by this manual procedure. See [Disaster recovery drill](dr-drill.md).

## 5. Record evidence and recovery objectives

| Field | Record |
| --- | --- |
| Source | Application commit/image, PostgreSQL image, schema/migration state |
| Snapshot | Backup start/finish UTC, byte size, protected storage location |
| Restore | Target identity, command exit status, duration, errors |
| Validation | Expected/actual fixture data, role/RLS checks, application checks |
| Full recovery time | Provisioning through accepted application behavior |
| Recovery point | Actual newest recovered write and known unrecovered interval |
| Follow-up | Failed checks, remediation, owner and next rehearsal date |

Backup age is an input to RPO, not a measurement of lost rows by itself. Define
RPO/RTO for the service and measure them in a full rehearsal. A daily dump can be
nearly 24 hours old; a one-hour objective requires a different backup/recovery
strategy and proof that it works.

## 6. Clean up this rehearsal

Only after recording the results:

```bash
docker rm -f -v "$DR_CONTAINER"
rm -f "$DR_DIR/database.dump" "$DR_DIR/restore.env" \
  "$DR_DIR/backup-started.txt" "$DR_DIR/backup-finished.txt"
rmdir "$DR_DIR"
unset DR_CONTAINER DR_IMAGE DR_DIR DR_READY DR_TABLES DR_STARTED DR_FINISHED
```

`-v` removes this disposable container's anonymous database volume. These commands
do not remove the quickstart's persistent volume. Delete sensitive temporary data
according to the storage medium's security policy; unlinking is not a claim of
secure erasure. A failed rehearsal remains failed until its cause is corrected
and the restore is repeated successfully.
