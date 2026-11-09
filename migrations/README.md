# PostgreSQL migrations

Yabanin uses `golang-migrate` and embeds its SQL migrations in the application.
The unified `yabanin migrate` command and the standalone `yabanin-migrate`
executable call the same [migration runner](../pkg/migrate/migrate.go).
Run the binary built from the release you intend to deploy: changing SQL files
beside an existing binary does not change its embedded migration set.

## Current schema and numbering

- Current embedded head: **0027** (`security_inbox`). A successful migration to
  this release records `version = 27` and `dirty = false`.
- Next available migration number: **0028**.
- The shipped set contains **26 up/down pairs**: `0001` through `0022`, then
  `0024` through `0027`. Version **0023 is permanently reserved and unused**;
  do not create a replacement file for it or renumber later migrations.
- Files use the format `NNNN_name.up.sql` and `NNNN_name.down.sql`, with a
  four-digit version and a lowercase descriptive name. Each version has exactly
  one matching pair.
- [This directory](.) is the readable source copy. The same SQL files must be
  byte-identical in [the embedded directory](../pkg/migrate/migrations).
  `TestEmbeddedMigrationsInSyncWithRoot` checks both file membership and bytes;
  the numbering tests check pairs, uniqueness, the reserved gap and this README.

`0001_init` is a consolidated schema and seed-data baseline. A fresh database
runs that baseline **and every later shipped up migration**. Historical comments
about a baseline-only installation do not describe the current runner's
`m.Up()` behavior. The baseline does not replace an upgrade plan for an arbitrary
older installation.

The later additions include:

| Versions | Schema changes |
| --- | --- |
| `0016`–`0017` | MCP credential-mode configuration and encrypted PKCE verifier storage |
| `0018` | Durable approval-operation state |
| `0019` | Deployment-wide active rates-catalog state and provenance |
| `0020` | Allowed actions on MCP grants |
| `0021` | Durable security-event documents |
| `0022` | Inventory asset records |
| `0024` | Fleet installation registry |
| `0025` | Organization classification taxonomies |
| `0026` | Row-level security for security-event documents |
| `0027` | Security inbox incidents |

A schema object's presence does not by itself establish that a feature is
configured, enabled or exposed by a particular deployment. Consult the SQL
files for exact columns, constraints and policies.

## Before applying migrations

1. Identify the database, application release and existing migration history.
   Use the same PostgreSQL target and region configuration as the intended
   deployment. Do not point a rehearsal at a production database.
2. Take a verified backup, retain the encryption keys needed to read its data,
   and rehearse restoration into a separate database. See the
   [backup and restore rehearsal](../docs/runbooks/backup-restore-rehearsal.md).
3. Review every pending up migration and application compatibility. Coordinate
   writers and schema-changing jobs through your deployment procedure; a schema
   migration is not a promise of zero-downtime application compatibility.
4. Use a migration role with the required DDL and extension privileges, separate
   from a least-privileged runtime role. The baseline creates the `vector`
   extension, so the PostgreSQL server must provide pgvector. The integration
   fixtures exercise PostgreSQL 16 with pgvector; do not infer support for every
   PostgreSQL version from the SQL filenames.

**Connection security:** migration SQL uses the configured pgx connection,
including its connection-string and environment TLS settings and certificate
verification. Configure `sslmode=verify-full` and a trusted CA when you require
authenticated TLS; the runner does not upgrade an explicitly insecure setting.
Percent-encode spaces in URI option values as `%20`, or use a keyword DSN.
Hostless PostgreSQL URIs and Unix-socket directory hosts, including fallback
hosts, are rejected before the migration pool is created; use an explicit TCP
host and port.

`Run` and `Down` pin the migration search path and version ledger to `public`,
overriding a custom startup search path. Alternate-schema migrations are not
supported. The migration session uses the login role (`SET ROLE NONE`) and the
requested `app.region`; it does not inherit a role override from the connection
string. A failed or cancelled operation returns an error, and its connection is
discarded before another operation can reuse the pool.

## Inspect and apply

The following commands assume the selected release's executable is in the
current directory and PostgreSQL client tools are installed. Set
`YABANIN_PG_URI` and `YABANIN_REGION` through your deployment's configuration or
secret mechanism; the placeholders below intentionally have no default target.

```bash
: "${YABANIN_PG_URI:?Set the intended PostgreSQL connection URI}"
: "${YABANIN_REGION:?Set the deployment region}"
export YABANIN_PG_URI YABANIN_REGION

# Read-only: determine whether this database has a migration ledger.
psql "$YABANIN_PG_URI" -X -v ON_ERROR_STOP=1 \
  -c "SELECT to_regclass('public.schema_migrations') AS migration_ledger;"
```

If the ledger exists, inspect it before changing the database:

```bash
psql "$YABANIN_PG_URI" -X -v ON_ERROR_STOP=1 \
  -c 'SELECT version, dirty FROM public.schema_migrations;'
```

An absent ledger does not prove an empty database. If application tables already
exist without a ledger, investigate their origin rather than applying the
baseline over them. For a fresh database or a verified compatible upgrade:

```bash
./yabanin migrate

# Confirm the expected release head and a clean ledger after success.
psql "$YABANIN_PG_URI" -X -v ON_ERROR_STOP=1 \
  -c 'SELECT version, dirty FROM public.schema_migrations;'
```

Alternatively, `./yabanin-migrate` uses the same embedded runner. The standalone
command also accepts `YABANIN_PG_URI_FILE` when `YABANIN_PG_URI` is unset. Do not
run both commands as separate deployment steps. Repeating an up migration at a
clean current head is a successful no-op.

The ledger stores the current version and dirty flag; it is not an append-only
history of all SQL files applied. The runner's logged `applied` value counts
ledger rows, so it must not be interpreted as the number of newly executed SQL
files. Verify the reported version and ledger state instead.

## Fresh installations and compatible upgrades

| Starting state | Expected handling |
| --- | --- |
| Empty database, no migration ledger | Apply baseline `0001` and all subsequent shipped up migrations; finish at clean version 27. |
| Clean version 1 created from this consolidated baseline | Apply the shared incremental set; the baseline is not replayed. |
| Clean earlier version from the same migration lineage | Review pending files and release compatibility, then apply later shipped up migrations. |
| Clean version 27 from this migration lineage | Successful no-op. |
| Dirty ledger | Up migration fails; investigate and resolve the failed operation before resuming. |
| Recorded version absent from this binary's set, including 23 | Migration fails with a missing-version error; do not invent or renumber files to make it continue. |
| Unknown or older consolidated history, even if its version number is familiar | Establish schema and history compatibility first; a matching integer alone is insufficient. |

The supported baseline-upgrade regression starts with the **actual current
`0001_init` SQL**, records clean version 1 through the migration library, and
then runs the shared incremental set. The fresh-install and baseline-upgrade
schema dumps must match in
`TestRun_FreshAndStamp1CohortsConvergeToIdenticalSchema`. This checks those two
specific paths, not arbitrary databases that have merely been assigned version
1. It also does not assert identical application data between installations.

## Dirty or incompatible migration state

Preserve the first error, release identity, ledger state and a database snapshot.
Inspect the failed migration and the actual tables, constraints, indexes and
relevant data on a restored copy. Determine whether the database contains the
state before the operation, after it, or a partial result. Do not assume all
prior changes were rolled back just because the command returned an error.

For `Dirty database version N`, repeated up attempts do not clear the flag.
For `no migration found for version N`, the binary cannot reconcile the recorded
version with its embedded source. Neither error is automatically repaired.

Do not blindly clear `dirty`, assign version 1, or stamp the current head.
Changing the ledger changes what the runner believes, not the schema or data.
Any metadata repair needs an explicit, reviewed recovery procedure backed by
schema/data inspection and a restorable backup. An older database that does not
match the current lineage may need its original migration history or a separate
upgrade procedure; this repository does not supply a universal conversion.

The failure-boundary tests deliberately corrupt bookkeeping on disposable,
known-good databases and then restore the known matching version. Those test
repairs are not production recovery instructions.

## Downgrades and recovery

Down migrations do not restore deleted data; they provide structural reversals only.

In particular, `0001_init.down.sql` drops the baseline objects. It is a full
schema reset, not a replay of older historical steps. Dropping a newer table can
also discard its contents. Running up again recreates structures and any seed
rows specified by the up scripts; it cannot reconstruct lost application data.

The shipped migration commands expose the up path. The Go `migrate.Down` helper
is used by migration audits; it is not a general rollback command for operators.
Do not feed arbitrary down files directly to `psql`, which bypasses the migration
ledger. Application rollback requires compatibility with the current schema;
restore-based recovery requires an explicit recovery point and a plan for writes
accepted since that point. See [production operations](../docs/runbooks/production.md).

The down-side checks are `TestDownMigrationsNeverRestoreData`,
`TestDownSideDetectorCatchesRestorationClasses`, and the database-backed
`TestRun_DownLeavesDeletedDataDeleted`. They verify that down migrations do not
claim to restore data. `TestRun_UpDownUpCycle` separately exercises the structural
cycle on a disposable database.

## Upgrade discipline after the baseline: expand-contract

- Every new up migration from **0016** starts with a phase marker:
  `-- expand-contract: expand — <what it adds>` or
  `-- expand-contract: contract — replaces expand NNNN_<stem>; <what it removes>`.
- An **expand** migration adds structures, constraints, policies, seed inserts
  or bounded idempotent backfills. It must not contain destructive statement
  classes: `DROP`, `TRUNCATE`, `DELETE FROM`, `ALTER COLUMN ... TYPE`, `RENAME`
  or `SET NOT NULL`.
- A **contract** migration names an earlier embedded expand migration that
  introduced the replacement. The version must be lower and the name must
  match the embedded predecessor. Ship the replacement alongside the old
  structure before removing the old structure in a later migration.
- The consolidated `0001` baseline is outside this incremental policy. The
  existing pre-policy exception is `0005`, which replaces `chk_provider` with
  a wider CHECK admitting `azure-openai` without changing existing rows. It is
  explicitly checked; it is not permission to add new undocumented exceptions.

`TestUpMigrationsExpandOnlyUnlessContract` checks the shipped up scripts and
`TestExpandContractREADMEStatesPolicy` checks this policy's version and marker
forms. `TestExpandContractDetectorCatchesViolationClasses` exercises forbidden
statement classes and invalid predecessor references;
`TestPrePolicyExemptionsStayLive` rejects obsolete exceptions. These are
structural guards, not a substitute for reviewing data compatibility or
rehearsing an upgrade on a representative restored database.

## Adding a migration

1. Allocate the next available version without reusing the reserved gap.
2. Add the matching up/down pair to both SQL directories with identical bytes.
   Keep released migrations immutable; introduce a new migration for a new
   schema change.
3. Apply the expand-contract rules and document destructive effects of the down
   side. Preserve the existing schema's tenant-isolation requirements.
4. Update this README's head, name, next available number and set size, together
   with any integration-test head constants affected by the new version.
5. Run the migration structural checks and database-backed fresh, upgrade,
   failure-boundary and up/down/up tests through the project's quality workflow.
   Retain source-matched evidence; a successful static check does not prove a
   database upgrade succeeded.
