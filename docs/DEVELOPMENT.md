# Development guide

Use the [quickstart](quickstart.md) for your first running gateway. This guide
covers source builds, targeted checks, configuration, and migration changes.
Commands run from the repository root unless a different directory is shown.

## Prerequisites

- Go matching the root `go.mod` directive (currently **1.27.4**). Check with
  `go version`; a generic Go 1.27 installation may be older than required.
- Git and make for source builds; dependency downloads need network access.
- Docker Engine/Desktop and Compose v2 for the quickstart and container-based
  integration tests. The quickstart lists its additional shell tools.
- Node.js and npm for dashboard or documentation work; use the relevant
  `package.json` and lockfile. Python 3 is needed by documentation checks.

Core includes public synthetic evaluation data and standalone product checks.
Private plans and agent execution records are maintained separately and are not
prerequisites for building or testing Core. Follow the
[quality guide](https://github.com/yabaninai/yabanin-core/blob/main/scripts/quality/README.md) to prepare tools and run the full
local checks; never copy private credentials or configuration into a checkout.

## Build the executables

```bash
make unified yb
./yb version
./yb --help
```

`./yabanin` runs server components, migrations, and seeding. `./yb` is the
operator CLI and contains `audit` and `evaluate`. `make build` also produces
legacy per-component executables; the Docker image uses the unified binary.

With a configured database, Redis, secrets, and model registry, the server can
run gateway, admin, and loggerd together:

```bash
./yabanin dev
```

This is a server command, not infrastructure provisioning. It does not start
PostgreSQL, Redis, the React dashboard, an embedder, or the optional MCP bridge.
Use the [quickstart](quickstart.md) to supply a complete local mock environment.
Do not run a second server against the quickstart's occupied ports.

## Source layout

| Path | Responsibility |
| --- | --- |
| `cmd/yabanin/` | Unified server command dispatch, migrations, seeding |
| `cmd/yb/`, `pkg/trcli/` | Operator commands and offline tools |
| `pkg/gateway/`, `services/gateway/` | Request handling and gateway entry point |
| `services/admin/` | Admin API and server entry point |
| `services/loggerd/` | Event consumption and request-log persistence |
| `pkg/config/` | Configuration loading and validation |
| `pkg/migrate/` | Embedded SQL migration runner |
| `migrations/`, `pkg/migrate/migrations/` | Mirrored numbered up/down migrations |
| `deploy/quickstart/` | Local mock Compose stack |
| `deploy/helm/` | Deployment chart templates |
| `web/dashboard/` | React dashboard |
| `web/site/`, `docs/` | Docusaurus site and documentation |
| `sdks/` | Go, Node, and Python clients |

The Go module path remains `github.com/reireirei/yabanin`; keep imports aligned
with `go.mod`. The repository's public distribution name does not change that
module identity.

## Test the part you changed

Start with focused tests. For example:

```bash
go test -race -count=1 ./pkg/rulesengine/...
```

For the repository's short Go tests:

```bash
go test -race -count=1 -short ./...
```

The `-short` flag skips tests that explicitly honor it; it is not a guarantee
that every package avoids external services. Read a failing test's dependency
requirements instead of treating an environmental failure as a pass. SDKs have
separate modules and test commands; see the [SDK matrix](clients/sdk-versions.md).

Gateway integration tests need a reachable Docker daemon and pull their
PostgreSQL/Redis dependencies through testcontainers:

```bash
go test -race -count=1 -tags=integration ./services/gateway/integration/...
```

A unit or integration test against a fake provider does not verify a paid
upstream. Keep the verification scope in review notes. The quickstart's own
smoke check verifies a successful mock response and asynchronous persistence.
The legacy `scripts/smoke_test.sh` has a different scope and tears down its
Compose stack; do not run it against a shared development deployment.

For frontend and documentation changes:

```bash
npm ci --prefix web/dashboard
npm --prefix web/dashboard run build

npm ci --prefix web/site
npm --prefix web/site run typecheck
npm --prefix web/site run build
```

The documentation site build checks MDX compilation and link integrity. Also
review the rendered changed pages; valid Markdown alone does not establish
readable navigation or a working command sequence. Keep public documentation
and API descriptions in English.

For a complete local check, run `make quality-full` after installing the
[quality prerequisites](https://github.com/yabaninai/yabanin-core/blob/main/scripts/quality/README.md). The runner writes source-bound
results under `artifacts/quality/`. Missing tools, inputs and failed checks are
errors, not successful validation. Quickstart and browser acceptance remain
separate checks.

## Docker image

Build the unified image from your current Git checkout:

```bash
docker build   --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"   -t yabanin:local .
```

The Dockerfile requires an integer source timestamp and builds with the pinned
Go image. It has no service-selecting `SERVICE` build argument. The runtime
command selects `gateway`, `admin`, `loggerd`, `migrate`, or another supported
unified subcommand. Services still need configuration and network dependencies.

Use `deploy/quickstart/docker-compose.yml` through the [quickstart](quickstart.md)
for local startup. The broader `deploy/docker-compose.yml` assumes additional
secrets and optional development resources; `make docker-up` is not the public
clean-checkout installation path.

## Migrations

The runner applies numbered **up** migrations embedded in the executable and
maintains `schema_migrations`. It requires both a PostgreSQL connection URI and
a region. The migration login must have the privileges needed for schema
changes; the application's restricted database role is not a migration role.

The quickstart runs migrations as a one-shot service before starting the app.
For a separately managed database, build the executable, set the target URI and
region deliberately, and then run:

```bash
# YABANIN_PG_URI and YABANIN_REGION must identify your intended database.
: "${YABANIN_PG_URI:?Set the migration database URI}"
: "${YABANIN_REGION:?Set the database region}"
./yabanin migrate
```

Success logs `migrations applied` with the region and schema version. Repeating
the command with no pending migrations succeeds without replaying the chain.
Back up an existing database and review the release's upgrade procedure before
applying a new schema. A dirty migration state requires investigation; do not
force a version or replay arbitrary SQL to hide a failure.

**Never execute `migrations/*.sql` in a shell loop.** The directory also contains
down migrations, which can remove data or schema. Do not use `make migrate-up`
as a substitute for this embedded runner: the legacy helper can apply SQL
directly without the same ledger behavior.

When adding a migration:

1. Inspect both migration directories and choose the next unused sequence
   number. Do not renumber already released migrations.
2. Add matching `NNNN_description.up.sql` and `.down.sql` files in both
   directories; keep the mirrored contents identical.
3. Review schema compatibility, row-level security, privileges, backfill,
   locking, and whether rollback can preserve data.
4. Test a fresh database and an upgrade from the supported prior schema.
   Keep destructive rollback/reset tests on an isolated disposable database.
5. Rebuild the executable: changing an external SQL file does not alter the
   migrations already embedded in an existing binary or image.

See the quickstart's explicitly destructive reset procedure only when you
intend to discard that local demonstration database. A reset is not an upgrade.

## Configuration

Services combine built-in defaults, YAML, and recognized environment overrides.
`YABANIN_CONFIG` selects the YAML path; the normal path is `config.yaml`.
Inspect `pkg/config/` for the exact supported variables and defaults rather
than deriving environment names from arbitrary YAML field names.

| Variable | Purpose |
| --- | --- |
| `YABANIN_PG_URI` | Database connection URI |
| `YABANIN_REGION` | Region used by database and routing controls |
| `YABANIN_REDIS_ADDR` | Redis address reachable from the service |
| `YABANIN_GATEWAY_LISTEN` | Gateway HTTP listen address |
| `YABANIN_ADMIN_LISTEN` | Admin API listen address |
| `YABANIN_SESSION_KEY` | Admin session signing secret |
| `YABANIN_CACHE_HMAC_SECRET` | Cached-response signing secret |
| `YABANIN_ENCRYPTION_KEY` | Stored-credential encryption key |
| `YABANIN_CONFIG_STRICT` | Fail config loading on malformed supported numeric environment values |

For settings resolved through the configuration helper, the corresponding
`_FILE` variable reads a secret file, for example `YABANIN_PG_URI_FILE`.
A directly set environment variable takes precedence, even if empty. Do not
set both forms accidentally, and verify startup validation rather than
assuming every arbitrary variable supports `_FILE`.

Keep configuration files containing secrets private and out of Git. Preserve
encryption keys with the database: replacing a key can make stored credentials
unreadable. Shell-expanded values passed as arguments can be visible in process
listings. Do not paste keys, database URIs, or private request content into bug
reports.

Boolean configuration values handled by the shared parser accept `1` or
`true` (case-insensitive) as true; other non-empty values are false. Strict
numeric parsing does not make arbitrary boolean spellings valid. Validate
configuration at startup and use explicit values.

## Extend the product

The [extension guides](extensions/README.md) describe supported client,
policy, and detector extension points. Trace the existing service lifecycle
and configuration validation before adding a component. Handle errors, provide
targeted tests, and document operational boundaries. Adding a service needs
explicit unified dispatch and runtime packaging work; an obsolete Docker
`SERVICE` argument will not create a new executable.

For coding clients, use their [client guides](compatibility.md). Internal
OpenCode agent wiring and private orchestration commands are not required to
operate or contribute to the public core.
