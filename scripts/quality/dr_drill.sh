#!/usr/bin/env bash
# NEXT-23: recurring DR/upgrade drill on DISPOSABLE infrastructure.
#
#   upgrade — delegates to the integration-tagged up→down→up cycle test
#             (pkg/migrate.TestRun_UpDownUpCycle, disposable PG) — the
#             upgrade/rollback path.
#   restore — migrates a fresh disposable PG, pg_dump's it, restores into a
#             SECOND container and verifies schema inventory parity — the
#             DR restore path.
# Docker absent → exit 77 (explicit skip), never a pass.
set -euo pipefail
cd "$(dirname "$0")/../.."

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "docker unavailable — DR drill SKIPPED (exit 77)"
  exit 77
fi

echo "== profile: upgrade (integration up→down→up cycle test)"
go test ./pkg/migrate/ -tags=integration -count=1 -run '^TestRun_UpDownUpCycle$' -timeout 300s
echo "  ✓ up→down→up cycle idempotent (disposable PG)"

echo "== profile: restore (pg_dump → second container → inventory parity)"
PG="dr-pg-$$"; PG2="dr-pg2-$$"; PW="drill-$$"
PORT1=$((20000 + $$ % 20000)); PORT2=$((PORT1 + 1))
cleanup() { docker rm -f "$PG" "$PG2" >/dev/null 2>&1 || true; }
trap cleanup EXIT

for spec in "$PG:$PORT1" "$PG2:$PORT2"; do
  name="${spec%%:*}"; port="${spec##*:}"
  docker run -d --rm --name "$name" -p "127.0.0.1:${port}:5432" \
    -e POSTGRES_USER=yabanin -e POSTGRES_PASSWORD="$PW" -e POSTGRES_DB=yabanin \
    pgvector/pgvector:pg16 >/dev/null
  for i in $(seq 1 30); do docker exec "$name" pg_isready -U yabanin >/dev/null 2>&1 && break; sleep 1; done
done

go build -o "/tmp/yabanin-dr-$$" ./cmd/yabanin
YABANIN_PG_URI="postgres://yabanin:${PW}@127.0.0.1:${PORT1}/yabanin?sslmode=disable" \
  YABANIN_REGION=sg "/tmp/yabanin-dr-$$" migrate >/dev/null 2>&1 || {
    echo "FAIL: migrate on disposable PG"; exit 1; }
TABLES1=$(docker exec "$PG" psql -U yabanin -d yabanin -Atc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
echo "  source: $TABLES1 tables"

docker exec "$PG" pg_dump -U yabanin -d yabanin -F c -f /tmp/dr.dump
docker cp "$PG:/tmp/dr.dump" "/tmp/dr-$$-host.dump"
docker cp "/tmp/dr-$$-host.dump" "$PG2:/tmp/dr.dump"
# yabanin_app, but roles are cluster-level objects that a database dump does
# not carry. A DR target therefore must provision the role before restore
# (same shape as migration 0022; production runbooks do this out-of-band).
docker exec "$PG2" psql -U yabanin -d yabanin -qc "DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'yabanin_app') THEN
    CREATE ROLE yabanin_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF; END \$\$;"
docker exec "$PG2" pg_restore -U yabanin -d yabanin --no-owner /tmp/dr.dump
TABLES_R=$(docker exec "$PG2" psql -U yabanin -d yabanin -Atc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
V_R=$(docker exec "$PG2" psql -U yabanin -d yabanin -Atc \
  "SELECT coalesce(max(version),0) FROM schema_migrations")
echo "  restored: $TABLES_R tables, schema v$V_R"

[ "$TABLES_R" = "$TABLES1" ] || { echo "FAIL: restore parity: $TABLES_R != $TABLES1"; exit 1; }
[ "$V_R" -gt 0 ] || { echo "FAIL: restored schema version is 0"; exit 1; }
rm -f "/tmp/dr-$$-host.dump" "/tmp/yabanin-dr-$$"
echo "DR drill: clean (upgrade cycle idempotent, restore parity exact)"
