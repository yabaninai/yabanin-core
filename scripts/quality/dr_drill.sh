#!/usr/bin/env bash
# NEXT-23: recurring DR/upgrade drill on DISPOSABLE infrastructure.
#
#   upgrade — delegates to the integration-tagged up→down→up cycle test
#             (pkg/migrate.TestRun_UpDownUpCycle, disposable PG) — the
#             upgrade/rollback path. The gate requires the NAMED test to
#             actually run and pass non-skipped (go test -json is parsed;
#             a green "no tests to run" or a skipped child is a FAIL).
#   restore — migrates a fresh disposable PG, pg_dump's it, restores into a
#             SECOND container and verifies schema inventory parity — the
#             DR restore path. Parity is EXACT, not statistical: the applied
#             migration ledger must equal the source's and match the head
#             derived from the embedded migration set in the product source,
#             and the public schema inventory (tables, exact column types
#             incl. typmod, indexes, constraints) must match byte-for-byte,
#             so equal table COUNTS over a different table SET fail, and
#             typmod-only drift (numeric(10,2) vs numeric(12,4)) fails too
#             (additive migrations such as 0030/0031 change columns/indexes,
#             not just counts).
# Docker absent → exit 77 (explicit skip), never a pass.
set -euo pipefail
cd "$(dirname "$0")/../.."

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "docker unavailable — DR drill SKIPPED (exit 77)"
  exit 77
fi

# derive_expected_head: highest version in the EMBEDDED migration set — the
# set the built binary actually applies (kept in sync with migrations/ by
# pkg/migrate.TestEmbeddedMigrationsInSyncWithRoot). Derived from current
# product source so new migrations (e.g. 0030/0031) raise the expectation
# without touching this gate.
derive_expected_head() {
  ls pkg/migrate/migrations/*.up.sql 2>/dev/null \
    | sed -n 's/.*\/\([0-9][0-9]*\)_[^/]*\.up\.sql$/\1/p' \
    | sort -n | tail -1
}

# require_named_test_pass <json-file> <test-name>: fail unless go test -json
# shows the named test running and passing EXACTLY once. Skips, empty
# packages and "no tests to run" all fail here even though `go test` exits 0.
# On failure the named test's captured output is printed (not discarded) and
# the caller preserves the raw json file for post-mortem.
require_named_test_pass() {
  python3 - "$1" "$2" <<'PY'
import json, sys
path, want = sys.argv[1], sys.argv[2]
ran = passed = skipped = 0
diag = []
with open(path, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue  # non-JSON build chatter; the go test exit code covers it
        if ev.get("Test") != want:
            continue
        action = ev.get("Action")
        if action == "run":
            ran += 1
        elif action == "pass":
            passed += 1
        elif action == "skip":
            skipped += 1
        elif action == "output":
            diag.append(ev.get("Output", ""))

def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    if diag:
        print(f"--- captured {want} output ---", file=sys.stderr)
        sys.stderr.writelines(diag[:80])
        print(f"--- end captured output ---", file=sys.stderr)
    sys.exit(1)

if skipped:
    fail(f"{want} was SKIPPED — a skip is not a DR pass")
if ran != 1 or passed != 1:
    fail(f"{want} did not run+pass exactly once (run events={ran}, pass events={passed})")
print(f"  named {want}: ran and passed (non-skipped)")
PY
}

echo "== profile: upgrade (integration up→down→up cycle test)"
GOJSON="$(mktemp /tmp/dr-drill-go.XXXXXX)"
go test ./pkg/migrate/ -tags=integration -count=1 -run '^TestRun_UpDownUpCycle$' \
  -timeout 300s -json > "$GOJSON"
if ! require_named_test_pass "$GOJSON" TestRun_UpDownUpCycle; then
  echo "FAIL: upgrade profile; captured go test output preserved at $GOJSON" >&2
  exit 1
fi
rm -f "$GOJSON"
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

EXPECTED_HEAD="$(derive_expected_head)"
[ -n "$EXPECTED_HEAD" ] || { echo "FAIL: no embedded migrations found under pkg/migrate/migrations"; exit 1; }
EXPECTED_HEAD="$((10#$EXPECTED_HEAD))"  # schema_migrations.version prints unpadded

go build -o "/tmp/yabanin-dr-$$" ./cmd/yabanin
YABANIN_PG_URI="postgres://yabanin:${PW}@127.0.0.1:${PORT1}/yabanin?sslmode=disable" \
  YABANIN_REGION=sg "/tmp/yabanin-dr-$$" migrate >/dev/null 2>&1 || {
    echo "FAIL: migrate on disposable PG"; exit 1; }

# snapshot <container> <outfile>: deterministic public-schema inventory plus
# the applied-migration ledger, each section ordered so diff output is stable.
# Ordering keys are NAME-based (never OIDs, never output ordinals beyond 1),
# so two databases created in different orders still snapshot identically.
# Column types use format_type(atttypid, atttypmod): numeric(10,2) and
# numeric(12,4) must NOT collide (information_schema data_type+udt_name
# alone would treat them as equal).
snapshot() { # <container> <outfile>
  local c="$1" out="$2"
  : > "$out"
  docker exec "$c" psql -U yabanin -d yabanin -Atc \
    "SELECT version::text || '|' || dirty::text FROM schema_migrations ORDER BY version" >> "$out"
  docker exec "$c" psql -U yabanin -d yabanin -Atc \
    "SELECT table_name || '|' || table_type FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name, table_type" >> "$out"
  docker exec "$c" psql -U yabanin -d yabanin -Atc \
    "SELECT c.table_name || '|' || c.ordinal_position || '|' || c.column_name || '|' || format_type(a.atttypid, a.atttypmod) || '|' || c.is_nullable || '|' || coalesce(c.column_default,'') FROM information_schema.columns c JOIN pg_attribute a ON a.attrelid = (quote_ident(c.table_schema) || '.' || quote_ident(c.table_name))::regclass AND a.attname = c.column_name AND NOT a.attisdropped WHERE c.table_schema='public' ORDER BY c.table_name, c.ordinal_position, c.column_name" >> "$out"
  docker exec "$c" psql -U yabanin -d yabanin -Atc \
    "SELECT indexname || '|' || indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY indexname" >> "$out"
  docker exec "$c" psql -U yabanin -d yabanin -Atc \
    "SELECT conrelid::regclass::text || '|' || conname || '|' || pg_get_constraintdef(oid, true) FROM pg_constraint WHERE connamespace = 'public'::regnamespace ORDER BY 1" >> "$out"
}

SNAP_SRC="$(mktemp /tmp/dr-drill-src.XXXXXX)"; SNAP_DST="$(mktemp /tmp/dr-drill-dst.XXXXXX)"
cleanup_snapshots() { rm -f "$SNAP_SRC" "$SNAP_DST"; cleanup; }
trap cleanup_snapshots EXIT

snapshot "$PG" "$SNAP_SRC"
SRC_MIG="$(head -1 "$SNAP_SRC")"
SRC_TABLES=$(grep -c '|BASE TABLE' "$SNAP_SRC" || true)
echo "  source: $SRC_TABLES tables, migration ledger [$SRC_MIG], expected head $EXPECTED_HEAD"

uri='postgresql:///yabanin?user=yabanin'
docker cp scripts/dr/backup_all.sh "$PG:/tmp/backup_all.sh"
docker exec "$PG" bash /tmp/backup_all.sh "$uri" /tmp/dr-backup
docker exec "$PG" sh -ec 'sha256sum -c /tmp/dr-backup/*.sha256 && cp /tmp/dr-backup/*.dump /tmp/dr.dump'
docker cp "$PG:/tmp/dr.dump" "/tmp/dr-$$-host.dump"
docker cp "/tmp/dr-$$-host.dump" "$PG2:/tmp/dr.dump"
# yabanin_app, but roles are cluster-level objects that a database dump does
# not carry. A DR target therefore must provision the role before restore
# (same shape as migration 0022; production runbooks do this out-of-band).
docker exec "$PG2" psql -U yabanin -d yabanin -qc "DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'yabanin_app') THEN
    CREATE ROLE yabanin_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF; END \$\$;"
docker cp scripts/dr/restore_all.sh "$PG2:/tmp/restore_all.sh"
docker exec "$PG2" bash /tmp/restore_all.sh "$uri" /tmp/dr.dump

snapshot "$PG2" "$SNAP_DST"
DST_MIG="$(head -1 "$SNAP_DST")"
DST_TABLES=$(grep -c '|BASE TABLE' "$SNAP_DST" || true)
echo "  restored: $DST_TABLES tables, migration ledger [$DST_MIG]"

# Qualification 1 — source really is at the CURRENT product head, not just
# any positive version (catches a stale/partial source before parity is even
# meaningful).
[ "$SRC_MIG" = "$EXPECTED_HEAD|false" ] || {
  echo "FAIL: source migration ledger [$SRC_MIG] != derived head $EXPECTED_HEAD (clean)"; exit 1; }

# Qualification 2 — restored ledger is EXACTLY the source ledger: same
# applied migration IDs, not dirty, not merely max(version)>0.
[ "$DST_MIG" = "$SRC_MIG" ] || {
  echo "FAIL: restored migration ledger [$DST_MIG] != source [$SRC_MIG]"; exit 1; }

# Qualification 3 — full public schema inventory matches byte-for-byte:
# table names AND types, column definitions, index definitions, constraint
# definitions. Equal counts over a different set produce a real diff here.
if ! diff -u "$SNAP_SRC" "$SNAP_DST" > "$SNAP_DST.diff"; then
  echo "FAIL: restore parity: schema inventory differs (ledger/tables/columns/indexes/constraints):"
  sed -n '1,40p' "$SNAP_DST.diff" | sed 's/^/    /'
  exit 1
fi
rm -f "$SNAP_DST.diff" "/tmp/dr-$$-host.dump" "/tmp/yabanin-dr-$$"
cleanup_snapshots; trap - EXIT
echo "DR drill: clean (upgrade cycle idempotent, restore parity exact)"
