#!/usr/bin/env bash
# ENT-05: restore a backup produced by backup.sh into a CLEAN database.
# Usage: restore.sh <pg-uri-to-empty-db> <dump-file>
# The target database must exist and be empty; the script refuses to run
# against a database that already has Yabanin tables (fail-closed).
set -euo pipefail

uri="${1:?usage: restore.sh <pg-uri> <empty-db> <dump>}"
dump="${2:?usage: restore.sh <pg-uri> <empty-db> <dump>}"

existing="$(psql "$uri" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
if [ "${existing:-0}" != "0" ]; then
  echo "refusing to restore: target database has $existing table(s) in public" >&2
  exit 1
fi

start="$(date +%s)"
pg_restore "$uri" --no-owner --exit-on-error "$dump"
end="$(date +%s)"
echo "restore completed in $((end - start))s"
