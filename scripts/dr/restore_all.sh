#!/usr/bin/env bash
# ENT-05: restore a backup_all.sh dump into a CLEAN database (fail-closed).
#
# Usage: restore_all.sh <pg-uri-to-empty-db> <dump-file>
set -euo pipefail

uri="${1:?usage: restore_all.sh <pg-uri-to-empty-db> <dump>}"
dump="${2:?usage: restore_all.sh <pg-uri-to-empty-db> <dump>}"

psql_cmd() {  # runs psql args on the target URI
  if command -v psql >/dev/null 2>&1; then psql "$uri" "$@"; 
  else docker run --rm -i --network host pgvector/pgvector:pg16 psql "$uri" "$@"; fi
}

existing="$(psql_cmd -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
if [ "${existing:-0}" != "0" ]; then
  echo "refusing to restore: target has $existing table(s) in public schema" >&2
  exit 1
fi

start="$(date +%s)"
if command -v pg_restore >/dev/null 2>&1; then
  pg_restore "$uri" --no-owner --exit-on-error "$dump"
else
  docker run --rm -i --network host -v "$(cd "$(dirname "$dump")" && pwd)":/backup:ro \
    pgvector/pgvector:pg16 pg_restore "$uri" --no-owner --exit-on-error "/backup/$(basename "$dump")"
fi
end="$(date +%s)"

tables="$(psql_cmd -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
echo "restore completed in $((end - start))s; tables in public: $tables"
