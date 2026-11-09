#!/usr/bin/env bash
# Strict mode WITHOUT `-o pipefail`: this script runs nightly as
# `sh /app/backup.sh` inside the postgres:16-alpine backup sidecar
# (deploy/docker-compose.prod.yml), whose busybox ash rejects the option
# ("set: Illegal option -o pipefail") and aborts before any backup is made.
# `set -eu` is honored by busybox ash and dash. The only pipeline (the
# PGPASSWORD extraction below) feeds a variable assignment that prefixes
# another command (`PGPASSWORD=$(echo | sed …) pg_dump …`): shell
# semantics ignore the substitution's exit status in that form — under
# `set -euo pipefail` and `set -eu` alike — so dropping pipefail changes
# no abort coverage. If sed ever failed, PGPASSWORD would end up garbled
# or empty and pg_dump would fail on auth, which `set -e` aborts on.
set -eu

BACKUP_DIR="${BACKUP_DIR:-/data/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PG_URI="$(cat /run/secrets/pg_uri)"

mkdir -p "$BACKUP_DIR"

# Postgres backup
echo "[$(date)] PostgreSQL backup..."
PGPASSWORD=$(echo "$PG_URI" | sed 's|.*://[^:]*:\([^@]*\)@.*|\1|') \
  pg_dump -h postgres -U yabanin --no-owner --no-acl -F c \
    -f "$BACKUP_DIR/pg_$TIMESTAMP.dump" yabanin

# Compress
if [ -f "$BACKUP_DIR/pg_$TIMESTAMP.dump" ]; then
    gzip "$BACKUP_DIR/pg_$TIMESTAMP.dump"
fi

# Keep last 7 days
find "$BACKUP_DIR" -name "pg_*.dump.gz" -mtime +7 -delete 2>/dev/null || true

echo "[$(date)] Backup complete: $BACKUP_DIR/pg_${TIMESTAMP}.dump.gz"
