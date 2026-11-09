#!/usr/bin/env bash
# Offline database upgrade drill.
#
# Executes the pre-upgrade safety sequence against a live database without
# touching the application deployment:
#   1. migration-mirror check — both catalogs carry the identical set
#   2. pre-upgrade database backup
#   3. yabanin-migrate up (a no-op on an up-to-date schema; applies pending
#      files otherwise)
#
# Usage: upgrade_drill.sh <pg-uri> <work-dir>
# Applies pending migrations. Run against an isolated restore first.
# Results are written to <work-dir>/evidence.txt.
set -euo pipefail
cd "$(dirname "$0")/../.."

uri="${1:?usage: upgrade_drill.sh <pg-uri> <work-dir>}"
work="${2:?usage: upgrade_drill.sh <pg-uri> <work-dir>}"
mkdir -p "$work"
evidence="$work/evidence.txt"
: > "$evidence"
step() { echo "[$(date -u +%H:%M:%SZ)] $1" | tee -a "$evidence"; }
# Build from current source: a stale migrate binary embeds a stale
# migration catalog and will corrupt schema_migrations (observed: dirty=37).
go build -o "$work/yabanin-migrate" ./cmd/yabanin-migrate
MIG="$work/yabanin-migrate"

step "1. migration catalog mirror check"
if diff <(ls migrations | grep -v README | sort) \
        <(ls pkg/migrate/migrations | grep -v README | sort) >/dev/null; then
  step "   OK: catalogs identical"
else
  step "   FAIL: catalogs diverge"; exit 1
fi

step "2. pre-upgrade backup"
bash scripts/dr/backup_all.sh "$uri" "$work/backups" 2>&1 | tee -a "$evidence"

step "3. yabanin-migrate up"
YABANIN_PG_URI="$uri" YABANIN_REGION="${YABANIN_REGION:-onprem}" "$MIG" 2>&1 | tail -3 | tee -a "$evidence"

step "upgrade drill completed; results in $evidence"
