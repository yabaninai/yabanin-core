#!/usr/bin/env bash
# ENT-05: logical backup of the Yabanin Postgres database.
# Usage: backup.sh <pg-uri> <output-dir>
# Produces <output-dir>/yabanin-<ts>.dump (pg_dump custom format) and a
# checksum file. RPO equals the backup interval; the manifest records the
# exact cutoff for DR accounting.
set -euo pipefail

uri="${1:?usage: backup.sh <pg-uri> <output-dir>}"
outdir="${2:?usage: backup.sh <pg-uri> <output-dir>}"
mkdir -p "$outdir"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
dump="$outdir/yabanin-$ts.dump"

start="$(date +%s)"
pg_dump "$uri" --format=custom --file="$dump"
end="$(date +%s)"

sha256sum "$dump" > "$dump.sha256"
size="$(wc -c < "$dump")"

# Record the backup manifest: RPO accounting needs the wall-clock cutoff.
{
  echo "backup_ts=$ts"
  echo "duration_s=$((end - start))"
  echo "size_bytes=$size"
  echo "format=custom"
} > "$dump.manifest"

echo "backup written: $dump (${size} bytes, $((end - start))s)"
