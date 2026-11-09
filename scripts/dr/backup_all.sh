#!/usr/bin/env bash
# ENT-05: logical backup of the Yabanin Postgres database.
#
# Usage: backup_all.sh <pg-uri> <output-dir>
#
# Works with or without host pg tools: when pg_dump is unavailable locally
# the script runs it through the pgvector:pg16 image on the host network.
# Produces yabanin-<ts>.dump (custom format) + .sha256 + .manifest with the
# wall-clock cutoff used for RPO accounting.
set -euo pipefail

uri="${1:?usage: backup_all.sh <pg-uri> <output-dir>}"
outdir="${2:?usage: backup_all.sh <pg-uri> <output-dir>}"
mkdir -p "$outdir"
ts="$(date -u +%Y%m%dT%H%M%SZ)"
dump="$outdir/yabanin-$ts.dump"

pg_dump_cmd() {
  if command -v pg_dump >/dev/null 2>&1; then
    pg_dump "$uri" --format=custom --file="$dump"
  else
    docker run --rm -i --network host pgvector/pgvector:pg16 \
      pg_dump "$uri" --format=custom > "$dump"
  fi
}

start="$(date +%s)"
pg_dump_cmd
end="$(date +%s)"
size="$(wc -c < "$dump" | tr -d ' ')"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$dump" > "$dump.sha256"
else
  shasum -a 256 "$dump" > "$dump.sha256"
fi

{
  echo "backup_ts=$ts"
  echo "duration_s=$((end - start))"
  echo "size_bytes=$size"
  echo "format=custom"
} > "$dump.manifest"

echo "backup written: $dump (${size} bytes, $((end - start))s)"
