#!/usr/bin/env bash
# B1: Local git-bundle backup of the repository (no remote, no credentials).
#
# Creates a timestamped bundle containing ALL branches and tags under a local
# backups/ directory (default: <repo>/.backups, overridable via BACKUP_DIR) and
# prunes bundles older than the last RETAIN (default: 5).
#
# Usage:
#   scripts/backup-bundle.sh              # backup into <repo>/.backups
#   BACKUP_DIR=/path RETAIN=10 scripts/backup-bundle.sh
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
BACKUP_DIR="${BACKUP_DIR:-$REPO_ROOT/.backups}"
RETAIN="${RETAIN:-5}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/yabanin-$STAMP.bundle"

mkdir -p "$BACKUP_DIR"

# Guard against same-second collisions: if a bundle with this stamp already
# exists, append a fixed-width (6-digit) random suffix so rapid runs never
# overwrite each other and lexicographic order still tracks chronological
# order (a bare stamp sorts before any "stamp-NNNNNN" variant).
if [ -e "$OUT" ]; then
  SUFFIX="$(od -An -N4 -tu2 /dev/urandom | tr -d ' ' | cut -c1-6)"
  OUT="$BACKUP_DIR/yabanin-${STAMP}-${SUFFIX}.bundle"
fi

# Snapshot the pre-existing bundles BEFORE creating the new one, so the
# retention pass can never prune the bundle we are about to write. Names embed
# a YYYYMMDD-HHMMSS stamp, so lexicographic order == chronological order.
EXISTING="$(ls -1 "$BACKUP_DIR"/yabanin-*.bundle 2>/dev/null | sort || true)"

# --all captures every ref (all branches + tags). Fails loudly if the repo has
# no commits yet, which is the only case where a bundle cannot be created.
git bundle create "$OUT" --all

echo "backup: wrote $OUT ($(du -h "$OUT" | cut -f1))"

# Retention: keep the newest $RETAIN bundles overall, delete the oldest extras.
# EXISTING holds only pre-existing bundles, so the new $OUT is always retained.
if [ -n "$EXISTING" ]; then
  # Print the oldest (total-RETAIN) lines and prune them; the newest RETAIN
  # pre-existing bundles plus the just-written $OUT are kept.
  TOTAL=$(printf '%s\n' "$EXISTING" | wc -l | tr -d ' ')
  if [ "$TOTAL" -gt "$RETAIN" ]; then
    CUT=$((TOTAL - RETAIN))
    printf '%s\n' "$EXISTING" | sed -n "1,${CUT}p" | while read -r old; do
      rm -f -- "$old"
      echo "backup: pruned $old"
    done
  fi
fi
