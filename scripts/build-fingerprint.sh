#!/usr/bin/env bash
# build-fingerprint.sh — deterministic source fingerprint for a static build.
#
# NEXT-06 (trustworthy browser gate): the gate serves a FRESH build of the
# current source, never a stale one. The webServer command records this
# fingerprint next to the build at build time; the same command re-computes it
# from the live source and FAILS the gate if they differ (stale build
# rejected). A fresh clone has no build, so it is built on demand.
#
# Usage: scripts/build-fingerprint.sh <path> [<path> ...]
#   <path> may be a file or a directory (directed). Output: one sha256 hex line.
#
# The hash covers the schema marker + file paths + permissions + contents in a
# stable (sorted) order, so any change to a tracked source file changes the
# fingerprint — and NOTHING ELSE does. It must be a pure function of tree
# content + declared inputs: no timestamps, no hostname/uname, no filesystem
# occupancy.
#
# FPv2 (FP-01, 2026-11-01): v1 extracted permissions with `stat -f '%Lp'`.
# BSD stat reads that as "format %Lp", but GNU coreutils stat reads `-f` as
# "filesystem status", so on Linux the hash input was polluted with VOLATILE
# free-block/free-inode counts and an unchanged tree produced a new
# fingerprint on every rerun (browser gate false STALE/UNVERIFIED). v2 detects
# the stat flavor once — GNU `stat -c '%a'` vs BSD `stat -f '%Lp'`, both of
# which print the octal permission bits (e.g. 644, 4755) — and hashes exactly:
#
#   fp-schema=<version>\n
#   <path> <octal-mode> <sha256-of-content>\n   (LC_ALL=C sorted by path)
#
# The `fp-schema=fpv2` line is part of the hashed input, so every fingerprint
# recorded under v1 mismatches the recomputed value exactly once; the consumer
# (scripts/quality/browser-build.sh) treats any mismatch as STALE/UNVERIFIED
# exit 1 with a rebuild-and-restamp instruction, after which a v2 value is
# recorded. No consumer parses hash values, so the one-time flip is safe.
#
# Determinism suite: scripts/quality/test_build_fingerprint.py.
set -euo pipefail

# Bump on ANY change that alters the hash input or its encoding.
FP_SCHEMA_VERSION="fpv2"

# fp_detect_stat_flavor: print "gnu" when stat understands GNU format strings
# (`stat -c FMT`), "bsd" when it understands BSD format strings (`stat -f FMT`),
# "unknown" when neither works (we then fail loudly instead of hashing garbage).
fp_detect_stat_flavor() {
  if stat -c '%a' / >/dev/null 2>&1; then
    printf 'gnu\n'
  elif stat -f '%Lp' / >/dev/null 2>&1; then
    printf 'bsd\n'
  else
    printf 'unknown\n'
  fi
}

# fp_file_mode <path>: permission bits in octal (644, 4755, ...) for the stat
# flavor detected by fp_detect_stat_flavor (caller sets $FP_STAT_FLAVOR).
fp_file_mode() {
  case "$FP_STAT_FLAVOR" in
    gnu) stat -c '%a' "$1" ;;
    bsd) stat -f '%Lp' "$1" ;;
    *)
      echo "build-fingerprint: no supported stat flavor (need GNU 'stat -c FMT' or BSD 'stat -f FMT')" >&2
      return 1
      ;;
  esac
}

# fp_fingerprint <path>...: one sha256 hex line over the deterministic input.
fp_fingerprint() {
  {
    printf 'fp-schema=%s\n' "$FP_SCHEMA_VERSION"
    (
      for p in "$@"; do
        if [ -f "$p" ] || [ -d "$p" ]; then
          find "$p" -type f
        else
          echo "build-fingerprint: path not found: $p" >&2
          exit 1
        fi
      done
    ) | LC_ALL=C sort | while IFS= read -r f; do
      # Assignment (not an inline substitution) so a failed stat aborts the
      # fingerprint under set -e instead of hashing an empty mode silently.
      mode="$(fp_file_mode "$f")"
      printf '%s %s ' "$f" "$mode"
      shasum -a 256 "$f" | cut -d' ' -f1
      printf '\n'
    done
  } | shasum -a 256 | cut -d' ' -f1
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  if [ "$#" -lt 1 ]; then
    echo "usage: build-fingerprint.sh <path>..." >&2
    exit 2
  fi
  FP_STAT_FLAVOR="$(fp_detect_stat_flavor)"
  fp_fingerprint "$@"
fi
