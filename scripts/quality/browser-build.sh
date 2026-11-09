#!/usr/bin/env bash
# browser-build.sh — link a served static build to the current source (NEXT-06).
#
# The browser gate must never serve a build it did not verify. This script:
#   * builds on demand when the build directory is missing, recording a
#     deterministic source fingerprint next to the build; and
#   * re-computes that fingerprint from the live source and FAILS (exit 1) when
#     it differs — i.e. a stale or unverified build is rejected.
#
# Presence of a dist/build directory is never trusted on its own: the fingerprint
# is the only proof that the served assets were produced from the verified source.
#
# Usage: scripts/quality/browser-build.sh <dashboard|site>
set -euo pipefail

target="${1:?usage: browser-build.sh <dashboard|site|stamp-dashboard|stamp-site>}"
cd "$(git rev-parse --show-toplevel)"

case "$target" in
  dashboard)
    build_dir="web/dashboard/dist"
    build_cmd="npm --prefix web/dashboard run build"
    srcs="web/dashboard/src web/dashboard/index.html web/dashboard/tailwind.config.js web/dashboard/package.json"
    ;;
  site)
    build_dir="web/site/build"
    build_cmd="npm --prefix web/site run build"
    srcs="web/site/src web/site/static web/site/docusaurus.config.ts web/site/sidebars.ts"
    ;;
  stamp-dashboard)
    build_dir="web/dashboard/dist"
    srcs="web/dashboard/src web/dashboard/index.html web/dashboard/tailwind.config.js web/dashboard/package.json"
    ;;
  stamp-site)
    build_dir="web/site/build"
    srcs="web/site/src web/site/static web/site/docusaurus.config.ts web/site/sidebars.ts"
    ;;
  *)
    echo "browser-build: unknown target: $target" >&2
    exit 2
    ;;
esac

fp_file="$build_dir/.build-fingerprint"
cur="$(./scripts/build-fingerprint.sh $srcs)"

# stamp-*: the dashboard/site quality gates run `npm run build`, which wipes the
# build dir and drops the fingerprint the browser gate relies on. They re-stamp
# it here (the build they just produced is from the current source), so a later
# browser gate in the same run sees a VERIFIED build rather than a false stale.
case "$target" in
  stamp-*)
    if [ ! -d "$build_dir" ]; then
      echo "browser-build: cannot stamp ${target}: ${build_dir} missing" >&2
      exit 1
    fi
    printf '%s' "$cur" > "$fp_file"
    echo "OK: stamped ${target} fingerprint ${cur}"
    exit 0
    ;;
esac

if [ ! -d "$build_dir" ]; then
  # No build: create it from the current source and stamp the fingerprint.
  $build_cmd
  mkdir -p "$build_dir"
  printf '%s' "$cur" > "$fp_file"
  echo "OK: built ${target} from source (fingerprint ${cur})"
  exit 0
fi

recorded="$(cat "$fp_file" 2>/dev/null || true)"
if [ -z "$recorded" ] || [ "$recorded" != "$cur" ]; then
  echo "STALE/UNVERIFIED ${target} build at ${build_dir}." >&2
  echo "  recorded fingerprint: ${recorded:-<none>}" >&2
  echo "  current  fingerprint: ${cur}" >&2
  echo "Remove ${build_dir} and re-run (the gate rebuilds missing builds)." >&2
  exit 1
fi

echo "OK: ${target} build verified against source (fingerprint ${cur})"
