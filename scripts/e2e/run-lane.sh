#!/usr/bin/env bash
# and output directory, so parallel lanes never collide on 14173/13100 or on
# artifacts. The root playwright.config.ts reads these E2E_* vars:
#
#   E2E_PORT        dashboard preview port (site preview keeps the default
#                   1073 gap below it); default 14173 (shared gate)
#   E2E_TEST_MATCH  optional testMatch glob filter
#   E2E_BASE_URL    optional externally served dashboard origin (skips the
#                   dashboard webServer)
#
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT="" OUT="" MATCH=""
while getopts "p:o:m:h" opt; do
  case "$opt" in
    p) PORT="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    m) MATCH="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: $0 [-p PORT] [-o OUT_DIR] [-m GLOB] [--] [spec...]" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

: "${PORT:=${E2E_PORT:-4522}}"
: "${OUT:=${E2E_OUTPUT_DIR:-/tmp/yabanin-e2e-lane-${PORT}}}"
export E2E_PORT="$PORT"
export E2E_OUTPUT_DIR="$OUT"
if [ -n "$MATCH" ]; then
  export E2E_TEST_MATCH="$MATCH"
fi
mkdir -p "$OUT"

echo "[run-lane] port=$PORT out=$OUT specs=${*:-<full suite>}"
exec npx playwright test "$@"
