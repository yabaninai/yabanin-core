#!/bin/sh
# TP-12: run a command, keep its full report, print a display-filtered view,
# and exit with the PRODUCER's exit code.
#
# This replaces the old `cmd 2>&1 | grep -E '...' || true` CI pattern where a
# failing test run could look green: the pipe hid the producer's status and
# `|| true` erased what grep saw. Here the filter is display-only — "no
# matching lines" on a clean run must not turn a producer failure into
# success, and a producer failure must stay visible with its report saved.
#
# Usage: run-with-report.sh <log-file> <egrep-filter> <command> [args...]
set -u

if [ "$#" -lt 3 ]; then
    echo "usage: $0 <log-file> <egrep-filter> <command> [args...]" >&2
    exit 2
fi

log=$1
filter=$2
shift 2

"$@" >"$log" 2>&1
status=$?

# Display filter only. grep exits 1 when nothing matches (e.g. a clean run
# with no filtered lines); that must never replace the producer's outcome.
grep -E "$filter" "$log" || true

exit "$status"
