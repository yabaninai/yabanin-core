#!/bin/sh
# TP-12: classify a finished govulncheck run by its documented exit-code
# contract instead of grepping the text for the word "vulnerability":
#
#   0  -> clean (no findings)
#   3  -> vulnerabilities found
#   other non-zero -> scanner/infrastructure error (DB, network, bad module)
#
# The scanner's stdout is DATA for reporting; it never decides the outcome —
# truncated or failed output that happens to mention "vulnerability" must not
# be read as a verdict, and a clean report must not mask a non-zero exit.
#
# Usage: govulncheck-classify.sh <govulncheck-exit-status> <output-log>
# Writes found=/result= to $GITHUB_OUTPUT when set. Exits with the honest
# outcome: 0 clean, 3 findings, the scanner's own status on error.
set -u

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <govulncheck-exit-status> <output-log>" >&2
    exit 2
fi

status=$1
log=$2

case "$status" in
    ''|*[!0-9]*)
        echo "govulncheck-classify: exit status must be numeric, got: $status" >&2
        exit 2
        ;;
esac

case "$status" in
    0) found=false; result=clean; exit_status=0 ;;
    3) found=true; result=findings; exit_status=3 ;;
    *) found=false; result=error; exit_status=$status ;;
esac

if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        printf 'found=%s\n' "$found"
        printf 'result=%s\n' "$result"
    } >> "$GITHUB_OUTPUT"
fi

printf 'govulncheck result: %s (exit %s)\n' "$result" "$status"
[ -f "$log" ] || { echo "govulncheck-classify: report log missing: $log" >&2; exit 2; }
exit "$exit_status"
