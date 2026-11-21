#!/usr/bin/env bash
# CV-03 org-presentation acceptance gate.
#
# Anti-vacuity contract (gate review): a bare `go test -run NAME` exits
# zero when the named test was renamed, moved or skipped, silently
# bypassing every in-test receipt check. This wrapper therefore enforces,
# on top of a successful go test:
#
#   1. the EXACT named PASS line is present in the -v log
#      (`--- PASS: TestCV03OrgPresentationBrowserAcceptance`), with no
#      SKIP/FAIL of that test;
#   2. the stand wrote its stand-summary.json receipt UNDER THIS GATE'S
#      OWN per-run output directory (exact run ownership — a receipt from
#      a concurrent or unrelated run can never satisfy the gate), fresh
#      for this invocation;
#   3. the receipt is mode == "acceptance" — a CONTROL-mode receipt can
#      never satisfy this gate;
#   4. clean global state: zero global/teardown errors, zero unexpected
#      and zero skipped specs;
#   5. the frozen case registry, pinned here as a set: exactly
#      AC-OP-MEMBER, AC-OP-SHARE, AC-OP-READER — no missing, unknown or
#      duplicate case ids — each at the Go stand's verdict "passed".
#
# Enforcement functions RETURN nonzero with a reason on stderr (never
# exit) so the selftest can assert each negative reason in isolation.
#
# `orgpresentation_gate.sh selftest` runs the OFFLINE negative checks
# (no Docker, no browser, no network). The selftest also runs at the
# start of every gate invocation — the enforcement itself is under test
# every time the gate runs.
set -euo pipefail

GATE_TEST_NAME='TestCV03OrgPresentationBrowserAcceptance'
GATE_RECEIPT_NAME='stand-summary.json'
GATE_FROZEN_CASES='AC-OP-MEMBER AC-OP-SHARE AC-OP-READER'

die() { echo "orgpresentation gate: $*" >&2; exit 1; }

# --- log enforcement (returns nonzero + reason on stderr) ------------------
gate_parse_go_log() {
	local log=$1
	if grep -qE "^--- (SKIP|FAIL): ${GATE_TEST_NAME}( |$)" "$log"; then
		echo "${GATE_TEST_NAME} was skipped or failed" >&2
		return 1
	fi
	if ! grep -qE "^--- PASS: ${GATE_TEST_NAME}( |$)" "$log"; then
		echo "no PASS line for ${GATE_TEST_NAME} (test renamed/moved/absent — vacuous run)" >&2
		return 1
	fi
}

# --- receipt enforcement (returns nonzero + reason on stderr) --------------
gate_verify_receipt() {
	local receipt=$1 start=$2
	python3 - "$receipt" "$start" <<'PY'
import json, os, sys

receipt, start = sys.argv[1], float(sys.argv[2])
def bad(msg):
    sys.exit(msg)

try:
    doc = json.load(open(receipt))
except Exception as exc:
    bad(f"receipt {receipt} is not valid JSON: {exc}")
if os.stat(receipt).st_mtime < start - 1:
    bad(f"receipt {receipt} is not fresh for this gate run (mtime before gate start)")
if doc.get("mode") != "acceptance":
    bad(f"receipt {receipt} mode={doc.get('mode')!r}: a control-mode receipt can never satisfy the acceptance gate")
stats = doc.get("stats") or {}
for field in ("unexpected", "skipped"):
    if stats.get(field, -1) != 0:
        bad(f"receipt {receipt}: stats.{field}={stats.get(field)!r} (require 0)")
if doc.get("global_errors", -1) != 0:
    bad(f"receipt {receipt}: global_errors={doc.get('global_errors')!r} (require 0; teardown/global Playwright errors)")
required = doc.get("required_cases") or []
frozen = {"AC-OP-MEMBER", "AC-OP-SHARE", "AC-OP-READER"}
if set(required) != frozen or len(required) != len(frozen):
    bad(f"receipt {receipt}: required_cases {required!r} does not pin exactly the frozen registry {sorted(frozen)}")
ids = [c.get("id") for c in doc.get("cases") or []]
if len(ids) != len(set(ids)):
    bad(f"receipt {receipt}: duplicate case ids in {ids!r}")
if set(ids) != frozen:
    bad(f"receipt {receipt}: case ids {sorted(set(ids))!r} deviate from the frozen registry (missing or unknown cases)")
cases = {c.get("id"): c.get("status") for c in doc.get("cases") or []}
for case in sorted(frozen):
    if cases.get(case) != "passed":
        bad(f"receipt {receipt}: required case {case} has status {cases.get(case)!r} (require 'passed')")
print(f"orgpresentation gate: receipt OK ({receipt})")
PY
}

# --- offline negative checks (the acceptance guard's teeth) ----------------
# Every negative case asserts its OWN reason: the rejection message must
# name the specific violation, so a rejection for the wrong reason still
# fails the selftest.
gate_selftest() {
	local tmp log start
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' RETURN
	start=$(date +%s)

	# go-log cases
	printf '=== RUN   TestSomethingElse\n--- PASS: TestSomethingElse (0.00s)\nok\n' >"$tmp/l-absent"
	if gate_parse_go_log "$tmp/l-absent" 2>"$tmp/e-absent"; then
		die "selftest: log without the named PASS must FAIL"
	fi
	grep -q "no PASS line" "$tmp/e-absent" || die "selftest: absent-test rejection must say so (got: $(cat "$tmp/e-absent"))"
	printf -- '--- SKIP: %s (0.00s)\nok\n' "$GATE_TEST_NAME" >"$tmp/l-skip"
	if gate_parse_go_log "$tmp/l-skip" 2>"$tmp/e-skip"; then
		die "selftest: skipped named test must FAIL"
	fi
	grep -q "skipped or failed" "$tmp/e-skip" || die "selftest: skip rejection must say so (got: $(cat "$tmp/e-skip"))"
	printf -- '--- FAIL: %s (0.00s)\nFAIL\n' "$GATE_TEST_NAME" >"$tmp/l-fail"
	if gate_parse_go_log "$tmp/l-fail" 2>"$tmp/e-fail"; then
		die "selftest: failed named test must FAIL"
	fi
	grep -q "skipped or failed" "$tmp/e-fail" || die "selftest: fail rejection must say so (got: $(cat "$tmp/e-fail"))"
	printf -- '=== RUN   %s\n--- PASS: %s (1.00s)\nok\n' "$GATE_TEST_NAME" "$GATE_TEST_NAME" >"$tmp/l-good"
	gate_parse_go_log "$tmp/l-good" || die "selftest: genuine named PASS log must PASS (got: $(cat "$tmp/l-good"))"

	# receipt cases. Healthy receipts carry the Go stand's actual field
	# values: verdict "passed" (cv02SpecVerdict), stats via cv02PWStats,
	# global_errors from the summary. Touched at @start: fresh under the
	# validator's start-1 tolerance.
	local good
	good=$(cat <<'JSON'
{"mode": "acceptance", "global_errors": 0,
 "stats": {"startTime": "x", "duration": 1, "expected": 3, "unexpected": 0, "flaky": 0, "skipped": 0},
 "required_cases": ["AC-OP-MEMBER", "AC-OP-SHARE", "AC-OP-READER"],
 "cases": [{"id": "AC-OP-MEMBER", "title": "member", "status": "passed"},
           {"id": "AC-OP-SHARE", "title": "share", "status": "passed"},
           {"id": "AC-OP-READER", "title": "reader", "status": "passed"}]}
JSON
	)
	local case
	for case in good control stale global unexpected registry-shrink registry-dup registry-unknown case-failed; do
		printf '%s\n' "$good" >"$tmp/r-$case.json"
	done
	touch -d "@$start" "$tmp"/r-*.json
	sed -i 's/"mode": "acceptance"/"mode": "control"/' "$tmp/r-control.json"
	touch -d "@$((start - 3600))" "$tmp/r-stale.json"
	sed -i 's/"global_errors": 0/"global_errors": 2/' "$tmp/r-global.json"
	sed -i 's/"unexpected": 0/"unexpected": 1/' "$tmp/r-unexpected.json"
	sed -i 's/"required_cases": \["AC-OP-MEMBER", "AC-OP-SHARE", "AC-OP-READER"\]/"required_cases": ["AC-OP-MEMBER"]/' "$tmp/r-registry-shrink.json"
	sed -i 's/{"id": "AC-OP-READER", "title": "reader", "status": "passed"}/{"id": "AC-OP-MEMBER", "title": "dup", "status": "passed"}/' "$tmp/r-registry-dup.json"
	sed -i 's/{"id": "AC-OP-READER", "title": "reader", "status": "passed"}/{"id": "AC-OP-EXTRA", "title": "extra", "status": "passed"}/' "$tmp/r-registry-unknown.json"
	sed -i '0,/AC-OP-SHARE", "title": "share", "status": "passed"/s//AC-OP-SHARE", "title": "share", "status": "failed"/' "$tmp/r-case-failed.json"

	gate_verify_receipt "$tmp/r-good.json" "$start" >/dev/null \
		|| die "selftest: fresh clean acceptance receipt must PASS"

	local negatives='control:control-mode receipt
stale:not fresh
global:global_errors
unexpected:stats.unexpected
registry-shrink:frozen registry
registry-dup:duplicate case ids
registry-unknown:frozen registry
case-failed:status'
	local entry name fragment
	for entry in $negatives; do
		name=${entry%%:*}
		fragment=${entry#*:}
		if gate_verify_receipt "$tmp/r-$name.json" "$start" >/dev/null 2>"$tmp/e-$name"; then
			die "selftest: $name receipt must FAIL"
		fi
		grep -q "$fragment" "$tmp/e-$name" \
			|| die "selftest: $name rejection must name its reason '$fragment' (got: $(cat "$tmp/e-$name"))"
	done

	echo "orgpresentation gate: selftest OK (4 log cases + 8 isolated receipt negatives + 1 positive)"
}

# --- main gate --------------------------------------------------------------
if [ "${1:-}" = "selftest" ]; then
	gate_selftest
	exit 0
fi

gate_selftest  # mandatory teeth on every gate run

repo=$(git rev-parse --show-toplevel) || die "not a git repo"
cd "$repo"
start=$(date +%s)

# Exact run ownership: the receipt must come from THIS gate's output tree.
# A caller (quality.py) may provide its per-run evidence dir; otherwise
# this gate creates its own and reports it.
if [ -z "${CV03_ORG_PRESENTATION_OUT:-}" ]; then
	CV03_ORG_PRESENTATION_OUT=$(mktemp -d "${TMPDIR:-/tmp}/cv03-gate-out.XXXXXX")
	export CV03_ORG_PRESENTATION_OUT
	echo "orgpresentation gate: per-run output at $CV03_ORG_PRESENTATION_OUT"
fi
out_root=$CV03_ORG_PRESENTATION_OUT

bash scripts/quality/browser-build.sh dashboard

log=$(mktemp)
trap 'rm -f "$log"' EXIT
set -o pipefail
go test -tags integration -v -run "^${GATE_TEST_NAME}\$" \
	./services/admin/handlers/ -count=1 -timeout 20m 2>&1 | tee "$log"
set +o pipefail
gate_parse_go_log "$log" || die "go test log lacks the required named PASS (see above)"

receipt=$(find "$out_root" -name "$GATE_RECEIPT_NAME" -newermt "@$((start - 1))" -printf '%T@ %p\n' 2>/dev/null \
	| sort -n | tail -1 | cut -d' ' -f2-)
[ -n "$receipt" ] || die "no fresh ${GATE_RECEIPT_NAME} under $out_root — the stand did not write a receipt for THIS gate run"
gate_verify_receipt "$receipt" "$start" || die "receipt rejected (see reason above)"
echo "orgpresentation gate: PASSED (named PASS + owned fresh acceptance receipt verified)"
