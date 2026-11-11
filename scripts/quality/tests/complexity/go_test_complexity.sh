#!/usr/bin/env bash
# QG-C01-01/QG-C01-02 fixtures: negative and boundary controls for the Go
# complexity differential analyzer (scripts/quality/complexity/go/go_complexity.py).
#
# Each control asserts exact function names, kinds and hand-counted
# complexity values — never just a non-zero exit. Every blocking control is
# paired with a reverse-control run (refactored body, boundary score,
# modified moved body, genuine rename) whose expected result is the
# opposite, proving the assertion binds to the measured behavior rather
# than to any failure at all. Expected cyclomatic values are hand-counted
# oracle constants, independent of the analyzer's own computation:
#   legacy untouched 25 | simple 8 | heavy base 9 -> head 18 / refactored 8
#   borderline 12 / boundary 10 | movable 2 | HeavyOriginal 18 (duplicate,
#   moved-with-reformat) | FmtOne 4 / FmtTwo 3 (formatting-only)
# QG-C01-02 controls add receipt validation (schema/SHA/model/staleness/
# binding rejections with distinct errors), the free-duplicate loophole,
# the carry-on-move debt ledger and gofmt/blank-line invariance.
# QG-C01-03 controls add whole-tree duplicate resolution (original in an
# unchanged file) and the real Makefile gate wiring: the live recipe is
# extracted from the product Makefile and driven through make, covering
# >15 without receipt, invalid receipts (same-model over 15, stale over
# 11-15), untouched-debt pass, valid 11-15 receipt via
# GO_COMPLEXITY_RECEIPT and a docs-only diff.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ANALYZER="$ROOT/scripts/quality/complexity/go/go_complexity.py"
FIXTURES="$ROOT/scripts/quality/tests/complexity/go_fixtures"
WORK=$(mktemp -d /tmp/go-complexity-fixtures.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# Fixture fleet model tiers (strongest first) consumed by the analyzer's
# receipt validation; the production default ordering lives in the script.
export GO_COMPLEXITY_MODEL_ORDER="fixture-senior,fixture-impl,fixture-junior"

BASE_BLOCKS="go_fn_legacy.go.tmpl go_fn_simple_base.go.tmpl go_fn_heavy_base.go.tmpl go_fn_movable_base.go.tmpl go_fn_removed_base.go.tmpl"
RC=""
total_failed=0
scenario_failed=0

new_repo() {
    local dir="$WORK/$1"
    mkdir -p "$dir"
    git -C "$dir" init -q
    git -C "$dir" config user.email fixtures@example.invalid
    git -C "$dir" config user.name "fixture builder"
    echo "$dir"
}

write_go() { # dest blocks...
    local dest=$1 block
    shift
    {
        printf 'package sample\n\n'
        for block in "$@"; do
            cat "$FIXTURES/$block"
            printf '\n'
        done
    } >"$dest"
}

commit_all() { # repo-dir message
    git -C "$1" add -A >/dev/null
    git -C "$1" commit -q -m "$2"
}

build_base() { # repo-dir -> prints base sha ; BASE_EXTRA adds base blocks
    write_go "$1/sample.go" $BASE_BLOCKS ${BASE_EXTRA:-}
    commit_all "$1" base
    git -C "$1" rev-parse HEAD
}

build_head() { # repo-dir sample-blocks... ; extra files via $EXTRA_FILES="name:blocks,..."
    local repo=$1
    shift
    write_go "$repo/sample.go" "$@"
    local extra name blocks
    for extra in ${EXTRA_FILES:-}; do
        name=${extra%%:*}
        blocks=${extra#*:}
        write_go "$repo/$name" ${blocks//,/ }
    done
    commit_all "$repo" head
}

run_analyzer() { # repo base report [extra...]
    local repo=$1 base=$2 report=$3
    shift 3
    python3 "$ANALYZER" --root "$repo" --base "$base" --report "$report" "$@" \
        >"$WORK/out.txt" 2>&1
    RC=$?
}

# make_receipt writes a schema go-complexity-review-receipt/1 document;
# overrides per control are applied by the caller via these arguments.
make_receipt() { # path head_sha base_sha reviewer impl date verdict functions-json
    python3 - "$@" <<'PY'
import json
import sys

path, head, base, reviewer, implementer, date, verdict, functions = sys.argv[1:9]
json.dump({
    "schema": "go-complexity-review-receipt/1",
    "source_commit": head,
    "base_commit": base,
    "implementer_model": implementer,
    "reviewer_model": reviewer,
    "review_date": date,
    "verdict": verdict,
    "functions": json.loads(functions),
}, open(path, "w"), indent=2)
PY
}

record() { # label pass/fail
    if [ "$2" = pass ]; then
        printf 'PASS %s\n' "$1"
    else
        printf 'FAIL %s\n' "$1"
        scenario_failed=$((scenario_failed + 1))
    fi
}

finish_scenario() { # name python-exit-code
    if [ "$2" -ne 0 ]; then
        scenario_failed=$((scenario_failed + 1))
        total_failed=$((total_failed + 1))
        printf 'scenario %-18s FAILED\n\n' "$1"
    else
        printf 'scenario %-18s OK\n\n' "$1"
    fi
    scenario_failed=0
}

# ---------------------------------------------------------------------------
scenario_clean_pass() {
    local repo
    repo=$(new_repo clean)
    local base
    base=$(build_base "$repo")
    EXTRA_FILES="moved.go:go_fn_moved_identical.go.tmpl" \
        build_head "$repo" go_fn_legacy.go.tmpl go_fn_simple_head.go.tmpl go_fn_heavy_ok_head.go.tmpl
    run_analyzer "$repo" "$base" "$WORK/clean.json"
    python3 - "$base" "$RC" "$WORK/clean.json" "$WORK/out.txt" <<'PY'
import json
import sys

base_sha, rc, report_path, out_path = sys.argv[1:5]
rc = int(rc)
report = json.load(open(report_path))
out = open(out_path).read()
entries = report["changed_functions"]
by_name = {e["function"]: e for e in entries}
failures = []


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f" [clean] {name}"
          + ("" if condition or not detail else f": {detail}"))
    if not condition:
        failures.append(name)


check("exit-0", rc == 0, f"rc={rc} out={out!r}")
simple = by_name.get("SimpleChanged", {})
check("simple-changed-8-ok",
      simple.get("kind") == "changed" and simple.get("old_cyclomatic") == 8
      and simple.get("new_cyclomatic") == 8 and simple.get("classification") == "ok",
      str(simple))
heavy = by_name.get("HeavyChanged", {})
check("heavy-refactored-8-ok",
      heavy.get("kind") == "changed" and heavy.get("old_cyclomatic") == 9
      and heavy.get("new_cyclomatic") == 8 and heavy.get("classification") == "ok",
      str(heavy))
moved = by_name.get("MovableHelper", {})
check("moved-recognized",
      moved.get("kind") == "moved" and moved.get("from_file") == "sample.go"
      and moved.get("classification") == "ok_moved_unchanged", str(moved))
check("legacy-not-in-changed",
      all(e["function"] != "LegacyUntouched" for e in entries))
debt = report["untouched_debt"]
check("legacy-only-in-debt",
      debt.get("cyclomatic_gt15") == 1
      and debt.get("functions_gt15") == [{"file": "sample.go",
                                          "function": "LegacyUntouched",
                                          "cyclomatic": 25, "kind": "untouched"}]
      and debt.get("untouched_functions") == 1, json.dumps(debt))
check("deleted-absent", "RemovedThing" not in open(report_path).read())
run = report["run"]
analyzer = report["analyzer"]
check("pins-and-binding",
      run.get("base_sha") == base_sha
      and len(run.get("measured_source_sha256", "")) == 64
      and analyzer.get("version") and analyzer.get("go_version", "").startswith("go")
      and len(analyzer.get("helper_source_sha256", "")) == 64,
      json.dumps({"run": run, "analyzer": analyzer})[:400])
check("no-blocks-or-reviews",
      all(e["classification"] in ("ok", "ok_moved_unchanged") for e in entries),
      str([e["classification"] for e in entries]))
sys.exit(1 if failures else 0)
PY
    finish_scenario clean-pass $?
}

# ---------------------------------------------------------------------------
scenario_block_over_15() {
    local repo
    repo=$(new_repo block)
    local base
    base=$(build_base "$repo")
    EXTRA_FILES="moved.go:go_fn_moved_identical.go.tmpl" \
        build_head "$repo" go_fn_legacy.go.tmpl go_fn_simple_head.go.tmpl go_fn_heavy_head.go.tmpl
    run_analyzer "$repo" "$base" "$WORK/block.json"
    python3 - "$base" "$RC" "$WORK/block.json" "$WORK/out.txt" <<'PY'
import json
import sys

base_sha, rc, report_path, out_path = sys.argv[1:5]
rc = int(rc)
report = json.load(open(report_path))
out = open(out_path).read()
entries = report["changed_functions"]
by_name = {e["function"]: e for e in entries}
failures = []


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f" [block] {name}"
          + ("" if condition or not detail else f": {detail}"))
    if not condition:
        failures.append(name)


heavy = by_name.get("HeavyChanged", {})
check("exit-1", rc == 1, f"rc={rc}")
check("exact-name-in-output", "HeavyChanged" in out, out[:200])
check("blocked-line-named", "BLOCKED HeavyChanged" in out, out[:300])
check("heavy-18-blocks",
      heavy.get("kind") == "changed" and heavy.get("old_cyclomatic") == 9
      and heavy.get("new_cyclomatic") == 18
      and heavy.get("classification") == "blocks", str(heavy))
simple = by_name.get("SimpleChanged", {})
check("others-still-measured",
      simple.get("classification") == "ok", str(simple))
moved = by_name.get("MovableHelper", {})
check("moved-not-reflagged-in-failing-run",
      moved.get("classification") == "ok_moved_unchanged", str(moved))
check("legacy-debt-still-nonblocking",
      report["untouched_debt"].get("cyclomatic_gt15") == 1,
      json.dumps(report["untouched_debt"]))
sys.exit(1 if failures else 0)
PY
    finish_scenario block-over-15 $?
}

# ---------------------------------------------------------------------------
scenario_receipt_band() {
    # Fixed commit dates keep the same-day review_date of the valid receipt
    # deterministic (stale = review_date before the source commit date).
    export GIT_AUTHOR_DATE="2026-11-05T09:00:00+00:00" \
           GIT_COMMITTER_DATE="2026-11-05T09:00:00+00:00"
    local repo
    repo=$(new_repo receipt)
    local base
    base=$(build_base "$repo")
    build_head "$repo" go_fn_legacy.go.tmpl go_fn_borderline_head.go.tmpl
    local head
    head=$(git -C "$repo" rev-parse HEAD)

    run_analyzer "$repo" "$base" "$WORK/receipt-none.json"
    python3 - "$RC" "$WORK/receipt-none.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
out = open(out_path).read()
failures = []


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f" [receipt] {name}"
          + ("" if condition or not detail else f": {detail}"))
    if not condition:
        failures.append(name)


entry = {e["function"]: e for e in report["changed_functions"]}.get("BorderlineFn", {})
check("band-exit-1", rc == 1, f"rc={rc}")
check("band-exact-name", "NEEDS REVIEW RECEIPT BorderlineFn" in out, out[:300])
check("band-classified",
      entry.get("classification") == "needs_review" and entry.get("receipt") is False
      and entry.get("new_cyclomatic") == 12 and entry.get("kind") == "added", str(entry))
sys.exit(1 if failures else 0)
PY
    local none_rc=$?

    run_analyzer "$repo" "$base" "$WORK/receipt-bad.json" --receipt "$WORK/no-such-receipt.json"
    check_receipt_missing=$([ "$RC" -eq 1 ] && echo pass || echo fail)
    printf '%s [receipt] missing-receipt-path-fails\n' "$(echo "$check_receipt_missing" | tr a-z A-Z)"
    [ "$check_receipt_missing" = pass ] || none_rc=$((none_rc + 1))

    make_receipt "$WORK/receipt.json" "$head" "$base" fixture-senior \
        fixture-impl 2026-11-05 approve-exception '["sample.go:BorderlineFn"]'
    run_analyzer "$repo" "$base" "$WORK/receipt-ok.json" --receipt "$WORK/receipt.json"
    python3 - "$RC" "$WORK/receipt-ok.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
failures = []


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f" [receipt] {name}"
          + ("" if condition or not detail else f": {detail}"))
    if not condition:
        failures.append(name)


entry = {e["function"]: e for e in report["changed_functions"]}.get("BorderlineFn", {})
receipt = report.get("receipt") or {}
check("accepted-receipt-exit-0", rc == 0, f"rc={rc}")
check("accepted-receipt-flagged",
      entry.get("classification") == "needs_review" and entry.get("receipt") is True,
      str(entry))
check("accepted-receipt-recorded",
      receipt.get("status") == "accepted"
      and receipt.get("reviewer_model") == "fixture-senior"
      and receipt.get("implementer_model") == "fixture-impl"
      and receipt.get("source_commit") == report["run"]["head_sha"]
      and receipt.get("base_commit") == report["run"]["base_sha"],
      str(receipt))
sys.exit(1 if failures else 0)
PY
    local with_rc=$?

    local boundary_repo
    boundary_repo=$(new_repo boundary)
    local boundary_base
    boundary_base=$(build_base "$boundary_repo")
    build_head "$boundary_repo" go_fn_legacy.go.tmpl go_fn_borderline_ok_head.go.tmpl
    run_analyzer "$boundary_repo" "$boundary_base" "$WORK/boundary.json"
    python3 - "$RC" "$WORK/boundary.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
entry = {e["function"]: e for e in report["changed_functions"]}.get("BorderlineFn", {})
condition = rc == 0 and entry.get("new_cyclomatic") == 10 and entry.get("classification") == "ok"
print(("PASS" if condition else "FAIL")
      + f" [receipt] boundary-10-needs-no-receipt: rc={rc} entry={entry}")
sys.exit(0 if condition else 1)
PY
    local boundary_rc=$?

    unset GIT_AUTHOR_DATE GIT_COMMITTER_DATE
    total=$((none_rc + with_rc + boundary_rc))
    if [ "$total" -ne 0 ]; then
        scenario_failed=$((scenario_failed + 1))
        total_failed=$((total_failed + 1))
        printf 'scenario %-18s FAILED\n\n' receipt-band
    else
        printf 'scenario %-18s OK\n\n' receipt-band
    fi
}

# ---------------------------------------------------------------------------
scenario_determinism() {
    scenario_failed=0
    local repo
    repo=$(new_repo determinism)
    local base
    base=$(build_base "$repo")
    EXTRA_FILES="moved.go:go_fn_moved_identical.go.tmpl" \
        build_head "$repo" go_fn_legacy.go.tmpl go_fn_simple_head.go.tmpl go_fn_heavy_head.go.tmpl
    run_analyzer "$repo" "$base" "$WORK/det1.json"
    run_analyzer "$repo" "$base" "$WORK/det2.json"
    if cmp -s "$WORK/det1.json" "$WORK/det2.json"; then
        printf 'PASS [determinism] identical-bytes\n'
    else
        printf 'FAIL [determinism] identical-bytes\n'
        scenario_failed=1
        total_failed=$((total_failed + 1))
    fi
    printf 'scenario %-18s %s\n\n' determinism "$([ "$scenario_failed" -eq 0 ] && echo OK || echo FAILED)"
}

# ---------------------------------------------------------------------------
scenario_moved_modified() {
    local repo
    repo=$(new_repo movedmod)
    local base
    base=$(build_base "$repo")
    EXTRA_FILES="moved.go:go_fn_moved_modified.go.tmpl" \
        build_head "$repo" go_fn_legacy.go.tmpl go_fn_simple_head.go.tmpl
    run_analyzer "$repo" "$base" "$WORK/movedmod.json"
    python3 - "$RC" "$WORK/movedmod.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
entries = report["changed_functions"]
entry = {e["function"]: e for e in entries}.get("MovableHelper", {})
failures = []


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f" [moved-modified] {name}"
          + ("" if condition or not detail else f": {detail}"))
    if not condition:
        failures.append(name)


check("modified-move-still-passes", rc == 0, f"rc={rc}")
check("modified-move-measured-as-added",
      entry.get("kind") == "added" and "from_file" not in entry
      and entry.get("new_cyclomatic") == 2, str(entry))
check("no-false-moved-label",
      all(e.get("classification") in ("ok", "ok_moved_unchanged") for e in entries),
      str([(e["function"], e["classification"]) for e in entries]))
sys.exit(1 if failures else 0)
PY
    finish_scenario moved-modified $?
}

# ---------------------------------------------------------------------------
scenario_receipt_validation() {
    # QG-C01-02 receipt policy: every invalid receipt must block (exit 1)
    # with a distinct, precise error; only the fully bound stronger-model
    # receipt passes the 11-15 band.
    export GIT_AUTHOR_DATE="2026-11-01T09:00:00+00:00" \
           GIT_COMMITTER_DATE="2026-11-01T09:00:00+00:00"
    local repo
    repo=$(new_repo receiptval)
    local base
    base=$(build_base "$repo")
    export GIT_AUTHOR_DATE="2026-11-05T09:00:00+00:00" \
           GIT_COMMITTER_DATE="2026-11-05T09:00:00+00:00"
    build_head "$repo" go_fn_legacy.go.tmpl go_fn_borderline_head.go.tmpl
    local head
    head=$(git -C "$repo" rev-parse HEAD)
    unset GIT_AUTHOR_DATE GIT_COMMITTER_DATE

    local zeros=0000000000000000000000000000000000000000
    make_receipt "$WORK/rv-valid.json" "$head" "$base" fixture-senior \
        fixture-impl 2026-11-05 approve-exception '["sample.go:BorderlineFn"]'
    make_receipt "$WORK/rv-source.json" "$zeros" "$base" fixture-senior \
        fixture-impl 2026-11-05 approve-exception '["sample.go:BorderlineFn"]'
    make_receipt "$WORK/rv-basesha.json" "$head" "$zeros" fixture-senior \
        fixture-impl 2026-11-05 approve-exception '["sample.go:BorderlineFn"]'
    make_receipt "$WORK/rv-same.json" "$head" "$base" fixture-impl \
        fixture-impl 2026-11-05 approve-exception '["sample.go:BorderlineFn"]'
    make_receipt "$WORK/rv-weaker.json" "$head" "$base" fixture-junior \
        fixture-impl 2026-11-05 approve-exception '["sample.go:BorderlineFn"]'
    make_receipt "$WORK/rv-stale.json" "$head" "$base" fixture-senior \
        fixture-impl 2026-11-04 approve-exception '["sample.go:BorderlineFn"]'
    make_receipt "$WORK/rv-verdict.json" "$head" "$base" fixture-senior \
        fixture-impl 2026-11-05 approve '["sample.go:BorderlineFn"]'
    make_receipt "$WORK/rv-unbound.json" "$head" "$base" fixture-senior \
        fixture-impl 2026-11-05 approve-exception '["other.go:Elsewhere"]'
    make_receipt "$WORK/rv-refactor.json" "$head" "$base" fixture-senior \
        fixture-impl 2026-11-05 require-refactor '["sample.go:BorderlineFn"]'
    printf '%s\n' "{\"schema\": \"go-complexity-review-receipt/1\", \"source_commit\": \"$head\", \"base_commit\": \"$base\", \"reviewer_model\": \"fixture-senior\", \"review_date\": \"2026-11-05\", \"verdict\": \"approve-exception\", \"functions\": [\"sample.go:BorderlineFn\"]}" >"$WORK/rv-noimpl.json"

    local case name substring receipt_file
    for case in "wrong-source-sha|source_commit mismatch|$WORK/rv-source.json" \
                "wrong-base-sha|base_commit mismatch|$WORK/rv-basesha.json" \
                "same-model|equals implementer_model|$WORK/rv-same.json" \
                "weaker-reviewer|not stronger than|$WORK/rv-weaker.json" \
                "stale-date|stale receipt|$WORK/rv-stale.json" \
                "unknown-verdict|unknown verdict|$WORK/rv-verdict.json" \
                "missing-implementer|implementer_model missing|$WORK/rv-noimpl.json"; do
        name=${case%%|*}
        local rest=${case#*|}
        substring=${rest%%|*}
        receipt_file=${rest#*|}
        run_analyzer "$repo" "$base" "$WORK/rv-$name.json" --receipt "$receipt_file"
        if [ "$RC" -eq 1 ] && grep -q "$substring" "$WORK/out.txt"; then
            printf 'PASS [receipt-validation] %s\n' "$name"
        else
            printf 'FAIL [receipt-validation] %s: rc=%s want-substring=%q out=%s\n' \
                "$name" "$RC" "$substring" "$(head -c 300 "$WORK/out.txt")"
            scenario_failed=$((scenario_failed + 1))
        fi
    done

    run_analyzer "$repo" "$base" "$WORK/rv-valid-run.json" --receipt "$WORK/rv-valid.json"
    python3 - "$RC" "$WORK/rv-valid-run.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
out = open(out_path).read()
failures = []


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f" [receipt-validation] {name}"
          + ("" if condition or not detail else f": {detail}"))
    if not condition:
        failures.append(name)


receipt = report.get("receipt") or {}
entry = {e["function"]: e for e in report["changed_functions"]}.get("BorderlineFn", {})
check("valid-receipt-passes-band",
      rc == 0 and entry.get("receipt") is True and receipt.get("status") == "accepted"
      and receipt.get("reviewer_model") == "fixture-senior"
      and receipt.get("verdict") == "approve-exception",
      f"rc={rc} entry={entry} receipt={receipt}")
check("same-day-review-not-stale",
      report["run"].get("head_commit_date") == "2026-11-05"
      and receipt.get("review_date") == "2026-11-05",
      str(receipt))
sys.exit(1 if failures else 0)
PY
    record receipt-validation-valid $([ $? -eq 0 ] && echo pass || echo fail)

    run_analyzer "$repo" "$base" "$WORK/rv-unbound-run.json" --receipt "$WORK/rv-unbound.json"
    python3 - "$RC" "$WORK/rv-unbound-run.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
out = open(out_path).read()
entry = {e["function"]: e for e in report["changed_functions"]}.get("BorderlineFn", {})
condition = (rc == 1 and "NEEDS REVIEW RECEIPT BorderlineFn" in out
             and "does not bind sample.go:BorderlineFn" in out
             and entry.get("receipt") is False
             and entry.get("receipt_reason")
             == "receipt does not bind sample.go:BorderlineFn")
print(("PASS" if condition else "FAIL")
      + f" [receipt-validation] unbound-function: rc={rc} entry={entry}")
sys.exit(0 if condition else 1)
PY
    record receipt-validation-unbound $([ $? -eq 0 ] && echo pass || echo fail)

    run_analyzer "$repo" "$base" "$WORK/rv-refactor-run.json" --receipt "$WORK/rv-refactor.json"
    python3 - "$RC" "$WORK/rv-refactor-run.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
out = open(out_path).read()
entry = {e["function"]: e for e in report["changed_functions"]}.get("BorderlineFn", {})
receipt = report.get("receipt") or {}
condition = (rc == 1 and "require-refactor" in out
             and "NEEDS REVIEW RECEIPT BorderlineFn" in out
             and entry.get("receipt") is False
             and receipt.get("status") == "valid_not_approving")
print(("PASS" if condition else "FAIL")
      + f" [receipt-validation] require-refactor-not-approval: rc={rc} "
        f"entry={entry} receipt={receipt}")
sys.exit(0 if condition else 1)
PY
    record receipt-validation-refactor $([ $? -eq 0 ] && echo pass || echo fail)

    if [ "$scenario_failed" -ne 0 ]; then
        total_failed=$((total_failed + 1))
        printf 'scenario %-18s FAILED\n\n' receipt-validation
    else
        printf 'scenario %-18s OK\n\n' receipt-validation
    fi
    scenario_failed=0
}

# ---------------------------------------------------------------------------
scenario_duplicate_over_15() {
    # QG-C01-02 free-duplicate loophole: a content-identical copy of a >15
    # base function, with the original still at head, must be measured as
    # added content and block; a valid receipt only feeds the exception
    # ledger and never unblocks it.
    export GIT_AUTHOR_DATE="2026-11-01T09:00:00+00:00" \
           GIT_COMMITTER_DATE="2026-11-01T09:00:00+00:00"
    local repo
    repo=$(new_repo dup)
    local base
    base=$(BASE_EXTRA="go_fn_debt_base.go.tmpl" build_base "$repo")
    export GIT_AUTHOR_DATE="2026-11-05T09:00:00+00:00" \
           GIT_COMMITTER_DATE="2026-11-05T09:00:00+00:00"
    EXTRA_FILES="dup.go:go_fn_debt_duplicate_head.go.tmpl" \
        build_head "$repo" go_fn_legacy.go.tmpl go_fn_simple_head.go.tmpl go_fn_debt_base.go.tmpl
    local head
    head=$(git -C "$repo" rev-parse HEAD)
    unset GIT_AUTHOR_DATE GIT_COMMITTER_DATE

    run_analyzer "$repo" "$base" "$WORK/dup.json"
    python3 - "$RC" "$WORK/dup.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
out = open(out_path).read()
entries = report["changed_functions"]
by_name = {e["function"]: e for e in entries}
failures = []


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f" [duplicate] {name}"
          + ("" if condition or not detail else f": {detail}"))
    if not condition:
        failures.append(name)


duplicate = by_name.get("HeavyDuplicate", {})
debt_list = report["untouched_debt"].get("functions_gt15", [])
check("exit-1", rc == 1, f"rc={rc}")
check("blocked-line-named", "BLOCKED HeavyDuplicate" in out, out[:300])
check("measured-as-added-under-thresholds",
      duplicate.get("kind") == "added" and duplicate.get("new_cyclomatic") == 18
      and duplicate.get("classification") == "blocks"
      and duplicate.get("duplicate_of") == "sample.go:HeavyOriginal",
      str(duplicate))
check("duplicate-not-in-moved-debt",
      all(item.get("kind") == "untouched" for item in debt_list)
      and any(item["function"] == "HeavyOriginal" for item in debt_list)
      and all(item["function"] != "HeavyDuplicate" for item in debt_list),
      json.dumps(debt_list))
sys.exit(1 if failures else 0)
PY
    record duplicate-over-15 $([ $? -eq 0 ] && echo pass || echo fail)

    make_receipt "$WORK/dup-receipt.json" "$head" "$base" fixture-senior \
        fixture-impl 2026-11-05 approve-exception '["dup.go:HeavyDuplicate"]'
    run_analyzer "$repo" "$base" "$WORK/dup-receipt-run.json" --receipt "$WORK/dup-receipt.json"
    python3 - "$RC" "$WORK/dup-receipt-run.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
out = open(out_path).read()
entry = {e["function"]: e for e in report["changed_functions"]}.get("HeavyDuplicate", {})
receipt = report.get("receipt") or {}
condition = (rc == 1 and "BLOCKED HeavyDuplicate" in out
             and "exception ledger only" in out
             and entry.get("classification") == "blocks"
             and entry.get("exception_receipt_recorded") is True
             and receipt.get("status") == "accepted")
print(("PASS" if condition else "FAIL")
      + f" [duplicate] receipt-never-unblocks-over-15: rc={rc} entry={entry} "
        f"receipt={receipt}")
sys.exit(0 if condition else 1)
PY
    record duplicate-receipt-ledger $([ $? -eq 0 ] && echo pass || echo fail)

    if [ "$scenario_failed" -ne 0 ]; then
        total_failed=$((total_failed + 1))
        printf 'scenario %-18s FAILED\n\n' duplicate-over-15
    else
        printf 'scenario %-18s OK\n\n' duplicate-over-15
    fi
    scenario_failed=0
}

# ---------------------------------------------------------------------------
scenario_moved_debt_carry() {
    # Carry-on-move policy: a renamed + reformatted >15 function whose base
    # original is gone is a genuine move — debt carried without
    # re-measurement, listed in the untouched-debt ledger, never blocking.
    local repo
    repo=$(new_repo carry)
    local base
    base=$(BASE_EXTRA="go_fn_debt_base.go.tmpl" build_base "$repo")
    EXTRA_FILES="moved.go:go_fn_debt_moved_head.go.tmpl" \
        build_head "$repo" go_fn_legacy.go.tmpl go_fn_simple_head.go.tmpl
    run_analyzer "$repo" "$base" "$WORK/carry.json"
    python3 - "$RC" "$WORK/carry.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
entries = report["changed_functions"]
entry = {e["function"]: e for e in entries}.get("HeavyMovedDebt", {})
debt = report["untouched_debt"]
failures = []


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f" [moved-debt] {name}"
          + ("" if condition or not detail else f": {detail}"))
    if not condition:
        failures.append(name)


carried = {"file": "moved.go", "function": "HeavyMovedDebt",
           "cyclomatic": 18, "kind": "moved"}
check("moved-carries-without-blocking", rc == 0, f"rc={rc}")
check("reformatted-move-still-recognized",
      entry.get("kind") == "moved" and entry.get("from_file") == "sample.go"
      and entry.get("from_function") == "HeavyOriginal"
      and entry.get("classification") == "ok_moved_unchanged"
      and "duplicate_of" not in entry, str(entry))
check("carried-debt-in-ledger",
      entry.get("new_cyclomatic") == 18 and carried in debt.get("functions_gt15", [])
      and debt.get("cyclomatic_gt15") == 2,
      json.dumps(debt.get("functions_gt15")))
sys.exit(1 if failures else 0)
PY
    record moved-debt-carry $([ $? -eq 0 ] && echo pass || echo fail)

    if [ "$scenario_failed" -ne 0 ]; then
        total_failed=$((total_failed + 1))
        printf 'scenario %-18s FAILED\n\n' moved-debt-carry
    else
        printf 'scenario %-18s OK\n\n' moved-debt-carry
    fi
    scenario_failed=0
}

# ---------------------------------------------------------------------------
scenario_formatting_only() {
    # gofmt/blank-line invariance: the canonical body hash is computed over
    # the AST printed against a synthetic single-line file set, so a
    # formatting-only edit produces zero changed functions.
    local repo
    repo=$(new_repo fmt)
    write_go "$repo/sample.go" go_fn_fmt_base.go.tmpl
    commit_all "$repo" base
    local base
    base=$(git -C "$repo" rev-parse HEAD)
    write_go "$repo/sample.go" go_fn_fmt_head.go.tmpl
    commit_all "$repo" head
    run_analyzer "$repo" "$base" "$WORK/fmt.json"
    python3 - "$RC" "$WORK/fmt.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
out = open(out_path).read()
failures = []


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f" [formatting] {name}"
          + ("" if condition or not detail else f": {detail}"))
    if not condition:
        failures.append(name)


debt = report["untouched_debt"]
check("exit-0", rc == 0, f"rc={rc}")
check("zero-changed-functions",
      report["changed_functions"] == [] and "changed function bodies: 0" in out,
      json.dumps(report["changed_functions"]))
check("both-bodies-untouched",
      debt.get("untouched_functions") == 2
      and debt.get("cyclomatic_gt15") == 0 and debt.get("cyclomatic_11_to_15") == 0,
      json.dumps(debt))
sys.exit(1 if failures else 0)
PY
    record formatting-only $([ $? -eq 0 ] && echo pass || echo fail)

    # Regression: a head change touching no Go files at all must exit 0
    # with an empty changed set and a complete report envelope, not crash
    # on the helper's empty batch output.
    local quiet_repo
    quiet_repo=$(new_repo fmtquiet)
    write_go "$quiet_repo/sample.go" go_fn_fmt_base.go.tmpl
    commit_all "$quiet_repo" base
    local quiet_base
    quiet_base=$(git -C "$quiet_repo" rev-parse HEAD)
    printf 'documentation-only change\n' >"$quiet_repo/NOTE.md"
    commit_all "$quiet_repo" note
    run_analyzer "$quiet_repo" "$quiet_base" "$WORK/fmt-empty.json"
    python3 - "$RC" "$WORK/fmt-empty.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
condition = (rc == 0 and report["changed_functions"] == []
             and report["run"]["measured_head_files"] == []
             and report["analyzer"]["go_version"])
print(("PASS" if condition else "FAIL")
      + f" [formatting] zero-go-file-change-clean: rc={rc} "
        f"run={report['run']['measured_head_files']}")
sys.exit(0 if condition else 1)
PY
    record formatting-only-no-go-files $([ $? -eq 0 ] && echo pass || echo fail)

    if [ "$scenario_failed" -ne 0 ]; then
        total_failed=$((total_failed + 1))
        printf 'scenario %-18s FAILED\n\n' formatting-only
    else
        printf 'scenario %-18s OK\n\n' formatting-only
    fi
    scenario_failed=0
}

# ---------------------------------------------------------------------------
scenario_treewide_duplicate() {
    # QG-C01-03 whole-tree duplicate resolution: duplicate detection indexes
    # the entire head tree, not only changed files. A content-identical copy
    # of a >15 function whose original survives untouched in an UNCHANGED
    # file is still measured as added content and blocks — it cannot escape
    # as a "move" merely because its original's file left the changed set.
    # (Against the pre-1.2.0 analyzer this control fails: the copy was
    # mislabeled moved and the run exited 0.)
    local repo
    repo=$(new_repo treedup)
    local base
    base=$(BASE_EXTRA="go_fn_debt_base.go.tmpl" build_base "$repo")
    # Head rewrites sample.go byte-identical (git reports no change for it)
    # and adds the duplicate in a brand-new file.
    EXTRA_FILES="treedup.go:go_fn_debt_duplicate_head.go.tmpl" \
        build_head "$repo" $BASE_BLOCKS go_fn_debt_base.go.tmpl
    run_analyzer "$repo" "$base" "$WORK/treedup.json"
    python3 - "$RC" "$WORK/treedup.json" "$WORK/out.txt" <<'PY'
import json
import sys

rc, report_path, out_path = sys.argv[1:4]
rc = int(rc)
report = json.load(open(report_path))
out = open(out_path).read()
entries = report["changed_functions"]
by_name = {e["function"]: e for e in entries}
failures = []


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f" [treewide-dup] {name}"
          + ("" if condition or not detail else f": {detail}"))
    if not condition:
        failures.append(name)


duplicate = by_name.get("HeavyDuplicate", {})
debt = report["untouched_debt"]
check("exit-1", rc == 1, f"rc={rc}")
check("blocked-line-named", "BLOCKED HeavyDuplicate" in out, out[:300])
check("duplicate-of-unchanged-original",
      duplicate.get("kind") == "added" and duplicate.get("new_cyclomatic") == 18
      and duplicate.get("classification") == "blocks"
      and duplicate.get("duplicate_of") == "sample.go:HeavyOriginal",
      str(duplicate))
check("no-moved-escape",
      all(e.get("classification") != "ok_moved_unchanged" for e in entries),
      str([(e["function"], e["classification"]) for e in entries]))
check("only-new-file-measured",
      report["run"].get("measured_head_files") == ["treedup.go"],
      str(report["run"].get("measured_head_files")))
check("unchanged-file-debt-outside-diff-ledger",
      # sample.go left the changed set, so its legacy debt (HeavyOriginal 18,
      # LegacyUntouched 25) is baseline debt, not this diff's ledger; the
      # duplicate itself blocks as added content above. Whole-tree baseline
      # debt tracking is QG-C02 scope.
      debt.get("untouched_functions") == 0 and debt.get("cyclomatic_gt15") == 0
      and debt.get("functions_gt15") == [],
      json.dumps(debt))
sys.exit(1 if failures else 0)
PY
    finish_scenario treewide-duplicate $?
}

# ---------------------------------------------------------------------------
scenario_gate_wiring() {
    # QG-C01-03 real gate wiring: extract the live _quality-go-complexity
    # recipe from the product Makefile and drive it through make in fixture
    # repos that carry a committed copy of the analyzer package (committed
    # at base so the copy itself never enters the measured diff). Controls:
    # >15 without receipt fails, invalid receipts fail (same-model over 15,
    # stale over 11-15), untouched debt passes, a valid 11-15 receipt passes
    # via GO_COMPLEXITY_RECEIPT, a docs-only diff passes with zero measured
    # bodies, and quality.py actually routes .go changes to the gate.
    # Pull the recipe straight from the product Makefile: the control fails
    # (empty extract) the moment the target is removed or renamed.
    sed -n '/^_quality-go-complexity:/,/^$/p' "$ROOT/Makefile" >"$WORK/gate.mk"
    if [ ! -s "$WORK/gate.mk" ] || ! grep -q "go_complexity.py" "$WORK/gate.mk"; then
        printf 'FAIL [gate-wiring] recipe-extracted-from-product-makefile\n'
        scenario_failed=$((scenario_failed + 1))
    else
        printf 'PASS [gate-wiring] recipe-extracted-from-product-makefile\n'
    fi

    gate_repo() { # name -> dir with the gate + analyzer committed at base
        local dir
        dir=$(new_repo "$1")
        mkdir -p "$dir/scripts/quality/complexity"
        cp -r "$ROOT/scripts/quality/complexity/go" \
            "$dir/scripts/quality/complexity/go"
        cp "$WORK/gate.mk" "$dir/gate.mk"
        echo "$dir"
    }

    run_gate() { # repo base [receipt-path]
        env QUALITY_BASE="$2" ${3:+GO_COMPLEXITY_RECEIPT="$3"} \
            make -C "$1" -f gate.mk _quality-go-complexity \
            >"$WORK/gate-out.txt" 2>&1
        GATE_RC=$?
    }

    export GIT_AUTHOR_DATE="2026-11-01T09:00:00+00:00" \
           GIT_COMMITTER_DATE="2026-11-01T09:00:00+00:00"
    local heavy_repo heavy_base heavy_head
    heavy_repo=$(gate_repo gateheavy)
    heavy_base=$(build_base "$heavy_repo")
    export GIT_AUTHOR_DATE="2026-11-05T09:00:00+00:00" \
           GIT_COMMITTER_DATE="2026-11-05T09:00:00+00:00"
    build_head "$heavy_repo" go_fn_legacy.go.tmpl go_fn_simple_head.go.tmpl go_fn_heavy_head.go.tmpl
    heavy_head=$(git -C "$heavy_repo" rev-parse HEAD)

    local band_repo band_base band_head
    band_repo=$(gate_repo gateband)
    band_base=$(build_base "$band_repo")
    build_head "$band_repo" go_fn_legacy.go.tmpl go_fn_borderline_head.go.tmpl
    band_head=$(git -C "$band_repo" rev-parse HEAD)

    local debt_repo debt_base
    debt_repo=$(gate_repo gatedebt)
    debt_base=$(build_base "$debt_repo")
    build_head "$debt_repo" go_fn_legacy.go.tmpl go_fn_simple_head.go.tmpl go_fn_heavy_ok_head.go.tmpl

    local quiet_repo quiet_base
    quiet_repo=$(gate_repo gatedocs)
    quiet_base=$(build_base "$quiet_repo")
    printf 'documentation-only change\n' >"$quiet_repo/NOTE.md"
    commit_all "$quiet_repo" note
    unset GIT_AUTHOR_DATE GIT_COMMITTER_DATE

    gate_case() { # name repo base want-rc-zero substr...
        local name=$1 repo=$2 base=$3 want_zero=$4
        shift 4
        run_gate "$repo" "$base" "${RECEIPT:-}"
        local ok=1 sub
        if [ "$want_zero" = yes ] && [ "$GATE_RC" -ne 0 ]; then ok=0; fi
        if [ "$want_zero" = no ] && [ "$GATE_RC" -eq 0 ]; then ok=0; fi
        for sub in "$@"; do
            grep -q "$sub" "$WORK/gate-out.txt" || ok=0
        done
        if [ "$ok" -eq 1 ]; then
            printf 'PASS [gate-wiring] %s\n' "$name"
        else
            printf 'FAIL [gate-wiring] %s: make-rc=%s want-zero=%s out=%s\n' \
                "$name" "$GATE_RC" "$want_zero" "$(head -c 300 "$WORK/gate-out.txt")"
            scenario_failed=$((scenario_failed + 1))
        fi
    }

    RECEIPT="" gate_case over-15-no-receipt-blocks "$heavy_repo" "$heavy_base" no \
        "BLOCKED HeavyChanged"
    make_receipt "$WORK/gate-same-model.json" "$heavy_head" "$heavy_base" fixture-impl \
        fixture-impl 2026-11-05 approve-exception '["sample.go:HeavyChanged"]'
    RECEIPT="$WORK/gate-same-model.json" \
        gate_case over-15-same-model-receipt-fails "$heavy_repo" "$heavy_base" no \
        "BLOCKED HeavyChanged" "equals implementer_model"
    make_receipt "$WORK/gate-stale.json" "$band_head" "$band_base" fixture-senior \
        fixture-impl 2026-11-04 approve-exception '["sample.go:BorderlineFn"]'
    RECEIPT="$WORK/gate-stale.json" \
        gate_case band-stale-receipt-fails "$band_repo" "$band_base" no \
        "stale receipt" "NEEDS REVIEW RECEIPT BorderlineFn"
    RECEIPT="" gate_case untouched-debt-passes "$debt_repo" "$debt_base" yes \
        "untouched legacy debt: 1 >15" "changed function bodies: 2"
    RECEIPT="" gate_case docs-only-zero-bodies "$quiet_repo" "$quiet_base" yes \
        "changed function bodies: 0"

    # A fresh dated repo gives the valid receipt a same-day commit.
    export GIT_AUTHOR_DATE="2026-11-05T09:00:00+00:00" \
           GIT_COMMITTER_DATE="2026-11-05T09:00:00+00:00"
    local band2_repo band2_base band2_head
    band2_repo=$(gate_repo gateband2)
    band2_base=$(build_base "$band2_repo")
    build_head "$band2_repo" go_fn_legacy.go.tmpl go_fn_borderline_head.go.tmpl
    band2_head=$(git -C "$band2_repo" rev-parse HEAD)
    unset GIT_AUTHOR_DATE GIT_COMMITTER_DATE
    make_receipt "$WORK/gate-valid.json" "$band2_head" "$band2_base" fixture-senior \
        fixture-impl 2026-11-05 approve-exception '["sample.go:BorderlineFn"]'
    RECEIPT="$WORK/gate-valid.json" \
        gate_case band-valid-receipt-passes "$band2_repo" "$band2_base" yes \
        '"status": "accepted"'

    # Binding the routing: quality.py must select the gate for .go diffs
    # (root and nested) and never for docs-only diffs.
    python3 - "$ROOT" <<'PY'
import importlib.util
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts/quality"))
spec = importlib.util.spec_from_file_location(
    "quality", root / "scripts/quality/quality.py")
quality = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quality)

checks = [
    ("go-diff-selects-gate", "go-complexity" in quality.classify(["cmd/gateway/main.go"])),
    ("nested-go-diff-selects-gate", "go-complexity" in quality.classify(["sdks/go/client.go"])),
    ("full-profile-contains-gate", "go-complexity" in quality.expand(["full"])),
    ("docs-diff-excludes-gate", "go-complexity" not in quality.classify(["README.md"])),
    ("manifests-exclude-gate", "go-complexity" not in quality.classify(["go.mod", "go.sum"])),
]
failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(("PASS" if ok else "FAIL") + f" [gate-wiring] routing-{name}")
sys.exit(1 if failed else 0)
PY
    if [ $? -ne 0 ]; then
        scenario_failed=$((scenario_failed + 1))
    fi

    if [ "$scenario_failed" -ne 0 ]; then
        total_failed=$((total_failed + 1))
        printf 'scenario %-18s FAILED\n\n' gate-wiring
    else
        printf 'scenario %-18s OK\n\n' gate-wiring
    fi
    scenario_failed=0
}

scenario_clean_pass
scenario_block_over_15
scenario_receipt_band
scenario_receipt_validation
scenario_duplicate_over_15
scenario_moved_debt_carry
scenario_formatting_only
scenario_determinism
scenario_moved_modified
scenario_treewide_duplicate
scenario_gate_wiring

echo "fixture result: $total_failed failed scenario assertion group(s)"
exit $([ "$total_failed" -eq 0 ] && echo 0 || echo 1)
