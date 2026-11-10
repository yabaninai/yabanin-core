#!/usr/bin/env bash
# QG-C01-01 fixtures: negative and boundary controls for the Go complexity
# differential analyzer (scripts/quality/complexity/go/go_complexity.py).
#
# Each control asserts exact function names, kinds and hand-counted
# complexity values — never just a non-zero exit. Every blocking control is
# paired with a reverse-control run (refactored body, boundary score,
# modified moved body) whose expected result is the opposite, proving the
# assertion binds to the measured behavior rather than to any failure at
# all. Expected cyclomatic values are hand-counted oracle constants,
# independent of the analyzer's own computation:
#   legacy untouched 25 | simple 8 | heavy base 9 -> head 18 / refactored 8
#   borderline 12 / boundary 10 | movable 2
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ANALYZER="$ROOT/scripts/quality/complexity/go/go_complexity.py"
FIXTURES="$ROOT/scripts/quality/tests/complexity/go_fixtures"
WORK=$(mktemp -d /tmp/go-complexity-fixtures.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

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

build_base() { # repo-dir -> prints base sha
    write_go "$1/sample.go" $BASE_BLOCKS
    git -C "$1" add -A >/dev/null
    git -C "$1" commit -q -m "base"
    git -C "$1" rev-parse HEAD
}

build_head() { # repo-dir sample-blocks... ; extra files via $EXTRA_FILES="name:blocks..."
    local repo=$1
    shift
    write_go "$repo/sample.go" "$@"
    local extra name blocks
    for extra in ${EXTRA_FILES:-}; do
        name=${extra%%:*}
        blocks=${extra#*:}
        write_go "$repo/$name" ${blocks//,/ }
    done
    git -C "$repo" add -A >/dev/null
    git -C "$repo" commit -q -m "head"
}

run_analyzer() { # repo base report [extra...]
    local repo=$1 base=$2 report=$3
    shift 3
    python3 "$ANALYZER" --root "$repo" --base "$base" --report "$report" "$@" \
        >"$WORK/out.txt" 2>&1
    RC=$?
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
    local repo
    repo=$(new_repo receipt)
    local base
    base=$(build_base "$repo")
    build_head "$repo" go_fn_legacy.go.tmpl go_fn_borderline_head.go.tmpl

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

    printf '%s\n' "{\"reviewer_model\": \"placeholder-stronger-model\", \"verdict\": \"approve\", \"functions\": [\"BorderlineFn\"], \"base_sha\": \"$base\"}" >"$WORK/receipt.json"
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
check("accepted-receipt-exit-0", rc == 0, f"rc={rc}")
check("accepted-receipt-flagged",
      entry.get("classification") == "needs_review" and entry.get("receipt") is True,
      str(entry))
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

scenario_clean_pass
scenario_block_over_15
scenario_receipt_band
scenario_determinism
scenario_moved_modified

echo "fixture result: $total_failed failed scenario assertion group(s)"
exit $([ "$total_failed" -eq 0 ] && echo 0 || echo 1)
