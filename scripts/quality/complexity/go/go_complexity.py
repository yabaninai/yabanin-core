#!/usr/bin/env python3
"""Go complexity differential analyzer (QG-C01 measurement core).

Compares Go function bodies between a base commit and the current working
tree (head = committed + uncommitted + untracked state), classifies every
added/changed body against the complexity thresholds of
standards/maintainability.md, recognizes moved/renamed functions with
unchanged content, and summarizes untouched legacy debt separately.

Python 3.9+ standard library plus the Go toolchain (used only to parse and
measure; the product is never built). This script measures and reports; gate
wiring (Makefile/quality.py integration) and receipt policy enforcement are
separate children (QG-C01-02/-03).

Usage:
  go_complexity.py --base <git-ref> [--report PATH|-] [--receipt PATH] [--root DIR]

Exit codes: 0 = all changed bodies within policy; 1 = gate failure (a changed
body >15, or 11-15 without an accepted receipt); 2 = operational error
(missing go toolchain, git failure, head file that cannot be parsed).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

VERSION = "1.0.0"
HELPER = Path(__file__).resolve().parent / "go_funcscan.go"
HELPER_VERSION_FIELD = "helper_source_sha256"

# Classification thresholds (maintainability.md 2026-11-10 owner decision):
# <=10 ok; 11-15 needs independent stronger-model review (receipt); >15 blocks.
CYCLOMATIC_OK_MAX = 10
CYCLOMATIC_REVIEW_MAX = 15
DEBT_LIST_LIMIT = 50

# Docs shipped verbatim in every report so a number is never detached from
# the rules that produced it.
CYCLOMATIC_RULES = (
    "cyclomatic = 1 + #if + #for( incl range ) + #case/comm clause "
    "(incl default clauses, gocyclo-style) + #&& + #||; else adds 0, a "
    "clause listing several values adds 1, func literals count toward "
    "their enclosing top-level function"
)
COGNITIVE_RULES = (
    "cognitive (Sonar-style, informational in this child): if/for/range/"
    "switch/type-switch/select +1 +nesting; else +1 flat (else-if = if at "
    "same nesting); labeled break/continue and goto +1 flat; each maximal "
    "run of the same &&/|| operator +1 flat; direct self-call +1 flat; "
    "nesting increases inside if/loop/switch/select bodies and func "
    "literals; everything inside a switch/select body counts as nesting+1"
)
MOVED_MATCHING = (
    "function identity = sha256 over canonical AST print of receiver + "
    "signature-without-name + body (go/printer against a synthetic "
    "single-line file set): formatting- and comment-independent; a head "
    "function whose hash matches any base function (repo-wide at base) is "
    "moved/renamed, not re-measured as new content; a receiver change is a "
    "content change"
)


class AnalyzerError(Exception):
    """Operational failure: report and exit 2."""


def run_git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", *args], cwd=str(root), stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise AnalyzerError(f"git {' '.join(args)} failed: {detail}") from error


def repo_root(explicit: str | None) -> Path:
    start = Path(explicit).resolve() if explicit else Path(__file__).resolve().parent
    try:
        output = subprocess.check_output(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise AnalyzerError(f"not a git repository ({start}): {detail}") from error
    return Path(output.decode().strip())


def resolve_base(root: Path, requested: str) -> str:
    commit = run_git(root, "rev-parse", "--verify", "--end-of-options",
                     requested + "^{commit}").decode().strip()
    # merge-base matches quality.py's changed selection semantics so the
    # measured set equals the gate's changed-file set on the same base.
    return run_git(root, "merge-base", commit, "HEAD").decode().strip()


def is_measured_go_path(path: str) -> bool:
    parts = Path(path).parts
    return (path.endswith(".go")
            and "vendor" not in parts and "node_modules" not in parts)


def names(raw: bytes) -> set:
    return {os.fsdecode(value) for value in raw.split(b"\0") if value}


def changed_go_files(root: Path, revision: str) -> list:
    raw = run_git(root, "diff", "--name-only", "--no-renames", "-z", revision, "--")
    raw += run_git(root, "ls-files", "--others", "--exclude-standard", "-z")
    paths = sorted(names(raw))
    return [path for path in paths
            if is_measured_go_path(path) and (root / path).is_file()]


def extract_base_tree(root: Path, revision: str, destination: Path) -> None:
    archive = subprocess.Popen(
        ["git", "archive", revision, "--", "*.go"],
        cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=archive.stdout, mode="r|") as tar:
            try:
                tar.extractall(destination, filter="data")
            except TypeError:  # Python < 3.12 security backport missing
                tar.extractall(destination)
    except tarfile.ReadError:
        if archive.wait() == 0:
            return  # base tree contains no Go files at all
        raise AnalyzerError(f"git archive {revision} produced no readable tar")
    if archive.wait() != 0:
        detail = archive.stderr.read().decode(errors="replace").strip()
        raise AnalyzerError(f"git archive {revision} failed: {detail}")


def base_go_files(tree: Path) -> list:
    files = []
    for path in tree.rglob("*.go"):
        if path.is_file():
            files.append(path.relative_to(tree).as_posix())
    return sorted(files)


def scan_functions(paths, cwd: Path, relative_to: Path) -> dict:
    """Run the AST helper over absolute paths; one process for the batch.

    The helper echoes the given path back; rewriting it to a path relative
    to `relative_to` keeps the report machine-independent and deterministic.
    """
    go = shutil.which("go")
    if go is None:
        raise AnalyzerError(
            "BLOCKER: no go toolchain on PATH; cannot parse or measure "
            "(standards/maintainability.md: a missing metric tool is a "
            "blocker, not a pass)")
    payload = "\n".join(str(path) for path in paths) + "\n"
    completed = subprocess.run(
        [go, "run", str(HELPER)], input=payload, cwd=str(cwd),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if completed.returncode != 0:
        raise AnalyzerError(
            f"go_funcscan failed ({completed.returncode}): {completed.stderr.strip()}")
    try:
        scan = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AnalyzerError(f"go_funcscan emitted invalid JSON: {error}") from error
    for entry in scan["files"]:
        entry["path"] = Path(entry["path"]).relative_to(relative_to).as_posix()
    return scan


def index_base(scan: dict) -> tuple:
    by_name, by_hash, failures = {}, {}, []
    for entry in scan["files"]:
        relative = entry["path"]
        if not entry.get("parse_ok"):
            failures.append(relative)
            continue
        for function in entry.get("functions") or ():
            record = dict(function, file=relative)
            by_name[(relative, function["name"])] = record
            by_hash.setdefault(function["body_sha256"], []).append(record)
    return by_name, by_hash, failures


def match_kind(head, by_name, by_hash, consumed):
    """Resolve how a head function relates to the base tree.

    Returns (kind, base_record): unchanged functions return "untouched" and
    carry no report entry; a moved function consumes one base candidate so
    two head copies cannot both claim the same origin.
    """
    same_place = by_name.get((head["file"], head["name"]))
    if same_place is not None and same_place["body_sha256"] == head["body_sha256"]:
        return "untouched", same_place
    for candidate in by_hash.get(head["body_sha256"], ()):
        if id(candidate) not in consumed:
            consumed.add(id(candidate))
            return "moved", candidate
    return ("changed" if same_place is not None else "added"), same_place


def score_class(cyclomatic) -> str:
    if cyclomatic is None:
        return "ok"
    if cyclomatic <= CYCLOMATIC_OK_MAX:
        return "ok"
    if cyclomatic <= CYCLOMATIC_REVIEW_MAX:
        return "needs_review"
    return "blocks"


def metric(entry, key):
    value = entry.get(key) if entry else None
    return value


def build_entry(head, kind, base, classification):
    return {
        "file": head["file"],
        "function": head["name"],
        "line": head["line"],
        "kind": kind,
        "old_cyclomatic": metric(base, "cyclomatic"),
        "new_cyclomatic": head["cyclomatic"],
        "old_cognitive": metric(base, "cognitive"),
        "new_cognitive": head["cognitive"],
        "cyclomatic_delta": None if head["cyclomatic"] is None or not base
        else head["cyclomatic"] - (base["cyclomatic"] or 0),
        "classification": classification,
    }


def analyze(head_scan, by_name, by_hash, receipt_valid):
    """Diff head functions against the base index.

    Returns (entries, untouched). Untouched functions stay out of the report
    body (debt summary only); deleted base functions are simply absent.
    """
    entries, untouched = [], []
    consumed = set()
    for entry in head_scan["files"]:
        if not entry.get("parse_ok"):
            raise AnalyzerError(
                f"changed file cannot be parsed, refusing to skip measurement: "
                f"{entry['path']}: {entry.get('error', 'parse error')}")
        for head in entry["functions"]:
            record = dict(head, file=entry["path"])
            kind, base = match_kind(record, by_name, by_hash, consumed)
            if kind == "untouched":
                untouched.append(record)
                continue
            classification = score_class(head["cyclomatic"])
            item = build_entry(record, kind, base, classification)
            if classification == "needs_review":
                item["receipt"] = receipt_valid
            if kind == "moved":
                item["from_file"] = base["file"]
                item["from_function"] = base["name"]
                item["classification"] = "ok_moved_unchanged"
            entries.append(item)
    return entries, untouched


def debt_kind(value):
    if value is None or value <= CYCLOMATIC_OK_MAX:
        return None
    return "over" if value > CYCLOMATIC_REVIEW_MAX else "review"


def debt_summary(untouched, moved_entries):
    """Bucket unchanged-content functions with high complexity as legacy
    debt: reported separately and never blocking (they predate the base)."""
    over, review = [], 0
    for record in untouched:
        kind = debt_kind(record["cyclomatic"])
        if kind == "over":
            over.append({"file": record["file"], "function": record["name"],
                         "cyclomatic": record["cyclomatic"], "kind": "untouched"})
        elif kind == "review":
            review += 1
    for item in moved_entries:
        kind = debt_kind(item["new_cyclomatic"])
        if kind == "over":
            over.append({"file": item["file"], "function": item["function"],
                         "cyclomatic": item["new_cyclomatic"], "kind": "moved"})
        elif kind == "review":
            review += 1
    over.sort(key=lambda entry: (entry["file"], entry["function"]))
    return {
        "policy": "untouched functions are legacy debt: reported, never blocking",
        "untouched_functions": len(untouched),
        "cyclomatic_gt15": len(over),
        "cyclomatic_11_to_15": review,
        "functions_gt15": over[:DEBT_LIST_LIMIT],
        "functions_gt15_truncated": len(over) > DEBT_LIST_LIMIT,
    }


def load_receipt(path):
    """Minimal placeholder validation only (QG-C01-02 owns the policy:
    reviewer capability, verdict and source binding are NOT checked here)."""
    if not path:
        return False
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(document, dict):
        return False
    strings_ok = all(isinstance(document.get(key), str) and document[key]
                     for key in ("reviewer_model", "verdict", "base_sha"))
    functions = document.get("functions")
    return strings_ok and isinstance(functions, list) and all(
        isinstance(item, str) and item for item in functions)


def source_digest(root: Path, files) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(os.fsencode(path) + b"\0")
        digest.update((root / path).read_bytes())
    return digest.hexdigest()


def failing(entries):
    blocked = [item for item in entries if item["classification"] == "blocks"]
    unreceipted = [item for item in entries
                   if item["classification"] == "needs_review"
                   and not item.get("receipt")]
    return blocked, unreceipted


def render_summary(entries, debt, blocked, unreceipted) -> str:
    lines = [f"changed function bodies: {len(entries)}"]
    for item in entries:
        lines.append(
            f"  {item['kind']:>6} {item['function']}: cyclomatic "
            f"{item['old_cyclomatic']} -> {item['new_cyclomatic']} "
            f"[{item['classification']}] ({item['file']})")
    lines.append(f"untouched legacy debt: {debt['cyclomatic_gt15']} >15, "
                 f"{debt['cyclomatic_11_to_15']} in 11-15 "
                 f"({debt['untouched_functions']} unchanged functions scanned)")
    for item in blocked:
        lines.append(f"BLOCKED {item['function']} ({item['file']}): cyclomatic "
                     f"{item['new_cyclomatic']} > {CYCLOMATIC_REVIEW_MAX}")
    for item in unreceipted:
        lines.append(f"NEEDS REVIEW RECEIPT {item['function']} ({item['file']}): "
                     f"cyclomatic {item['new_cyclomatic']} in "
                     f"{CYCLOMATIC_OK_MAX + 1}-{CYCLOMATIC_REVIEW_MAX}")
    return "\n".join(lines)


def build_report(analyzer, run, entries, debt, base_failures):
    return {
        "schema_version": 1,
        "analyzer": analyzer,
        "run": {
            "requested_base": run["requested_base"],
            "base_sha": run["base_sha"],
            "head_sha": run["head_sha"],
            "dirty_working_tree": run["dirty"],
            "measured_head_files": run["head_files"],
            "measured_source_sha256": run["source_digest"],
            "base_parse_failures": base_failures,
            "deterministic": "no wall-clock fields; identical inputs and "
                             "toolchain produce identical bytes",
        },
        "changed_functions": entries,
        "untouched_debt": debt,
    }


def analyzer_meta(scan) -> dict:
    return {
        "name": "go-complexity-differential",
        "version": VERSION,
        "go_version": scan["go_version"],
        HELPER_VERSION_FIELD: hashlib.sha256(HELPER.read_bytes()).hexdigest(),
        "classification_metric": "cyclomatic (thresholds 10/15)",
        "cyclomatic_rules": CYCLOMATIC_RULES,
        "cognitive_rules": COGNITIVE_RULES,
        "moved_detection": MOVED_MATCHING,
        "receipt_validation": "minimal placeholder: existing JSON object with "
                              "reviewer_model/verdict/base_sha strings and a "
                              "functions list; policy binding is QG-C01-02",
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default="HEAD",
                        help="git ref to diff against (recorded in the report)")
    parser.add_argument("--report", default="-",
                        help="JSON report path, or '-' for stdout")
    parser.add_argument("--receipt",
                        help="stronger-model review receipt (QG-C01-02 policy; "
                             "here only existence and minimal shape)")
    parser.add_argument("--root", help="repository root (default: discover)")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        root = repo_root(args.root)
        base_sha = resolve_base(root, args.base)
        head_files = changed_go_files(root, base_sha)
        receipt_valid = load_receipt(args.receipt)
        with tempfile.TemporaryDirectory(prefix="go-complexity-base-") as tmp:
            tree = Path(tmp) / "base"
            tree.mkdir()
            extract_base_tree(root, base_sha, tree)
            base_paths = [tree / relative for relative in base_go_files(tree)]
            base_scan = scan_functions(base_paths, tree, tree)
        head_scan = scan_functions([root / path for path in head_files], root, root)
        by_name, by_hash, base_failures = index_base(base_scan)
        entries, untouched = analyze(head_scan, by_name, by_hash, receipt_valid)
        moved = [item for item in entries if item["kind"] == "moved"]
        debt = debt_summary(untouched, moved)
        analyzer = analyzer_meta(head_scan)
        run = {
            "requested_base": args.base, "base_sha": base_sha,
            "head_sha": run_git(root, "rev-parse", "HEAD").decode().strip(),
            "dirty": bool(run_git(root, "status", "--porcelain", "-z")),
            "head_files": head_files,
            "source_digest": source_digest(root, head_files),
        }
        report = build_report(analyzer, run, entries, debt, base_failures)
    except AnalyzerError as error:
        print(f"go_complexity error: {error}", file=sys.stderr)
        return 2

    document = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    summary_stream = sys.stdout if args.report != "-" else sys.stderr
    print(render_summary(entries, debt, *failing(entries)), file=summary_stream)
    if args.report == "-":
        sys.stdout.write(document)
    else:
        Path(args.report).write_text(document, encoding="utf-8")

    blocked, unreceipted = failing(entries)
    if blocked:
        print(f"gate: {len(blocked)} changed function(s) exceed cyclomatic "
              f"{CYCLOMATIC_REVIEW_MAX}; refactor or a recorded bounded "
              f"exception is required", file=sys.stderr)
        return 1
    if unreceipted:
        print(f"gate: {len(unreceipted)} changed function(s) in "
              f"{CYCLOMATIC_OK_MAX + 1}-{CYCLOMATIC_REVIEW_MAX} lack a review "
              f"receipt (pass --receipt; validation policy lands in QG-C01-02)",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
