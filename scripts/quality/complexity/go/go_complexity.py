#!/usr/bin/env python3
"""Go complexity differential analyzer (QG-C01 measurement core).

Compares Go function bodies between a base commit and the current working
tree (head = committed + uncommitted + untracked state), classifies every
added/changed body against the complexity thresholds of
standards/maintainability.md, recognizes moved/renamed functions with
unchanged content, and summarizes untouched legacy debt separately.

Threshold decisions (QG-C01-02): a content-identical copy of a function
whose base original still exists at head is a DUPLICATE, measured as
added/changed content under the full thresholds; only a move whose original
is gone carries pre-existing debt (listed in the untouched-debt ledger,
never blocking). The 11-15 band passes only with a source-bound
stronger-model review receipt (see scripts/quality/complexity/go/README.md
for the schema); receipts never unblock >15 bodies for new/changed code.

Python 3.9+ standard library plus the Go toolchain (used only to parse and
measure; the product is never built). This script measures and reports; gate
wiring (Makefile/quality.py integration) is child QG-C01-03.

Usage:
  go_complexity.py --base <git-ref> [--report PATH|-] [--receipt PATH] [--root DIR]

Exit codes: 0 = all changed bodies within policy; 1 = gate failure (a changed
body >15, an 11-15 body without an accepted receipt, or a rejected receipt);
2 = operational error (missing go toolchain, git failure, head file that
cannot be parsed).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

VERSION = "1.1.0"
HELPER = Path(__file__).resolve().parent / "go_funcscan.go"
HELPER_VERSION_FIELD = "helper_source_sha256"

# Classification thresholds (maintainability.md 2026-11-10 owner decision):
# <=10 ok; 11-15 needs independent stronger-model review (receipt); >15 blocks.
CYCLOMATIC_OK_MAX = 10
CYCLOMATIC_REVIEW_MAX = 15
DEBT_LIST_LIMIT = 50

# Review receipts (schema in README.md) bind the stronger-model verdict to
# the exact analyzed diff. Verdict "approve-exception" approves 11-15 bodies
# and feeds the recorded-exception ledger for >15 bodies (which still block);
# "require-refactor" is a structurally valid verdict that approves nothing.
RECEIPT_SCHEMA = "go-complexity-review-receipt/1"
RECEIPT_APPROVING_VERDICT = "approve-exception"
RECEIPT_VERDICTS = (RECEIPT_APPROVING_VERDICT, "require-refactor")
# Model strength ordering, strongest first. The reviewer named on a receipt
# must rank strictly above the implementer. The default lists the known
# coordination model only; deployments widen it via GO_COMPLEXITY_MODEL_ORDER
# (comma-separated, strongest first) — a model absent from the ordering can
# neither implement nor review, because relative capability is unproven.
DEFAULT_MODEL_ORDER = ("yabanin/glm-5.3",)
HEX_DIGITS = frozenset("0123456789abcdef")

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
    "single-line file set): formatting- and comment-independent (including "
    "blank lines: every position maps to line 1); a head function whose "
    "hash matches any base function (repo-wide at base) is moved/renamed, "
    "not re-measured as new content; a receiver or body change is a content "
    "change. Duplicate rule (QG-C01-02): if the matched base original still "
    "exists at head with identical content, the head copy is a duplicate and "
    "is measured as added/changed content under the full thresholds. Move "
    "policy: a move whose original is gone carries pre-existing debt without "
    "re-measurement but is listed in the untouched-debt ledger (kind "
    "'moved', never blocking); at most one head function may claim a given "
    "base original as its move origin"
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
    # Older helper builds may marshal an empty batch as null; a zero-file
    # diff must yield a clean empty report, never a crash.
    scan["files"] = scan.get("files") or []
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


def match_kind(head, by_name, by_hash, consumed, head_index):
    """Resolve how a head function relates to the base tree.

    Returns (kind, base_record, note): unchanged functions return
    "untouched" and carry no report entry; a moved function consumes one
    base candidate so two head copies cannot both claim the same origin.
    A hash match whose base original still exists at head with identical
    content is a free duplicate: it is measured as added/changed content
    under the full thresholds instead of escaping as a move, with the
    origin named in the note.
    """
    same_place = by_name.get((head["file"], head["name"]))
    if same_place is not None and same_place["body_sha256"] == head["body_sha256"]:
        return "untouched", same_place, None
    for candidate in by_hash.get(head["body_sha256"], ()):
        original_at_head = head_index.get((candidate["file"], candidate["name"]))
        if original_at_head is not None \
                and original_at_head["body_sha256"] == head["body_sha256"]:
            return (("changed" if same_place is not None else "added"),
                    same_place, {"duplicate_of":
                                 f'{candidate["file"]}:{candidate["name"]}'})
        if id(candidate) not in consumed:
            consumed.add(id(candidate))
            return "moved", candidate, None
    return ("changed" if same_place is not None else "added"), same_place, None


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


def receipt_binding(record) -> str:
    return f'{record["file"]}:{record["name"]}'


def receipt_decision(receipt, record):
    """Decide whether the validated receipt approves this 11-15 body.

    Returns (approved, reason). A receipt that exists but does not approve
    carries a precise reason surfaced in the summary and the report.
    """
    if receipt is None:
        return False, None
    if receipt.get("verdict") != RECEIPT_APPROVING_VERDICT:
        return False, f"receipt verdict is {receipt.get('verdict')!r}, not an approval"
    if receipt_binding(record) not in receipt.get("functions", ()):
        return False, f"receipt does not bind {receipt_binding(record)}"
    return True, None


def analyze(head_scan, by_name, by_hash, receipt):
    """Diff head functions against the base index.

    Returns (entries, untouched). Untouched functions stay out of the report
    body (debt summary only); deleted base functions are simply absent.
    """
    entries, untouched = [], []
    consumed = set()
    head_index = {}
    for entry in head_scan["files"]:
        if not entry.get("parse_ok"):
            raise AnalyzerError(
                f"changed file cannot be parsed, refusing to skip measurement: "
                f"{entry['path']}: {entry.get('error', 'parse error')}")
        for head in entry["functions"]:
            record = dict(head, file=entry["path"])
            head_index[(record["file"], record["name"])] = record
    for entry in head_scan["files"]:
        for head in entry["functions"]:
            record = dict(head, file=entry["path"])
            kind, base, note = match_kind(record, by_name, by_hash, consumed,
                                          head_index)
            if kind == "untouched":
                untouched.append(record)
                continue
            classification = score_class(head["cyclomatic"])
            item = build_entry(record, kind, base, classification)
            if classification == "needs_review":
                approved, reason = receipt_decision(receipt, record)
                item["receipt"] = approved
                if reason:
                    item["receipt_reason"] = reason
            if receipt is not None and classification == "blocks" \
                    and receipt.get("verdict") == RECEIPT_APPROVING_VERDICT \
                    and receipt_binding(record) in receipt.get("functions", ()):
                # Receipts never unblock >15; this records the reviewed
                # exception in the ledger only (maintainability.md).
                item["exception_receipt_recorded"] = True
            if kind == "moved":
                item["from_file"] = base["file"]
                item["from_function"] = base["name"]
                item["classification"] = "ok_moved_unchanged"
            if note is not None:
                item.update(note)
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


def model_strength_order() -> list:
    raw = os.environ.get("GO_COMPLEXITY_MODEL_ORDER", "")
    if not raw:
        return list(DEFAULT_MODEL_ORDER)
    return [tier.strip() for tier in raw.split(",") if tier.strip()]


def require_string(document, key):
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        return None, f"{key} missing or empty"
    return value, None


def require_commit(document, key, expected, role):
    value, error = require_string(document, key)
    if error:
        return None, error
    if len(value) != 40 or any(char not in HEX_DIGITS for char in value.lower()):
        return None, f"{key} {value!r} is not a full 40-hex commit SHA"
    if value.lower() != expected:
        return None, (f"{key} mismatch: receipt binds {role} {value}, "
                      f"analyzed {expected}")
    return value, None


def require_review_date(document, key):
    value, error = require_string(document, key)
    if error:
        return None, error
    try:
        return datetime.date.fromisoformat(value), None
    except ValueError:
        return None, f"{key} {value!r} is not an ISO YYYY-MM-DD date"


def receipt_field_errors(document, head_sha, base_sha, head_date, order):
    """All policy checks for one receipt document; first error wins."""
    if document.get("schema") != RECEIPT_SCHEMA:
        return (f"unsupported schema {document.get('schema')!r}; "
                f"expected {RECEIPT_SCHEMA!r}")
    for key in ("implementer_model", "reviewer_model"):
        _, error = require_string(document, key)
        if error:
            return error
    if document.get("verdict") not in RECEIPT_VERDICTS:
        return f"unknown verdict {document.get('verdict')!r}; expected one of {RECEIPT_VERDICTS}"
    _, error = require_commit(document, "source_commit", head_sha,
                              "the analyzed head commit")
    if error:
        return error
    _, error = require_commit(document, "base_commit", base_sha,
                              "the analyzed base commit")
    if error:
        return error
    review_date, error = require_review_date(document, "review_date")
    if error:
        return error
    if review_date < head_date:
        return (f"stale receipt: review_date {review_date.isoformat()} "
                f"precedes source commit date {head_date.isoformat()}")
    return model_order_error(document, order)


def model_order_error(document, order):
    implementer = document["implementer_model"]
    reviewer = document["reviewer_model"]
    if reviewer == implementer:
        return f"reviewer_model equals implementer_model ({reviewer}); self-review is not accepted"
    if reviewer not in order:
        return f"reviewer_model {reviewer!r} is not in the model strength ordering"
    if implementer not in order:
        return f"implementer_model {implementer!r} is not in the model strength ordering"
    if order.index(reviewer) >= order.index(implementer):
        return (f"reviewer_model {reviewer!r} is not stronger than "
                f"implementer_model {implementer!r}")
    return None


def receipt_functions_error(document):
    functions = document.get("functions")
    if not isinstance(functions, list) or not functions:
        return "functions must be a non-empty list of 'file.go:Function' bindings"
    for item in functions:
        if not isinstance(item, str) or item.count(":") != 1:
            return f"functions entry {item!r} is not a 'file.go:Function' binding"
        path, name = item.split(":")
        if not path.endswith(".go") or not name:
            return f"functions entry {item!r} is not a 'file.go:Function' binding"
    return None


def validate_receipt(path, head_sha, base_sha, head_date, order):
    """Load and fully validate a review receipt (schema in README.md).

    Returns (document, error): (None, None) when no receipt was requested;
    (None, reason) for any rejected receipt — the reason is precise enough
    to name the violated binding. Policy: the reviewer must be a strictly
    stronger model than the implementer, the verdict must be a known one,
    and source/base commits and review date must bind the analyzed diff.
    """
    if not path:
        return None, None
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return None, f"cannot read receipt {path}: {error}"
    if not isinstance(document, dict):
        return None, "receipt is not a JSON object"
    error = receipt_field_errors(document, head_sha, base_sha, head_date, order)
    if error:
        return None, error
    error = receipt_functions_error(document)
    if error:
        return None, error
    return document, None


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
        duplicate = f" duplicate_of={item['duplicate_of']}" if "duplicate_of" in item else ""
        lines.append(
            f"  {item['kind']:>6} {item['function']}: cyclomatic "
            f"{item['old_cyclomatic']} -> {item['new_cyclomatic']} "
            f"[{item['classification']}] ({item['file']}){duplicate}")
    lines.append(f"untouched legacy debt: {debt['cyclomatic_gt15']} >15, "
                 f"{debt['cyclomatic_11_to_15']} in 11-15 "
                 f"({debt['untouched_functions']} unchanged functions scanned)")
    for item in blocked:
        ledger = ("; receipt recorded for the exception ledger only"
                  if item.get("exception_receipt_recorded") else "")
        lines.append(f"BLOCKED {item['function']} ({item['file']}): cyclomatic "
                     f"{item['new_cyclomatic']} > {CYCLOMATIC_REVIEW_MAX}"
                     f"{ledger}")
    for item in unreceipted:
        detail = f" ({item['receipt_reason']})" if item.get("receipt_reason") else ""
        lines.append(f"NEEDS REVIEW RECEIPT {item['function']} ({item['file']}): "
                     f"cyclomatic {item['new_cyclomatic']} in "
                     f"{CYCLOMATIC_OK_MAX + 1}-{CYCLOMATIC_REVIEW_MAX}{detail}")
    return "\n".join(lines)


def receipt_section(path, receipt, error):
    """Deterministic echo of the receipt state for the report."""
    if not path:
        return None
    if error:
        return {"path": path, "status": "rejected", "reason": error}
    status = ("accepted" if receipt.get("verdict") == RECEIPT_APPROVING_VERDICT
              else "valid_not_approving")
    return {"path": path, "status": status, "schema": receipt["schema"],
            "source_commit": receipt["source_commit"],
            "base_commit": receipt["base_commit"],
            "implementer_model": receipt["implementer_model"],
            "reviewer_model": receipt["reviewer_model"],
            "verdict": receipt["verdict"], "review_date": receipt["review_date"],
            "functions": sorted(receipt["functions"])}


def build_report(analyzer, run, entries, debt, base_failures, receipt):
    return {
        "schema_version": 2,
        "analyzer": analyzer,
        "run": {
            "requested_base": run["requested_base"],
            "base_sha": run["base_sha"],
            "head_sha": run["head_sha"],
            "head_commit_date": run["head_commit_date"],
            "dirty_working_tree": run["dirty"],
            "measured_head_files": run["head_files"],
            "measured_source_sha256": run["source_digest"],
            "base_parse_failures": base_failures,
            "deterministic": "no wall-clock fields; identical inputs and "
                             "toolchain produce identical bytes",
        },
        "receipt": receipt,
        "changed_functions": entries,
        "untouched_debt": debt,
    }


def analyzer_meta(scan, order) -> dict:
    return {
        "name": "go-complexity-differential",
        "version": VERSION,
        "go_version": scan["go_version"],
        HELPER_VERSION_FIELD: hashlib.sha256(HELPER.read_bytes()).hexdigest(),
        "classification_metric": "cyclomatic (thresholds 10/15)",
        "cyclomatic_rules": CYCLOMATIC_RULES,
        "cognitive_rules": COGNITIVE_RULES,
        "moved_detection": MOVED_MATCHING,
        "model_strength_order": order,
        "receipt_validation": "full (QG-C01-02): schema "
                              f"{RECEIPT_SCHEMA}; binds source_commit and "
                              "base_commit (full SHAs) to the analyzed diff, "
                              "functions as file:Name bindings, an "
                              "implementer_model with a strictly stronger "
                              "reviewer_model per the configured strength "
                              "ordering, a known verdict and a review_date "
                              "not predating the source commit; invalid "
                              "receipts are rejected with exit 1 and never "
                              "unblock >15 bodies",
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default="HEAD",
                        help="git ref to diff against (recorded in the report)")
    parser.add_argument("--report", default="-",
                        help="JSON report path, or '-' for stdout")
    parser.add_argument("--receipt",
                        help="stronger-model review receipt JSON (schema: "
                             "scripts/quality/complexity/go/README.md); "
                             "rejected receipts fail the run with exit 1")
    parser.add_argument("--root", help="repository root (default: discover)")
    return parser.parse_args(argv)


def commit_date(root: Path, commit: str) -> datetime.date:
    raw = run_git(root, "show", "-s", "--format=%cI", commit).decode().strip()
    try:
        return datetime.date.fromisoformat(raw[:10])
    except ValueError as error:
        raise AnalyzerError(
            f"cannot determine commit date of {commit}: {raw!r}") from error


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        root = repo_root(args.root)
        base_sha = resolve_base(root, args.base)
        head_sha = run_git(root, "rev-parse", "HEAD").decode().strip()
        receipt, receipt_error = validate_receipt(
            args.receipt, head_sha, base_sha, commit_date(root, head_sha),
            model_strength_order())
        head_files = changed_go_files(root, base_sha)
        with tempfile.TemporaryDirectory(prefix="go-complexity-base-") as tmp:
            tree = Path(tmp) / "base"
            tree.mkdir()
            extract_base_tree(root, base_sha, tree)
            base_paths = [tree / relative for relative in base_go_files(tree)]
            base_scan = scan_functions(base_paths, tree, tree)
        head_scan = scan_functions([root / path for path in head_files], root, root)
        by_name, by_hash, base_failures = index_base(base_scan)
        entries, untouched = analyze(head_scan, by_name, by_hash, receipt)
        moved = [item for item in entries if item["kind"] == "moved"]
        debt = debt_summary(untouched, moved)
        analyzer = analyzer_meta(head_scan, model_strength_order())
        run = {
            "requested_base": args.base, "base_sha": base_sha,
            "head_sha": head_sha,
            "head_commit_date": commit_date(root, head_sha).isoformat(),
            "dirty": bool(run_git(root, "status", "--porcelain", "-z")),
            "head_files": head_files,
            "source_digest": source_digest(root, head_files),
        }
        report = build_report(analyzer, run, entries, debt, base_failures,
                              receipt_section(args.receipt, receipt,
                                              receipt_error))
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
    if receipt_error:
        print(f"gate: receipt rejected: {receipt_error}", file=sys.stderr)
        return 1
    if unreceipted:
        print(f"gate: {len(unreceipted)} changed function(s) in "
              f"{CYCLOMATIC_OK_MAX + 1}-{CYCLOMATIC_REVIEW_MAX} lack a review "
              f"receipt (pass --receipt; schema in "
              f"scripts/quality/complexity/go/README.md)",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
