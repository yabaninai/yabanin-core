#!/usr/bin/env python3
"""NEXT-16 secret scanner. Two modes:

  diff  (default) — scan the working-tree diff (staged+unstaged+untracked):
  only NEW additions can fail the gate; history is a separate explicit mode.
  history — scan tracked files; output is REDACTED (file + line + rule name,
  never the match bytes).

Deterministic in-house patterns (no external tool to pin for secrets; the
ADR documents this choice). Scanner error != pass: any internal error exits
2. Findings without a live exception exit 1.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import json
import math
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
EXCEPTIONS = ROOT / "scripts/quality/security-exceptions.yaml"

# High-confidence patterns. Each carries a short id, the regex and a
# human name. Entropy-gated generic tokens avoid flagging placeholders.
PATTERNS = [
    ("yb-api-key", re.compile(r"\byb_[A-Za-z0-9]{24,}\b"), "Yabanin API key"),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "OpenAI-style key"),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9-]{20,}\b"), "Anthropic key"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "GitHub token"),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    ("private-key-block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key block"),
    ("nebius-token", re.compile(r"\beyJhbGciOi[A-Za-z0-9._-]{100,}\b"), "Long JWT (Nebius-style token)"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "Google API key"),
]
# Deliberately allowlisted paths (fixtures/docs that TEACH the patterns).
ALLOW_SUFFIXES = ("secret_scan.py",)
ALLOW_PATH_PARTS = (
    "/.opencode/skills/",
    "/docs/strategy/qa/",
)

BASE64 = re.compile(r"^[A-Za-z0-9+/_-]+$")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def load_exceptions():
    """Minimal YAML subset: entries of
        - id: <rule-id>
          path: <substring>
          reason: ...
          owner: ...
          expires: YYYY-MM-DD
    """
    import datetime
    out = []
    if not EXCEPTIONS.exists():
        return [], []
    cur = None
    for line in EXCEPTIONS.read_text().splitlines():
        s = line.strip()
        if s.startswith("- id:"):
            if cur:
                out.append(cur)
            cur = {"id": s.split(":", 1)[1].strip()}
        elif cur is not None and ":" in s and not s.startswith("#"):
            k, v = s.split(":", 1)
            cur[k.strip()] = v.strip()
    if cur:
        out.append(cur)
    # The YAML file is shared by independent scanners. Exceptions that name
    # another scanner must not be interpreted as secret rules.
    out = [entry for entry in out
           if entry.get("scanner", "") in ("", "secret_scan", "gitleaks")]
    today = datetime.date.today().isoformat()
    live = [e for e in out if e.get("expires", "") >= today]
    expired = [e for e in out if e.get("expires", "") < today]
    return live, expired


def reviewed_fixture(path: str, content: bytes) -> bool:
    if not path.startswith("datasets/eval/"):
        return False
    policy = json.loads((ROOT / "scripts/quality/synthetic-fixtures.json").read_text())
    if policy.get("schema") != 1 or not isinstance(policy.get("sha256"), dict):
        raise ValueError("invalid synthetic fixture policy")
    expected = policy["sha256"].get(path)
    return expected is not None and hashlib.sha256(content).hexdigest() == expected


def scan_text(path: str, text: str, only_added_lines=False):
    findings = []
    if any(part in "/" + path for part in ALLOW_PATH_PARTS):
        return findings
    if any(path.endswith(suf) for suf in ALLOW_SUFFIXES):
        return findings
    for lineno, line in enumerate(text.splitlines(), 1):
        if only_added_lines and not line.startswith("+"):
            continue
        for rid, rx, name in PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            token = m.group(0)
            # Entropy gate for the generic long-JWT rule: low-entropy
            # placeholders (aaaa...) are not secrets.
            if rid == "nebius-token" and shannon(token) < 3.5:
                continue
            findings.append({"rule": rid, "name": name, "path": path,
                             "line": lineno if not only_added_lines else lineno})
    return findings


def diff_mode(base=None):
    """Scan additions in the working tree (staged+unstaged vs HEAD) plus
    untracked files."""
    findings = []
    revision = "HEAD"
    if base:
        revision = subprocess.check_output(
            ["git", "rev-parse", "--verify", "--end-of-options", base + "^{commit}"],
            cwd=ROOT, text=True).strip()
    reviewed = set()
    try:
        diff = subprocess.run(
            ["git", "diff", revision, "--no-color", "-U0"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as exc:
        print(f"scanner error: git diff failed: {exc}", file=sys.stderr)
        sys.exit(2)
    current_file = None
    lineno = 0
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            path = ROOT / current_file
            if path.is_file() and not path.is_symlink() and reviewed_fixture(current_file, path.read_bytes()):
                reviewed.add(current_file)
        elif line.startswith("@@") and current_file:
            m = re.search(r"\+(\d+)", line)
            lineno = int(m.group(1)) if m else 0
        elif line.startswith("+") and not line.startswith("+++") and current_file:
            if current_file in reviewed:
                lineno += 1
                continue
            for rid, rx, name in PATTERNS:
                m = rx.search(line[1:])
                if m:
                    token = m.group(0)
                    if rid == "nebius-token" and shannon(token) < 3.5:
                        continue
                    findings.append({"rule": rid, "name": name,
                                     "path": current_file, "line": lineno})
            lineno += 1
    # Untracked files: whole file is an addition.
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
    for path in untracked:
        if any(part in "/" + path for part in ALLOW_PATH_PARTS):
            continue
        try:
            file = ROOT / path
            text = os.readlink(file) if file.is_symlink() else file.read_text(errors="replace")
        except OSError:
            continue
        if file.is_symlink() or not reviewed_fixture(path, file.read_bytes()):
            findings.extend(scan_text(path, text))
    return findings


def history_mode():
    """Scan every committed patch, including secrets later deleted/renamed."""
    commits = subprocess.run(
        ["git", "rev-list", "--all", "--reverse"], cwd=ROOT,
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    return scan_commits(commits)


def scan_commits(commits):
    findings = []
    for commit in commits:
        diff = subprocess.run(
            ["git", "show", "--root", "--format=", "--no-ext-diff", "--no-renames", "-U0", commit],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        current_file = None
        lineno = 0
        reviewed = set()
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                if current_file.startswith("datasets/eval/"):
                    content = subprocess.check_output(["git", "show", f"{commit}:{current_file}"], cwd=ROOT)
                    if reviewed_fixture(current_file, content):
                        reviewed.add(current_file)
            elif line.startswith("@@") and current_file:
                m = re.search(r"\+(\d+)", line)
                lineno = int(m.group(1)) if m else 0
            elif line.startswith("+") and not line.startswith("+++") and current_file:
                added = [] if current_file in reviewed else scan_text(current_file, line[1:])
                for finding in added:
                    finding["line"] = lineno
                findings.extend(added)
                lineno += 1
    return findings


def redacted(findings):
    """Never print the matched bytes."""
    return [f"  {f['rule']}: {f['path']}:{f['line']} ({f['name']})" for f in findings]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", nargs="?", choices=["diff", "history", "range"], default="diff")
    ap.add_argument("--base", help="exclusive starting commit for range mode")
    ap.add_argument("--head", help="inclusive ending commit for range mode (default HEAD)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        if args.mode == "range":
            if not args.base:
                raise ValueError("range mode requires --base")
            head = args.head or "HEAD"
            commits = subprocess.run(
                ["git", "rev-list", "--reverse", f"{args.base}..{head}"],
                cwd=ROOT, capture_output=True, text=True, check=True,
            ).stdout.splitlines()
            findings = scan_commits(commits)
        else:
            findings = diff_mode(args.base or os.environ.get("QUALITY_BASE")) if args.mode == "diff" else history_mode()
        live, expired = load_exceptions()
    except Exception as exc:  # noqa: BLE001 — scanner error must not pass
        print(f"scanner error: {exc}", file=sys.stderr)
        sys.exit(2)
    for e in expired:
        print(f"EXPIRED EXCEPTION: {e.get('id')} {e.get('path')} (expired {e.get('expires')})", file=sys.stderr)
    # Exceptions mask matching rule+path-substring findings.
    def excepted(f):
        return any(e.get("id") == f["rule"] and e.get("path", "") in f["path"] for e in live)
    real = [f for f in findings if not excepted(f)]
    if args.json:
        print(json.dumps({"mode": args.mode, "findings": real,
                          "exceptions_live": len(live), "exceptions_expired": len(expired)}, indent=2))
    else:
        print(f"secret scan ({args.mode}): {len(real)} finding(s), "
              f"{len(findings) - len(real)} excepted; output redacted")
        for line in redacted(real):
            print(line)
    if expired:
        sys.exit(1)
    sys.exit(1 if real else 0)


if __name__ == "__main__":
    main()
