#!/usr/bin/env python3
"""Run pinned Gitleaks locally and emit a value-free summary."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GITLEAKS = os.environ.get("GITLEAKS", str(Path.home() / "go" / "bin" / "gitleaks"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("history", "range"))
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args()
    if args.mode == "range" and not args.base:
        parser.error("range mode requires --base")
    try:
        lock = json.loads((ROOT / "scripts/security/scanner-lock.json").read_text())
        expected = lock["scanners"]["gitleaks"]["version"]
        version = subprocess.run([GITLEAKS, "version"], capture_output=True,
                                 text=True, timeout=30, check=True)
        actual = (version.stdout or version.stderr).strip()
        if actual.splitlines()[0] != expected:
            raise RuntimeError("Gitleaks version does not match scripts/security/scanner-lock.json")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print(f"secret scanner error: pinned Gitleaks unavailable: {exc}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="yabanin-gitleaks-") as temp_dir:
        report = Path(temp_dir) / "findings.json"
        command = [GITLEAKS, "git"]
        if args.mode == "range":
            command += [f"--log-opts={args.base}..{args.head}"]
        command += ["--redact=100", "--no-banner", "--report-format=json",
                    f"--report-path={report}", "--exit-code=1", str(ROOT)]
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True,
                                    text=True, timeout=1800)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"secret scanner error: {exc}", file=sys.stderr)
            return 2
        if result.returncode not in (0, 1):
            print(f"secret scanner error: gitleaks exit {result.returncode}; "
                  "details redacted", file=sys.stderr)
            return 2
        if not report.is_file():
            print("secret scanner error: gitleaks did not write its report", file=sys.stderr)
            return 2
        try:
            findings = json.loads(report.read_text())
        except (OSError, ValueError):
            print("secret scanner error: gitleaks report is unreadable", file=sys.stderr)
            return 2
        if not isinstance(findings, list):
            print("secret scanner error: gitleaks report has an invalid schema", file=sys.stderr)
            return 2
        if (result.returncode == 0) != (len(findings) == 0):
            print("secret scanner error: report and exit code disagree", file=sys.stderr)
            return 2
        print(f"gitleaks {args.mode}: {len(findings)} finding(s); secret values redacted")
        for finding in findings:
            if not isinstance(finding, dict):
                print("secret scanner error: invalid finding record", file=sys.stderr)
                return 2
            print(f"  {finding.get('RuleID', 'unknown-rule')}: "
                  f"{finding.get('File', 'unknown-file')}:{finding.get('StartLine', 0)}")
        return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
