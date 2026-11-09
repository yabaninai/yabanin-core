#!/usr/bin/env python3
"""Local dependency audit: reachable Go advisories and lockfile CVEs.

No registry receives a copy of package manifests. Vulnerability databases are
updated separately (`make security-db-update`); a missing/stale database is an
error, never a clean result.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
import argparse
import datetime as dt
from functools import lru_cache
from fnmatch import fnmatchcase

ROOT = Path(__file__).resolve().parent.parent.parent
TRIVY = os.environ.get("TRIVY", str(Path.home() / "go" / "bin" / "trivy"))
GOVULNCHECK = os.environ.get("GOVULNCHECK", str(Path.home() / "go" / "bin" / "govulncheck"))
CACHE = Path(os.environ.get("YABANIN_SECURITY_CACHE",
                            Path.home() / ".cache" / "yabanin-security"))
GO_DB = CACHE / "govuln"
ROOT_GO_VERSION = next((line.split()[1] for line in (ROOT / "go.mod").read_text().splitlines()
                        if line.startswith("go ")), "")


def database_fresh(metadata_path: Path) -> bool:
    try:
        metadata = json.loads(metadata_path.read_text())
        fetched = datetime.fromisoformat(metadata["fetched_at"])
        return (fetched.tzinfo is not None
                and timedelta(0) <= datetime.now(timezone.utc) - fetched.astimezone(timezone.utc)
                <= timedelta(hours=24))
    except (OSError, ValueError, KeyError, TypeError):
        return False


@lru_cache(maxsize=1)
def indexed_paths() -> list[str]:
    """Read the tracked path list once; index enumeration is deterministic."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT,
            capture_output=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"git could not enumerate tracked paths: {exc}") from exc
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def tracked_paths(pattern: str) -> list[str]:
    """Match basenames and explicit path globs across root and nested modules."""
    if "/" in pattern:
        return [path for path in indexed_paths() if fnmatchcase(path, pattern)]
    return [path for path in indexed_paths() if fnmatchcase(Path(path).name, pattern)]


def go_modules() -> list[Path]:
    return sorted({(ROOT / path).parent for path in tracked_paths("go.mod")})


def parse_json_stream(payload: str) -> list[object]:
    """Decode govulncheck's stream of JSON values, including pretty JSON."""
    decoder = json.JSONDecoder()
    values = []
    offset = 0
    while offset < len(payload):
        while offset < len(payload) and payload[offset].isspace():
            offset += 1
        if offset == len(payload):
            break
        try:
            value, offset = decoder.raw_decode(payload, offset)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid govulncheck JSON at byte {exc.pos}") from exc
        values.append(value)
    return values


def go_vuln(module: Path) -> tuple[str, str]:
    """Run symbol-reachability scan; malformed/incomplete output is an error."""
    try:
        proc = subprocess.run(
            [GOVULNCHECK, "-db", GO_DB.resolve().as_uri(), "-json", "./..."], cwd=module,
            capture_output=True, text=True, timeout=600,
            env={**os.environ, "GOTOOLCHAIN": "go" + ROOT_GO_VERSION},
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return "error", f"govulncheck unavailable or timed out: {exc}"
    try:
        events = parse_json_stream(proc.stdout)
    except ValueError as exc:
        return "error", str(exc)
    if not events or not all(isinstance(event, dict) for event in events):
        return "error", "govulncheck returned an empty or invalid event stream"
    if not any("config" in event for event in events):
        return "error", "govulncheck stream has no config event (incomplete scan)"
    findings = []
    for event in events:
        if "finding" not in event:
            continue
        finding = event["finding"]
        if (not isinstance(finding, dict) or not isinstance(finding.get("osv"), str)
                or not isinstance(finding.get("trace"), list)):
            return "error", "govulncheck returned a malformed finding event"
        findings.append(finding)
    # govulncheck also emits one module-only trace for a vulnerable module
    # present in the build list. It is not evidence that vulnerable code is
    # called. A function frame in the trace is the reachability signal.
    reachable = [finding for finding in findings
                 if any(isinstance(frame, dict) and isinstance(frame.get("function"), str)
                        and frame["function"] for frame in finding["trace"])]
    if proc.returncode:
        # Preserve the security finding while also classifying a nonzero
        # scanner exit as an execution failure at the caller.
        return "error", f"govulncheck exit {proc.returncode}; findings={len(findings)}"
    return ("fail" if reachable else "ok"), (
        f"reachable_findings={len(reachable)}; module_only_findings={len(findings) - len(reachable)}")


def trivy_audit() -> tuple[str, str]:
    """Scan tracked dependency manifests with the pre-fetched local DB."""
    manifests = [p for p in tracked_paths("package-lock.json")]
    manifests += [p for p in tracked_paths("pnpm-lock.yaml")]
    manifests += [p for p in tracked_paths("yarn.lock")]
    manifests += [p for p in tracked_paths("Pipfile.lock")]
    if not manifests:
        return "error", "no tracked dependency lockfiles found"
    try:
        import yaml
    except ImportError as exc:
        return "error", f"PyYAML is required to load security exceptions: {exc}"
    try:
        document = yaml.safe_load((ROOT / "scripts/quality/security-exceptions.yaml").read_text())
        if not isinstance(document, dict) or document.get("schema") != 1:
            return "error", "security-exceptions.yaml has an unsupported schema"
        exceptions = document.get("exceptions")
        if not isinstance(exceptions, list):
            return "error", "security-exceptions.yaml has no exceptions list"
    except (OSError, yaml.YAMLError) as exc:
        return "error", f"could not load dependency exceptions: {exc}"
    today = dt.date.today()
    dependency_exceptions = [item for item in exceptions
                             if isinstance(item, dict) and item.get("scanner") == "dep_audit"]
    required_fields = ("vulnerability_id", "package", "version", "scope",
                       "reason", "owner", "expires")
    for item in dependency_exceptions:
        if not all(isinstance(item.get(field), str) and item[field].strip()
                   for field in required_fields):
            return "error", f"dependency exception {item.get('id', 'unknown')} is not exact-scoped"
    expired = [item.get("id", "unknown") for item in dependency_exceptions
               if item.get("expires", "") < today.isoformat()]
    try:
        lock = json.loads((ROOT / "scripts/security/scanner-lock.json").read_text())
        expected = lock["scanners"]["trivy"]["version"]
        version = subprocess.run([TRIVY, "--version"], capture_output=True, text=True,
                                 timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
        return "error", f"Trivy version check failed: {exc}"
    if f"Version: {expected}" not in version:
        return "error", "Trivy version does not match scripts/security/scanner-lock.json"
    # Trivy recursively finds nested lockfiles from one target. Passing the
    # root plus each package directory double-counts nested findings.
    targets = ["."]
    # Trivy accepts one filesystem target per invocation. Scan every directory
    # containing a tracked lockfile rather than passing several paths (which
    # Trivy interprets as an invalid multi-target request).
    findings = []
    for target in targets:
        try:
            proc = subprocess.run(
                [TRIVY, "fs", "--scanners", "vuln", "--severity", "HIGH,CRITICAL",
                 "--exit-code", "1", "--skip-db-update", "--skip-check-update",
                 "--skip-version-check", "--offline-scan", "--format", "json", target],
                cwd=ROOT, capture_output=True, text=True, timeout=900,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            return "error", f"Trivy unavailable or timed out for {target}: {exc}"
        try:
            document = json.loads(proc.stdout)
        except (ValueError, TypeError):
            return "error", f"Trivy returned invalid JSON for {target}; scanner/database failure"
        results = document.get("Results") if isinstance(document, dict) else None
        if not isinstance(results, list):
            return "error", f"Trivy JSON has no Results array for {target}"
        for result in results:
            if not isinstance(result, dict):
                return "error", f"Trivy JSON contains an invalid result for {target}"
            items = result.get("Vulnerabilities") or []
            if not isinstance(items, list):
                return "error", f"Trivy JSON contains an invalid Vulnerabilities field for {target}"
            for finding in items:
                if not isinstance(finding, dict) or finding.get("Severity") not in ("HIGH", "CRITICAL"):
                    continue
                finding = {**finding, "target": result.get("Target", target)}
                findings.append(finding)
        if proc.returncode not in (0, 1):
            return "error", f"Trivy exit {proc.returncode} for {target}"
        if proc.returncode == 1 and not any(
                item.get("Severity") in ("HIGH", "CRITICAL")
                for result in results for item in (result.get("Vulnerabilities") or [])):
            return "error", f"Trivy returned failure without a recognized finding for {target}"
    unresolved = []
    for finding in findings:
        excepted = any(
            item.get("vulnerability_id") == finding.get("VulnerabilityID")
            and item.get("package") == finding.get("PkgName")
            and item.get("version") == finding.get("InstalledVersion")
            and item.get("scope") == finding.get("target")
            and item.get("expires", "") >= today.isoformat()
            for item in dependency_exceptions
        )
        if not excepted:
            unresolved.append(finding)
    details = [f"high_critical_findings={len(unresolved)}; lockfile_directories={len(targets)}"]
    details.extend(f"{item.get('VulnerabilityID')} {item.get('PkgName')}@{item.get('InstalledVersion')} "
                   f"{item.get('Severity')} target={item.get('target')} "
                   f"fixed={item.get('FixedVersion') or 'none-listed'}"
                   for item in unresolved)
    details.append(f"exact_exceptions_applied={len(findings) - len(unresolved)}")
    if expired:
        details.append("expired_dependency_exceptions=" + ",".join(sorted(expired)))
    return ("fail" if unresolved or expired else "ok"), "; ".join(details)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-root", action="store_true",
                        help="root Go module was already checked by make analyze-security")
    args = parser.parse_args(argv)
    if not database_fresh(CACHE / "govuln-metadata.json"):
        print("dependency audit: ERROR: local Go vulnerability DB is missing or older than 24 hours; "
              "run make security-db-update", file=sys.stderr)
        return 2
    if not database_fresh(CACHE / "trivy-db-metadata.json"):
        print("dependency audit: ERROR: local Trivy DB is missing or older than 24 hours; "
              "run make security-db-update", file=sys.stderr)
        return 2
    results = []
    modules = go_modules()
    if args.skip_root:
        modules = [module for module in modules if module.resolve() != ROOT.resolve()]
    if not modules:
        print("dependency audit: ERROR: no tracked Go modules found", file=sys.stderr)
        return 2
    for module in modules:
        status, detail = go_vuln(module)
        relative = module.relative_to(ROOT).as_posix() or "."
        results.append((status, f"govulncheck {relative}: {detail}"))
    status, detail = trivy_audit()
    results.append((status, f"trivy: {detail}"))
    print("local dependency audit:")
    for status, detail in results:
        print(f"  [{status:5s}] {detail}")
    if any(status == "error" for status, _ in results):
        print("dependency audit: scanner error (not a pass)", file=sys.stderr)
        return 2
    if any(status == "fail" for status, _ in results):
        return 1
    print("dependency audit: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
