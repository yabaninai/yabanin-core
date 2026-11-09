#!/usr/bin/env python3
"""Scan a locally available release image with the pinned Trivy binary."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

TRIVY = os.environ.get("TRIVY", str(Path.home() / "go" / "bin" / "trivy"))


def validate_report(document: object, exit_code: int) -> dict:
    """Require evidence that advisory matchers examined actual packages."""
    if not isinstance(document, dict):
        raise ValueError("Trivy report is not an object")
    results = document.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Trivy report has no nonempty Results array")
    metadata = document.get("Metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("invalid image metadata")
    os_info = metadata.get("OS", {})
    if not isinstance(os_info, dict):
        raise ValueError("invalid OS metadata")
    family = os_info.get("Family", "")
    if not isinstance(family, str):
        raise ValueError("invalid OS family")
    eosl = os_info.get("EOSL", False)
    if not isinstance(eosl, bool):
        raise ValueError("invalid OS support status")
    findings = []
    package_count = 0
    versioned_count = 0
    os_matchers = set()
    for item in results:
        if not isinstance(item, dict):
            raise ValueError("invalid Trivy result")
        if item.get("Class") not in ("os-pkgs", "lang-pkgs"):
            raise ValueError("result has no vulnerability matcher class")
        if not isinstance(item.get("Type"), str) or not item["Type"]:
            raise ValueError("result has no vulnerability matcher type")
        if not isinstance(item.get("Target"), str) or not item["Target"]:
            raise ValueError("result has no scanned target")
        packages = item.get("Packages")
        if not isinstance(packages, list) or not packages:
            raise ValueError("matcher has no inventoried packages")
        identities = set()
        for package in packages:
            if not isinstance(package, dict) or not isinstance(package.get("Name"), str) or not package["Name"]:
                raise ValueError("invalid inventoried package")
            version = package.get("Version")
            if isinstance(version, str) and version:
                identities.add((package["Name"], version))
                versioned_count += 1
            elif not (version in (None, "") and item["Class"] == "lang-pkgs"
                      and item["Type"] == "gobinary" and package.get("Relationship") == "root"):
                raise ValueError("invalid inventoried package version")
            # Go main modules built from source can legitimately have no
            # version. They are inventory metadata, not advisory coverage.
        if not identities:
            raise ValueError("matcher has no versioned packages for advisory coverage")
        package_count += len(packages)
        if item["Class"] == "os-pkgs":
            os_matchers.add(item["Type"])
        vulnerabilities = item.get("Vulnerabilities")
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise ValueError("invalid vulnerability list")
        for finding in vulnerabilities:
            if not isinstance(finding, dict) or not all(
                isinstance(finding.get(key), str) and finding[key]
                for key in ("VulnerabilityID", "Severity", "PkgName", "InstalledVersion")
            ):
                raise ValueError("malformed vulnerability finding")
            if finding["Severity"] not in ("HIGH", "CRITICAL"):
                raise ValueError("Trivy severity filter and report disagree")
            if (finding["PkgName"], finding["InstalledVersion"]) not in identities:
                raise ValueError("finding is not bound to an inventoried package")
            findings.append(finding)
    if family not in ("", "none", "unknown"):
        if not isinstance(os_info.get("Name"), str) or not os_info["Name"]:
            raise ValueError("detected OS has no version")
        if family not in os_matchers:
            raise ValueError("detected OS has no matching package vulnerability result")
    elif os_matchers:
        raise ValueError("OS package matcher has no detected distribution")
    if exit_code not in (0, 1) or bool(findings) != (exit_code == 1):
        raise ValueError("Trivy exit code and report disagree")
    return {"high_critical": len(findings), "packages": package_count,
            "versioned_packages": versioned_count,
            "targets": len(results), "os_family": family,
            "os_version": os_info.get("Name", ""), "eosl": eosl}


def main() -> int:
    image = os.environ.get("SECURITY_IMAGE", "").strip()
    expected_id = os.environ.get("SECURITY_IMAGE_ID", "").strip()
    if not image:
        print("image audit error: SECURITY_IMAGE is required", file=sys.stderr)
        return 2
    try:
        lock = json.loads((Path(__file__).resolve().parent / "scanner-lock.json").read_text())
        expected = lock["scanners"]["trivy"]["version"]
        version = subprocess.run([TRIVY, "--version"], capture_output=True, text=True,
                                 timeout=30, check=True).stdout
        if f"Version: {expected}" not in version.splitlines():
            raise ValueError("Trivy version does not match scripts/security/scanner-lock.json")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
        print(f"image audit error: pinned Trivy unavailable: {exc}", file=sys.stderr)
        return 2
    try:
        inspect = subprocess.run(["docker", "image", "inspect", image], capture_output=True,
                                 text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"image audit error: Docker inspect failed: {exc}", file=sys.stderr)
        return 2
    if inspect.returncode:
        print("image audit error: image is not present in the local Docker daemon", file=sys.stderr)
        return 2
    try:
        image_rows = json.loads(inspect.stdout)
        if not isinstance(image_rows, list) or len(image_rows) != 1:
            raise ValueError("expected one local image")
        image_id = image_rows[0]["Id"]
        if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("image has no immutable ID")
        if not expected_id or image_id != expected_id:
            raise ValueError("image changed after the security job was queued")
    except (ValueError, KeyError, IndexError, TypeError):
        print("image audit error: Docker returned invalid image metadata", file=sys.stderr)
        return 2
    try:
        configured_evidence = os.environ.get("SECURITY_IMAGE_EVIDENCE_DIR")
        evidence_root = (Path(configured_evidence).resolve() if configured_evidence else
                         Path(__file__).resolve().parents[2] / "artifacts/security/image-audit")
        evidence_root.mkdir(parents=True, exist_ok=True)
        evidence = Path(tempfile.mkdtemp(prefix="run-", dir=evidence_root))
        report = evidence / "trivy.json"
        command = [TRIVY, "image", "--image-src", "docker", "--scanners", "vuln",
                   "--severity", "HIGH,CRITICAL", "--exit-code", "1", "--skip-db-update",
                   "--skip-java-db-update", "--skip-check-update", "--skip-version-check",
                   "--offline-scan", "--list-all-pkgs", "--ignorefile", "",
                   "--format", "json", f"--output={report}", image_id]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
        except (OSError, subprocess.TimeoutExpired) as exc:
            receipt = {"image_id": image_id, "command": command,
                       "execution_error": type(exc).__name__}
            if report.is_file():
                receipt["report_sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
            (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"image audit evidence: {evidence}")
            print(f"image audit error: scanner execution failed ({type(exc).__name__})", file=sys.stderr)
            return 2
        # The private run directory is retained on success and failure. Raw
        # reports can contain image metadata, so never print their contents.
        (evidence / "trivy.stdout.log").write_text(result.stdout)
        (evidence / "trivy.stderr.log").write_text(result.stderr)
        receipt = {"image_id": image_id, "scanner_exit_code": result.returncode,
                   "command": command}
        if report.is_file():
            receipt["report_sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(f"image audit evidence: {evidence}")
        if "report_sha256" in receipt:
            print(f"image audit report SHA256: {receipt['report_sha256']}")
        if result.returncode not in (0, 1) or not report.is_file():
            print(f"image audit error: Trivy exit {result.returncode}; details withheld", file=sys.stderr)
            return 2
        try:
            summary = validate_report(json.loads(report.read_text()), result.returncode)
        except (OSError, ValueError) as exc:
            print(f"image audit error: {exc}", file=sys.stderr)
            return 2
        receipt["coverage"] = summary
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(f"image audit {image} ({image_id}): HIGH/CRITICAL={summary['high_critical']}; "
              f"packages={summary['packages']}; targets={summary['targets']}")
        if summary["eosl"]:
            print("image audit failed: distribution support has ended; refresh the base image", file=sys.stderr)
        return 1 if summary["high_critical"] or summary["eosl"] else 0
    except OSError as exc:
        print(f"image audit error: could not retain scan evidence: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
