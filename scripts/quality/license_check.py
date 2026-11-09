#!/usr/bin/env python3
"""Conservative license audit for proprietary or permissive-core distributions.

Default: Go (including tests/replacements) and npm dependency policy gate.
--release: also require own licensing and scoped human evidence for surfaces
that metadata cannot establish (Python, containers, models, assets, ownership,
enterprise boundary and distribution notices). This is not a legal opinion.
Exit 0 = selected checks pass, 1 = policy/release gaps, 2 = scanner error.
--report writes an inventory, NOT a complete attribution bundle.
"""
from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timezone
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def source_files():
    """Tracked + nonignored untracked source; do not walk caches/artifacts."""
    try:
        proc = subprocess.run(["git", "ls-files", "--cached", "--others",
                               "--exclude-standard", "-z"], cwd=ROOT,
                              capture_output=True, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScannerError(f"source discovery failed: {exc}") from exc
    return sorted({Path(os.fsdecode(p)) for p in proc.stdout.split(b"\0")
                   if p and (ROOT / os.fsdecode(p)).is_file()})


def source_fingerprint(files):
    """Hash source bytes INCLUDING binary assets; reports are gitignored."""
    digest = hashlib.sha256()
    for path in files:
        digest.update(os.fsencode(str(path)) + b"\0")
        digest.update((ROOT / path).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


class ScannerError(RuntimeError):
    """Environment/tool failure — never a pass."""


# Forbidden markers are checked FIRST: a permissive grant plus a clawback
# (e.g. "Apache 2.0 modified with Commons Clause") must fail, not pass.
FORBIDDEN = [
    ("AGPL", re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE", re.I)),
    ("LGPL", re.compile(r"GNU (LESSER|LIBRARY) GENERAL PUBLIC LICENSE", re.I)),
    ("GPL", re.compile(r"GNU GENERAL PUBLIC LICENSE", re.I)),
    ("MPL", re.compile(r"MOZILLA PUBLIC LICENSE", re.I)),
    ("SSPL", re.compile(r"SERVER SIDE PUBLIC LICENSE", re.I)),
    ("CDDL", re.compile(r"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE", re.I)),
    ("EPL", re.compile(r"ECLIPSE PUBLIC LICENSE", re.I)),
    ("BUSL", re.compile(r"BUSINESS SOURCE LICENSE", re.I)),
    ("FSL", re.compile(r"FUNCTIONAL SOURCE LICENSE", re.I)),
    ("RSAL", re.compile(r"REDIS SOURCE AVAILABLE LICENSE", re.I)),
    ("Commons-Clause", re.compile(r"COMMONS CLAUSE", re.I)),
]
PERMISSIVE = [
    ("Apache", re.compile(r"Apache License", re.I)),
    ("MIT", re.compile(r"MIT License|Permission is hereby granted, free of charge", re.I)),
    ("BSD", re.compile(r"Redistribution and use in source and binary forms", re.I)),
    ("ISC", re.compile(r"ISC License|Permission to use, copy, modify, and/or distribute this software", re.I)),
    ("PublicDomain", re.compile(r"dedicated to the public domain|released into the public domain", re.I)),
    ("PSF", re.compile(r"PYTHON SOFTWARE FOUNDATION LICENSE|PSF LICENSE|BEOPEN PYTHON", re.I)),
    ("Boost", re.compile(r"BOOST SOFTWARE LICENSE", re.I)),
    ("zlib", re.compile(r"zlib License|The origin of this software must not be misrepresented", re.I)),
    ("WTFPL", re.compile(r"DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE", re.I)),
]

# SPDX identifiers accepted in npm lockfiles. Anything else ("UNLICENSED",
# "SEE LICENSE IN ...", "*", GPL family) is a finding.
ALLOWED_SPDX = {
    "MIT", "MIT-0", "X11", "ISC", "Apache-2.0", "Apache-1.1",
    "BSD-2-Clause", "BSD-3-Clause", "BSD-2-Clause-FreeBSD", "0BSD",
    "CC0-1.0", "Unlicense", "WTFPL", "Python-2.0", "BlueOak-1.0.0",
    "BSL-1.0", "PSF-2.0", "Zlib", "CC-BY-4.0", "CC-BY-3.0",
}

LICENSE_NAME = re.compile(r"(LICENSE|LICENCE|COPYING|COPYRIGHT)", re.I)
# Docs-only licenses (e.g. opencontainers/go-digest LICENSE.docs = CC-BY-SA)
# govern the project's documentation, not the compiled code we ship.
DOCS_ONLY = re.compile(r"licen[cs]e\.docs?(\.md)?$", re.I)
LIST_TEMPLATE = "{{if and (not .Standard) .Module}}{{if not .Module.Main}}{{if not .Error}}{{.Module.Path}}|{{.Module.Version}}|{{if .Module.Replace}}{{.Module.Replace.Dir}}{{else}}{{.Module.Dir}}{{end}}{{end}}{{end}}{{end}}"


def classify_text(text: str):
    """Classify a license text: ('allowed'|'forbidden'|'unknown', label)."""
    head = text
    for label, rx in FORBIDDEN:
        if rx.search(head):
            return "forbidden", label
    for label, rx in PERMISSIVE:
        if rx.search(head):
            return "allowed", label
    return "unknown", ""


def classify_module_dir(directory: Path):
    """Classify a module by its top-level license files (all must pass)."""
    try:
        files = sorted(p for p in directory.iterdir()
                       if p.is_file() and LICENSE_NAME.match(p.name) and not DOCS_ONLY.search(p.name))
    except OSError as exc:
        raise ScannerError(f"unreadable module directory {directory}: {exc}") from exc
    if not files:
        return "nolicense", "no top-level license file"
    labels = []
    for f in files:
        kind, label = classify_text(f.read_text(errors="replace"))
        if kind != "allowed":
            return kind, f"{f.name}: {label or 'unrecognized license text'}"
        labels.append(label)
    return "allowed", "+".join(dict.fromkeys(labels))


def cache_dir(gomodcache: Path, module: str, version: str) -> Path:
    """Module cache path with Go's case escaping (A -> !a)."""
    escaped = "".join("!" + ch.lower() if ch.isupper() else ch for ch in module)
    return gomodcache / f"{escaped}@{version}"


def module_cache() -> Path:
    env = os.environ.get("GOMODCACHE")
    if env:
        return Path(env)
    try:
        proc = subprocess.run(["go", "env", "GOMODCACHE"],
                              capture_output=True, text=True, timeout=30)
        if proc.returncode == 0 and proc.stdout.strip():
            return Path(proc.stdout.strip())
    except (subprocess.SubprocessError, OSError):
        pass
    return Path.home() / "go" / "pkg" / "mod"


def imported_modules(module_dir: Path):
    """Actual dependency directories, including replacements and test imports.

    -e keeps ./... semantics while tolerating unloadable directories: the
    site build copies docs-linked .go samples (mixed package names) into the
    gitignored web/site/build output, which hard-fails plain `go list ./...`
    ("found packages X and Y"). Error rows carry no usable module (or the
    main module, filtered by the template), and the {{if not .Error}} guard
    keeps unloadable uncertainty out of the inventory rather than trusting it.
    """
    try:
        proc = subprocess.run(
            ["go", "list", "-e", "-mod=readonly", "-deps", "-test", "-f",
             LIST_TEMPLATE, "./..."],
            cwd=module_dir, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise ScannerError(f"go list unavailable in {module_dir}: {exc}") from exc
    if proc.returncode != 0:
        raise ScannerError(f"go list failed in {module_dir}: {proc.stderr.strip()[:500]}")
    mods = set()
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) != 3 or not parts[0] or not parts[2]:
            raise ScannerError(f"incomplete go list metadata in {module_dir}: {line}")
        mods.add(tuple(parts))
    return sorted(mods)


def scan_go_modules(gomodcache: Path):
    """gomodcache retained for callers; go list supplies actual resolved Dir."""
    findings, inventory, errors = [], [], []
    for manifest in source_files():
        if manifest.name != "go.mod":
            continue
        scope = str(manifest.parent)
        try:
            mods = imported_modules(ROOT / manifest.parent)
            for path, ver, directory in mods:
                d = Path(directory)
                if not d.is_dir():
                    raise ScannerError(f"resolved module directory missing: {path}@{ver}: {d}")
                status, detail = classify_module_dir(d)
                name = f"{path}@{ver or 'local-replacement'}"
                inventory.append((scope, name, status, detail))
                if status != "allowed":
                    findings.append({"scope": scope, "dependency": name, "issue": detail})
        except (ScannerError, OSError) as exc:
            errors.append(str(exc))
    return findings, inventory, errors


def relpath(path: Path) -> str:
    """Repo-relative display path; fixture paths outside the repo stay absolute."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def spdx_allowed(expr: str):
    """Parse the WHOLE expression before evaluating; invalid OR branches fail."""
    tokens = re.findall(r"\(|\)|[^\s()]+", expr)
    pos = 0

    def atom():
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError("missing operand")
        token = tokens[pos]
        pos += 1
        if token == "(":
            value = disjunction()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ValueError("unclosed expression")
            pos += 1
            return value
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:-]*", token) or token in ("OR", "AND", "WITH"):
            raise ValueError("invalid license operand")
        if pos < len(tokens) and tokens[pos] == "WITH":
            pos += 1
            if pos >= len(tokens) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", tokens[pos]):
                raise ValueError("missing exception identifier")
            pos += 1
            return False  # exceptions require explicit review
        return token in ALLOWED_SPDX

    def conjunction():
        nonlocal pos
        value = atom()
        while pos < len(tokens) and tokens[pos] == "AND":
            pos += 1
            right = atom()
            value = value and right
        return value

    def disjunction():
        nonlocal pos
        value = conjunction()
        while pos < len(tokens) and tokens[pos] == "OR":
            pos += 1
            right = conjunction()
            value = value or right
        return value

    try:
        allowed = disjunction()
        return allowed and pos == len(tokens), expr.strip()
    except ValueError:
        return False, expr.strip() or "empty"


def _lock_v1_licenses(data: dict):
    """Yield (name, license, version, source) from a lockfileVersion-1 tree.

    A missing/non-string version yields None; scan_lock flags it as a
    "missing version field" finding instead of passing an unknown state.
    """
    stack = [data.get("dependencies", {})]
    while stack:
        deps = stack.pop() or {}
        for name, meta in deps.items():
            if isinstance(meta, dict):
                version = meta.get("version")
                resolved = meta.get("resolved")
                yield (name, meta.get("license"),
                       version if isinstance(version, str) and version else None,
                       resolved if isinstance(resolved, str) else None)
                stack.append(meta.get("dependencies", {}))


def scan_lock(path: Path, inventory=None):
    """Scan one npm lockfile. Returns (findings, license counts)."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ScannerError(f"unreadable lockfile {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ScannerError(f"unexpected lockfile structure: {path}")
    if data.get("lockfileVersion") not in (1, 2, 3):
        raise ScannerError(f"unsupported lockfileVersion: {path}")
    findings, counts = [], {}
    scope = relpath(path)
    entries = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        pseudo_version = "unknown"
        for name, meta in packages.items():
            if not name or not isinstance(meta, dict) or meta.get("link"):
                continue
            lic = meta.get("license") or meta.get("licenses")
            if isinstance(lic, list):
                lic = " OR ".join(str(x) for x in lic)
            resolved = meta.get("resolved")
            entries.append((name, lic, meta.get("version"),
                            resolved if isinstance(resolved, str) else None))
    else:
        if data.get("lockfileVersion") != 1 or not isinstance(data.get("dependencies"), dict):
            raise ScannerError(f"missing dependency inventory in {path}")
        pseudo_version = "lock-v1"
        entries = list(_lock_v1_licenses(data))
    for name, lic, version, source in entries:
        # An unknown version is a partial state: it is reported, never a pass.
        if not isinstance(version, str) or not version:
            findings.append({"scope": scope, "dependency": name,
                             "issue": "missing version field", "version": pseudo_version})
            version = pseudo_version
        if inventory is not None:
            inventory.append((scope, f"{name}@{version}",
                              "allowed" if lic and spdx_allowed(str(lic))[0] else "review",
                              str(lic or "missing license field"), source))
        if not lic:
            findings.append({"scope": scope, "dependency": name,
                             "issue": "missing license field", "version": version})
            continue
        counts[lic] = counts.get(lic, 0) + 1
        ok, _ = spdx_allowed(str(lic))
        if not ok:
            findings.append({"scope": scope, "dependency": name,
                             "issue": f"license {lic!r} not on permissive allowlist", "version": version})
    return findings, counts


def license_exceptions(path=None):
    """Entries from security-exceptions.yaml with scanner: license_check.

    `path` is the dependency identifier (npm package name or Go
    module@version). Expired entries are returned separately and block.

    The optional `path` argument names a different exceptions FILE (same
    format): the public export ships a reviewed, public-safe subset under
    this same filename, and tests validate that file without a checkout
    dance. The default stays the repo-local file; behavior is unchanged.
    """
    import datetime
    path = Path(path) if path else ROOT / "scripts/quality/security-exceptions.yaml"
    out, cur = [], None
    if not path.exists():
        return [], []
    for line in path.read_text().splitlines():
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
    today = datetime.date.today().isoformat()
    live = [e for e in out if e.get("scanner") == "license_check" and e.get("expires", "") >= today]
    expired = [e for e in out if e.get("scanner") == "license_check" and e.get("expires", "") < today]
    return live, expired


def own_package_advisories():
    """Own package.json files without a license field (publication risk)."""
    out = []
    for path in source_files():
        if path.name != "package.json":
            continue
        proj = str(path.parent)
        pj = ROOT / path
        if not pj.exists():
            continue
        try:
            data = json.loads(pj.read_text())
        except (OSError, ValueError) as exc:
            raise ScannerError(f"unreadable own package {pj}: {exc}") from exc
        if not isinstance(data, dict):
            raise ScannerError(f"unexpected package structure: {pj}")
        if isinstance(data, dict) and not data.get("license"):
            out.append(f"{proj or '.'}: package.json has no license field (set one before publishing)")
    return out


def scan_python_inventory(path, inventory):
    """Read pip inspect output from the exact environment; never use host guesses."""
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or data.get("version") != "1" or not isinstance(data.get("installed"), list):
            raise ValueError("expected pip inspect schema version 1")
        findings = []
        for item in data["installed"]:
            meta = item.get("metadata", {})
            name, version = meta.get("name"), meta.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                raise ValueError("package name/version missing")
            direct_url = item.get("direct_url")
            if direct_url is not None and not isinstance(direct_url, dict):
                raise ValueError(f"invalid direct_url metadata: {name}")
            source = direct_url.get("url") if direct_url else None
            if source is not None and not isinstance(source, str):
                raise ValueError(f"invalid direct_url metadata: {name}")
            # Own distribution metadata is still a release ownership/license gap.
            if (name.lower().replace("_", "-") == "tokenrouter"
                    and source == (ROOT / "sdks/python").as_uri()):
                inventory.append((relpath(path), f"{name}@{version}", "own-code-review",
                                  "own license decision required", source))
                continue
            license_expr = meta.get("license_expression") or meta.get("license") or ""
            if not isinstance(license_expr, str):
                raise ValueError(f"invalid license metadata: {name}")
            allowed = spdx_allowed(license_expr)[0]
            # Legacy Core Metadata can contain a full grant instead of SPDX.
            if not allowed and "\n" in license_expr:
                allowed = classify_text(license_expr)[0] == "allowed"
            status = "allowed" if allowed else "review"
            inventory.append((relpath(path), f"{name}@{version}", status,
                              license_expr or "missing license metadata", source))
            if not allowed:
                findings.append({"scope": relpath(path), "dependency": f"{name}@{version}",
                                 "issue": f"Python license {license_expr or 'missing metadata'} requires review"})
        return findings
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        raise ScannerError(f"invalid pip inspect inventory {path}: {exc}") from exc


def external_references(files):
    """Surface references for review, not license determinations or image SBOMs."""
    out = []
    patterns = {
        "container": re.compile(r"^\s*(?:image:|FROM)\s+(\S+)", re.I),
        "model": re.compile(r"(?:meta-llama|mistralai|BAAI|Xenova|intfloat)/[A-Za-z0-9._/-]+"),
        "python-install": re.compile(r"^RUN\s+pip\s+install\s+(.+)$"),
    }
    for path in files:
        if not (str(path).startswith("deploy/") or path.name.startswith("Dockerfile")):
            continue
        if path.suffix not in (".yml", ".yaml", ".py") and not path.name.startswith("Dockerfile"):
            continue
        for number, line in enumerate((ROOT / path).read_text(errors="replace").splitlines(), 1):
            for kind, pattern in patterns.items():
                for match in pattern.finditer(line):
                    out.append({"kind": kind, "path": str(path), "line": number,
                                "reference": match.group(1) if match.lastindex else match.group(0),
                                "status": "review-required"})
    return out


REVIEW_AREAS = ("python", "containers", "models", "assets", "ownership",
                "enterprise", "distribution")


def release_gaps(files, fingerprint, evidence_path=None):
    """Human attestations supplement dependency checks; never suppress them."""
    gaps = []
    policy_path = ROOT / "scripts/quality/license-policy.json"
    try:
        policy = json.loads(policy_path.read_text())
        if policy.get("schema_version") != 1:
            raise ValueError("unsupported policy schema")
    except (OSError, ValueError, AttributeError) as exc:
        raise ScannerError(f"invalid license policy: {exc}") from exc
    if policy.get("decision") != "approved":
        gaps.append("own licensing decision is pending; no license grant has been made")
    license_path = ROOT / "LICENSE"
    if not license_path.is_file() or not license_path.read_text().strip():
        gaps.append("root LICENSE is missing or empty")
    for package in own_package_advisories():
        gaps.append(package)
    evidence = {}
    if evidence_path:
        try:
            evidence = json.loads(evidence_path.read_text())
            if not isinstance(evidence, dict):
                raise ValueError("expected object")
        except (OSError, ValueError) as exc:
            raise ScannerError(f"invalid release evidence: {exc}") from exc
    if evidence.get("source_sha256") != fingerprint:
        gaps.append("release review evidence absent or stale (source_sha256 mismatch)")
        evidence = {}
    reviews = evidence.get("reviews", {})
    if not isinstance(reviews, dict):
        raise ScannerError("release evidence reviews must be an object")
    for area in REVIEW_AREAS:
        review = reviews.get(area, {})
        if not isinstance(review, dict) or review.get("approved") is not True or not all(
                isinstance(review.get(k), str) and review[k].strip()
                for k in ("owner", "reason", "evidence")):
            gaps.append(f"{area}: needs scoped review with owner/reason/evidence (or justified N/A)")
    return gaps


def python_env_binding(spec: str):
    """Parse a --python-env LABEL=FILE binding; malformed specs never pass."""
    label, sep, value = spec.partition("=")
    if not sep or not label.strip() or not value:
        raise ScannerError(f"invalid --python-env binding (expected LABEL=FILE): {spec}")
    return label.strip(), Path(value)


def python_bindings(specs):
    """Parse all --python-env specs; one label must never claim two files.

    A repeated identical binding is an idempotent retry and collapses to one
    entry; the same label bound to different files would put two distinct
    environments under one identity in the report, so it is a scanner error.
    """
    out, by_label = [], {}
    for spec in specs:
        label, path = python_env_binding(spec)
        resolved = str(path.resolve())
        if label in by_label:
            if by_label[label] != resolved:
                raise ScannerError(
                    f"conflicting --python-env bindings for label {label!r}: "
                    f"{by_label[label]} vs {resolved}")
            continue
        by_label[label] = resolved
        out.append((label, path))
    return out


def report_paths(report, json_report):
    """Reject one file serving as both text and JSON report (last writer wins)."""
    if report is not None and json_report is not None \
            and str(report.resolve()) == str(json_report.resolve()):
        raise ScannerError(f"--report and --json-report must be different files: {report}")
    return report, json_report


def atomic_write_text(path: Path, text: str):
    """Write a report atomically; an interrupted run never leaves a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="text inventory, not a NOTICE bundle")
    parser.add_argument("--json-report", type=Path, help="machine-readable complete audit result")
    parser.add_argument("--python-inventory", type=Path, action="append", default=[],
                        help="pip inspect JSON of an exact Python environment; repeat per environment")
    parser.add_argument("--python-env", action="append", default=[], metavar="LABEL=FILE",
                        help="same as --python-inventory FILE, but the report records the "
                             "environment id LABEL (pins policy per environment is a separate owner decision)")
    parser.add_argument("--release", action="store_true", help="fail on distribution readiness gaps")
    parser.add_argument("--release-evidence", type=Path, help="human review attestations for this source hash")
    args = parser.parse_args()
    try:
        python_scans = [(None, path) for path in args.python_inventory]
        python_scans += python_bindings(args.python_env)
        report_paths(args.report, args.json_report)
        files = source_files()
        fingerprint = source_fingerprint(files)
        live_exc, expired_exc = license_exceptions()
        findings, inventory, errors = scan_go_modules(module_cache())
        for lock in files:
            if lock.name != "package-lock.json":
                continue
            try:
                lock_findings, _ = scan_lock(ROOT / lock, inventory)
                findings.extend(lock_findings)
            except ScannerError as exc:
                errors.append(str(exc))
        for _, python_inventory in python_scans:
            try:
                findings.extend(scan_python_inventory(python_inventory, inventory))
            except ScannerError as exc:
                errors.append(str(exc))
        for package in files:
            if package.name == "package.json" and not (ROOT / package.parent / "package-lock.json").is_file():
                errors.append(f"npm project without lockfile: {package}")
        gaps = release_gaps(files, fingerprint, args.release_evidence)
    except (ScannerError, OSError) as exc:
        print(f"SCANNER ERROR (not a pass): {exc}", file=sys.stderr)
        return 2

    # Exceptions may waive metadata gaps only, never a known restrictive license.
    suppressed, active = [], []
    for finding in findings:
        matches = [e for e in live_exc if e.get("path") == finding["dependency"]
                   and e.get("scope") == finding["scope"]
                   and e.get("version") == finding.get("version")
                   and e.get("owner") and e.get("reason")]
        if matches and finding["issue"] == "missing license field":
            suppressed.append({**finding, "exceptions": matches})
        else:
            active.append(finding)
    code = 2 if errors else 1 if active or expired_exc or (args.release and gaps) else 0
    # Report construction and writes stay guarded: an unreadable surface or a
    # failed write is an environment failure (exit 2 with a diagnosable cause),
    # never an unhandled traceback (which would exit 1, a policy code).
    try:
        result = {
            "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_sha256": fingerprint, "mode": "release" if args.release else "dependencies",
            "exit_code": code, "inventory": [dict(zip(("scope", "dependency", "status", "license", "source"), row))
                                             for row in inventory],
            "findings": active, "suppressed": suppressed, "expired_exceptions": expired_exc,
            "errors": errors, "release_gaps": gaps, "advisories": own_package_advisories(),
            "external_references": external_references(files),
            "python_inventories": [{"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                                    "environment": label}
                                   for label, p in python_scans if p.is_file()],
            "surfaces": [str(p) for p in files if p.name in ("go.mod", "package-lock.json", "pyproject.toml")
                         or p.name.startswith("requirements") or p.name.startswith("Dockerfile")
                         or p.suffix in (".woff", ".woff2", ".ttf", ".otf", ".svg")],
            "limitations": ["Go scope: current GOOS/GOARCH/build tags, including tests; release binaries need separate SBOM review",
                            "License text recognition is heuristic; package-specific/subdirectory licenses need review",
                            "npm metadata does not prove notice delivery; inventory is not an attribution bundle",
                            "Python/container/model/asset/ownership compliance requires scoped human evidence",
                            "Python environment binding records operator-provided environment ids; shipped environments are the Dockerfile-built images pinned by committed constraints files (owner decision D1, 2026-10-12)"],
        }
        if args.report:
            lines = ["# Yabanin license inventory — NOT a distribution NOTICE bundle\n"]
            lines.append(f"# source_sha256: {fingerprint}\n# exit_code: {code}\n\n")
            for row in inventory:
                scope, name, status, detail = row[:4]
                source = row[4] if len(row) > 4 else None
                lines.append(f"[{status}] {scope}: {name}: {detail}"
                             + (f" [source: {source}]\n" if source else "\n"))
            for key in ("findings", "suppressed", "errors", "release_gaps", "limitations"):
                lines.append(f"\n# {key}\n" + json.dumps(result[key], ensure_ascii=False, indent=2) + "\n")
            atomic_write_text(args.report, "".join(lines))
            print(f"inventory written: {args.report}")
        if args.json_report:
            atomic_write_text(args.json_report,
                              json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            print(f"JSON audit written: {args.json_report}")
    except (ScannerError, OSError) as exc:
        print(f"SCANNER ERROR (not a pass): report failure: {exc}", file=sys.stderr)
        return 2
    print(f"license check: {len(inventory)} dependency entries, {len(active)} finding(s), "
          f"{len(errors)} scanner error(s); mode={result['mode']}")
    for f in active:
        print(f"FAIL: {f['scope']}: {f['dependency']}: {f['issue']}")
    for f in suppressed:
        print(f"SUPPRESSED (metadata exception): {f['scope']}: {f['dependency']}")
    for e in expired_exc:
        print(f"EXPIRED LICENSE EXCEPTION: {e.get('id')} {e.get('path')}", file=sys.stderr)
    for gap in gaps:
        print(f"{'RELEASE BLOCKER' if args.release else 'RELEASE ADVISORY'}: {gap}")
    for error in errors:
        print(f"SCANNER ERROR (not a pass): {error}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
