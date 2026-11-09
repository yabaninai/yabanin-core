#!/usr/bin/env python3
"""Local quality gates. Python 3.9+ standard library; no CI service required."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
import uuid

import commands as command_registry


PROFILES = {
    "self": ["self"],
    "fast": ["self", "fast"],
    "static": ["self", "static"],
    "security": ["self", "static", "security", "secrets", "deps", "licenses", "policy", "package", "alerts", "dr", "claims"],
    "security-code": ["self", "static", "security", "secrets", "commit-secrets", "deps", "licenses", "policy"],
    "security-runtime": ["self", "tests", "int-modules", "integration"],
    "security-release": ["self", "static", "security", "secrets", "history-secrets",
                         "deps", "licenses", "policy", "tests", "int-modules",
                         "integration", "package", "image-scan"],
    "tests": ["self", "tests"],
    # browser is a web-profile leaf, deliberately NOT part of `full`: the
    # acceptance evidence (full) does not depend on the browser runtime, while
    # web-profile runs and changed-file runs that touch e2e/** get the gate.
    "web": ["dashboard", "site", "design", "browser"],
    "sdk": ["node-sdk", "python-sdk", "bridge", "go-sdk"],
    "docs": ["docs"],
    # Private planning data does not change the product. Keep its validator
    # separate from full, which must also work in the public core export.
    "plan": ["plan"],
    "nested-go": ["nested-go"],
    "eval": ["routing", "guards"],
    "integration": ["integration"],
    "int-modules": ["int-modules"],
    "full": ["self", "static", "security", "tests", "routing", "guards",
             "dashboard", "site", "design", "node-sdk", "python-sdk", "bridge",
             "go-sdk", "docs", "nested-go", "int-modules",
             "secrets", "deps", "licenses", "policy", "package", "alerts", "dr", "claims"],
}
LEAVES = {gate for gates in PROFILES.values() for gate in gates}
RELEASE_PLAN_DIR = "__private_release_plan__/"  # internal plans archive (not part of the public export)
# Canonical machine registry embedded in Markdown; card/stream docs stay
# Markdown (self+plan+docs), and unknown/executable files keep the full fallback.
RELEASE_PLAN_DATA = {RELEASE_PLAN_DIR + "PLAN-DATA.md"}

# NEXT-14 resource classes. HEAVY = Go toolchain gates that saturate cores
# and share build/lint caches — they never overlap regardless of --jobs.
# LIGHT = everything else (npm projects, docs, sdk leaves, secrets) — these
# fill up to --jobs concurrent lanes.
# NEXT-14a: DOCKER = gates sharing the Docker daemon (testcontainers DB/Redis
# suites, image builds, disposable PG drills). Docker Desktop runs the daemon
# in a CPU-limited VM; overlapping them starves time-sensitive tests into
# flakes (observed 2026-10-06: slowlog/timing failures under jobs=4). They
HEAVY_GATES = {"static", "security", "tests", "routing", "guards", "int-modules", "nested-go", "deps", "history-secrets", "commit-secrets"}
LIGHT_GATES = LEAVES - HEAVY_GATES
DOCKER_GATES = {"tests", "int-modules", "integration", "package", "dr", "image-scan"}
# NEXT-14b: ordering constraints for the parallel scheduler. The browser gate
# serves the production builds produced by dashboard/site; those builds wipe
# their output directories mid-run (Makefile re-stamps the fingerprint after
# the build), so a concurrently served build yields false element-not-found
# failures (observed 2026-10-13 under jobs=3). In serial reference mode the
# gate order already guarantees this; the map only constrains jobs>1.
GATE_ORDER = {"browser": ("dashboard", "site")}


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE)


def repository():
    return Path(git(Path(__file__).resolve().parent, "rev-parse", "--show-toplevel")
                .decode().strip())


def names(raw):
    return {os.fsdecode(value) for value in raw.split(b"\0") if value}


def changed_paths(root, base=None):
    # Include staged, unstaged, deleted and committed changes, and BOTH rename paths.
    revision = "HEAD"
    if base:
        commit = git(root, "rev-parse", "--verify", "--end-of-options", base + "^{commit}").decode().strip()
        revision = git(root, "merge-base", commit, "HEAD").decode().strip()
    paths = names(git(root, "diff", "--name-only", "--no-renames", "-z", revision, "--"))
    paths |= names(git(root, "ls-files", "--others", "--exclude-standard", "-z"))
    return sorted(paths), revision


def snapshot(root):
    paths = names(git(root, "ls-files", "-z"))
    paths |= names(git(root, "ls-files", "--others", "--exclude-standard", "-z"))
    digest = hashlib.sha256()
    for name in sorted(paths):
        path = root / name
        digest.update(os.fsencode(name) + b"\0")
        if path.is_symlink():
            digest.update(b"link\0" + os.fsencode(os.readlink(path)))
        elif path.is_file():
            digest.update(str(path.stat().st_mode & 0o777).encode() + b"\0")
            # Assets, archives and WASM can change delivered behavior too.
            # Generated QA output belongs in ignored artifacts, not outside
            # the source fingerprint. Stream bytes to bound memory usage.
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif path.is_dir():
            raise ValueError(f"Unverified directory/gitlink in tracked source: {name}")
        else:
            digest.update(b"deleted")
        digest.update(b"\0")
    return {"commit": git(root, "rev-parse", "HEAD").decode().strip(),
            "source_sha256": digest.hexdigest(),
            "dirty": bool(git(root, "status", "--porcelain", "-z"))}


def classify(paths):
    reasons = {"self": ["verify the quality infrastructure"]}

    def add(gates, path):
        for gate in gates:
            reasons.setdefault(gate, []).append(path)

    for path in paths:
        if path.startswith(RELEASE_PLAN_DIR):
            add(["plan"], path)
            if path in RELEASE_PLAN_DATA:
                continue
            # Markdown still selects docs below. Executable/unknown files
            # (including validate.py) retain the conservative full fallback.
        # Nested Go modules (own go.mod): their own leaf, not root scope.
        if path.startswith(("sdks/go/", "deploy/mock-provider/", "deploy/mock-embedder/", "scripts/loadtest/")):
            if path.endswith((".go", ".mod", ".sum")):
                gates = ["go-sdk"] if path.startswith("sdks/go/") else ["nested-go"]
                if path.endswith((".mod", ".sum")):
                    gates.append("licenses")
                add(gates, path)
                continue
        # Licensing changes and externally bundled surfaces require explicit review.
        if (Path(path).name in ("LICENSE", "NOTICE", "COPYING", "pyproject.toml")
                or Path(path).name.startswith(("LICENSE.", "NOTICE-", "requirements", "Dockerfile"))
                or path.startswith("deploy/") and path.endswith((".yml", ".yaml"))
                or path in ("standards/license-compliance.md", "scripts/quality/license-policy.json")):
            add(["licenses"], path)
        # Documentation edits carry the docs gate (link/freshness/registry).
        if path.endswith((".md", ".mdx")) and not path.startswith(("docs/strategy/qa/", "docs/plans/")):
            add(["docs"], path)
            continue
        # Dependency manifests always select the license leaf (non-consuming:
        # the file still reaches its directory gates below).
        if Path(path).name in ("package.json", "package-lock.json"):
            add(["licenses"], path)
        # Package names cannot reliably identify trust boundaries. Go changes
        # conservatively receive all cumulative mandatory Go gates.
        if path.endswith("_test.go") and ("integration" in Path(path).parent.name or path.endswith(("integration_test.go", "updown_test.go", "rls_verify_test.go", "drill_test.go", "e2e_test.go"))):
            add(["int-modules"], path)
        elif path.endswith(".go") or Path(path).name in ("go.mod", "go.sum") or path.startswith("migrations/"):
            gates = ["static", "security", "tests", "routing", "guards"]
            if Path(path).name in ("go.mod", "go.sum"):
                gates.append("licenses")
            add(gates, path)
        elif path in ("Makefile", ".golangci.yml") or path.startswith(("scripts/quality/", ".opencode/skills/go-")):
            add(PROFILES["full"], path)
        elif path.startswith("web/dashboard/"):
            add(["dashboard", "design"], path)
        elif path.startswith("web/site/"):
            add(["site"], path)
        elif path.startswith("e2e/") or path in ("playwright.config.ts", "scripts/quality/browser.sh", "scripts/quality/browser-build.sh", "scripts/build-fingerprint.sh"):
            add(["browser"], path)
        elif path.startswith("design/"):
            add(["design"], path)
        elif path.startswith("sdks/node/"):
            add(["node-sdk"], path)
        elif path.startswith("sdks/python/"):
            add(["python-sdk"], path)
        elif path.startswith("services/subscription-bridge/"):
            add(["bridge"], path)
        elif path.startswith("datasets/eval/"):
            add(["routing", "guards"], path)
        elif not path.endswith((".md", ".png", ".jpg", ".svg")):
            add(PROFILES["full"], path)
    return reasons


def expand(profiles):
    gates = []
    for profile in profiles:
        if profile not in PROFILES and profile not in LEAVES:
            raise ValueError(f"Unknown profile: {profile}")
        gates.extend(PROFILES.get(profile, [profile]))
    return list(dict.fromkeys(gates))


def write_json(path, document):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def timestamp():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def cross_process_locks(root, resources, cancelled=None):
    """Serialize resource-heavy gates across independent quality.py runs."""
    if not resources:
        yield True
        return
    import fcntl
    common = git(root, "rev-parse", "--git-common-dir").decode().strip()
    common_dir = (root / common).resolve()
    root_key = hashlib.sha256(str(common_dir).encode()).hexdigest()[:16]
    lock_dir = Path(tempfile.gettempdir()) / "yabanin-quality-locks"
    lock_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    streams = []
    try:
        for resource in resources:
            stream = (lock_dir / f"{root_key}-{resource}.lock").open("a")
            streams.append(stream)
            while True:
                if cancelled is not None and cancelled.is_set():
                    yield False
                    return
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(0.1)
        yield True
    finally:
        for stream in reversed(streams):
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            finally:
                stream.close()


PROCESS_CLEANUP_GRACE_SECONDS = 25.0
PROCESS_KILL_CONFIRM_SECONDS = 5.0
PROCESS_CLEANUP_POLL_SECONDS = 0.05
PROCESS_EXIT_CONFIRM_SECONDS = 1.0


def stop_process(proc, grace_period=None):
    """Stop one owned process group, allowing bounded TERM cleanup first."""
    if grace_period is None:
        grace_period = PROCESS_CLEANUP_GRACE_SECONDS
    warnings = []

    def wait_for_child(timeout):
        try:
            proc.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        proc.wait()
        return None
    except PermissionError:
        # Preserve the prior direct-child fallback, but make the unverified
        # process-group cleanup explicit in the gate report.
        warnings.append("Process-group cleanup denied; only direct child terminated; descendant cleanup unverified")
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        if not wait_for_child(PROCESS_KILL_CONFIRM_SECONDS):
            warnings.append("Direct child termination could not be confirmed after SIGKILL")
        return "; ".join(warnings)

    deadline = time.monotonic() + max(0.0, grace_period)
    while True:
        # Reap an exited direct child before checking group existence, or its
        # zombie could keep the process group visible until the deadline.
        proc.poll()
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            proc.wait()
            return "; ".join(warnings) or None
        except PermissionError:
            # Darwin denies probes that land on a child whose exit is already
            # in progress but not yet reapable, and a recycled pgid may answer
            # for a foreign process. Give the exit a bounded window: a reaped
            # direct child proves nothing owned remains in the group, so this
            # is a clean stop, not a permission failure.
            if wait_for_child(PROCESS_EXIT_CONFIRM_SECONDS):
                return "; ".join(warnings) or None
            if not warnings:
                warnings.append("Process-group termination could not be verified due to permission denial")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(PROCESS_CLEANUP_POLL_SECONDS, remaining))

    # The process group still exists after the grace period. Force termination
    # once, then allow a bounded interval to reap the child and confirm the
    # group disappeared.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        warnings.append("Process-group SIGKILL denied; only direct child termination attempted")
        try:
            proc.kill()
        except ProcessLookupError:
            pass

    kill_deadline = time.monotonic() + PROCESS_KILL_CONFIRM_SECONDS
    if not wait_for_child(max(0.0, kill_deadline - time.monotonic())):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        if not wait_for_child(max(0.0, kill_deadline - time.monotonic())):
            warnings.append("Direct child termination could not be confirmed after SIGKILL")

    while time.monotonic() < kill_deadline:
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            if proc.poll() is None and not wait_for_child(max(0.0, kill_deadline - time.monotonic())):
                warnings.append("Direct child termination could not be confirmed after SIGKILL")
            return "; ".join(dict.fromkeys(warnings)) or None
        except PermissionError:
            # Same terminating-child rule as above: the denial may describe a
            # child that is finishing its exit, not a cleanup failure.
            if wait_for_child(min(PROCESS_EXIT_CONFIRM_SECONDS,
                                  max(0.0, kill_deadline - time.monotonic()))):
                return "; ".join(dict.fromkeys(warnings)) or None
            if not warnings:
                warnings.append("Process-group termination could not be verified due to permission denial")
            break
        time.sleep(min(PROCESS_CLEANUP_POLL_SECONDS,
                       max(0.0, kill_deadline - time.monotonic())))

    warnings.append("Process group remained or could not be verified after SIGKILL; descendant cleanup unverified")
    return "; ".join(dict.fromkeys(warnings))


class ProcessRegistry:
    """Tracks only subprocess groups started by this quality invocation."""

    def __init__(self):
        import threading
        self.cancelled = threading.Event()
        self._lock = threading.Lock()
        self._processes = {}
        self._cleanup_warnings = []

    def register(self, proc, gate_name=None):
        with self._lock:
            if self.cancelled.is_set():
                return False
            self._processes[proc] = gate_name
            return True

    def unregister(self, proc):
        with self._lock:
            self._processes.pop(proc, None)

    def record_cleanup_warning(self, gate_name, warning):
        if warning:
            with self._lock:
                self._cleanup_warnings.append({"gate": gate_name, "warning": warning})

    def attach_cleanup_warnings(self, report):
        with self._lock:
            warnings = list(self._cleanup_warnings)
        gates = {gate["name"]: gate for gate in report["gates"]}
        for item in warnings:
            gate = gates.get(item["gate"])
            if gate is None:
                report.setdefault("cleanup_warnings", []).append(item)
            else:
                gate.setdefault("cleanup_warnings", []).append(item["warning"])

    def cancel(self):
        self.cancelled.set()

    def stop_all(self):
        self.cancel()
        with self._lock:
            processes = list(self._processes.items())
        if not processes:
            return
        # Signal and wait for owned groups concurrently so N graceful cleanups
        # share one bounded window instead of extending shutdown by N times.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(processes)) as executor:
            futures = {executor.submit(stop_process, proc): gate_name
                       for proc, gate_name in processes}
            for future, gate_name in futures.items():
                self.record_cleanup_warning(gate_name, future.result())


def interrupted_result(started):
    return {"status": "interrupted", "exit_code": 130,
            "duration_seconds": round(time.monotonic() - started, 3)}


MAKE_SKIP_RE = re.compile(r"Error 77\s*$")


def log_tail_lines(log):
    try:
        return [line.strip() for line in log.read_text(errors="replace").splitlines()
                if line.strip()]
    except OSError:
        return []


def skip_reason(log):
    # A gate that exits 77 prints its skip reason to stdout first; surface the
    # last meaningful line so the manifest records WHY it was skipped. Through
    # the make wrapper the recipe's exit 77 surfaces as make's own "Error 77"
    # line (GNU make exits 2 on any recipe failure) — the reason is the line
    # the recipe printed right before it.
    lines = log_tail_lines(log)
    if not lines:
        return "gate reported skip (exit 77)"
    if MAKE_SKIP_RE.search(lines[-1]) and len(lines) > 1:
        return lines[-2]
    return lines[-1]


def gate_status(code, log=None):
    # 0 = passed, 77 = explicit skip (browser runtime absent), else failed.
    # GNU make collapses a failing recipe to exit 2, printing "Error 77" for a
    # recipe that exited 77; the project-wide convention is that 77 means skip,
    # so recognize that documented marker in the log tail.
    if code == 0:
        return "passed"
    if code == 77:
        return "skipped"
    if code == 2 and log is not None:
        lines = log_tail_lines(log)
        if lines and MAKE_SKIP_RE.search(lines[-1]):
            return "skipped"
    return "failed"


def execute(command, root, log, timeout, process_registry=None, gate_name=None):
    started = time.monotonic()
    try:
        with log.open("wb") as output:
            if process_registry is not None and process_registry.cancelled.is_set():
                return interrupted_result(started)
            proc = subprocess.Popen(command, cwd=root, stdout=output,
                                    stderr=subprocess.STDOUT, start_new_session=True)
            if process_registry is not None and not process_registry.register(proc, gate_name):
                process_registry.record_cleanup_warning(gate_name, stop_process(proc))
                return interrupted_result(started)
            try:
                code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                warning = stop_process(proc)
                return {"status": "timeout", "exit_code": 124, "cleanup_warning": warning,
                        "duration_seconds": round(time.monotonic() - started, 3)}
            except BaseException:
                warning = stop_process(proc)
                if process_registry is not None:
                    process_registry.record_cleanup_warning(gate_name, warning)
                raise
            finally:
                if process_registry is not None:
                    process_registry.unregister(proc)
        if process_registry is not None and process_registry.cancelled.is_set():
            return interrupted_result(started)
        status = gate_status(code, log)
        result = {"status": status, "exit_code": code,
                  "duration_seconds": round(time.monotonic() - started, 3)}
        if status == "skipped":
            result["skip_reason"] = skip_reason(log)
        return result
    except OSError as exc:
        return {"status": "error", "exit_code": 2, "error": str(exc)}


def test_summary(log):
    summary = {"skipped": [], "failed": [], "coverage": []}
    for line in log.read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            if line.startswith("total:"):
                summary["total_coverage"] = line.split()[-1]
            continue
        if not isinstance(event, dict):
            continue
        if event.get("Action") in ("skip", "fail"):
            key = "skipped" if event["Action"] == "skip" else "failed"
            summary[key].append({"package": event.get("Package"), "test": event.get("Test")})
        output = event.get("Output", "")
        if "coverage:" in output:
            summary["coverage"].append({"package": event.get("Package"), "output": output.strip()})
    return summary


# ---------------------------------------------------------------------------
# NEXT-07: skip registry + coverage ratchet
# ---------------------------------------------------------------------------

def parse_skips(path):
    """Parse skips.yaml (simple YAML subset, stdlib only). Returns list of
    dicts with keys: test, condition, reason, owner, proof, expires."""
    if not path.exists():
        return []
    entries = []
    cur = None
    in_skips = False
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("skips:"):
            in_skips = True
            continue
        if in_skips and stripped.startswith("- test: "):
            if cur:
                entries.append(cur)
            cur = {"test": stripped.split("- test: ", 1)[1].strip()}
            continue
        if in_skips and cur is not None:
            m = __import__("re").match(r"^\s+([a-z_]+): (.*)$", line)
            if m:
                key, val = m.group(1), m.group(2).strip().strip('"')
                cur[key] = val
    if cur:
        entries.append(cur)
    return entries


def validate_skips(manifest_report, skip_entries):
    """Return a list of finding strings. Empty list = all skips explained."""
    findings = []
    known = {e["test"] for e in skip_entries}
    # Build the set of "package.TestName" from the manifest's test skips.
    manifest_skips = set()
    for gate in manifest_report.get("gates", []):
        for s in gate.get("tests", {}).get("skipped", []):
            pkg = s.get("package", "")
            test = s.get("test", "")
            # Go test JSON reports the full import path; the registry uses
            # the short path. Try both.
            manifest_skips.add(f"{pkg}.{test}")
            # Short form: last two path elements (pkg/Name.TestName)
            parts = pkg.rsplit("/", 1)
            short = parts[-1] if len(parts) == 1 else parts[-1]
            manifest_skips.add(f"pkg/{short}.{test}" if not pkg.startswith("pkg/") else f"{pkg.rsplit('/', 1)[0].rsplit('/', 1)[-1]}/{short}.{test}")
    for skip in manifest_skips:
        if skip not in known:
            # Try matching by just the TestName suffix (package paths vary).
            test_name = skip.rsplit(".", 1)[-1]
            if not any(e["test"].endswith("." + test_name) for e in skip_entries):
                findings.append(f"unexplained skip: {skip}")
    # Check for expired exceptions.
    from datetime import date
    today = date.today().isoformat()
    for e in skip_entries:
        exp = e.get("expires", "")
        if exp and exp < today:
            findings.append(f"expired skip exception: {e['test']} (expired {exp})")
    return findings


def validate_coverage(manifest_report, baseline_path):
    """Return (findings, updated_baseline_data). The ratchet: total coverage
    and per-package coverage must not drop below the measured baseline.
    Returns None for baseline_data when no update is needed."""
    findings = []
    if not baseline_path.exists():
        return findings, None
    baseline = json.loads(baseline_path.read_text())
    total_min = baseline.get("total_coverage_pct", 0)
    pkg_min = baseline.get("packages", {})

    # Find the tests gate in the manifest.
    tests_gate = next((g for g in manifest_report.get("gates", []) if g["name"] == "tests"), None)
    if tests_gate is None:
        return findings, None
    tests_data = tests_gate.get("tests", {})
    total_str = tests_data.get("total_coverage", "")
    if not total_str:
        findings.append("coverage data missing from tests gate")
        return findings, None
    try:
        total_pct = float(total_str.replace("%", ""))
    except ValueError:
        findings.append(f"unparseable total coverage: {total_str!r}")
        return findings, None
    # Tolerance for test non-determinism (randomized order, timing): a drop
    # of ≤ 0.5 pp is noise; anything larger is a real regression.
    tolerance = 0.5
    if total_pct < total_min - tolerance:
        findings.append(
            f"total coverage {total_pct}% is below ratchet baseline {total_min}%"
            f" (tolerance {tolerance}pp)"
        )
    # Per-package ratchet: packages present in the baseline must not drop.
    cov_entries = tests_data.get("coverage", [])
    current_pkg = {}
    for entry in cov_entries:
        pkg = entry.get("package", "")
        output = entry.get("output", "")
        if "\tok" not in output and "\t\t" not in output and "coverage:" in output:
            try:
                pct = float(output.split("coverage: ")[1].replace("% of statements", ""))
                current_pkg[pkg] = pct
            except (IndexError, ValueError):
                pass
    for pkg, min_pct in pkg_min.items():
        if pkg in current_pkg and current_pkg[pkg] < min_pct - tolerance:
            findings.append(
                f"coverage regression: {pkg} {current_pkg[pkg]}% < baseline {min_pct}%"
                f" (tolerance {tolerance}pp)"
            )
    return findings, None


def rerun_prior_path(root, report, manifest_dir):
    """QR-1: resolve the prior manifest referenced by a rerun report's
    rerun_of link. Resolution order: the recorded absolute path
    (rerun_of_manifest, robust against relative invocations), the canonical
    location under artifacts/quality/<rerun_of_run_id>/, then rerun_of as
    given (absolute or relative to the referencing manifest). Raises
    ValueError when no candidate exists."""
    candidates = []
    if report.get("rerun_of_manifest"):
        candidates.append(Path(report["rerun_of_manifest"]))
    if report.get("rerun_of_run_id"):
        candidates.append(root / "artifacts/quality" / report["rerun_of_run_id"] / "manifest.json")
    if report.get("rerun_of"):
        link = Path(report["rerun_of"])
        candidates.append(link if link.is_absolute() else manifest_dir / link)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ValueError(f"broken rerun link: prior manifest not found "
                     f"({', '.join(str(path) for path in candidates) or 'no reference recorded'})")


def evidence_chain(root, manifest):
    """QR-1: return the rerun chain [newest, ..., original] as (path, report)
    pairs. A manifest without rerun_of is a chain of length one. Raises
    ValueError on an unreadable manifest, a broken link or a cycle."""
    chain = []
    seen = set()
    path = manifest
    while True:
        try:
            report = json.loads(path.read_text())
        except OSError as exc:
            raise ValueError(f"chain manifest is unreadable: {path} ({exc})") from None
        except ValueError as exc:
            raise ValueError(f"chain manifest is not valid JSON: {path} ({exc})") from None
        if not isinstance(report, dict):
            raise ValueError(f"chain manifest is not a JSON object: {path}")
        resolved = path.resolve()
        if resolved in seen:
            raise ValueError(f"rerun chain contains a cycle at {path}")
        seen.add(resolved)
        chain.append((path, report))
        if not report.get("rerun_of"):
            return chain
        path = rerun_prior_path(root, report, path.parent)


def verify_evidence(root, manifest, required):
    """Validate a quality manifest as evidence for the required gates.

    QR-1: a manifest may extend a rerun chain (rerun_of links). The chain is
    valid when every link binds to the current source snapshot, every
    recorded log hash matches in the directory of the run that actually
    executed the gate (carried records resolve through the chain to that
    run), the gate set is identical along the chain and carried records are
    verbatim copies of their prior records, the effective gate set (union
    along the chain, newest record per gate) passes, and the newest manifest
    is passed while older links are failed or interrupted."""
    try:
        chain = evidence_chain(root, manifest)
    except ValueError:
        # A broken link or a cycle means the chain itself cannot be trusted.
        return False
    current = snapshot(root)
    links = []
    for path, report in chain:
        version = report.get("schema_version")
        # NEXT-10 backward compatibility: v1 manifests (pre-registry) verify
        # under the unchanged rules forever; v2 additionally re-derives the
        # registry hash. A v2 manifest whose registry changed since the run
        # is stale — exactly the tamper case the card demands to catch.
        if version not in (1, 2) or not report.get("gates"):
            return False
        if version == 2:
            ev = report.get("evidence") or {}
            rec = ev.get("command_registry")
            if rec is not None:
                try:
                    if command_registry.registry_sha256(root / rec.get("path", "")) != rec.get("sha256"):
                        return False
                except (OSError, command_registry.RegistryError):
                    return False
        # Source identity: a chain is evidence only for this exact tree.
        if report.get("source") != current or report.get("source_after") != current:
            return False
        links.append((path, report, {gate["name"]: gate for gate in report["gates"]}))
    # The gate set is fixed by the original run: a rerun must neither add,
    # drop nor rename gates.
    names = set(links[0][2])
    for _path, _report, by_name in links[1:]:
        if set(by_name) != names:
            return False
    if not set(required) <= names:
        return False
    # A carried record must be a verbatim copy of the same gate's record in
    # the link it references, plus the log_source marker — inventing or
    # editing carried evidence is a tamper, not a carry.
    for index in range(len(links) - 1):
        for name, gate in links[index][2].items():
            prior = links[index + 1][2].get(name)
            if gate.get("log_source") == "prior" and gate != dict(prior, log_source="prior"):
                return False

    def log_dir(index, name):
        """Directory holding a gate's log: this link's own directory unless
        the record was carried from an older run; carried records resolve
        through the chain to the run that executed the gate."""
        for j in range(index, len(links)):
            if links[j][2][name].get("log_source") != "prior":
                return links[j][0].parent
        return None

    # Only passed and skipped records are evidence claims; every one of them
    # must hash-match where it lives. Failed, interrupted and pending records
    # of older links are superseded diagnostics — their logs may not even
    # exist (a gate killed before writing output) and prove nothing.
    for index, (_path, _report, by_name) in enumerate(links):
        for name, gate in by_name.items():
            if gate.get("status") not in ("passed", "skipped"):
                continue
            if name not in LEAVES or gate.get("log") != name + ".log":
                return False
            directory = log_dir(index, name)
            if directory is None:
                return False
            try:
                log_bytes = (directory / gate["log"]).read_bytes()
            except OSError:
                # A deleted or unreadable log invalidates the evidence; it
                # must not crash the validator into a generic error exit.
                return False
            if hashlib.sha256(log_bytes).hexdigest() != gate.get("log_sha256"):
                return False
    # Status semantics apply to the effective records only: older links
    # legitimately carry failed records superseded by the rerun.
    effective = {}
    for index, (_path, _report, by_name) in enumerate(links):
        for name, gate in by_name.items():
            effective.setdefault(name, (index, gate))
    for name, (index, gate) in effective.items():
        status, code = gate.get("status"), gate.get("exit_code")
        # A gate is either passed, or an explicit skip (exit 77 with a
        # recorded reason). Anything else is a failure. NEXT-07 adds the
        # registry that restricts which skips are legitimate; here we require
        # the skip to be explicit and self-describing so it can never
        # masquerade as a pass.
        if status == "passed":
            if code != 0:
                return False
        elif status == "skipped":
            # 77 = the gate process itself skipped; 2 = the make wrapper
            # collapsed a recipe-level `exit 77` (GNU make exits 2 on any
            # recipe failure, printing the same "Error 77" marker the runner
            # accepts at gate_status time). Either way the skip must carry a
            # recorded reason.
            if code == 2:
                directory = log_dir(index, name)
                lines = log_tail_lines(directory / gate.get("log", "")) if directory else []
                wrapper_skip = bool(lines) and bool(MAKE_SKIP_RE.search(lines[-1]))
            else:
                wrapper_skip = False
            if code != 77 and not (code == 2 and wrapper_skip):
                return False
            if not gate.get("skip_reason"):
                return False
        else:
            return False
    # Chain verdict: the newest manifest carries the run's outcome, and a
    # passed manifest is never rerun — so older links must be failed or
    # interrupted.
    if chain[0][1].get("status") != "passed":
        return False
    for _path, report in chain[1:]:
        if report.get("status") not in ("failed", "interrupted"):
            return False
    return True


def execute_gate(gate, command, root, log_path, timeout, report, directory,
                 report_hook=None, process_registry=None):
    gate["status"] = "running"
    if report is not None:
        write_json(directory / "manifest.json", report)
    elif report_hook is not None:
        report_hook(gate)
    print(f"RUN {gate['name']} (log: {log_path})", flush=True)
    gate.update(execute(command, root, log_path, timeout, process_registry,
                        gate.get("name")))
    if log_path.exists():
        gate["log_sha256"] = hashlib.sha256(log_path.read_bytes()).hexdigest()
        if gate["name"] == "tests":
            gate["tests"] = test_summary(log_path)
    print(f"{gate['status'].upper()} {gate['name']} (exit {gate['exit_code']})", flush=True)


LIMITATIONS = ["Reports are local evidence, not signed attestations.",
               "full excludes Docker integration; run integration explicitly.",
               "Go tests may skip external-service cases; consult logs."]


def gate_entry(gate, directory):
    """Manifest entry for one gate; run-scoped outputs (coverage file,
    browser traces) are isolated inside this run's evidence directory."""
    entry = {"name": gate, "status": "pending",
             "command": ["make", "--no-print-directory", "_quality-" + gate],
             "log": gate + ".log"}
    if gate == "tests":
        entry["command"].append("COVERAGE_FILE=" + str(directory / "coverage.out"))
    elif gate == "browser":
        # Isolate this run's traces/screenshots/report in the evidence dir.
        entry["command"] = ["env", "QUALITY_BROWSER_OUT=" + str(directory / "browser")] + entry["command"]
    return entry


def new_run_directory(root):
    # Ignored output location and unique directories prevent source pollution
    # and concurrent log overwrites.
    directory = root / "artifacts/quality" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
    directory.mkdir(parents=True)
    return directory


def evidence_block(root):
    # NEXT-10 evidence v2: record the protected command registry the run's
    # tooling consulted, so any post-run registry modification invalidates
    # the evidence (tamper-evidence, not crypto signing by design).
    reg_path = root / "scripts/quality/commands.json"
    if reg_path.exists():
        return {"version": 2, "command_registry": {
            "path": "scripts/quality/commands.json",
            "sha256": command_registry.registry_sha256(reg_path)}}
    # A run without a registry is still evidence — recorded as absent,
    # never silently registry-backed (fixture repos have none).
    return {"version": 2, "command_registry": None,
            "absent_reason": "registry not present in this repository"}


def run(root, gates, profiles, timeout, base=None, reasons=None, jobs=1):
    if not gates:
        # An empty gate set must never be reported as a successful run.
        raise ValueError("No gates selected for run")
    paths, revision = changed_paths(root, base)
    before = snapshot(root)
    directory = new_run_directory(root)
    report = {"schema_version": 2, "evidence": evidence_block(root),
              "profiles": profiles, "started_at": timestamp(),
              "status": "running", "source": before, "base": revision,
              "changed_paths": paths, "reasons": reasons or {},
              "environment": {"platform": platform.platform(), "python": platform.python_version()},
              "limitations": LIMITATIONS,
              "gates": [gate_entry(gate, directory) for gate in gates]}
    return execute_report(root, report, directory, before, timeout, jobs)


def rerun(root, prior_arg, timeout, jobs=1):
    """QR-1 / owner decision D5 (2026-10-29): re-execute only the failed
    gates of a prior failed or interrupted run. Fresh results bind to the
    exact source snapshot recorded by the prior manifest; passed and skipped
    gates are carried over as prior-log evidence — the bytes are never
    copied, the validator resolves them in the prior run's directory."""
    prior_path = Path(prior_arg)
    try:
        prior = json.loads(prior_path.read_text())
    except OSError as exc:
        raise ValueError(f"prior manifest is unreadable: {exc}") from None
    except ValueError as exc:
        raise ValueError(f"prior manifest is not valid JSON: {exc}") from None
    if not isinstance(prior, dict) or prior.get("schema_version") not in (1, 2):
        raise ValueError(f"unsupported prior manifest schema_version: "
                         f"{prior.get('schema_version') if isinstance(prior, dict) else type(prior).__name__!r}")
    prior_id = prior_path.parent.name
    prior_status = prior.get("status")
    if prior_status == "passed":
        raise ValueError(f"prior run {prior_id} passed; nothing to rerun — "
                         "its evidence already stands")
    if prior_status not in ("failed", "interrupted"):
        raise ValueError(f"prior run {prior_id} status is {prior_status!r}; "
                         "only failed or interrupted runs can be rerun")
    prior_gates = prior.get("gates") or []
    if not prior_gates or any(not isinstance(gate, dict) or not gate.get("name")
                              or not gate.get("status") for gate in prior_gates):
        raise ValueError(f"prior run {prior_id} has malformed gate entries")
    # Anti-tamper anchor: a rerun binds fresh results to the prior manifest's
    # exact source state. Any drift in commit, dirty flag or content hash
    # makes partial results meaningless — a full run is required.
    before = snapshot(root)
    if before != prior.get("source"):
        raise ValueError(f"source moved since run {prior_id} (commit, dirty "
                         "flag or source_sha256 differs); a full run is "
                         "required — a rerun must not bind fresh results to "
                         "a changed source")
    rerun_names = {gate["name"] for gate in prior_gates
                   if gate["status"] not in ("passed", "skipped")}
    if any(gate["name"] == "self" for gate in prior_gates):
        # The runner's self-test is cheap and guards the rerun machinery
        # itself: it always re-executes when the prior profile carried it.
        rerun_names.add("self")
    if not rerun_names:
        raise ValueError(f"prior run {prior_id} has no rerunnable gate; "
                         "resolve its policy findings with a fresh full run")
    directory = new_run_directory(root)
    gates = []
    for gate in prior_gates:
        if gate["name"] in rerun_names:
            gates.append(gate_entry(gate["name"], directory))
        else:
            carried = dict(gate)
            # Mark prior-sourced records so the validator resolves their
            # logs in the prior manifest's directory.
            carried["log_source"] = "prior"
            gates.append(carried)
    print(f"Rerun of {prior_id}: re-executing {', '.join(sorted(rerun_names))}; "
          f"carrying {len(gates) - len(rerun_names)} prior gate(s)", flush=True)
    report = {"schema_version": 2, "evidence": evidence_block(root),
              "profiles": prior.get("profiles", []), "started_at": timestamp(),
              "status": "running", "source": before,
              "base": prior.get("base", "HEAD"),
              "changed_paths": prior.get("changed_paths", []),
              "reasons": prior.get("reasons", {}),
              "environment": {"platform": platform.platform(), "python": platform.python_version()},
              "limitations": LIMITATIONS,
              "rerun_of": str(prior_arg),
              "rerun_of_run_id": prior_id,
              "rerun_of_manifest": str(prior_path.resolve()),
              "rerun_gates": sorted(rerun_names),
              "gates": gates}
    return execute_report(root, report, directory, before, timeout, jobs)


def finalize(root, report, before, interrupted):
    """Close a finished report: closing snapshot, skip registry and coverage
    ratchet findings, and the final run status. Shared by fresh runs and
    reruns."""
    report["finished_at"] = timestamp()
    report["source_after"] = snapshot(root)
    unchanged = before == report["source_after"]
    # An explicit skip (exit 77, recorded reason) is neither a pass nor a
    # failure: it is a declared, visible absence of the runtime. NEXT-07
    # constrains WHICH skips are legitimate via the skip registry.
    report["skips"] = [{"name": g["name"], "exit_code": g["exit_code"],
                        "reason": g.get("skip_reason", "")}
                       for g in report["gates"] if g["status"] == "skipped"]
    # NEXT-07: validate test skips against the registry and coverage
    # against the ratchet baseline. Findings downgrade the run to failed.
    policy_findings = []
    skip_entries = parse_skips(root / "scripts/quality/skips.yaml")
    policy_findings.extend(validate_skips(report, skip_entries))
    cov_findings, _ = validate_coverage(report, root / "scripts/quality/coverage-baseline.json")
    policy_findings.extend(cov_findings)
    if policy_findings:
        report["policy_findings"] = policy_findings
    all_ok = all(g["status"] in ("passed", "skipped") for g in report["gates"])
    if policy_findings:
        report["status"] = "failed"
    else:
        report["status"] = ("interrupted" if interrupted else "stale" if not unchanged else
                            "passed" if all_ok else "failed")


def execute_report(root, report, directory, before, timeout, jobs=1):
    """Shared gate execution machinery for fresh runs and --rerun-failed;
    finalizes the manifest and returns the process exit code."""
    manifest = directory / "manifest.json"
    write_json(manifest, report)
    print(f"Quality evidence: {manifest}", flush=True)
    interrupted = False
    process_registry = ProcessRegistry()

    def execute_locked(gate, report_hook=None):
        resources = []
        if gate["name"] in HEAVY_GATES:
            resources.append("go")
        if gate["name"] in DOCKER_GATES:
            resources.append("docker")
        with cross_process_locks(root, resources, process_registry.cancelled) as acquired:
            if not acquired or process_registry.cancelled.is_set():
                gate["status"] = "pending"
                return gate
            return execute_gate(gate, gate["command"], root, directory / gate["log"],
                                timeout, report if report_hook is None else None,
                                directory, report_hook=report_hook,
                                process_registry=process_registry)

    try:
        if jobs <= 1:
            # Reference semantics (unchanged): strictly sequential. Carried
            # gates of a rerun are prior-run evidence: never re-executed.
            for gate in report["gates"]:
                if gate.get("log_source") == "prior":
                    continue
                execute_locked(gate)
                write_json(manifest, report)
        else:
            # (Go toolchains share caches/cores); Docker gates share a second
            # gates fill up to jobs concurrent lanes. Lock order is always
            # go→docker, so the two semaphores cannot deadlock. Manifest
            # writes are serialized.
            import concurrent.futures
            import threading
            manifest_lock = threading.Lock()
            heavy_sem = threading.Semaphore(1)
            docker_sem = threading.Semaphore(1)
            done_events = {gate["name"]: threading.Event() for gate in report["gates"]}

            def acquire_or_cancel(semaphore):
                while not process_registry.cancelled.is_set():
                    if semaphore.acquire(timeout=0.1):
                        return True
                return False

            def wait_for_dependencies(gate):
                # NEXT-14b: never serve a build while its producer gate may
                # still be wiping/rebuilding it (GATE_ORDER). Dependencies are
                # always earlier in the gate list, so no deadlock is possible.
                for dep in GATE_ORDER.get(gate["name"], ()):
                    event = done_events.get(dep)
                    if event is None:
                        continue
                    while not event.is_set():
                        if process_registry.cancelled.is_set():
                            return False
                        event.wait(timeout=0.1)
                return not process_registry.cancelled.is_set()

            def interrupt_pending_gate(gate):
                # This gate never started; preserve it as pending in evidence.
                gate["status"] = "pending"

            @contextmanager
            def acquire_lanes(semaphores):
                acquired = []
                try:
                    for semaphore in semaphores:
                        if not acquire_or_cancel(semaphore):
                            yield False
                            return
                        acquired.append(semaphore)
                    yield True
                finally:
                    for semaphore in reversed(acquired):
                        semaphore.release()

            def sched(gate):
                # NOTE: no manifest writes here — a single locked writer in
                # the completion loop keeps manifest.json consistent.
                def no_report(_gate, *_a):
                    pass
                name = gate["name"]
                if gate.get("log_source") == "prior":
                    # Carried rerun evidence: return immediately so its
                    # done-event is set for GATE_ORDER dependents.
                    return gate
                if not wait_for_dependencies(gate):
                    interrupt_pending_gate(gate)
                    return gate
                needs_go = name in HEAVY_GATES
                needs_docker = name in DOCKER_GATES
                lanes = ([heavy_sem] if needs_go else []) + ([docker_sem] if needs_docker else [])
                with acquire_lanes(lanes) as acquired:
                    if not acquired or process_registry.cancelled.is_set():
                        interrupt_pending_gate(gate)
                        return gate
                    return execute_locked(gate, report_hook=no_report)

            ex = concurrent.futures.ThreadPoolExecutor(max_workers=jobs)
            futures = {}
            try:
                for gate in report["gates"]:
                    futures[ex.submit(sched, gate)] = gate
                for fut in concurrent.futures.as_completed(futures):
                    fut.result()
                    done_events[futures[fut]["name"]].set()
                    with manifest_lock:
                        write_json(manifest, report)
            except KeyboardInterrupt:
                # Cancel before executor shutdown: workers must see cancellation
                # before acquiring lanes or launching their queued gate.
                interrupted = True
                process_registry.cancel()
                for future in futures:
                    future.cancel()
                process_registry.stop_all()
            finally:
                ex.shutdown(wait=True, cancel_futures=True)
    except KeyboardInterrupt:
        interrupted = True
        process_registry.cancel()
        process_registry.stop_all()
        for gate in report["gates"]:
            if gate["status"] == "running":
                gate.update(status="interrupted", exit_code=130)
                log_path = directory / gate["log"]
                if log_path.exists():
                    gate["log_sha256"] = hashlib.sha256(log_path.read_bytes()).hexdigest()
    finally:
        process_registry.attach_cleanup_warnings(report)
        finalize(root, report, before, interrupted)
        write_json(manifest, report)
    print(f"Quality result: {report['status']}; evidence: {manifest}", flush=True)
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    launch = sub.add_parser("run")
    launch.add_argument("profiles", nargs="*", choices=sorted(set(PROFILES) | LEAVES))
    launch.add_argument("--rerun-failed", dest="rerun_failed", type=Path, metavar="MANIFEST",
                        help="QR-1: re-execute only the failed gates of a prior failed or "
                             "interrupted run; passed and skipped gates are carried over as "
                             "prior-log evidence")
    changed = sub.add_parser("changed")
    changed.add_argument("--execute", action="store_true")
    for command in (launch, changed):
        command.add_argument("--base", help="Include changes since merge-base with this ref, plus working tree")
        command.add_argument("--timeout", type=int, default=1800, help="Per-gate timeout in seconds")
        command.add_argument("--jobs", type=int, default=1, help="NEXT-14: concurrent gate lanes (heavy Go gates never overlap; 1 = sequential reference)")
    verify = sub.add_parser("evidence")
    verify.add_argument("manifest", type=Path)
    verify.add_argument("--require", choices=sorted(set(PROFILES) | {"changed"}), default="full",
                        help="Required profile, or gates inferred from the current diff; defaults to full")
    verify.add_argument("--base", help="With --require changed: include committed changes since merge-base")
    args = parser.parse_args()
    root = repository()
    if args.action in ("run", "changed") and args.base is None \
            and not getattr(args, "rerun_failed", None):
        # QBASE1 (2026-11-02): the Makefile exports QUALITY_BASE for every
        # recipe, but only quality-changed passes --base explicitly — without
        # this default a full-profile manifest records base=HEAD and loses the
        # union's committed scope. Empty/unset keeps the HEAD behavior, an
        # explicit --base flag always wins, and a --rerun-failed run keeps
        # binding to its prior manifest's recorded base.
        args.base = os.environ.get("QUALITY_BASE") or None
    if args.action == "evidence":
        if args.base and args.require != "changed":
            parser.error("evidence --base requires --require changed")
        if args.require == "changed":
            paths, _ = changed_paths(root, args.base)
            required = list(classify(paths))
        else:
            required = expand([args.require])
        valid = verify_evidence(root, args.manifest, required)
        print("Evidence matches current source and logs" if valid else "Evidence failed, stale or modified")
        return 0 if valid else 1
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.action == "run" and args.rerun_failed:
        if args.base:
            parser.error("--rerun-failed cannot be combined with --base: a rerun binds to "
                         "the prior manifest's recorded base and source snapshot")
        return rerun(root, args.rerun_failed, args.timeout, jobs=getattr(args, "jobs", 1))
    if args.action == "run" and not args.profiles:
        parser.error("no gates selected: pass gates/profiles, or --rerun-failed MANIFEST")
    if args.action == "changed":
        paths, _ = changed_paths(root, args.base)
        reasons = classify(paths)
        print(json.dumps({"changed_paths": paths, "gates": reasons}, indent=2))
        if not args.execute:
            return 0
        return run(root, list(reasons), ["changed"], args.timeout, args.base, reasons, jobs=getattr(args, "jobs", 1))
    return run(root, expand(args.profiles), args.profiles, args.timeout, args.base, jobs=getattr(args, "jobs", 1))


if __name__ == "__main__":
    def interrupted_signal(*_):
        raise KeyboardInterrupt
    # SIGINT must be installed explicitly, not left to Python's
    # default_int_handler: POSIX async jobs of non-interactive shells (fleet
    # orchestrators, nohup scripts) inherit SIGINT as SIG_IGN, and Python
    # keeps an inherited SIG_IGN instead of installing the default handler —
    # so the CLI would silently ignore cancellation SIGINT for as long as
    # gates run (watchlist 2026-10-29 SIGINT self-gate flake class: SIGINT
    # variants failed only in background-launched covering gates). Installing
    # our own handler makes prompt-cancellation launch-context-independent
    # and identical for both POSIX stop signals.
    signal.signal(signal.SIGINT, interrupted_signal)
    signal.signal(signal.SIGTERM, interrupted_signal)
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"quality error: {error}", file=sys.stderr)
        sys.exit(2)
