#!/usr/bin/env python3
"""Commit-aware local security queue with isolated Git worktrees.

Commands: start/status/stop, one-shot scan, runtime, release, image, database
update/status. The background worker follows one explicitly selected branch.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "artifacts" / "security-local"
DB = STATE / "queue.sqlite3"
WORKTREES = STATE / "worktrees"
REPORTS = STATE / "reports"
PIDFILE = STATE / "worker.pid"
LOGFILE = STATE / "worker.log"
SCRIPT = Path(__file__).resolve()
POLL_SECONDS = 10
_active_child = None
_stopping = False


def git(*args, cwd=None, check=True):
    return subprocess.run(["git", *args], cwd=cwd or ROOT, capture_output=True,
                          text=True, check=check, timeout=60)


def active_ref() -> str:
    result = git("symbolic-ref", "-q", "HEAD", check=False)
    if result.returncode or not result.stdout.strip().startswith("refs/heads/"):
        raise RuntimeError("security worker needs an attached local branch")
    return result.stdout.strip()


def validate_ref(ref: str) -> str:
    if not ref.startswith("refs/heads/"):
        ref = "refs/heads/" + ref
    git("check-ref-format", ref)
    result = git("rev-parse", "--verify", f"{ref}^{{commit}}", check=False)
    if result.returncode:
        raise RuntimeError(f"local branch not found: {ref}")
    return ref


def connect():
    STATE.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS refs (
        ref TEXT PRIMARY KEY,
        observed_sha TEXT,
        completed_sha TEXT,
        pending_base TEXT,
        pending_head TEXT,
        status TEXT NOT NULL DEFAULT 'idle',
        updated_at TEXT NOT NULL,
        last_report TEXT
    )""")
    conn.commit()
    return conn


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def observe(conn, ref: str) -> None:
    result = git("rev-parse", "--verify", f"{ref}^{{commit}}", check=False)
    if result.returncode:
        conn.execute("UPDATE refs SET status='ref-missing', updated_at=? WHERE ref=?",
                     (timestamp(), ref))
        conn.commit()
        return
    head = result.stdout.strip()
    row = conn.execute("SELECT * FROM refs WHERE ref=?", (ref,)).fetchone()
    if row is None:
        conn.execute("INSERT INTO refs(ref, observed_sha, pending_head, status, updated_at) "
                     "VALUES (?, ?, ?, 'queued', ?)", (ref, head, head, timestamp()))
    elif row["observed_sha"] != head:
        pending_base = row["pending_base"] if row["pending_head"] else row["completed_sha"]
        conn.execute("UPDATE refs SET observed_sha=?, pending_base=?, pending_head=?, "
                     "status='queued', updated_at=? WHERE ref=?",
                     (head, pending_base, head, timestamp(), ref))
    conn.commit()


def db_fresh() -> bool:
    result = subprocess.run([sys.executable, str(ROOT / "scripts/security/local_security.py"),
                             "db-status"], cwd=ROOT, capture_output=True, text=True)
    return result.returncode == 0


def refresh_databases() -> tuple[bool, str]:
    if db_fresh():
        return True, "cached databases are fresh"
    result = subprocess.run([sys.executable, str(ROOT / "scripts/security/local_security.py"),
                             "db-update"], cwd=ROOT, capture_output=True, text=True, timeout=1800)
    detail = (result.stdout + result.stderr).strip()
    return result.returncode == 0, detail[-2000:]


def add_checkout(sha: str, run_id: str) -> Path:
    WORKTREES.mkdir(parents=True, exist_ok=True)
    path = WORKTREES / f"{sha}-{run_id}"
    git("worktree", "add", "--detach", str(path), sha)
    return path


def clean_checkout(path: Path) -> None:
    if not path.exists():
        return
    dirty = git("status", "--porcelain", "--untracked-files=all", cwd=path).stdout
    if dirty.strip():
        raise RuntimeError(f"owned security checkout is unexpectedly dirty: {path.name}")
    git("worktree", "remove", str(path))


def run_quality(checkout: Path, profile: str, base: str | None = None,
                image: str | None = None, image_id: str | None = None) -> tuple[int, dict | None, str]:
    global _active_child
    env = os.environ.copy()
    if base:
        env["SECURITY_BASE"] = base
    env["SECURITY_HEAD"] = git("rev-parse", "HEAD", cwd=checkout).stdout.strip()
    if image:
        env["SECURITY_IMAGE"] = image
        env["SECURITY_IMAGE_ID"] = image_id or ""
        # Keep raw image coverage evidence outside the disposable checkout.
        env["SECURITY_IMAGE_EVIDENCE_DIR"] = str(REPORTS / "image-audit")
    env["GOMAXPROCS"] = "4"
    env["GOFLAGS"] = ("-p=4 " + env.get("GOFLAGS", "")).strip()
    command = [sys.executable, "scripts/quality/quality.py", "run", profile, "--jobs", "2"]
    STATE.mkdir(parents=True, exist_ok=True)
    log_path = STATE / f"{env['SECURITY_HEAD']}-{profile}.log"
    with log_path.open("ab") as log:
        child = subprocess.Popen(command, cwd=checkout, env=env, stdout=log,
                                 stderr=subprocess.STDOUT)
        _active_child = child
        sent_interrupt = False
        while child.poll() is None:
            if _stopping and not sent_interrupt:
                child.send_signal(signal.SIGINT)
                sent_interrupt = True
            try:
                child.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                continue
        _active_child = None
        manifests = sorted((checkout / "artifacts/quality").glob("*/manifest.json"),
                           key=lambda p: p.stat().st_mtime_ns)
        manifest = None
        if manifests:
            try:
                candidate = json.loads(manifests[-1].read_text())
                if candidate.get("source", {}).get("commit") == env["SECURITY_HEAD"]:
                    candidate["_gate_log_dir"] = str(manifests[-1].parent)
                    manifest = candidate
            except (OSError, ValueError):
                pass
    try:
        output = log_path.read_text(errors="replace")[-5000:]
    except OSError:
        output = ""
    return child.returncode, manifest, output


def retryable_scanner_failure(manifest: dict) -> bool:
    scanner_gates = {"security", "deps", "secrets", "commit-secrets",
                     "history-secrets", "image-scan"}
    log_dir = Path(manifest.get("_gate_log_dir", ""))
    for gate in manifest.get("gates", []):
        if gate.get("name") not in scanner_gates:
            continue
        if gate.get("status") in ("error", "timeout", "interrupted", "pending", "skipped"):
            return True
        if gate.get("status") != "failed":
            continue
        try:
            contents = (log_dir / gate.get("log", "")).read_text(errors="replace").lower()
        except OSError:
            return True
        if any(marker in contents for marker in (
                "scanner error", "unavailable or timed out", "database is missing",
                "database update failed", "invalid json", "not found", "timed out")):
            return True
    return False


def run_sha(ref: str, base: str | None, sha: str, profile: str,
            image: str | None = None) -> dict:
    run_id = uuid.uuid4().hex[:10]
    checkout = add_checkout(sha, run_id)
    try:
        image_id = None
        if image:
            inspected = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", image],
                                       cwd=ROOT, capture_output=True, text=True, timeout=30)
            if inspected.returncode or not inspected.stdout.strip().startswith("sha256:"):
                return write_report({"status": "image-error", "ref": ref, "sha": sha,
                                     "base": base, "image": image})
            image_id = inspected.stdout.strip()
        db_ok, db_detail = refresh_databases()
        if not db_ok:
            result = {"status": "database-error", "details": db_detail,
                      "ref": ref, "sha": sha, "base": base}
            return write_report(result)
        code, manifest, output = run_quality(checkout, profile, base, image, image_id)
        if manifest is None:
            return write_report({"status": "evidence-error", "details": output,
                                 "ref": ref, "sha": sha, "base": base})
        retryable = retryable_scanner_failure(manifest)
        manifest.pop("_gate_log_dir", None)
        manifest_path = checkout / "artifacts/quality"
        manifest_files = sorted(manifest_path.glob("*/manifest.json"), key=lambda p: p.stat().st_mtime_ns)
        source_manifest = manifest_files[-1]
        REPORTS.mkdir(parents=True, exist_ok=True)
        # The manifest names its gate logs relative to its own directory.
        # Preserve that directory before deleting the disposable checkout.
        retained_dir = REPORTS / f"{sha}-{profile}-{source_manifest.parent.name}"
        shutil.copytree(source_manifest.parent, retained_dir)
        retained = retained_dir / "manifest.json"
        record = {"schema": 1,
                  "status": "passed" if code == 0 else "scanner-error" if retryable else "failed",
                  "ref": ref, "sha": sha, "base": base, "profile": profile,
                  "quality_manifest": str(retained.relative_to(ROOT)),
                  "manifest_sha256": hashlib.sha256(retained.read_bytes()).hexdigest(),
                  "database_status": db_detail, "updated_at": timestamp()}
        if image:
            record["image"] = image
            record["image_id"] = image_id
        record["scanner_versions"] = scanner_versions()
        record["vulnerability_databases"] = database_evidence()
        return write_report(record)
    finally:
        clean_checkout(checkout)


def write_report(record: dict) -> dict:
    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / f"{record['sha']}-{record.get('profile', 'security-code')}.json"
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(record, indent=2) + "\n")
    temp.replace(path)
    record["report"] = str(path.relative_to(ROOT))
    return record


def scanner_versions() -> dict:
    versions = {}
    for name, command in (
        ("govulncheck", [str(Path.home() / "go" / "bin" / "govulncheck"), "-version"]),
        ("trivy", [str(Path.home() / "go" / "bin" / "trivy"), "--version"]),
        ("gitleaks", [str(Path.home() / "go" / "bin" / "gitleaks"), "version"]),
    ):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            versions[name] = ((result.stdout or result.stderr).strip().splitlines()[0]
                              if result.returncode == 0 else "unavailable")
        except (OSError, subprocess.TimeoutExpired):
            versions[name] = "unavailable"
    return versions


def database_evidence() -> dict:
    result = {}
    cache = Path(os.environ.get("YABANIN_SECURITY_CACHE",
                                Path.home() / ".cache" / "yabanin-security"))
    for name, path in (
        ("govuln", cache / "govuln-metadata.json"),
        ("trivy", cache / "trivy-db-metadata.json"),
    ):
        try:
            result[name] = json.loads(path.read_text())
        except (OSError, ValueError):
            result[name] = {"status": "missing"}
    return result


def poll_once(ref: str) -> bool:
    conn = connect()
    try:
        observe(conn, ref)
        row = conn.execute("SELECT * FROM refs WHERE ref=?", (ref,)).fetchone()
        if not row or not row["pending_head"]:
            return False
        if row["status"] in ("database-error", "evidence-error", "image-error", "scanner-error"):
            updated = datetime.fromisoformat(row["updated_at"])
            if (datetime.now(timezone.utc) - updated.astimezone(timezone.utc)).total_seconds() < 300:
                return False
        base, sha = row["pending_base"], row["pending_head"]
        conn.execute("UPDATE refs SET status='running', updated_at=? WHERE ref=?",
                     (timestamp(), ref))
        conn.commit()
        result = run_sha(ref, base, sha, "security-code")
        completed = result["status"] in ("passed", "failed")
        if completed:
            conn.execute("UPDATE refs SET completed_sha=?, pending_base=NULL, pending_head=NULL, "
                         "status=?, updated_at=?, last_report=? WHERE ref=? AND pending_head=?",
                         (sha, result["status"], timestamp(), result.get("report"), ref, sha))
        else:
            conn.execute("UPDATE refs SET status=?, updated_at=?, last_report=? "
                         "WHERE ref=? AND pending_head=?",
                         (result["status"], timestamp(), result.get("report"), ref, sha))
        conn.commit()
        print(json.dumps(result, sort_keys=True), flush=True)
        return True
    finally:
        conn.close()


def worker(ref: str, once: bool = False) -> int:
    global _stopping

    def stop(_sig, _frame):
        global _stopping
        _stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not _stopping:
        try:
            did_work = poll_once(ref)
            if once:
                return 0 if did_work else 1
        except Exception as exc:
            print(f"security worker error: {exc}", file=sys.stderr, flush=True)
        for _ in range(POLL_SECONDS * 10):
            if _stopping:
                break
            time.sleep(0.1)
    return 0


def process_command_line(pid: int) -> str:
    try:
        return subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                              capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start", help="start background scanning of the current branch")
    start.add_argument("--ref")
    status = sub.add_parser("status", help="show worker and latest branch report")
    status.add_argument("--ref")
    stop = sub.add_parser("stop", help="stop the owned background worker")
    scan = sub.add_parser("scan", help="scan one immutable commit now")
    scan.add_argument("--ref", default=None)
    scan.add_argument("--head", default="HEAD")
    scan.add_argument("--base")
    runtime = sub.add_parser("runtime", help="run runtime tests against one immutable commit")
    runtime.add_argument("--head", default="HEAD")
    release = sub.add_parser("release", help="run release profile for a local image and commit")
    release.add_argument("--head", default="HEAD")
    release.add_argument("--image", required=True)
    worker_parser = sub.add_parser("_worker", help=argparse.SUPPRESS)
    worker_parser.add_argument("--ref", required=True)
    worker_parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "_worker":
            return worker(validate_ref(args.ref), args.once)
        if args.command == "start":
            ref = validate_ref(args.ref) if args.ref else active_ref()
            STATE.mkdir(parents=True, exist_ok=True)
            if PIDFILE.exists():
                try:
                    old_pid = int(PIDFILE.read_text().strip())
                except ValueError:
                    old_pid = -1
                if old_pid > 0 and str(SCRIPT) in process_command_line(old_pid):
                    print(f"security worker already running (pid {old_pid})")
                    return 0
            with LOGFILE.open("ab") as log:
                child = subprocess.Popen([sys.executable, str(SCRIPT), "_worker", "--ref", ref],
                                         cwd=ROOT, stdin=subprocess.DEVNULL,
                                         stdout=log, stderr=subprocess.STDOUT,
                                         start_new_session=True, close_fds=True)
            temp = PIDFILE.with_suffix(".tmp")
            temp.write_text(str(child.pid) + "\n")
            temp.replace(PIDFILE)
            print(f"security worker started (pid {child.pid}, ref {ref})")
            return 0
        if args.command == "stop":
            if not PIDFILE.exists():
                print("security worker is not running")
                return 0
            pid = int(PIDFILE.read_text().strip())
            if str(SCRIPT) not in process_command_line(pid):
                PIDFILE.unlink(missing_ok=True)
                print("removed stale worker pid file; no process was signalled")
                return 0
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and str(SCRIPT) in process_command_line(pid):
                time.sleep(0.2)
            if str(SCRIPT) in process_command_line(pid):
                raise RuntimeError("worker did not stop after SIGTERM; it was not force-killed")
            PIDFILE.unlink(missing_ok=True)
            print("security worker stopped")
            return 0
        if args.command == "status":
            if PIDFILE.exists():
                pid = int(PIDFILE.read_text().strip())
                alive = str(SCRIPT) in process_command_line(pid)
                print(f"worker: {'running' if alive else 'stopped'} (pid {pid})")
            else:
                print("worker: stopped")
            conn = connect()
            try:
                ref = validate_ref(args.ref) if args.ref else active_ref()
                row = conn.execute("SELECT * FROM refs WHERE ref=?", (ref,)).fetchone()
                if row:
                    print(json.dumps(dict(row), indent=2))
                else:
                    print(f"no scan recorded for {ref}")
            finally:
                conn.close()
            return 0
        if args.command == "scan":
            ref = validate_ref(args.ref) if args.ref else "detached"
            sha = git("rev-parse", "--verify", f"{args.head}^{{commit}}").stdout.strip()
            result = run_sha(ref, args.base, sha, "security-code")
            print(json.dumps(result, indent=2))
            return 0 if result["status"] == "passed" else 1
        if args.command in ("runtime", "release"):
            sha = git("rev-parse", "--verify", f"{args.head}^{{commit}}").stdout.strip()
            profile = "security-runtime" if args.command == "runtime" else "security-release"
            image = getattr(args, "image", None)
            result = run_sha("detached", None, sha, profile, image)
            print(json.dumps(result, indent=2))
            return 0 if result["status"] == "passed" else 1
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        print(f"security worker: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
