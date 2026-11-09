#!/usr/bin/env python3
"""Offline-capable security support commands for local development.

The only networked operation is the explicit database update. Scans use
local, cached databases and never send a repository or lockfile to a service.
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
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
CACHE = Path(os.environ.get("YABANIN_SECURITY_CACHE",
                           Path.home() / ".cache" / "yabanin-security"))
GO_DB = CACHE / "govuln"
GO_DB_URL = "https://vuln.go.dev/vulndb.zip"
TRIVY = os.environ.get("TRIVY", str(Path.home() / "go" / "bin" / "trivy"))
TRIVY_DEFAULT_CACHE = (Path.home() / "Library" / "Caches" / "trivy"
                       if sys.platform == "darwin" else Path.home() / ".cache" / "trivy")
TRIVY_CACHE = Path(os.environ.get("TRIVY_CACHE_DIR", TRIVY_DEFAULT_CACHE))


def atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
    temp.replace(path)


def update_go_db() -> dict:
    CACHE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="govuln-db-", dir=CACHE) as temp_dir:
        temp = Path(temp_dir)
        archive_path = temp / "vulndb.zip"
        try:
            subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error",
                            "--max-time", "120", "--output", str(archive_path), GO_DB_URL],
                           check=True, timeout=150)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"could not download Go vulnerability database: {exc}") from exc
        archive = archive_path.read_bytes()
        digest = hashlib.sha256(archive).hexdigest()
        unpack = temp / "unpack"
        unpack.mkdir()
        try:
            with zipfile.ZipFile(__import__("io").BytesIO(archive)) as bundle:
                for member in bundle.infolist():
                    target = (unpack / member.filename).resolve()
                    if unpack.resolve() not in target.parents and target != unpack.resolve():
                        raise ValueError("vulnerability database contains an unsafe archive path")
                bundle.extractall(unpack)
        except (zipfile.BadZipFile, OSError) as exc:
            raise RuntimeError(f"could not unpack Go vulnerability database: {exc}") from exc
        if not (unpack / "index" / "db.json").is_file():
            raise RuntimeError("Go vulnerability database is missing index/db.json")
        modified = json.loads((unpack / "index" / "db.json").read_text()).get("modified")
        if not isinstance(modified, str) or not modified.endswith("Z"):
            raise RuntimeError("Go vulnerability database has no valid modified timestamp")
        staging = CACHE / "govuln.new"
        shutil.rmtree(staging, ignore_errors=True)
        shutil.copytree(unpack, staging)
        previous = CACHE / "govuln.old"
        shutil.rmtree(previous, ignore_errors=True)
        if GO_DB.exists():
            GO_DB.rename(previous)
        staging.rename(GO_DB)
        shutil.rmtree(previous, ignore_errors=True)
    from datetime import datetime, timezone
    metadata = {"fetched_at": datetime.now(timezone.utc).isoformat(),
                "modified": modified, "sha256": digest, "source": GO_DB_URL}
    atomic_json(CACHE / "govuln-metadata.json", metadata)
    return metadata


def update_trivy_db() -> dict:
    command = [TRIVY, "image", "--download-db-only", "--skip-java-db-update",
               "--skip-check-update", "--skip-version-check"]
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Trivy database update failed: {exc}") from exc
    if result.returncode:
        raise RuntimeError(f"Trivy database update exited {result.returncode}: "
                           f"{result.stderr[-500:]}")
    from datetime import datetime, timezone
    database = TRIVY_CACHE / "db"
    digest = hashlib.sha256()
    files = sorted(path for path in database.rglob("*") if path.is_file()) if database.exists() else []
    if not files:
        raise RuntimeError("Trivy reported success but no local vulnerability database was written")
    for path in files:
        digest.update(path.relative_to(database).as_posix().encode() + b"\0")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    metadata = {"fetched_at": datetime.now(timezone.utc).isoformat(),
                "database_sha256": digest.hexdigest(),
                "trivy_version": subprocess.run([TRIVY, "--version"], capture_output=True,
                                                text=True, check=True, timeout=30).stdout.splitlines()[0]}
    atomic_json(CACHE / "trivy-db-metadata.json", metadata)
    return metadata


def database_fresh(path: Path, max_age_hours: int = 24) -> bool:
    try:
        from datetime import datetime, timedelta, timezone
        metadata = json.loads(path.read_text())
        fetched = datetime.fromisoformat(metadata["fetched_at"])
        if fetched.tzinfo is None:
            return False
        age = datetime.now(timezone.utc) - fetched.astimezone(timezone.utc)
        return timedelta(0) <= age <= timedelta(hours=max_age_hours)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def database_update() -> int:
    from shutil import which
    if not Path(TRIVY).is_file() and not which(TRIVY):
        print(f"security database update failed: Trivy binary not found: {TRIVY}", file=sys.stderr)
        return 2
    try:
        go = update_go_db()
        trivy = update_trivy_db()
    except Exception as exc:  # all partial updates are explicit failures
        print(f"security database update failed: {exc}", file=sys.stderr)
        return 2
    print(f"Go vulnerability DB updated: {go['modified']} sha256={go['sha256']}")
    print(f"Trivy DB updated: {trivy['fetched_at']} ({trivy['trivy_version']})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("db-update", help="download/update local vulnerability databases")
    status = subparsers.add_parser("db-status", help="check local vulnerability database freshness")
    status.add_argument("--go-only", action="store_true",
                        help="check only the Go database for make analyze-security")
    args = parser.parse_args()
    if args.command == "db-update":
        return database_update()
    go_ok = database_fresh(CACHE / "govuln-metadata.json")
    trivy_ok = database_fresh(CACHE / "trivy-db-metadata.json")
    print(f"Go vulnerability DB: {'fresh' if go_ok else 'stale or missing'}")
    if args.go_only:
        return 0 if go_ok else 2
    print(f"Trivy DB: {'fresh' if trivy_ok else 'stale or missing'}")
    return 0 if go_ok and trivy_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
