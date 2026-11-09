#!/usr/bin/env python3
"""Install hash-pinned Trivy and Gitleaks release binaries (macOS/Linux)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "scripts/security/scanner-lock.json"


def install(name: str, spec: dict, target: Path, system: str, machine: str) -> dict:
    asset_record = spec["assets"].get(f"{system}/{machine}")
    if not asset_record:
        raise RuntimeError(f"no pinned {name} binary for {system}/{machine}")
    filename, expected_sha = asset_record
    owner = "aquasecurity/trivy" if name == "trivy" else "gitleaks/gitleaks"
    tag = "v" + spec["version"]
    url = f"https://github.com/{owner}/releases/download/{tag}/{filename}"
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"{name}-install-") as temp_dir:
        archive_path = Path(temp_dir) / filename
        try:
            subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error",
                            "--output", str(archive_path), url], check=True, timeout=600)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"could not download pinned {name} asset: {exc}") from exc
        actual_sha = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            raise RuntimeError(f"{name} release checksum mismatch: {actual_sha}")
        try:
            with tarfile.open(archive_path, "r:gz") as archive:
                candidates = [member for member in archive.getmembers()
                              if Path(member.name).name == name and member.isfile()]
                if len(candidates) != 1:
                    raise RuntimeError(f"pinned {name} archive does not contain one {name} binary")
                stream = archive.extractfile(candidates[0])
                if stream is None:
                    raise RuntimeError(f"could not read {name} binary from its archive")
                binary = stream.read()
        except (OSError, tarfile.TarError) as exc:
            raise RuntimeError(f"invalid {name} archive: {exc}") from exc
        staged = target.with_suffix(target.suffix + ".new")
        staged.write_bytes(binary)
        staged.chmod(0o755)
        os.replace(staged, target)
    return {"version": spec["version"], "asset": filename,
            "sha256": expected_sha, "source": url}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        lock = json.loads(LOCK.read_text())
        if lock.get("schema") != 1 or set(lock.get("scanners", {})) != {"trivy", "gitleaks"}:
            raise ValueError("unsupported scanner lock schema")
        system = platform.system().lower()
        machine = platform.machine().lower()
        if machine == "x86_64":
            machine = "amd64"
        elif machine in ("aarch64", "arm64"):
            machine = "arm64"
        metadata = {}
        for name, spec in lock["scanners"].items():
            metadata[name] = install(name, spec, args.bin_dir / name, system, machine)
        metadata_path = ROOT / "artifacts/security-local/scanner-install.json"
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        temp = metadata_path.with_suffix(".tmp")
        temp.write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
        temp.replace(metadata_path)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print(f"security scanner install failed: {exc}", file=__import__("sys").stderr)
        return 2
    print(f"Installed hash-verified Trivy {metadata['trivy']['version']} and "
          f"Gitleaks {metadata['gitleaks']['version']} to {args.bin_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
