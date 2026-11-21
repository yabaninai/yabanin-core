"""Bounded, self-contained provisioning for the pinned Syft scanner.

RELEASE-SYFT-PORTABILITY: the real-scanner controls in test_release_artifacts
must run on any ordinary checkout or CI runner, not only on machines that
already carry the scanner. Resolution order:

1. SYFT_BIN (explicit; the exact pin is verified — a wrong scanner fails)
2. PATH lookup (same exact pin verification)
3. provision: download the OFFICIAL pinned release archive from the single
   upstream GitHub release URL, verify its reviewed exact SHA-256, extract it
   with a safe (traversal/absolute/symlink-rejecting) tar filter into a
   caller-owned per-test temp directory, and verify the extracted binary
   self-identifies as the pin from its own `version` output.

Stdlib only. No global install, no new dependency, no publication channel:
everything lands in per-test (or per-process cache) temp directories that are
removed with the test run. A missing, wrong-version or unreachable tool is an
explicit failure — these controls never skip.
"""

import atexit
import hashlib
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

SYFT_PIN = "1.57.2"
SYFT_PIN_GIT_COMMIT = "1a72047fd46c72e0a12ee77e24b23d2316753d08"
SYFT_RELEASE_BASE = f"https://github.com/anchore/syft/releases/download/v{SYFT_PIN}"
# Reviewed exact SHA-256 digests of the official v1.57.2 release archives,
# cross-checked against syft_1.57.2_checksums.txt published in the same
# release. linux_amd64 was additionally verified end-to-end: this archive
# extracts to binary sha256 17cc40c1e40dbfdeb8c84b6d9928909bceb793f22e8a80
# 23ef408625f1d96ec5, the exact pinned scanner behind the offline
# determinism evidence. The others are pinned from the checksums file for
# ordinary darwin/arm64 checkouts; each is verified on first use.
SYFT_ARCHIVE_SHA256 = {
    ("linux", "amd64"):
        "ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b",
    ("linux", "arm64"):
        "8efe605309c98798e1ee0cffdcf8c05ca26819b4cd44c0b03650f1e963e9bdb6",
    ("darwin", "amd64"):
        "73c6100bc43fbcc1c99aed3428d859c6289c4076be7e296dde7e427324c15908",
    ("darwin", "arm64"):
        "38afbcc03a9d9afac2d7572432fd2c435e051e03930582ea90f4710ffb515224",
}
# Official archives are ~10-30 MiB; anything past this bound is not the
# pinned artifact and is refused instead of written unbounded to disk.
SYFT_ARCHIVE_MAX_BYTES = 128 * 1024 * 1024
SYFT_DOWNLOAD_TIMEOUT_S = 120


class SyftProvisionError(RuntimeError):
    """Provisioning failed; the real-scanner controls fail on this, never
    skip."""


def platform_key():
    system = platform.system().lower()
    machine = platform.machine().lower()
    machine = {"x86_64": "amd64", "amd64": "amd64",
               "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
    key = (system, machine)
    if key not in SYFT_ARCHIVE_SHA256:
        raise SyftProvisionError(
            f"no official pinned syft {SYFT_PIN} archive for {system}/{machine}; "
            "install the pinned scanner and set SYFT_BIN (real-scanner "
            "controls never skip)")
    return key


def archive_url_and_sha256(key=None):
    key = platform_key() if key is None else key
    name = f"syft_{SYFT_PIN}_{key[0]}_{key[1]}.tar.gz"
    return f"{SYFT_RELEASE_BASE}/{name}", SYFT_ARCHIVE_SHA256[key]


def download_file(url, dest, *, timeout=SYFT_DOWNLOAD_TIMEOUT_S,
                  max_bytes=SYFT_ARCHIVE_MAX_BYTES):
    dest = Path(dest)
    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "yabanin-quality-self/1.0"})
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            with open(dest, "wb") as out:
                size = 0
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_bytes:
                        raise SyftProvisionError(
                            f"archive exceeds {max_bytes} bytes: {url}")
                    out.write(chunk)
    except SyftProvisionError:
        raise
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SyftProvisionError(f"download failed: {url}: {exc}") from exc
    return dest


def verify_sha256(path, expected, *, label="archive"):
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if digest != expected:
        raise SyftProvisionError(
            f"{label} sha256 mismatch for {path}: got {digest}, "
            f"expected {expected}")
    return digest


def extract_syft_archive(archive, dest_dir):
    """Safely extract the pinned archive; refuse traversal, absolute escapes,
    non-regular members. Returns the top-level syft binary path."""
    archive, dest_dir = Path(archive), Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, "r:gz") as tf:
            try:
                tf.extractall(dest_dir, filter="data")
            except TypeError:
                # Python without PEP 706 extraction filters: validate every
                # member by hand before the classic extractall.
                root = dest_dir.resolve()
                for member in tf.getmembers():
                    if member.isdir():
                        continue
                    if not member.isreg():
                        raise SyftProvisionError(
                            f"non-regular archive member rejected: {member.name}")
                    target = (dest_dir / member.name).resolve()
                    if os.path.commonpath([str(root), str(target)]) != str(root):
                        raise SyftProvisionError(
                            f"unsafe archive member rejected: {member.name}")
                tf.extractall(dest_dir)
    except tarfile.TarError as exc:
        raise SyftProvisionError(
            f"unsafe or malformed syft archive ({archive}): {exc}") from exc
    syft = dest_dir / "syft"
    if not syft.is_file():
        raise SyftProvisionError(
            f"archive did not contain a top-level syft binary: {archive}")
    syft.chmod(syft.stat().st_mode | 0o111)
    return syft


def verify_pinned_syft(case, syft_bin):
    """The scanner must BE the required pin, verified from its own version
    output — a different scanner changes SPDX facts and is an explicit
    failure, never a skip."""
    proc = subprocess.run([str(syft_bin), "version"], capture_output=True,
                          text=True)
    case.assertEqual(proc.returncode, 0,
                     f"syft version failed: {proc.stdout}{proc.stderr}")
    fields = dict(re.findall(r"^([A-Za-z]+):\s*(.*)$", proc.stdout, re.M))
    case.assertEqual(fields.get("Version", "").strip(), SYFT_PIN,
                     f"syft Version {fields.get('Version')!r} != required pin {SYFT_PIN!r}")
    case.assertEqual(fields.get("GitCommit", "").strip(), SYFT_PIN_GIT_COMMIT,
                     "syft GitCommit does not match the required pinned scanner")


# One verified archive download per process (the suite runs several
# real-scanner controls; the archive is re-verified and re-extracted per
# call). The cache lives in a process-owned temp directory removed at exit —
# no machine-global state.
_ARCHIVE_CACHE = {}
_ARCHIVE_CACHE_DIR = None


def _cached_archive(url, sha256):
    global _ARCHIVE_CACHE_DIR
    key = (url, sha256)
    cached = _ARCHIVE_CACHE.get(key)
    if cached is not None and cached.is_file():
        return cached
    if _ARCHIVE_CACHE_DIR is None:
        _ARCHIVE_CACHE_DIR = Path(tempfile.mkdtemp(prefix="syft-pin-cache-"))
        atexit.register(shutil.rmtree, _ARCHIVE_CACHE_DIR,
                        ignore_errors=True)
    dest = _ARCHIVE_CACHE_DIR / (
        hashlib.sha256(f"{url}\n{sha256}".encode()).hexdigest() + ".tar.gz")
    download_file(url, dest)
    verify_sha256(dest, sha256, label="downloaded archive")
    _ARCHIVE_CACHE[key] = dest
    return dest


def provision_pinned_syft(case=None, *, url=None, sha256=None):
    """Download + verify + extract the official pinned archive into a
    caller-owned per-call temp directory (registered for cleanup when `case`
    is given). Returns the extracted syft binary path. Explicit url/sha256
    overrides exist for the offline fake-archive controls."""
    default_url, default_sha = archive_url_and_sha256()
    url = default_url if url is None else url
    sha256 = default_sha if sha256 is None else sha256
    dest = Path(tempfile.mkdtemp(prefix="syft-provision-"))
    if case is not None:
        case.addCleanup(shutil.rmtree, dest, ignore_errors=True)
    archive = dest / "syft-archive.tar.gz"
    if (url, sha256) == (default_url, default_sha):
        shutil.copy2(_cached_archive(url, sha256), archive)
    else:
        download_file(url, archive)
    verify_sha256(archive, sha256, label="archive")
    return extract_syft_archive(archive, dest / "extracted")


def locate_pinned_syft(case, env=None, provisioner=None):
    """Resolve the pinned scanner for the real-scanner controls.

    SYFT_BIN first, then PATH — each candidate must BE the exact pin or the
    control fails. Otherwise the bounded provisioning leaf runs (unless
    provisioner=False requests pure discovery, in which case a missing
    scanner is an explicit failure). The provisioned binary is pinned-verified
    exactly like an explicit one."""
    env = dict(env if env is not None else os.environ)
    candidates = []
    if env.get("SYFT_BIN"):
        candidates.append(Path(env["SYFT_BIN"]))
    which = shutil.which("syft", path=env.get("PATH"))
    if which:
        candidates.append(Path(which))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            verify_pinned_syft(case, candidate)
            return candidate
    if provisioner is False:
        case.fail(f"required pinned syft {SYFT_PIN} ({SYFT_PIN_GIT_COMMIT}) not "
                  "found via SYFT_BIN or PATH — real-scanner controls never skip")
    provision = provision_pinned_syft if provisioner is None else provisioner
    try:
        syft_bin = provision(case)
    except SyftProvisionError as exc:
        case.fail(f"pinned syft {SYFT_PIN} ({SYFT_PIN_GIT_COMMIT}) not found "
                  f"via SYFT_BIN/PATH and provisioning failed: {exc} — set "
                  "SYFT_BIN to the pinned scanner or make the pinned archive "
                  "reachable; real-scanner controls never skip")
    verify_pinned_syft(case, syft_bin)
    return Path(syft_bin)
