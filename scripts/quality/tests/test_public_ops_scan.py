# SPDX-License-Identifier: Apache-2.0
# Adapted from Yabanin's Apache-2.0 artifact-verification regression suite.
"""Hermetic behavior tests for the delivered-bytes scanner.

Everything runs against fixtures: a fake docker (save/history) and a fake
npm (pack) that build real tar archives from per-test directory trees, so
the scanner's actual unpacking, layer-walking and pattern logic is exercised
without any daemon, network or real registry.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


FAKE_DOCKER = r'''#!/usr/bin/env python3
import io, json, os, pathlib, sys, tarfile
args = sys.argv[1:]
if args[0] == "info":
    if os.environ.get("SCAN_FAIL_INFO"): sys.exit(1)
    sys.exit(0)
if args[0] == "history":
    ref = args[-1]
    env_name = "SCAN_HISTORY_DASHBOARD" if "dashboard" in ref else "SCAN_HISTORY_ROOT"
    text = os.environ.get(env_name) or 'RUN /bin/sh -c apk add --no-cache ca-certificates curl\nCMD ["/bin/sh"]\n'
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
    sys.exit(0)
if args[0] == "save":
    if os.environ.get("SCAN_FAIL_SAVE"): sys.exit(1)
    out = args[args.index("-o") + 1]
    profile = "dashboard" if "dashboard" in args[-1] else "root"
    if os.environ.get("SCAN_CORRUPT_SAVE"):
        pathlib.Path(out).write_bytes(b"not an image tar archive")
        sys.exit(0)
    if os.environ.get("SCAN_EMPTY_SAVE"):
        with tarfile.open(out, "w") as outer:
            manifest = json.dumps({"SchemaVersion": 2}).encode()
            info = tarfile.TarInfo("manifest.json"); info.size = len(manifest)
            outer.addfile(info, io.BytesIO(manifest))
        sys.exit(0)
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as lt:
        root = os.environ.get("SCAN_LAYER_ROOT")
        source = pathlib.Path(root) / profile if root else None
        if source and source.is_dir():
            for path in sorted(source.rglob("*")):
                lt.add(path, arcname=str(path.relative_to(source)), recursive=False)
        else:
            for name, data in (("etc/os-release", b"NAME=fixture\n"), ("app/yabanin", b"binary\n")):
                info = tarfile.TarInfo(name); info.size = len(data)
                lt.addfile(info, io.BytesIO(data))
    with tarfile.open(out, "w") as outer:
        blob = layer.getvalue()
        info = tarfile.TarInfo("layer0/layer.tar"); info.size = len(blob)
        outer.addfile(info, io.BytesIO(blob))
        manifest = json.dumps({"SchemaVersion": 2}).encode()
        info = tarfile.TarInfo("manifest.json"); info.size = len(manifest)
        outer.addfile(info, io.BytesIO(manifest))
    sys.exit(0)
sys.exit(2)
'''

FAKE_NPM = r'''#!/usr/bin/env python3
import io, json, os, pathlib, sys, tarfile
if len(sys.argv) > 1 and sys.argv[1] == "pack":
    dest = pathlib.Path(sys.argv[sys.argv.index("--pack-destination") + 1])
    tarball = "fixture-pkg-1.0.0.tgz"
    with tarfile.open(dest / tarball, "w:gz") as tf:
        root = os.environ.get("SCAN_NPM_PACK_ROOT")
        if root and os.path.isdir(root):
            base = pathlib.Path(root)
            for path in sorted(base.rglob("*")):
                tf.add(path, arcname="package/" + str(path.relative_to(base)), recursive=False)
        else:
            data = b'{"name":"fixture"}\n'
            info = tarfile.TarInfo("package/package.json"); info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    print(json.dumps([{"filename": tarball}]))
    sys.exit(0)
sys.exit(2)
'''

# Shell utilities the scanner script invokes besides docker/npm. The sandbox
# PATH links exactly these into a private dir, so tool presence is decided
# only by which fake dirs a test installs — never by host /usr/bin content.
SANDBOX_TOOLS = ("bash", "cat", "dirname", "mkdir", "mktemp", "rm", "tee")


class ScanDeliveredBytesTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scan-delivered-bytes-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, source in (("docker", FAKE_DOCKER), ("npm", FAKE_NPM)):
            path = self.bin / name
            path.write_text(source)
            path.chmod(0o755)
        self.sysbin = self.root / "sysbin"
        self.sysbin.mkdir()
        for name in SANDBOX_TOOLS:
            resolved = shutil.which(name, path="/usr/bin:/bin")
            if resolved is None:
                raise AssertionError(f"sandbox tool missing on this host: {name}")
            os.symlink(resolved, self.sysbin / name)
        os.symlink(sys.executable, self.sysbin / "python3")
        quality = self.root / "scripts/quality"
        quality.mkdir(parents=True)
        source = Path(__file__).resolve().parent.parent.joinpath("scan_delivered_bytes.sh")
        self.script = quality / "scan_delivered_bytes.sh"
        shutil.copy2(source, self.script)
        self.script.chmod(0o755)
        self.allow = quality / "scan_delivered_bytes.allow"
        self.allow.write_text("# test allowlist\n")
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()
        sdk = self.root / "sdks/node"
        sdk.mkdir(parents=True)
        (sdk / "package.json").write_text('{"name":"fixture-sdk"}\n')

    def write(self, base, files):
        for rel, (data, mode) in files.items():
            path = self.root / base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            if mode is not None:
                path.chmod(mode)
        return str(self.root / base)

    def env(self, toolset="all", **overrides):
        # Hermetic PATH: only test-controlled directories. Single-tool sets
        # get private dirs holding symlinks to the shared fakes; sysbin carries
        # the interpreter and shell utilities the scanner itself needs. Host
        # binary directories never appear, so an absent docker/npm is a
        # property of the sandbox, not of the machine running the tests.
        search = []
        if toolset == "all":
            search.append(str(self.bin))
        else:
            for tool in ("docker-only", "npm-only"):
                if toolset == tool:
                    lone = self.bin / tool
                    lone.mkdir(exist_ok=True)
                    os.symlink(self.bin / tool.split("-")[0], lone / tool.split("-")[0])
                    search.append(str(lone))
        search.append(str(self.sysbin))
        env = dict(os.environ)
        env["PATH"] = os.pathsep.join(dict.fromkeys(search))
        env.update({key: str(value) for key, value in overrides.items() if value is not None})
        return env

    def run_scan(self, toolset="all", profile="dashboard", **overrides):
        return subprocess.run(
            [str(self.script), "--out", str(self.root / "out"), "--npm-pack", "sdks/node",
             "--image", "yabanin-root:test", "--profile", "root",
             "--image", "yabanin-dashboard:test", "--profile", profile],
            cwd=self.root, env=self.env(toolset=toolset, **overrides),
            capture_output=True, text=True, timeout=90)

    def report(self):
        return (self.root / "out/report.txt").read_text()

    def test_clean_run_passes_and_records_provenance(self):
        result = self.run_scan()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = self.report()
        for stage in ("npm\t", "image:root\t", "image:dashboard\t"):
            self.assertIn(stage, report)
        self.assertIn("sha256=", report)
        self.assertIn("layers=", report)
        self.assertNotIn("FAIL\t", report)
        self.assertNotIn("SKIP\t", report)
        self.assertIn("delivered-bytes scan: clean", result.stdout)

    def test_npm_secret_content_fails_redacted(self):
        secret = b"sk-" + b"abcabcabcabcabcabcabc123"
        pack = self.write("fixtures/npm-secret", {"src/client.ts": (b'const k = "' + secret + b'";\n', None)})
        result = self.run_scan(SCAN_NPM_PACK_ROOT=pack)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = self.report()
        self.assertIn("secret-content", report)
        self.assertIn("rule=openai-key", report)
        self.assertNotIn(secret.decode(), report)
        self.assertNotIn(secret.decode(), result.stdout + result.stderr)

    def test_npm_git_dir_fails(self):
        pack = self.write("fixtures/npm-git", {".git/config": (b"[core]\n", None)})
        result = self.run_scan(SCAN_NPM_PACK_ROOT=pack)
        self.assertEqual(result.returncode, 1)
        self.assertIn("git-dir", self.report())

    def test_npm_executable_fails(self):
        pack = self.write("fixtures/npm-exec", {"src/run.ts": (b"x\n", 0o755)})
        result = self.run_scan(SCAN_NPM_PACK_ROOT=pack)
        self.assertEqual(result.returncode, 1)
        self.assertIn("executable", self.report())

    def test_npm_oversized_fails(self):
        pack = self.write("fixtures/npm-big", {"src/big.ts": (b"0" * (2 * 1024 * 1024 + 512), None)})
        result = self.run_scan(SCAN_NPM_PACK_ROOT=pack)
        self.assertEqual(result.returncode, 1)
        self.assertIn("oversized", self.report())

    def test_npm_unexpected_class_fails(self):
        pack = self.write("fixtures/npm-class", {"evil.exe": (b"mz\n", None), "etc/x.txt": (b"x\n", None)})
        result = self.run_scan(SCAN_NPM_PACK_ROOT=pack)
        self.assertEqual(result.returncode, 1)
        report = self.report()
        self.assertIn("unexpected-class", report)
        self.assertIn("evil.exe", report)
        self.assertIn("etc/x.txt", report)

    def test_layer_git_dir_fails(self):
        layers = self.write("fixtures/lay-git", {"root/.git/config": (b"[core]\n", None)})
        result = self.run_scan(SCAN_LAYER_ROOT=layers)
        self.assertEqual(result.returncode, 1)
        self.assertIn("git-dir", self.report())

    def test_layer_credential_shapes_fail(self):
        layers = self.write("fixtures/lay-cred", {
            "root/etc/id_rsa": (b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\n", None),
            "root/.ssh/known_hosts": (b"host\n", None),
            # The suffix branch must be alive on its own (regression: the
            # first regex revision fused it into a dead alternative).
            "root/app/tls/server.pem": (b"-----BEGIN " + b"PRIVATE KEY-----\n", None),
            "root/app/tls/server.key": (b"-----BEGIN " + b"PRIVATE KEY-----\n", None),
        })
        result = self.run_scan(SCAN_LAYER_ROOT=layers)
        self.assertEqual(result.returncode, 1)
        report = self.report()
        self.assertIn("credential-file", report)
        self.assertIn("credential-dir", report)
        self.assertIn("server.pem", report)
        self.assertIn("server.key", report)

    def test_layer_public_trust_store_pem_is_not_a_finding(self):
        layers = self.write("fixtures/lay-store", {
            "root/etc/ssl/certs/ca-cert-ISRG_Root_X1.pem": (b"public ca\n", None),
            "root/etc/ssl/cert.pem": (b"public bundle\n", None),
            "root/etc/ssl1.1/cert.pem": (b"public bundle\n", None),
            # Private material in the private dir stays a finding.
            "root/etc/ssl/private/server.pem": (b"-----BEGIN " + b"PRIVATE KEY-----\n", None),
        })
        result = self.run_scan(SCAN_LAYER_ROOT=layers)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = self.report()
        self.assertNotIn("ca-cert-ISRG_Root_X1.pem", report)
        self.assertNotIn("etc/ssl/cert.pem", report)
        self.assertNotIn("etc/ssl1.1", report)
        self.assertIn("etc/ssl/private/server.pem", report)

    def test_layer_node_modules_fails(self):
        layers = self.write("fixtures/lay-nm", {"root/node_modules/left-pad/index.js": (b"module.exports=1\n", None)})
        result = self.run_scan(SCAN_LAYER_ROOT=layers)
        self.assertEqual(result.returncode, 1)
        self.assertIn("node_modules", self.report())

    def test_layer_package_manager_caches_fail(self):
        layers = self.write("fixtures/lay-cache", {
            "root/var/cache/apt/pkg.bin": (b"x\n", None),
            "root/var/lib/apt/lists/main": (b"x\n", None),
            "root/root/.npm/_cacache/index": (b"x\n", None),
            "root/root/.cache/pip/entry": (b"x\n", None),
        })
        result = self.run_scan(SCAN_LAYER_ROOT=layers)
        self.assertEqual(result.returncode, 1)
        report = self.report()
        self.assertEqual(report.count("build-cache"), 4)

    def test_layer_sourcemap_in_deliverable_fails(self):
        layers = self.write("fixtures/lay-map", {
            "dashboard/usr/share/nginx/html/assets/app.js.map": (b"{}\n", None)})
        result = self.run_scan(SCAN_LAYER_ROOT=layers)
        self.assertEqual(result.returncode, 1)
        self.assertIn("sourcemap", self.report())

    def test_layer_secret_content_fails_redacted(self):
        secret = b"AKIA" + b"1234567890ABCDEF"
        layers = self.write("fixtures/lay-secret", {"root/etc/app.ini": (b"key=" + secret + b"\n", None)})
        result = self.run_scan(SCAN_LAYER_ROOT=layers)
        self.assertEqual(result.returncode, 1)
        report = self.report()
        self.assertIn("secret-content", report)
        self.assertIn("rule=aws-access-key", report)
        self.assertNotIn(secret.decode(), report)

    def test_history_leaks_fail(self):
        leaks = {
            "--secret flag": "RUN /bin/sh -c something --secret=id_rsa.properties",
            "-e KEY=VALUE": "RUN /bin/sh -c true -e OPENAI_API_KEY=sk-abcabcabcabcabcabc",
            "--build-arg value": "RUN /bin/sh -c build --build-arg GH_TOKEN=abc123",
            "credential env literal": "ENV API_SECRET=hardcoded42",
            "secret literal": "RUN /bin/sh -c echo sk-" + "abcabcabcabcabcabc99",
        }
        for name, line in leaks.items():
            with self.subTest(leak=name):
                result = self.run_scan(SCAN_HISTORY_ROOT=line + "\n")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("history-", self.report())
                # Leak evidence is redacted: the value never reaches stdout,
                # stderr or the report.
                combined = result.stdout + result.stderr + self.report()
                self.assertNotIn("sk-abcabcabcabcabcabc", combined)
                self.assertNotIn("hardcoded42", combined)
                self.assertNotIn("GH_TOKEN=abc123", combined)

    def test_save_without_layers_fails_closed(self):
        result = self.run_scan(SCAN_EMPTY_SAVE=1)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no-layers", self.report())

    def test_corrupt_saved_image_fails_closed(self):
        result = self.run_scan(SCAN_CORRUPT_SAVE=1)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("delivered-bytes scan: clean", result.stdout)

    def test_docker_save_error_fails_closed(self):
        result = self.run_scan(SCAN_FAIL_SAVE=1)
        self.assertEqual(result.returncode, 1)
        self.assertIn("docker save failed", self.report())

    def test_absent_docker_is_loud_skip_not_pass(self):
        result = self.run_scan(toolset="npm-only")
        self.assertEqual(result.returncode, 77)
        self.assertIn("SKIP", result.stderr)
        self.assertIn("docker", result.stderr)
        report = self.report()
        self.assertIn("SKIP\timage:root", report)
        self.assertIn("SKIP\timage:dashboard", report)
        self.assertIn("npm\t", report)
        self.assertNotIn("delivered-bytes scan: clean", result.stdout)

    def test_absent_npm_is_loud_skip_not_pass(self):
        result = self.run_scan(toolset="docker-only")
        self.assertEqual(result.returncode, 77)
        self.assertIn("npm not found", result.stderr)
        # The docker-backed stages still ran: a skip never masks the others.
        self.assertIn("INFO\timage:root\t", self.report())
        self.assertIn("INFO\timage:dashboard\t", self.report())

    def test_allowlist_suppresses_matching_finding_only(self):
        pack = self.write("fixtures/npm-big", {"src/big.ts": (b"0" * (2 * 1024 * 1024 + 512), None)})
        self.allow.write_text("npm oversized src/big.ts\n")
        result = self.run_scan(SCAN_NPM_PACK_ROOT=pack)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALLOWED\tnpm\toversized\tsrc/big.ts", self.report())

        self.allow.write_text("npm executable src/big.ts\n")
        result = self.run_scan(SCAN_NPM_PACK_ROOT=pack)
        self.assertEqual(result.returncode, 1)
        report = self.report()
        self.assertIn("oversized", report)

    def test_large_layer_secret_and_chunk_boundary_are_not_skipped(self):
        secret = b"AKIA" + b"1234567890ABCDEF"
        for prefix in [1024 * 1024 - 10, 9 * 1024 * 1024]:
            with self.subTest(prefix=prefix):
                layers = self.write("fixtures/large", {"root/app/large.bin": (b"!" * prefix + secret + b"\n", None)})
                result = self.run_scan(SCAN_LAYER_ROOT=layers)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("secret-content", self.report())
                self.assertNotIn(secret.decode(), self.report())

    def test_apk_cache_is_rejected(self):
        layers = self.write("fixtures/apk-cache", {"root/var/cache/apk/cached.apk": (b"cached archive", None)})
        result = self.run_scan(SCAN_LAYER_ROOT=layers)
        self.assertEqual(result.returncode, 1)
        self.assertIn("build-cache", self.report())

    def test_malformed_allowlist_fails_with_diagnostic(self):
        self.allow.write_text("bad-line\n")
        result = self.run_scan()
        self.assertEqual(result.returncode, 1)
        self.assertIn("malformed-entry", self.report())
        self.assertNotIn("Traceback", result.stderr)

    def test_empty_selection_is_not_a_clean_scan(self):
        result = subprocess.run([str(self.script), "--out", str(self.root / "out")],
                                cwd=self.root, env=self.env(), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)

    def test_stale_allowlist_entry_fails(self):
        self.allow.write_text("npm oversized src/gone.bin\n")
        result = self.run_scan()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("stale-allow", self.report())
        self.assertIn("drift", self.report())

    def test_unknown_profile_is_usage_error(self):
        result = self.run_scan(profile="bogus")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown image profile", result.stderr)


if __name__ == "__main__":
    unittest.main()
