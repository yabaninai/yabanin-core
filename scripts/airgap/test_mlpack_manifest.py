"""Behavior tests for scripts/airgap/mlpack_manifest.sh (N11-P04-T02).

The card pins the JSON digest manifest of ML model packs (R058):
sha256 per artifact + schema_version, deterministic build output, and a
fail-closed verifier — a wrong digest, a missing weight or a malformed
manifest must never yield a ready verdict (exit 0), mirroring the runtime
refusals of pkg/mlpack (digest mismatch / weights missing / unsafe path).

No network, no docker, no real model weights — deterministic temp
directories with tiny fake payloads and locally computed digests.
"""
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "mlpack_manifest.sh"
REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"


def run_script(*args):
    """Run the script the way an operator would (bash, captured output)."""
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MLPackManifestTestBase(unittest.TestCase):
    def make_pack(self, files: dict) -> Path:
        """Create a pack directory with fake weight payloads."""
        pack = Path(tempfile.mkdtemp(prefix="mlpack-test-"))
        self.addCleanup(shutil.rmtree, pack)
        for rel, payload in files.items():
            target = pack / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        return pack

    def build(self, pack: Path, extra=None):
        args = [
            "build",
            str(pack),
            "--id", "BAAI/bge-small-en-v1.5",
            "--version", "v1.5",
            "--revision", REVISION,
            "--license", "MIT",
        ]
        return run_script(*(args + (extra or [])))

    def canonical_manifest(self, entries: str, schema=1, rev=REVISION,
                           id_="BAAI/bge-small-en-v1.5", version="v1.5",
                           license_="MIT") -> str:
        return (
            "{\n"
            f'  "schema_version": {schema},\n'
            f'  "id": "{id_}",\n'
            f'  "version": "{version}",\n'
            f'  "revision": "{rev}",\n'
            f'  "license": "{license_}",\n'
            '  "files": [\n'
            f"{entries}\n"
            "  ]\n"
            "}\n"
        )


class TestBuild(MLPackManifestTestBase):
    def test_writes_canonical_manifest(self):
        weights, tok = b"fake-weights", b'{"tok": true}'
        pack = self.make_pack({
            "model.safetensors": weights,
            "tokenizer/tokenizer.json": tok,
        })
        res = self.build(pack)
        self.assertEqual(res.returncode, 0, res.stderr)
        manifest = json.loads((pack / "pack.json").read_text())
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["id"], "BAAI/bge-small-en-v1.5")
        self.assertEqual(manifest["version"], "v1.5")
        self.assertEqual(manifest["revision"], REVISION)
        self.assertEqual(manifest["license"], "MIT")
        # deterministic order: files sorted by path, one entry each
        self.assertEqual([f["path"] for f in manifest["files"]],
                         ["model.safetensors", "tokenizer/tokenizer.json"])
        digests = {f["path"]: f["sha256"] for f in manifest["files"]}
        self.assertEqual(digests["model.safetensors"], sha256(weights))
        self.assertEqual(digests["tokenizer/tokenizer.json"], sha256(tok))
        # the manifest itself is never a digested artifact
        self.assertNotIn("pack.json", digests)

    def test_deterministic_byte_identical_output(self):
        files = {"b.bin": b"B", "a.bin": b"A", "dir/c.bin": b"C"}
        pack_a = self.make_pack(files)
        pack_b = self.make_pack(files)
        self.assertEqual(self.build(pack_a).returncode, 0)
        self.assertEqual(self.build(pack_b).returncode, 0)
        # same contents in a different directory → byte-identical manifest
        self.assertEqual((pack_a / "pack.json").read_bytes(),
                         (pack_b / "pack.json").read_bytes())
        # rebuild over an existing manifest is idempotent
        before = (pack_a / "pack.json").read_bytes()
        self.assertEqual(self.build(pack_a).returncode, 0)
        self.assertEqual((pack_a / "pack.json").read_bytes(), before)

    def test_refuses_unpinned_revision(self):
        pack = self.make_pack({"model.safetensors": b"w"})
        # a non-40-hex revision is a refusal: floating refs must never pass
        for rev in ("main", "abcdef", REVISION.upper(), "g" * 40):
            res = run_script(
                "build", str(pack),
                "--id", "m", "--version", "v1", "--revision", rev,
                "--license", "MIT",
            )
            self.assertEqual(res.returncode, 1, rev)
            self.assertIn("40-hex", res.stderr)
            self.assertFalse((pack / "pack.json").exists(),
                             "a refused build must not leave a manifest")
        # an absent revision value is a usage error, not a silent default
        res = run_script(
            "build", str(pack),
            "--id", "m", "--version", "v1", "--revision", "",
            "--license", "MIT",
        )
        self.assertEqual(res.returncode, 2)
        self.assertFalse((pack / "pack.json").exists())

    def test_refuses_missing_provenance_flags(self):
        pack = self.make_pack({"model.safetensors": b"w"})
        res = run_script("build", str(pack))
        self.assertEqual(res.returncode, 2)

    def test_refuses_missing_dir(self):
        res = run_script("build", "/nonexistent/pack-dir-xyz",
                         "--id", "m", "--version", "v1",
                         "--revision", REVISION, "--license", "MIT")
        self.assertEqual(res.returncode, 1)

    def test_refuses_empty_pack(self):
        pack = self.make_pack({})
        res = self.build(pack)
        self.assertEqual(res.returncode, 1)
        self.assertIn("weights missing", res.stderr)
        self.assertFalse((pack / "pack.json").exists())

    def test_refuses_symlinked_weight(self):
        pack = self.make_pack({"real.bin": b"payload"})
        (pack / "model.safetensors").symlink_to(pack / "real.bin")
        res = self.build(pack)
        self.assertEqual(res.returncode, 1)
        self.assertIn("symlink", res.stderr)
        self.assertFalse((pack / "pack.json").exists())

    def test_refuses_manifest_only_directory_does_not_count(self):
        # a stale manifest alone is not a pack: zero artifacts must refuse
        pack = self.make_pack({})
        (pack / "pack.json").write_text("{}")
        res = self.build(pack)
        self.assertEqual(res.returncode, 1)
        self.assertIn("weights missing", res.stderr)


class TestVerify(MLPackManifestTestBase):
    def setUp(self):
        self.weights = b"verifiable-weights"
        self.pack = self.make_pack({"model.safetensors": self.weights})
        self.assertEqual(self.build(self.pack).returncode, 0)

    def test_built_pack_verifies(self):
        res = run_script("verify", str(self.pack))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("all digests match", res.stdout)

    def test_digest_mismatch_refuses(self):
        (self.pack / "model.safetensors").write_bytes(b"tampered")
        res = run_script("verify", str(self.pack))
        self.assertEqual(res.returncode, 1)
        self.assertIn("digest mismatch", res.stderr)
        self.assertIn("must not enter the distribution", res.stderr)
        self.assertIn("NOT ready", res.stderr)

    def test_missing_weight_refuses(self):
        (self.pack / "model.safetensors").unlink()
        res = run_script("verify", str(self.pack))
        self.assertEqual(res.returncode, 1)
        self.assertIn("weights missing", res.stderr)

    def test_missing_manifest_refuses(self):
        (self.pack / "pack.json").unlink()
        res = run_script("verify", str(self.pack))
        self.assertEqual(res.returncode, 1)
        self.assertIn("pack.json missing", res.stderr)

    def test_unsupported_schema_refuses(self):
        raw = (self.pack / "pack.json").read_text()
        (self.pack / "pack.json").write_text(
            raw.replace('"schema_version": 1', '"schema_version": 2'))
        res = run_script("verify", str(self.pack))
        self.assertEqual(res.returncode, 1)
        self.assertIn("unsupported manifest schema_version", res.stderr)

    def test_manifest_without_schema_refuses(self):
        # e.g. a hand-written manifest: without schema_version the verifier
        # refuses instead of guessing (fail-closed forward compatibility).
        (self.pack / "pack.json").write_text(
            self.canonical_manifest(
                '    {"path": "model.safetensors", "sha256": "%s"}'
                % sha256(self.weights)).replace(
                '  "schema_version": 1,\n', ""))
        res = run_script("verify", str(self.pack))
        self.assertEqual(res.returncode, 1)
        self.assertIn("schema_version", res.stderr)

    def test_traversal_path_refuses(self):
        for bad in ("../escape.bin", "a/../../b.bin", "/etc/passwd", ""):
            manifest = self.canonical_manifest(
                '    {"path": "%s", "sha256": "%s"}' % (bad, sha256(b"x")))
            (self.pack / "pack.json").write_text(manifest)
            res = run_script("verify", str(self.pack))
            self.assertEqual(res.returncode, 1, repr(bad))
            self.assertIn("unsafe path", res.stderr, repr(bad))

    def test_unpinned_revision_in_manifest_refuses(self):
        manifest = self.canonical_manifest(
            '    {"path": "model.safetensors", "sha256": "%s"}'
            % sha256(self.weights), rev="main")
        (self.pack / "pack.json").write_text(manifest)
        res = run_script("verify", str(self.pack))
        self.assertEqual(res.returncode, 1)
        self.assertIn("40-hex", res.stderr)

    def test_all_problems_reported_together(self):
        # parity with pkg/mlpack Verify: every file problem is listed in one
        # refusal, not just the first.
        (self.pack / "extra.bin").write_bytes(b"different")
        manifest = self.canonical_manifest("\n".join([
            '    {"path": "model.safetensors", "sha256": "%s"}' % sha256(b"changed"),
            '    {"path": "extra.bin", "sha256": "%s"}' % sha256(b"second"),
            '    {"path": "gone.bin", "sha256": "%s"}' % sha256(b"gone"),
        ]))
        (self.pack / "pack.json").write_text(manifest)
        res = run_script("verify", str(self.pack))
        self.assertEqual(res.returncode, 1)
        for want in ('"model.safetensors" digest mismatch',
                     '"extra.bin" digest mismatch',
                     '"gone.bin" declared by pack.json is missing'):
            self.assertIn(want, res.stderr)

    def test_noncanonical_format_refuses(self):
        # pretty-printed by another tool: right facts, wrong (non-canonical)
        # serialization → refuse instead of guessing.
        manifest = {
            "schema_version": 1,
            "id": "BAAI/bge-small-en-v1.5",
            "version": "v1.5",
            "revision": REVISION,
            "license": "MIT",
            "files": [
                {"path": "model.safetensors", "sha256": sha256(self.weights)},
            ],
        }
        (self.pack / "pack.json").write_text(json.dumps(manifest, indent=4))
        res = run_script("verify", str(self.pack))
        self.assertEqual(res.returncode, 1)
        self.assertIn("canonical", res.stderr)


class TestUsage(unittest.TestCase):
    def test_no_arguments_is_usage_error(self):
        res = run_script()
        self.assertEqual(res.returncode, 2)

    def test_unknown_command_is_usage_error(self):
        res = run_script("explode", "/tmp")
        self.assertEqual(res.returncode, 2)

    def test_verify_requires_exactly_one_dir(self):
        for args in (["verify"], ["verify", "/tmp", "/tmp"]):
            res = run_script(*args)
            self.assertEqual(res.returncode, 2)

    def test_help(self):
        res = run_script("--help")
        self.assertEqual(res.returncode, 0)
        self.assertIn("build", res.stdout)
        self.assertIn("verify", res.stdout)


if __name__ == "__main__":
    unittest.main()
