"""Behavior tests for scripts/airgap/mlpack_bake_check.sh (baked-TEI mode).

The baked-TEI optional-classifier mode (compose-documented pack mode) serves
a verified pack from a local directory: TEI reads --model-id /pack, the
gateway mounts the same directory read-only and verifies pack.json at
startup (YABANIN_ML_PACK_DIR). These tests pin the OFFLINE half of that
contract: a pack that passes the digest layer must still be refused when
the TEI runtime would not start (missing config/tokenizer/weights) or when
a serving file would reach the runtime unverified (present but not declared
in the manifest). A wrong digest or a missing runtime prerequisite must
never yield a ready verdict — the same negative semantics the gateway
enforces at startup, checked before deployment.

No network, no docker, no real model weights — deterministic temp
directories with tiny fake payloads built by the real mlpack_manifest.sh.
"""
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "mlpack_bake_check.sh"
MANIFEST = Path(__file__).resolve().parent / "mlpack_manifest.sh"
REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"

CONFIG = b'{"model_type": "bert", "architectures": ["BertModel"]}'
TOKENIZER = b'{"version": "1.0", "model": {"type": "WordPiece"}}'
SPIECE = b"fake-sentencepiece-model"
WEIGHTS = b"fake-safetensors-payload"


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


class BakeCheckTestBase(unittest.TestCase):
    def make_pack(self, files: dict) -> Path:
        """Create a pack directory with fake payloads and a canonical manifest."""
        pack = Path(tempfile.mkdtemp(prefix="mlpack-bake-"))
        self.addCleanup(shutil.rmtree, pack)
        for rel, payload in files.items():
            target = pack / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        built = subprocess.run(
            [
                "bash", str(MANIFEST), "build", str(pack),
                "--id", "BAAI/bge-small-en-v1.5",
                "--version", "v1.5",
                "--revision", REVISION,
                "--license", "MIT",
            ],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(built.returncode, 0, built.stderr)
        return pack

    def bake_pack(self, files: dict) -> Path:
        """A pack with the full TEI serving set, manifest built over all files."""
        return self.make_pack({
            "config.json": CONFIG,
            "tokenizer.json": TOKENIZER,
            "model.safetensors": WEIGHTS,
            **files,
        })

    def check(self, pack, *extra):
        return run_script("check", str(pack), *extra)


class BakeCheckHappyPath(BakeCheckTestBase):
    def test_full_pack_passes_and_prints_the_serving_contract(self):
        pack = self.bake_pack({})
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = proc.stdout
        self.assertIn("OK: bake check passed", out)
        self.assertIn("id=BAAI/bge-small-en-v1.5", out)
        self.assertIn("version=v1.5", out)
        self.assertIn("weights=model.safetensors", out)
        # The compose-documented pack mode: read-only mount, local-dir TEI,
        # gateway verification of the same directory, model = pack id.
        self.assertIn(":/pack:ro", out)
        self.assertIn("--model-id /pack", out)
        self.assertIn("YABANIN_ML_PACK_DIR=/pack", out)
        self.assertIn("must equal the pack id", out)
        self.assertIn("bake ready", out)
        # The example pack never leaves a stray manifest behind.
        self.assertTrue((pack / "pack.json").is_file())

    def test_manifest_is_the_canonical_schema(self):
        pack = self.bake_pack({})
        manifest = json.loads((pack / "pack.json").read_text())
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["id"], "BAAI/bge-small-en-v1.5")
        self.assertEqual(manifest["license"], "MIT")
        paths = {f["path"]: f["sha256"] for f in manifest["files"]}
        self.assertEqual(paths["config.json"], sha256(CONFIG))
        self.assertEqual(paths["model.safetensors"], sha256(WEIGHTS))

    def test_sentencepiece_variant_passes_without_tokenizer_json(self):
        pack = self.make_pack({
            "config.json": CONFIG,
            "spiece.model": SPIECE,
            "model.safetensors": WEIGHTS,
        })
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("OK: bake check passed", proc.stdout)

    def test_expect_id_match_passes(self):
        pack = self.bake_pack({})
        proc = self.check(pack, "--expect-id", "BAAI/bge-small-en-v1.5")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_multiple_weights_pass_with_a_warning(self):
        pack = self.bake_pack({"pytorch_model.bin": b"fake-bin-payload"})
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WARN: multiple weights files", proc.stderr)
        self.assertIn("prefers model.safetensors", proc.stderr)
        self.assertIn("weights=model.safetensors", proc.stdout)

    def test_extra_undeclared_file_warns_but_passes(self):
        pack = self.bake_pack({})
        (pack / "README.txt").write_bytes(b"not a serving file")
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WARN: file \"README.txt\"", proc.stderr)
        self.assertIn("ships unverified", proc.stderr)
        self.assertIn("bake ready", proc.stdout)


class BakeCheckDigestLayer(BakeCheckTestBase):
    def test_tampered_weight_refuses(self):
        pack = self.bake_pack({})
        (pack / "model.safetensors").write_bytes(b"tampered payload")
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("digest mismatch", proc.stderr)
        self.assertIn("NOT ready", proc.stderr)
        self.assertIn("aborted at the digest layer", proc.stderr)
        self.assertNotIn("bake ready", proc.stdout)

    def test_missing_manifest_refuses(self):
        pack = Path(tempfile.mkdtemp(prefix="mlpack-bake-"))
        self.addCleanup(shutil.rmtree, pack)
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("pack.json missing", proc.stderr)
        self.assertIn("NOT ready", proc.stderr)

    def test_unsupported_schema_refuses(self):
        pack = self.bake_pack({})
        raw = (pack / "pack.json").read_text()
        (pack / "pack.json").write_text(raw.replace('"schema_version": 1', '"schema_version": 2'))
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("unsupported manifest schema_version: 2", proc.stderr)

    def test_missing_pack_dir_refuses(self):
        proc = self.check(Path(tempfile.gettempdir()) / "mlpack-bake-no-such-dir-9x")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("is not a directory", proc.stderr)


class BakeCheckServeLayer(BakeCheckTestBase):
    def test_missing_tokenizer_refuses(self):
        pack = self.make_pack({"config.json": CONFIG, "model.safetensors": WEIGHTS})
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("serving prerequisite missing", proc.stderr)
        self.assertIn("tokenizer.json", proc.stderr)
        self.assertIn("spiece.model", proc.stderr)
        self.assertIn("would not start", proc.stderr)
        self.assertIn("NOT ready", proc.stderr)
        self.assertNotIn("bake ready", proc.stdout)

    def test_missing_config_refuses(self):
        pack = self.make_pack({"tokenizer.json": TOKENIZER, "model.safetensors": WEIGHTS})
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("config.json", proc.stderr)
        self.assertIn("NOT ready", proc.stderr)

    def test_no_weights_refuses(self):
        pack = self.make_pack({"config.json": CONFIG, "tokenizer.json": TOKENIZER})
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no weights file declared", proc.stderr)
        self.assertIn("weights missing", proc.stderr)
        self.assertIn("NOT ready", proc.stderr)

    def test_undeclared_serving_file_refuses(self):
        # The manifest was built over config+weights; the tokenizer dropped in
        # afterwards would reach the TEI runtime with no digest over it.
        pack = self.make_pack({"config.json": CONFIG, "model.safetensors": WEIGHTS})
        (pack / "tokenizer.json").write_bytes(TOKENIZER)
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("tokenizer.json\" is present in the pack but NOT declared", proc.stderr)
        self.assertIn("digest protects only declared files", proc.stderr)
        self.assertIn("NOT ready", proc.stderr)

    def test_undeclared_weight_file_refuses(self):
        pack = self.bake_pack({})
        (pack / "pytorch_model.bin").write_bytes(b"unverified-weights")
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("pytorch_model.bin\" is present in the pack but NOT declared", proc.stderr)

    def test_all_problems_reported_together(self):
        pack = self.make_pack({"tokenizer.json": TOKENIZER})
        (pack / "config.json").write_bytes(CONFIG)
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 1)
        err = proc.stderr
        self.assertIn("config.json\" is present in the pack but NOT declared", err)
        self.assertIn("no weights file declared", err)
        self.assertIn("NOT ready", err)


class BakeCheckPredictableAttach(BakeCheckTestBase):
    def test_expect_id_mismatch_refuses(self):
        pack = self.bake_pack({})
        proc = self.check(pack, "--expect-id", "intfloat/multilingual-e5-small")
        self.assertEqual(proc.returncode, 1)
        err = proc.stderr
        self.assertIn("does not match the expected model", err)
        self.assertIn("BAAI/bge-small-en-v1.5", err)
        self.assertIn("intfloat/multilingual-e5-small", err)
        self.assertIn("NOT ready", err)
        self.assertNotIn("bake ready", proc.stdout)

    def test_negative_wording_names_the_serving_consequence(self):
        # Parity with the runtime refusals: the refusal line names the branch
        # (cannot start / not digest-protected) instead of a bare failure.
        pack = self.make_pack({"config.json": CONFIG, "model.safetensors": WEIGHTS})
        proc = self.check(pack)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("did not pass the baked-TEI bake check", proc.stderr)
        self.assertIn("serving this pack would not start", proc.stderr)


class BakeCheckUsageContract(BakeCheckTestBase):
    def test_missing_command_is_usage_error(self):
        proc = run_script()
        self.assertEqual(proc.returncode, 2)
        self.assertIn("missing command", proc.stderr)

    def test_unknown_command_is_usage_error(self):
        proc = run_script("build", "x")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unknown command", proc.stderr)

    def test_check_without_dir_is_usage_error(self):
        proc = run_script("check")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("check requires a pack directory", proc.stderr)

    def test_unknown_flag_is_usage_error(self):
        pack = self.bake_pack({})
        proc = self.check(pack, "--model", "x")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unknown check argument", proc.stderr)

    def test_expect_id_without_value_is_usage_error(self):
        pack = self.bake_pack({})
        proc = self.check(pack, "--expect-id")
        self.assertEqual(proc.returncode, 2)

    def test_help_exits_zero(self):
        proc = run_script("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("baked-TEI serve-readiness check", proc.stdout)
        self.assertIn("check <pack_dir>", proc.stdout)


if __name__ == "__main__":
    unittest.main()
