"""Verify the signed root manifest and reject a signature for different bytes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


VERIFY = Path(__file__).resolve().parents[2] / "release/verify_signature_composition.sh"


class SignedChecksumManifestTest(unittest.TestCase):
    def test_root_signature_and_tampered_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release = root / "release"
            inventory = release / "delivered-inventory"
            inventory.mkdir(parents=True)
            signatures = root / "signatures"
            signatures.mkdir()
            subject = release / "example.bin"
            subject.write_bytes(b"sample release binary\n")
            for name in ("spdx.json", "cdx.json"):
                (inventory / name).write_text("{}\n")
            sbom_hash = hashlib.sha256(b"{}\n").hexdigest()
            row = {"subject": "example", "kind": "binary", "reference": str(subject),
                   "subject_sha256": hashlib.sha256(subject.read_bytes()).hexdigest(),
                   "sbom_spdx": "spdx.json", "sbom_spdx_sha256": sbom_hash,
                   "sbom_cdx": "cdx.json", "sbom_cdx_sha256": sbom_hash}
            (inventory / "SBOM-SUBJECTS.json").write_text(json.dumps({"subjects": [row]}))
            assets = [{"path": str(p.relative_to(release)),
                       "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                      for p in sorted(release.rglob("*")) if p.is_file()]
            manifest = release / "SHA256SUMS-FULL"
            manifest.write_text("".join(f"{a['sha256']}  {a['path']}\n" for a in assets))
            enriched = row.copy()
            enriched["sbom_spdx_original"] = enriched.pop("sbom_spdx")
            enriched["sbom_spdx_original_sha256"] = enriched.pop("sbom_spdx_sha256")
            enriched.update(sbom_spdx_normalized="spdx.json", sbom_spdx_normalized_sha256=sbom_hash)
            (inventory / "sbom-handoff.json").write_text(json.dumps({
                "assets": assets, "sbom_subjects": [enriched]}))

            # Exercise the verifier's CLI contract using a temporary key and detached signature.
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey",
                            "-noout", "-out", "fixture.key"], cwd=root, check=True)
            subprocess.run(["openssl", "pkey", "-in", "fixture.key", "-pubout",
                            "-out", "fixture.pub"], cwd=root, check=True)
            (signatures / "delivered-inventory").mkdir()
            signature = signatures / "SHA256SUMS-FULL.sig"
            for target in (manifest, inventory / "sbom-handoff.json"):
                sidecar = signatures / (str(target.relative_to(release)) + ".sig")
                subprocess.run(["openssl", "dgst", "-sha256", "-sign", "fixture.key",
                                "-out", sidecar, target], cwd=root, check=True)
            tool = root / "cosign"
            tool.write_text('#!/bin/sh\nset -eu\n'
                            'test "$1" = verify-blob && test "$2" = --key && '
                            'test "$4" = --signature || exit 1\n'
                            'exec openssl dgst -sha256 -verify "$3" -signature "$5" "$6"\n')
            tool.chmod(0o700)
            command = ["bash", VERIFY, "--release-dir", release, "--signatures-dir",
                       signatures, "--key", root / "fixture.pub"]
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"])
            valid = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
            signature.write_bytes(b"invalid signature")
            invalid = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("signature verification FAILED for SHA256SUMS-FULL", invalid.stdout)
