# SPDX-License-Identifier: Apache-2.0
"""Fast regressions for the quickstart. Run with unittest discovery here."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from console import Console
from stand import base_url, providers


class ProviderSetupTest(unittest.TestCase):
    def test_malformed_endpoints(self):
        for url in ("http://host/v1", "https://user:key@host/v1", "https://host:99999/v1",
                    "https://host/v1?token=example", "https://host/v1#private"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                base_url(url)

    def test_distinct_private_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "providers.json"
            rows = []
            for model in ("one", "two"):
                key = root / model
                key.write_text(model)
                key.chmod(0o600)
                rows.append({"model": model, "base_url": "https://" + model + "/v1", "key_file": model})
            manifest.write_text(json.dumps(rows))
            self.assertEqual(providers(manifest), [("one", "https://one/v1", b"one"),
                                                   ("two", "https://two/v1", b"two")])
            manifest.write_text(json.dumps(rows + [rows[0]]))
            with self.assertRaisesRegex(ValueError, "unique"):
                providers(manifest)
            (root / "two").chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private"):
                providers(manifest)

    def test_key_path_is_confined_to_manifest_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = root / "providers"
            inputs.mkdir()
            foreign = root / "other.key"
            foreign.write_text("example")
            foreign.chmod(0o600)
            (inputs / "linked").symlink_to(foreign)
            manifest = inputs / "providers.json"
            for path in ("../other.key", "linked", str(foreign)):
                with self.subTest(path=path):
                    manifest.write_text(json.dumps([{"model": "one", "base_url": "https://one/v1", "key_file": path}]))
                    with self.assertRaisesRegex(ValueError, "inside"):
                        providers(manifest)

    def test_substituted_model_fails_probe(self):
        console = Console(3000)
        receipt = {"model_requested": "one", "model_used": "two", "status_code": 200}
        with patch.object(console, "request", return_value=(200, json.dumps(receipt))):
            with self.assertRaisesRegex(ValueError, "different model"):
                console.verify_route("probe-id", "one")


if __name__ == "__main__":
    unittest.main()
