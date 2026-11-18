# SPDX-License-Identifier: Apache-2.0
"""Fast regressions for the quickstart. Run with unittest discovery here."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from console import Console
from stand import base_url, providers, validate_topology


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

    def test_parent_manifest_cannot_import_checkout_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            checkout = directory / "core"
            checkout.mkdir()
            manifest = directory / "models.json"
            manifest.write_text(json.dumps([{"model": "one", "base_url": "https://one/v1", "key_file": "core/secret"}]))
            with patch("stand.ROOT", checkout), self.assertRaisesRegex(ValueError, "build context"):
                providers(manifest)

    def test_reset_refuses_an_additional_volume(self):
        services = dict.fromkeys(("postgres", "redis", "migrate", "db-app-role", "yabanin", "dashboard"))
        services.update({"seed": {"environment": {"SEED_UPSTREAM_URL": "http://10.0.0.9:8081"}},
                         "mock-openai": {"networks": {"default": {"ipv4_address": "10.0.0.9"}}}})
        spec = {"name": "demo", "services": services, "volumes": {"pg_data": {"name": "demo_pg_data"}}}
        validate_topology(spec, True)
        spec["volumes"]["shared"] = {"name": "shared"}
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            validate_topology(spec, True)

    def test_request_link_includes_first_and_last_sample_minutes(self):
        console = Console(3000)
        rows = [{"status_code": 200, "labels": {"ci.job_name": job}, "created_at": timestamp}
                for job, timestamp in zip(("docs", "tools", "review", "support"),
                                          ("2026-11-18T12:34:59.4Z", "2026-11-18T12:35:00Z",
                                           "2026-11-18T12:35:01.0047+00:00", "2026-11-18T12:35:02.01Z"))]
        with patch.object(console, "get", side_effect=rows):
            fragment = urlsplit(console.requests_link("demo")).fragment
        query = parse_qs(fragment.split("?", 1)[1])
        self.assertEqual(query["from"], ["2026-11-18T12:34:00+00:00"])
        self.assertEqual(query["to"], ["2026-11-18T12:36:00+00:00"])

    def test_substituted_model_fails_probe(self):
        console = Console(3000)
        receipt = {"model_requested": "one", "model_used": "two", "status_code": 200}
        with patch.object(console, "request", return_value=(200, json.dumps(receipt))):
            with self.assertRaisesRegex(ValueError, "different model"):
                console.verify_route("probe-id", "one")


if __name__ == "__main__":
    unittest.main()
