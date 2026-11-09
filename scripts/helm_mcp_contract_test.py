"""Deployment contract: MCP registration and invocation share an allow-list."""
import json
from pathlib import Path
import subprocess
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class HelmMCPContractTests(unittest.TestCase):
    def render(self, chart, overrides):
        result = subprocess.run(
            ["helm", "template", "mcp-contract", str(ROOT / "deploy/helm" / chart),
             "--values", "-"],
            input=json.dumps(overrides), text=True, capture_output=True, check=True,
        )
        return [doc for doc in yaml.safe_load_all(result.stdout) if doc]

    def test_regular_chart_shares_allowlist_and_preserves_boolean_config(self):
        for domains, enabled in (([], False), (["github.com", "*.example.com"], True)):
            with self.subTest(domains=domains):
                docs = self.render("yabanin", {"gateway": {
                    "mcp_allowed_upstreams": domains, "mcp_gateway_enabled": enabled,
                }})
                configmap = next(d for d in docs if d["kind"] == "ConfigMap")
                gateway = yaml.safe_load(configmap["data"]["config.yaml"])["gateway"]
                self.assertIs(gateway["mcp_gateway_enabled"], enabled)
                self.assertIs(gateway["circuit_enabled"], True)
                self.assertEqual(gateway.get("mcp_allowed_upstreams") or [], domains)
                admin = next(d for d in docs if d["kind"] == "Deployment"
                             and d["metadata"]["name"].endswith("-admin"))
                container = next(c for c in admin["spec"]["template"]["spec"]["containers"]
                                 if c["name"] == "admin")
                env = {e["name"]: e.get("value") for e in container["env"]}
                self.assertEqual(env["YABANIN_MCP_ALLOWED_UPSTREAMS"], ",".join(domains))


if __name__ == "__main__":
    unittest.main()
