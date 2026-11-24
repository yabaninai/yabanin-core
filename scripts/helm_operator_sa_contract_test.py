"""Rendered-chart contract gate: ServiceAccount references and migrate init env.

P1: every explicit pod-template serviceAccountName is a ServiceAccount the
    chart itself renders (no pre-created account may be required).
P2: every `migrate` container in the cloud chart receives YABANIN_PG_URI from
    the rendered secret's `pg_uri` key plus a non-empty YABANIN_REGION.
N1/N2: known-red fixtures (misspelled account ref, missing secret key) must
    fail P1/P2 through the same checks.

Usage: python3 scripts/helm_operator_sa_contract_test.py  (from repo root; helm required)
"""
import copy
import json
from pathlib import Path
import subprocess
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
RELEASE = "sa-contract"

POD_TEMPLATE_KINDS = ("Deployment", "Job", "StatefulSet", "DaemonSet", "ReplicationController")


def render(chart, values_file=None):
    args = ["helm", "template", RELEASE, str(ROOT / "deploy/helm" / chart), "--kube-version", "1.25.0"]
    if values_file:
        args += ["-f", str(values_file)]
    result = subprocess.run(args, text=True, capture_output=True, check=True)
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def pod_template_specs(docs):
    for doc in docs:
        if doc.get("kind") in POD_TEMPLATE_KINDS:
            spec = doc.get("spec", {}).get("template", {}).get("spec", {})
            if spec:
                yield doc, spec


def migrate_containers(docs):
    for doc, spec in pod_template_specs(docs):
        for container in spec.get("initContainers", []) + spec.get("containers", []):
            if container.get("name") == "migrate":
                yield doc, container


def env_map(container):
    return {e.get("name"): e for e in container.get("env", [])}


def assert_referenced_service_accounts_rendered(docs, min_explicit_refs=0):
    rendered = {d["metadata"]["name"] for d in docs if d.get("kind") == "ServiceAccount"}
    checked = 0
    for doc, spec in pod_template_specs(docs):
        sa = spec.get("serviceAccountName")
        if not sa:
            continue
        checked += 1
        if sa != "default" and sa not in rendered:
            raise AssertionError(
                f"{doc['kind']}/{doc['metadata']['name']}: serviceAccountName "
                f"{sa!r} is not rendered by the chart (rendered: {sorted(rendered) or 'none'}); "
                f"pods would reference a pre-created account that does not exist")
    if checked < min_explicit_refs:
        raise AssertionError(
            f"expected >= {min_explicit_refs} explicit serviceAccountName references, got {checked}: "
            f"the assertion ran vacuously")


def assert_migrate_pg_binding(docs, release=RELEASE):
    """Cloud-chart contract: YABANIN_PG_URI bound to <release>-secrets/pg_uri."""
    found = 0
    for doc, container in migrate_containers(docs):
        found += 1
        env = env_map(container)
        binding = env.get("YABANIN_PG_URI")
        if binding is None:
            raise AssertionError(f"{doc['kind']}/{doc['metadata']['name']}: migrate container has no YABANIN_PG_URI env")
        ref = (binding.get("valueFrom") or {}).get("secretKeyRef") or {}
        if ref.get("key") != "pg_uri" or ref.get("name") != f"{release}-secrets":
            raise AssertionError(
                f"{doc['kind']}/{doc['metadata']['name']}: migrate container YABANIN_PG_URI must come from "
                f"secret {release}-secrets key pg_uri, got {ref!r} "
                f"(envFrom imports keys under literal names the runner never reads)")
        region = env.get("YABANIN_REGION")
        if not (region or {}).get("value"):
            raise AssertionError(f"{doc['kind']}/{doc['metadata']['name']}: migrate container has no non-empty YABANIN_REGION env")
    if found == 0:
        raise AssertionError("no migrate container found: the pg_uri binding assertion ran vacuously")


class HelmServiceAccountContractTests(unittest.TestCase):
    def test_every_referenced_service_account_is_rendered(self):
        for chart in ("yabanin", "yabanin-onprem"):
            variants = sorted((ROOT / "deploy/helm" / chart).glob("values*.yaml"))
            for values_file in [None, *variants]:
                with self.subTest(chart=chart, values=values_file and values_file.name):
                    min_refs = 3 if chart == "yabanin" else 0
                    assert_referenced_service_accounts_rendered(render(chart, values_file), min_refs)

    def test_cloud_chart_migrate_init_reads_pg_uri_key(self):
        for values_file in [None, *(ROOT / "deploy/helm/yabanin").glob("values*.yaml")]:
            with self.subTest(values=values_file and values_file.name):
                assert_migrate_pg_binding(render("yabanin", values_file))

    def control_failure(self, assertion, docs, label):
        """A known-red fixture must fail the real assertion, not merely differ."""
        with self.assertRaises(AssertionError, msg=f"negative control {label} passed vacuously"):
            assertion(docs)

    def test_negative_control_misspelled_account_reference_fails_p1(self):
        docs = render("yabanin")
        mutant = copy.deepcopy(docs)
        for doc, spec in pod_template_specs(mutant):
            if doc["kind"] == "Deployment":
                spec["serviceAccountName"] = f"{RELEASE}-yabinin"
        self.control_failure(assert_referenced_service_accounts_rendered, mutant, "N1 misspelled account")

    def test_negative_control_missing_secret_key_fails_p2(self):
        docs = render("yabanin")
        mutant = copy.deepcopy(docs)
        touched = False
        for _doc, container in migrate_containers(mutant):
            env = env_map(container)
            broken = {"name": "YABANIN_PG_URI",
                      "valueFrom": {"secretKeyRef": {"name": f"{RELEASE}-secrets", "key": "pg_uri_missing"}}}
            if env.get("YABANIN_PG_URI") is not None:
                container["env"] = [e for e in container["env"] if e.get("name") != "YABANIN_PG_URI"]
            container.setdefault("env", []).append(broken)
            touched = True
        self.assertTrue(touched, "no migrate container to mutate: N2 ran vacuously")
        self.control_failure(assert_migrate_pg_binding, mutant, "N2 missing secret key")


if __name__ == "__main__":
    unittest.main()
