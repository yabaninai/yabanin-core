import datetime as dt
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("dep_audit", ROOT / "scripts/quality/dep_audit.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)

# Positive exception tests must hold for the life of the registered
# exceptions: every scan runs at this frozen date through the audit's
# dt.date boundary, so the suite stays valid after 2026-11-30. Expiry
# refusals use explicit dates mismatched against this clock, never the
# ambient wall clock.
FROZEN_TODAY = dt.date(2026, 11, 18)


class FrozenDate(dt.date):
    @classmethod
    def today(cls):
        return FROZEN_TODAY


# Sentinel distinguishing an untouched Vulnerabilities field from an
# explicitly served null.
_UNSET = object()

# SDK dev-toolchain criticals proven (pinned trivy 0.75.0, offline, same DB)
# to be omitted from lockfile reports unless the invocation passes
# --include-dev-deps; used to discriminate the audit's trivy invocation.
SDK_DEV_CRITICALS = [
    {"VulnerabilityID": "CVE-2026-104848", "PkgName": "tinypool",
     "InstalledVersion": "0.8.4", "Severity": "CRITICAL", "FixedVersion": "2.1.1"},
    {"VulnerabilityID": "CVE-2026-104849", "PkgName": "tinypool",
     "InstalledVersion": "0.8.4", "Severity": "CRITICAL", "FixedVersion": "2.1.2"},
    {"VulnerabilityID": "CVE-2026-47429", "PkgName": "vitest",
     "InstalledVersion": "1.6.1", "Severity": "CRITICAL", "FixedVersion": "3.2.6, 4.1.0"},
]

# The dashboard lock carries picomatch 4.0.5 at exactly these two nested
# keys (tinyglobby and vite chains); the aggregated v4 finding binds to both.
DASHBOARD_V4_KEYS = ["node_modules/tinyglobby/node_modules/picomatch",
                     "node_modules/vite/node_modules/picomatch"]

# The dashboard's real 4.0.5 lock instances behind those keys, as
# (key, version, dev) tuples for independent lock fixtures.
DASHBOARD_V4_INSTANCES = [("node_modules/tinyglobby/node_modules/picomatch", "4.0.5", True),
                          ("node_modules/vite/node_modules/picomatch", "4.0.5", True)]


class DependencyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts/quality").mkdir(parents=True)
        (self.root / "scripts/security").mkdir(parents=True)
        self.policy = self.root / "scripts/quality/security-exceptions.yaml"
        self.policy.write_bytes((ROOT / "scripts/quality/security-exceptions.yaml").read_bytes())
        (self.root / "scripts/security/scanner-lock.json").write_text(
            json.dumps({"scanners": {"trivy": {"version": "0.75.0"}}}))
        self.findings = []

    def _write_lock_keys(self, target, instances, joined=0, compact=()):
        """Write a real-shaped packages map; return key -> 1-based line.

        Each instance is (key, version, dev) or (key, version, dev, extra)
        with the extra fields merged into the entry, so npm alias entries
        can name their real package; a None version omits the field and a
        non-string version is written verbatim, so malformed lock metadata
        can be served deliberately. The last `joined` entries share the
        previous entry's line for same-line lock shapes; keys in `compact`
        are written without the expected spacing after the colon.
        """
        path = self.root / target
        path.parent.mkdir(parents=True, exist_ok=True)
        parts, line_of = [], {}
        for index, instance in enumerate(instances):
            key, version, dev = instance[0], instance[1], instance[2]
            fields = dict(instance[3]) if len(instance) > 3 else {}
            if version is not None:
                fields["version"] = version
            if dev is not None:
                fields["dev"] = dev
            if key in compact:
                part = f'    "{key}":' + json.dumps(fields, separators=(",", ":"))
            else:
                part = f'    "{key}": ' + json.dumps(fields)
            if joined and index >= len(instances) - joined:
                parts[-1] += ", " + part.strip()
            else:
                parts.append(part)
            line_of[key] = len(parts) + 1
        path.write_text('{"packages": {\n' + ",\n".join(parts) + "\n}}\n")
        return line_of

    def _lock_instances(self, findings, lock_extra):
        """Lock instances implied by the findings' reported paths."""
        instances, seen = [], set()
        for finding in findings:
            for key in finding.get("_paths") or [f"node_modules/{finding['PkgName']}"]:
                if key not in seen:
                    seen.add(key)
                    instances.append(
                        (key, finding["InstalledVersion"], finding.get("_lock_dev", True)))
        return instances + list(lock_extra)

    def _package_records(self, findings, line_of):
        """Trivy Packages[] records and served findings sharing their UIDs.

        Real Trivy serves each finding with the PkgIdentifier.UID of its
        Packages record; only the _unbound defect omits it, so production
        binding requirements see the actual scanner shape.
        """
        packages, served = [], []
        for finding in findings:
            record = {k: v for k, v in finding.items() if not k.startswith("_")}
            if not finding.get("_unbound"):
                uid = f"{finding['PkgName']}@{finding['InstalledVersion']}"
                record["PkgIdentifier"] = {"UID": uid}
                version = ("0.0.0" if finding.get("_mismatched_identity")
                           else finding["InstalledVersion"])
                locations = [{"StartLine": line_of[key]}
                             for key in finding.get("_paths")
                             or [f"node_modules/{finding['PkgName']}"]]
                if finding.get("_bad_location"):
                    locations = [{"StartLine": 1}]
                if finding.get("_locations") is not None:
                    locations = finding["_locations"]
                packages.append({"ID": uid, "Name": finding["PkgName"],
                                 "Version": version, "Identifier": {"UID": uid},
                                 "Locations": ([] if finding.get("_no_locations")
                                               else locations)})
            served.append(record)
        return packages, served

    def _trivy_report(self, target, findings, result_type="npm",
                      vulns_override=_UNSET, drop_vulns=False,
                      lock_extra=(), lock_instances=None, lock_joined=0,
                      lock_compact=(), lock_raw=None, lock_raw_lines=None,
                      packages_override=_UNSET, drop_packages=False):
        """Serve findings with the real Trivy aggregation shape.

        One Packages[] record per name@version UID carries Name, Version
        and Locations pointing at physical lockfile keys. _paths selects
        the keys a finding reports. The lockfile itself is written from
        lock_instances when given, else from every finding path plus
        lock_extra, so real-but-unreported instances exist independently
        of what the scan reports. _lock_dev sets a lock entry's dev
        classification; _unbound, _bad_location, _no_locations and
        _mismatched_identity model metadata defects the scanner must fail
        closed on. vulns_override/drop_vulns control the Vulnerabilities
        field itself.
        """
        if lock_instances is None:
            lock_instances = self._lock_instances(findings, lock_extra)
        if lock_raw is not None:
            # Serve a verbatim lockfile whose byte-level shape is the
            # defect under test; locations come from lock_raw_lines when
            # given (the physical lines the scanner would report) and
            # default to line 2 otherwise.
            path = self.root / target
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(lock_raw)
            line_of = (lock_raw_lines if lock_raw_lines is not None
                       else {instance[0]: 2 for instance in lock_instances})
        else:
            line_of = self._write_lock_keys(target, lock_instances, lock_joined,
                                            lock_compact)
        packages, served = self._package_records(findings, line_of)
        result = {"Target": target, "Type": result_type, "Packages": packages,
                  "Vulnerabilities": (served if vulns_override is _UNSET
                                      else vulns_override)}
        if packages_override is not _UNSET:
            result["Packages"] = packages_override
        if drop_packages:
            del result["Packages"]
        if drop_vulns:
            del result["Vulnerabilities"]
        return {"Results": [result]}

    def _flagged_high_critical(self, body):
        """Simulated exit-code truth for a served report.

        Only list-valued Vulnerabilities entries are scanned, so a
        truthy scalar payload reaches production validation unchanged
        instead of raising inside the test double.
        """
        for result in body["Results"]:
            items = result.get("Vulnerabilities")
            if not isinstance(items, list):
                continue
            for item in items:
                if (isinstance(item, dict)
                        and item.get("Severity") in ("HIGH", "CRITICAL")):
                    return True
        return False

    def _run_scan(self, module, target, findings, serve_always, result_type="npm",
                  vulns_override=_UNSET, drop_vulns=False,
                  lock_extra=(), lock_instances=None, lock_joined=0,
                  lock_compact=(), lock_raw=None, lock_raw_lines=None,
                  packages_override=_UNSET, drop_packages=False,
                  raw_stdout=_UNSET):
        body = self._trivy_report(target, findings, result_type, vulns_override,
                                  drop_vulns, lock_extra, lock_instances, lock_joined,
                                  lock_compact, lock_raw, lock_raw_lines,
                                  packages_override, drop_packages)
        argv_seen = []

        def invoke(args, **kwargs):
            if args[-1] == "--version":
                return subprocess.CompletedProcess(args, 0, "Version: 0.75.0\n", "")
            argv_seen.append(list(args))
            # Serve the crafted report whenever it carries findings or an
            # explicit Vulnerabilities-field or Packages-field shape; exit
            # nonzero only when the served report actually flags
            # HIGH/CRITICAL findings, the way the real scanner does.
            crafted = (bool(findings) or vulns_override is not _UNSET
                       or drop_vulns or packages_override is not _UNSET
                       or drop_packages)
            served = crafted and (serve_always or "--include-dev-deps" in args)
            if served:
                # raw_stdout serves verbatim bytes so byte-level defects
                # (a repeated Severity key) that a dict cannot represent
                # still reach production decoding unchanged.
                stdout = (raw_stdout if raw_stdout is not _UNSET
                          else json.dumps(body))
                flagged = self._flagged_high_critical(body)
            else:
                stdout = json.dumps(
                    {"Results": [{"Target": target, "Vulnerabilities": []}]})
                flagged = False
            return subprocess.CompletedProcess(args, int(served and flagged),
                                               stdout, "")

        with patch.object(module, "ROOT", self.root), \
             patch.object(module, "dt", types.SimpleNamespace(date=FrozenDate)), \
             patch.object(module, "tracked_paths",
                          side_effect=lambda pattern: [target] if pattern == "package-lock.json" else []), \
             patch.object(module.subprocess, "run", side_effect=invoke):
            result = module.trivy_audit()
        return (*result, argv_seen)

    def scan(self, target="web/dashboard/package-lock.json"):
        status, details, _ = self._run_scan(audit, target, self.findings, serve_always=True)
        return status, details

    def scan_with_scanner_semantics(self, module, target="sdks/node/package-lock.json"):
        """Serve dev-marked packages the way the pinned trivy 0.75.0 serves a
        lockfile: only when the invocation passes --include-dev-deps."""
        status, details, argv_seen = self._run_scan(
            module, target, SDK_DEV_CRITICALS, serve_always=False)
        return status, details, argv_seen

    def _materialize_variant(self, name, text):
        """Compile an isolated audit variant under the temp root."""
        # The module reads ROOT/go.mod at import; the copy under the temp
        # root's scripts/quality makes its computed ROOT the temp root.
        (self.root / "go.mod").write_bytes((ROOT / "go.mod").read_bytes())
        path = self.root / "scripts/quality" / f"{name}.py"
        path.write_text(text)
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def load_isolated_original_module(self):
        """Current source with exactly the include-dev argument removed.

        Only the single --include-dev-deps argument is removed; every
        other byte stays, including --offline-scan and
        --skip-version-check, so the variant reproduces the pre-fix flag
        semantics and nothing else. This keeps the control valid
        regardless of commit ancestry: the integration cherry-pick does
        not make dd2623c an ancestor. Actual original scanner logs remain
        separate evidence.
        """
        source = (ROOT / "scripts/quality/dep_audit.py").read_text()
        token = '"--include-dev-deps",'
        self.assertEqual(source.count(token), 1)
        variant = source.replace(token, "")
        self.assertNotIn("--include-dev-deps", variant)
        return self._materialize_variant("dep_audit_original", variant)

    def load_path_blind_module(self):
        """Isolated legacy matcher that ignores physical paths and dev class.

        This is the pre-fix matching semantics: an entry matching the
        finding's CVE/package/version/scope alone covers every instance.
        The current scanner must refuse exactly what this variant accepts.
        """
        source = (ROOT / "scripts/quality/dep_audit.py").read_text()
        legacy_matcher = '''

def _uncovered_lock_keys(finding, instances, dependency_exceptions, today):
    # Legacy path-blind matcher (isolated negative control): no physical
    # path, coverage or development matching; scope alone applies.
    matched = any(item.get("vulnerability_id") == finding.get("VulnerabilityID")
                  and item.get("package") == finding.get("PkgName")
                  and item.get("version") == finding.get("InstalledVersion")
                  and item.get("scope") == finding.get("target")
                  for item in dependency_exceptions)
    return [] if matched else [key for key, _ in instances]
'''
        return self._materialize_variant("dep_audit_path_blind", source + legacy_matcher)

    def test_original_audit_missed_dev_marked_criticals(self):
        # Discriminator, original leg: the pre-fix invocation (isolated
        # variant without the flag) never passes --include-dev-deps, so the
        # scanner omits every dev-marked package and the audit passed while
        # the SDK tree carried criticals.
        status, details, argv_seen = self.scan_with_scanner_semantics(
            self.load_isolated_original_module())
        self.assertEqual(status, "ok", details)
        self.assertIn("exact_exceptions_applied=0", details)
        self.assertFalse(any("--include-dev-deps" in argv for argv in argv_seen))
        fixed_status, fixed_details, fixed_argv = self.scan_with_scanner_semantics(audit)
        self.assertEqual(fixed_status, "fail", fixed_details)
        original_scan = next(argv for argv in argv_seen if argv[-1] != "--version")
        fixed_scan = next(argv for argv in fixed_argv if argv[-1] != "--version")
        # The variant changes exactly one argument: every other flag,
        # including the offline and version-check hardening, is identical.
        self.assertEqual(fixed_scan.count("--include-dev-deps"), 1)
        self.assertEqual([arg for arg in fixed_scan if arg != "--include-dev-deps"],
                         original_scan)
        for flag in ("--offline-scan", "--skip-version-check",
                     "--skip-db-update", "--skip-check-update"):
            self.assertIn(flag, original_scan)
            self.assertIn(flag, fixed_scan)

    def test_audit_requests_and_reports_dev_marked_criticals(self):
        # Corrected leg: the flag is passed, the same canned tree yields the
        # dev criticals and the audit fails on them.
        status, details, argv_seen = self.scan_with_scanner_semantics(audit)
        self.assertEqual(status, "fail", details)
        for cve in ("CVE-2026-104848", "CVE-2026-104849", "CVE-2026-47429"):
            self.assertIn(cve, details)
        self.assertTrue(any("--include-dev-deps" in argv for argv in argv_seen),
                        "the audit must invoke trivy with --include-dev-deps")

    def test_public_license_policy_allows_scanner_to_run(self):
        status, details = self.scan()
        self.assertEqual(status, "ok", details)
        self.assertIn("exact_exceptions_applied=0", details)

    def test_license_metadata_exception_cannot_hide_a_vulnerability(self):
        self.findings = [{"VulnerabilityID": "CVE-2099-0001", "PkgName": "eval",
                          "InstalledVersion": "0.1.8", "Severity": "HIGH", "FixedVersion": "0.1.9"}]
        status, details = self.scan()
        self.assertEqual(status, "fail", details)
        self.assertIn("CVE-2099-0001", details)
        self.assertIn("exact_exceptions_applied=0", details)

    def test_dep_audit_exception_applies_to_exact_finding(self):
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": ""}]
        status, details = self.scan(target="web/site/package-lock.json")
        self.assertEqual(status, "ok", details)
        self.assertIn("exact_exceptions_applied=1", details)

    def test_dep_audit_exception_rejects_mismatched_finding(self):
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": ""}
        for label, mismatched, target in (
            ("package", {**finding, "PkgName": "micromatch"}, "web/site/package-lock.json"),
            ("version", {**finding, "InstalledVersion": "2.3.1"}, "web/site/package-lock.json"),
            # Same CVE/package/version reported at an uncovered lockfile: the
            # site exception is scoped to web/site and must not apply.
            ("scope", dict(finding), "sdks/node/package-lock.json"),
        ):
            with self.subTest(mismatch=label):
                self.findings = [mismatched]
                status, details = self.scan(target=target)
                self.assertEqual(status, "fail", details)
                self.assertIn("CVE-2026-112366", details)
                self.assertIn("exact_exceptions_applied=0", details)

    def test_dashboard_dep_audit_exceptions_apply_to_exact_versions(self):
        # The v2 exception covers the single hoisted dashboard instance.
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": ""}]
        status, details = self.scan(target="web/dashboard/package-lock.json")
        self.assertEqual(status, "ok", details)
        self.assertIn("exact_exceptions_applied=1", details)

    def test_dashboard_exception_requires_every_physical_instance(self):
        # Real Trivy shape: ONE aggregated v4 finding whose package record
        # Locations point at both nested lockfile keys. Both registry
        # entries are needed; the finding is excepted exactly once.
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                          "_paths": DASHBOARD_V4_KEYS}]
        status, details = self.scan(target="web/dashboard/package-lock.json")
        self.assertEqual(status, "ok", details)
        self.assertIn("exact_exceptions_applied=1", details)

    def test_aggregated_and_single_findings_count_per_finding(self):
        # Exception counting stays per finding: the aggregated v4 finding
        # (two physical instances, two entries) plus the single v2 finding
        # apply twice total, not three times.
        self.findings = [
            {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
             "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
             "_paths": DASHBOARD_V4_KEYS},
            {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
             "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": ""},
        ]
        status, details = self.scan(target="web/dashboard/package-lock.json")
        self.assertEqual(status, "ok", details)
        self.assertIn("exact_exceptions_applied=2", details)

    def test_dashboard_exception_refuses_missing_physical_instance(self):
        # Removing only the vite-path entry must leave the aggregated v4
        # finding unresolved at that physical instance (DASHBOARD-PATH-01).
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                          "_paths": DASHBOARD_V4_KEYS}]
        policy = yaml.safe_load(self.policy.read_text())
        policy["exceptions"] = [entry for entry in policy["exceptions"]
                                if entry.get("id") != "dashboard-picomatch-v4-vite-extglob-redos"]
        self.policy.write_text(yaml.safe_dump(policy))
        status, details = self.scan(target="web/dashboard/package-lock.json")
        self.assertEqual(status, "fail", details)
        self.assertIn("CVE-2026-112366", details)
        self.assertIn("picomatch", details)
        self.assertIn("node_modules/vite/node_modules/picomatch", details)
        self.assertIn("exact_exceptions_applied=0", details)

    def test_binding_metadata_defects_fail_closed(self):
        # Missing, wrong or ambiguous identity/location metadata is a
        # scanner error, never a silently broadened exception.
        base = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                "_paths": DASHBOARD_V4_KEYS}
        for label, knob in (
            ("wrong-location", {"_bad_location": True}),
            ("no-locations", {"_no_locations": True}),
            ("unbound-finding", {"_unbound": True}),
            ("identity-mismatch", {"_mismatched_identity": True}),
        ):
            with self.subTest(defect=label):
                self.findings = [{**base, **knob}]
                status, details = self.scan(target="web/dashboard/package-lock.json")
                self.assertEqual(status, "error", details)
                self.assertNotEqual(details.strip(), "")

    def test_dashboard_exception_rejects_underreported_physical_coverage(self):
        # LOCATION-COVERAGE-01: the lockfile, not the report, defines the
        # physical instances. A scan reporting only one of the two real v4
        # instances is an error even while both registry entries exist —
        # it must never narrow the exception to the reported instance.
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                          "_paths": ["node_modules/tinyglobby/node_modules/picomatch"]}]
        extra = [("node_modules/vite/node_modules/picomatch", "4.0.5", True)]
        status, details, _ = self._run_scan(audit, "web/dashboard/package-lock.json",
                                            self.findings, serve_always=True,
                                            lock_extra=extra)
        self.assertEqual(status, "error", details)
        self.assertIn("physical instances", details)

    def test_dashboard_location_wrong_version_identity_rejected(self):
        # LOCATION-COVERAGE-01: a reported location that resolves to a real
        # lock entry of the same package but a different version is an
        # identity mismatch, not coverage, even though the Trivy package
        # record itself carries the expected name and version. The lock
        # fixture is explicit and unique: the hoisted entry is actually
        # 2.3.2 and the two distinct nested entries are actually 4.0.5.
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                          "_paths": ["node_modules/picomatch"]}]
        lock = [("node_modules/picomatch", "2.3.2", True),
                ("node_modules/tinyglobby/node_modules/picomatch", "4.0.5", True),
                ("node_modules/vite/node_modules/picomatch", "4.0.5", True)]
        status, details, _ = self._run_scan(audit, "web/dashboard/package-lock.json",
                                            self.findings, serve_always=True,
                                            lock_instances=lock)
        self.assertEqual(status, "error", details)
        self.assertIn("resolves to a lockfile entry that is not this package "
                      "version", details)

    def test_dashboard_lock_entry_without_usable_version_fails_closed(self):
        # A key matching the package name but carrying no usable string
        # version is an ambiguity error, not a silently skipped instance:
        # incomplete coverage must not hide behind malformed lock metadata.
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                          "_paths": DASHBOARD_V4_KEYS}]
        for label, version in (("missing-version", None), ("non-string-version", 1.2)):
            with self.subTest(defect=label):
                lock = [("node_modules/tinyglobby/node_modules/picomatch", "4.0.5", True),
                        ("node_modules/vite/node_modules/picomatch", version, True)]
                status, details, _ = self._run_scan(
                    audit, "web/dashboard/package-lock.json", self.findings,
                    serve_always=True, lock_instances=lock)
                self.assertEqual(status, "error", details)
                self.assertIn("has no usable version", details)
    def test_alias_lock_entries_count_in_physical_coverage(self):
        # PHYSICAL-ALIAS-01 / BLANK-VERSION-01: an npm alias lock entry
        # names its real package explicitly, so it is a physical instance
        # that complete coverage must count, and a relevant entry with a
        # blank version is ambiguous metadata, never silently skipped. The
        # lock fixture exists independently of the reported paths.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": list(DASHBOARD_V4_KEYS)}
        alias = ("node_modules/pmc", "4.0.5", True, {"name": "picomatch"})
        lock = [("node_modules/picomatch", "2.3.2", True)] + list(DASHBOARD_V4_INSTANCES) + [alias]
        with self.subTest(defect="alias-omitted-from-report"):
            status, details, _ = self._run_scan(
                audit, "web/dashboard/package-lock.json", [finding],
                serve_always=True, lock_instances=lock)
            self.assertEqual(status, "error", details)
            self.assertIn("reports 2 of 3 physical instances", details)
        with self.subTest(defect="alias-reported-but-uncovered"):
            reported = dict(finding, _paths=list(DASHBOARD_V4_KEYS) + ["node_modules/pmc"])
            status, details, _ = self._run_scan(
                audit, "web/dashboard/package-lock.json", [reported],
                serve_always=True, lock_instances=lock)
            self.assertEqual(status, "fail", details)
            self.assertIn("uncovered_paths=node_modules/pmc", details)
        with self.subTest(defect="blank-version-sibling"):
            blank = list(DASHBOARD_V4_INSTANCES)
            blank[0] = (blank[0][0], "", blank[0][2])
            status, details, _ = self._run_scan(
                audit, "web/dashboard/package-lock.json", [finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "2.3.2", True)] + blank)
            self.assertEqual(status, "error", details)
            self.assertIn("has no usable version", details)
        with self.subTest(defect="whitespace-version-sibling"):
            padded = list(DASHBOARD_V4_INSTANCES)
            padded[0] = (padded[0][0], "   ", padded[0][2])
            status, details, _ = self._run_scan(
                audit, "web/dashboard/package-lock.json", [finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "2.3.2", True)] + padded)
            self.assertEqual(status, "error", details)
            self.assertIn("has no usable version", details)
        with self.subTest(defect="alias-covered-approves"):
            policy = yaml.safe_load(self.policy.read_text())
            policy["exceptions"].append({
                "id": "control-dashboard-picomatch-alias-extglob-redos",
                "scanner": "dep_audit", "vulnerability_id": "CVE-2026-112366",
                "package": "picomatch", "version": "4.0.5",
                "scope": "web/dashboard/package-lock.json", "path": "node_modules/pmc",
                "reason": "control: alias instance carries the same coverage contract",
                "owner": "yabanin", "expires": "2026-11-30", "development": True})
            self.policy.write_text(yaml.safe_dump(policy))
            reported = dict(finding, _paths=list(DASHBOARD_V4_KEYS) + ["node_modules/pmc"])
            status, details, _ = self._run_scan(
                audit, "web/dashboard/package-lock.json", [reported],
                serve_always=True, lock_instances=lock)
            # ok status requires every physical instance, the alias
            # included, to be covered; the counter totals fully-covered
            # findings, which is one row here.
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_mixed_version_same_line_location_is_ambiguous(self):
        # LOCATION-AMBIGUITY-01: two lockfile entries of different
        # versions starting on one line make any reported location on that
        # line ambiguous in the full packages map. Resolving against the
        # version-filtered view alone accepted exactly this shape.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/tinyglobby/node_modules/picomatch"]}
        lock = [("node_modules/picomatch", "2.3.2", True),
                ("node_modules/tinyglobby/node_modules/picomatch", "4.0.5", True)]
        status, details, _ = self._run_scan(
            audit, "web/dashboard/package-lock.json", [finding],
            serve_always=True, lock_instances=lock, lock_joined=1)
        self.assertEqual(status, "error", details)
        self.assertIn("does not resolve to exactly one matching lockfile entry", details)
    def test_reverse_alias_path_does_not_inherit_exception(self):
        # EXPLICIT-NAME-PRECEDENCE-01: an explicit `name` naming a
        # different package outranks the install path, so that entry is
        # not a picomatch instance and a picomatch finding pointing at it
        # must fail closed instead of inheriting the path exception.
        renamed = {"node_modules/picomatch": {"name": "not-picomatch",
                                              "version": "4.0.5", "dev": True}}
        self.assertEqual(audit._lock_package_instances(renamed, "picomatch", "4.0.5"),
                         ([], None))
        for malformed in (3, True, None, "", "   "):
            with self.subTest(malformed=malformed):
                broken = {"node_modules/other": {"name": malformed, "version": "1.0.0"}}
                instances, error = audit._lock_package_instances(broken, "picomatch", "4.0.5")
                self.assertEqual(instances, [])
                self.assertIn("has malformed identity for exception scoping", error)
        with self.subTest(defect="path-relevant-non-object-entry"):
            broken = {"node_modules/picomatch": "not-an-object"}
            instances, error = audit._lock_package_instances(broken, "picomatch", "4.0.5")
            self.assertEqual(instances, [])
            self.assertIn("has malformed metadata for exception scoping", error)
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/picomatch"]}
        lock = [("node_modules/picomatch", "4.0.5", True, {"name": "not-picomatch"})]
        status, details, _ = self._run_scan(
            audit, "sdks/node/package-lock.json", [finding],
            serve_always=True, lock_instances=lock)
        self.assertEqual(status, "error", details)
        self.assertIn("has no lockfile entries for sdks/node/package-lock.json", details)

    def test_mixed_spacing_same_line_locations_are_ambiguous(self):
        # PARSER-LOCATION-01: two entries of different versions starting
        # on one line stay ambiguous whatever the legal JSON spacing,
        # because uniqueness comes from parsed packages-member start
        # lines. The substring resolver accepted exactly this shape when
        # only one entry used the expected space.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/tinyglobby/node_modules/picomatch"]}
        lock = [("node_modules/picomatch", "2.3.2", True),
                ("node_modules/tinyglobby/node_modules/picomatch", "4.0.5", True)]
        status, details, _ = self._run_scan(
            audit, "web/dashboard/package-lock.json", [finding],
            serve_always=True, lock_instances=lock, lock_joined=1,
            lock_compact=("node_modules/picomatch",))
        self.assertEqual(status, "error", details)
        self.assertIn("does not resolve to exactly one matching lockfile entry", details)
        with self.subTest(spacing="unique-lines-bind-normally"):
            # Ordinary unique locations resolve with per-line spacing
            # variants too: a compact entry and a spaced entry each begin
            # exactly one member, so binding and exceptions still work.
            status, details, _ = self._run_scan(
                audit, "web/dashboard/package-lock.json", [finding],
                serve_always=True, lock_instances=lock,
                lock_compact=("node_modules/picomatch",))
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_malformed_trivy_locations_fail_closed(self):
        # LOCATION-TYPES-01: Locations must be a list of objects whose
        # StartLine is a positive, non-boolean integer. Malformed
        # metadata returns the scanner error status, never an uncaught
        # exception or an accidental clean pass; a valid positive line
        # still reaches normal binding and exception behavior.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": ""}
        with self.subTest(defect="locations-not-a-list"):
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json",
                [dict(finding, _locations=3)], serve_always=True)
            self.assertEqual(status, "error", details)
            self.assertIn("has a malformed Locations field", details)
        for start in (True, 0, -5, "3"):
            with self.subTest(startline=start):
                status, details, _ = self._run_scan(
                    audit, "web/site/package-lock.json",
                    [dict(finding, _locations=[{"StartLine": start}])], serve_always=True)
                self.assertEqual(status, "error", details)
                self.assertIn("has an invalid StartLine", details)
        with self.subTest(defect="valid-positive-location-binds"):
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [finding], serve_always=True)
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)
    def test_duplicate_lockfile_members_fail_closed(self):
        # PARSER-LOCATION-01 duplicates: a second `packages` block or two
        # members sharing one key leave the member-to-line mapping
        # ambiguous — including which duplicate the json view kept — so
        # binding fails closed instead of collapsing to one winner.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/picomatch"]}
        lock = [("node_modules/picomatch", "4.0.5", True)]
        duplicate_member = ('{"packages": {\n'
                            '    "node_modules/picomatch": {"version": "4.0.5"},\n'
                            '    "node_modules/picomatch": {"version": "4.0.5"}\n'
                            '}}\n')
        duplicate_block = ('{"packages": {"node_modules/picomatch": '
                           '{"version": "4.0.5"}},\n'
                           ' "packages": {"node_modules/picomatch": '
                           '{"version": "4.0.5"}}}\n')
        for label, raw in (("duplicate-member-key", duplicate_member),
                           ("duplicate-packages-block", duplicate_block)):
            with self.subTest(defect=label):
                status, details, _ = self._run_scan(
                    audit, "web/dashboard/package-lock.json", [finding],
                    serve_always=True, lock_instances=lock, lock_raw=raw)
                self.assertEqual(status, "error", details)
                self.assertIn("ambiguous lockfile member metadata", details)




    def test_repeated_merge_keys_fail_closed(self):
        # REPEATED-MERGE-KEYS-01: base flatten_mapping removes repeated
        # `<<` keys before duplicate checking, silently combining two
        # merges with disjoint fields. Two merge keys in one mapping are
        # a policy error wherever they appear, including inside a nested
        # merge source; a single `<<` over a sequence of the same
        # disjoint mappings stays valid.
        head = ('schema: 1\n'
                'exceptions:\n'
                '  - id: repeated-merge\n'
                '    path: node_modules/picomatch\n'
                '    vulnerability_id: CVE-2026-112366\n'
                '    package: picomatch\n'
                '    version: 4.0.7\n'
                '    scope: sdks/node/package-lock.json\n'
                '    reason: repeated-merge regression fixture\n')
        sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                       "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                       "_paths": ["node_modules/picomatch"]}
        shapes = {
            "two-merge-keys": (
                '    <<: &left\n'
                '      owner: yabanin\n'
                '    <<: &right\n'
                '      scanner: dep_audit\n'
                '      expires: "2026-11-30"\n'
                '    development: true\n'),
            "nested-source-two-merges": (
                '    <<: &outer\n'
                '      <<: {owner: yabanin}\n'
                '      <<: {scanner: dep_audit, expires: "2026-11-30"}\n'
                '    development: true\n'),
        }
        for label, tail in shapes.items():
            with self.subTest(defect=label):
                self.policy.write_text(head + tail)
                status, details = self.scan()
                self.assertEqual(status, "error", details)
                self.assertIn("could not load dependency exceptions", details)
                self.assertIn("repeated YAML merge key", details)
        with self.subTest(shape="sequence-merge-valid"):
            self.policy.write_text(
                head + '    <<: [&left {owner: yabanin}, '
                '&right {scanner: dep_audit, expires: "2026-11-30"}]\n'
                '    development: true\n')
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_invalid_registry_expiry_fail_closed(self):
        # YAML-CONSTRUCTION-ERROR-01: an unquoted invalid expiry parses as
        # a timestamp and raises ValueError while constructing registry
        # objects, before exception validation; the audit must return a
        # policy error, not escape. Quoted-string expiry keeps working.
        head = ('schema: 1\n'
                'exceptions:\n'
                '  - id: invalid-expiry\n'
                '    path: node_modules/picomatch\n'
                '    vulnerability_id: CVE-2026-112366\n'
                '    package: picomatch\n'
                '    version: 4.0.7\n'
                '    scope: sdks/node/package-lock.json\n'
                '    reason: invalid-expiry regression fixture\n'
                '    owner: yabanin\n'
                '    scanner: dep_audit\n')
        with self.subTest(defect="unquoted-invalid-date"):
            self.policy.write_text(head + '    expires: 2026-02-30\n'
                                   + '    development: true\n')
            status, details = self.scan()
            self.assertEqual(status, "error", details)
            self.assertIn("could not load dependency exceptions", details)
            self.assertIn("day is out of range for month", details)
        with self.subTest(shape="quoted-expiry-preserved"):
            self.policy.write_text(head + '    expires: "2026-11-30"\n'
                                   + '    development: true\n')
            sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                           "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                           "_paths": ["node_modules/picomatch"]}
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)


    def test_malformed_yaml_bool_fail_closed(self):
        # YAML-BOOL-CONSTRUCTOR-01: an explicit !!bool tag with an
        # unrecognized scalar raises KeyError while constructing registry
        # objects; the audit must return a policy error, not a traceback.
        head = ('schema: 1\n'
                'exceptions:\n'
                '  - id: malformed-bool\n'
                '    path: node_modules/picomatch\n'
                '    vulnerability_id: CVE-2026-112366\n'
                '    package: picomatch\n'
                '    version: 4.0.7\n'
                '    scope: sdks/node/package-lock.json\n'
                '    reason: malformed-bool regression fixture\n'
                '    owner: yabanin\n'
                '    scanner: dep_audit\n'
                '    expires: "2026-11-30"\n')
        with self.subTest(defect="explicit-bool-tag"):
            self.policy.write_text(head + '    development: !!bool maybe\n')
            status, details = self.scan()
            self.assertEqual(status, "error", details)
            self.assertIn("could not load dependency exceptions", details)
            self.assertIn("'maybe'", details)
        with self.subTest(shape="valid-bool-preserved"):
            self.policy.write_text(head + '    development: true\n')
            sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                           "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                           "_paths": ["node_modules/picomatch"]}
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_exception_id_type_fail_closed(self):
        # EXCEPTION-ID-TYPE-01: a numeric or missing id must fail as a
        # policy error during exact-scope validation, before expiry
        # collection, instead of crashing the gate's expired-ID join.
        # An expired entry with a valid string id keeps its named fail
        # diagnostic.
        fields = ('    path: node_modules/picomatch\n'
                  '    vulnerability_id: CVE-2026-112366\n'
                  '    package: picomatch\n'
                  '    version: 4.0.7\n'
                  '    scope: sdks/node/package-lock.json\n'
                  '    reason: id-type regression fixture\n'
                  '    owner: yabanin\n'
                  '    scanner: dep_audit\n')
        sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                       "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                       "_paths": ["node_modules/picomatch"]}
        lock = [("node_modules/picomatch", "4.0.7", True)]
        defects = {
            "numeric-id": "schema: 1\nexceptions:\n  - id: 42\n" + fields
                          + '    expires: "2026-01-01"\n    development: true\n',
            "missing-id": "schema: 1\nexceptions:\n  -\n" + fields
                          + '    expires: "2026-01-01"\n    development: true\n',
        }
        for label, body in defects.items():
            with self.subTest(defect=label):
                self.policy.write_text(body)
                status, details = self.scan()
                self.assertEqual(status, "error", details)
                self.assertIn("not exact-scoped", details)
        with self.subTest(shape="expired-string-id-retains-fail"):
            self.policy.write_text("schema: 1\nexceptions:\n  - id: merge-expired\n"
                                   + fields + '    expires: "2026-01-01"\n'
                                   + '    development: true\n')
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True, lock_instances=lock)
            self.assertEqual(status, "fail", details)
            self.assertIn("expired_dependency_exceptions=merge-expired", details)
            self.assertIn("high_critical_findings=1", details)
        with self.subTest(shape="valid-string-id-preserved"):
            self.policy.write_text("schema: 1\nexceptions:\n  - id: valid-id\n"
                                   + fields + '    expires: "2026-11-30"\n'
                                   + '    development: true\n')
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True, lock_instances=lock)
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)


    def test_constructor_attribute_index_fail_closed(self):
        # YAML-CONSTRUCTOR-ATTRIBUTE/INDEX-01: explicit !!timestamp on an
        # unmatchable scalar raises AttributeError and !!int on an empty
        # scalar raises IndexError while constructing registry objects;
        # both must surface as policy errors at the loading boundary,
        # not tracebacks, while a valid registry keeps applying.
        fields = ('    path: node_modules/picomatch\n'
                  '    vulnerability_id: CVE-2026-112366\n'
                  '    package: picomatch\n'
                  '    version: 4.0.7\n'
                  '    scope: sdks/node/package-lock.json\n'
                  '    reason: constructor regression fixture\n'
                  '    owner: yabanin\n'
                  '    scanner: dep_audit\n')
        head = 'schema: 1\nexceptions:\n  - id: constructor-fixture\n' + fields
        defects = {
            "timestamp-attribute": head + '    expires: !!timestamp invalid\n'
                                      + '    development: true\n',
            "integer-index": 'schema: 1\nexceptions:\n  - id: !!int \'\'\n' + fields
                             + '    expires: "2026-11-30"\n    development: true\n',
        }
        for label, body in defects.items():
            with self.subTest(defect=label):
                self.policy.write_text(body)
                status, details = self.scan()
                self.assertEqual(status, "error", details)
                self.assertIn("could not load dependency exceptions", details)
        with self.subTest(shape="valid-registry-preserved"):
            self.policy.write_text(head + '    expires: "2026-11-30"\n'
                                   + '    development: true\n')
            sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                           "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                           "_paths": ["node_modules/picomatch"]}
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)


    def test_tagged_node_kind_fail_closed(self):
        # YAML-NODE-KIND-01: an empty sequence explicitly tagged !!map
        # constructs as an empty mapping and its entry is then skipped,
        # yielding a clean audit for malformed registry content. Any
        # node-kind mismatch must fail closed at the loading boundary.
        with self.subTest(defect="tagged-sequence-as-map"):
            self.policy.write_text('schema: 1\nexceptions: [!!map []]\n')
            status, details = self.scan()
            self.assertEqual(status, "error", details)
            self.assertIn("could not load dependency exceptions", details)
            self.assertIn("not a mapping", details)
        with self.subTest(shape="valid-registry-preserved"):
            self.policy.write_text(
                'schema: 1\n'
                'exceptions:\n'
                '  - id: node-kind-fixture\n'
                '    path: node_modules/picomatch\n'
                '    vulnerability_id: CVE-2026-112366\n'
                '    package: picomatch\n'
                '    version: 4.0.7\n'
                '    scope: sdks/node/package-lock.json\n'
                '    reason: node-kind regression fixture\n'
                '    owner: yabanin\n'
                '    scanner: dep_audit\n'
                '    expires: "2026-11-30"\n'
                '    development: true\n')
            sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                           "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                           "_paths": ["node_modules/picomatch"]}
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)


    def test_merge_operand_kind_fail_closed(self):
        # YAML-MERGE-OPERAND-KIND-01: base flatten_mapping consumes an
        # empty sequence tagged !!map as a no-op merge operand before
        # _unique_mapping can reject its tag, keeping a malformed
        # registry active. Each operand's tag must match its node kind
        # before merge expansion; valid merges keep applying.
        head = ('schema: 1\n'
                'exceptions:\n'
                '  - id: merge-operand-kind\n'
                '    path: node_modules/picomatch\n'
                '    vulnerability_id: CVE-2026-112366\n'
                '    package: picomatch\n'
                '    version: 4.0.7\n'
                '    scope: sdks/node/package-lock.json\n'
                '    reason: merge-operand regression fixture\n')
        tail = ('    owner: yabanin\n'
                '    scanner: dep_audit\n'
                '    expires: "2026-11-30"\n'
                '    development: true\n')
        defects = {
            "map-tagged-sequence": '    <<: !!map []\n',
            "seq-tagged-mapping": '    <<: !!seq {}\n',
        }
        for label, merge_line in defects.items():
            with self.subTest(defect=label):
                self.policy.write_text(head + merge_line + tail)
                status, details = self.scan()
                self.assertEqual(status, "error", details)
                self.assertIn("could not load dependency exceptions", details)
                self.assertIn("merge operand", details)
        with self.subTest(shape="sequence-merge-valid"):
            self.policy.write_text(
                head + '    <<: [&left {owner: yabanin}, '
                '&right {scanner: dep_audit, expires: "2026-11-30"}]\n'
                '    development: true\n')
            sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                           "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                           "_paths": ["node_modules/picomatch"]}
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)
        with self.subTest(shape="valid-registry-preserved"):
            self.policy.write_text(head + tail)
            sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                           "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                           "_paths": ["node_modules/picomatch"]}
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)


    def test_merge_source_tag_fail_closed(self):
        # YAML-MERGE-SOURCE-TAG-01: base flatten_mapping consumes a
        # mistagged mapping and applies its fields, both directly and
        # as a sequence member. Each merge source must be a MappingNode
        # with the YAML map tag before expansion; valid merges keep
        # applying.
        head = ('schema: 1\n'
                'exceptions:\n'
                '  - id: merge-source-tag\n'
                '    path: node_modules/picomatch\n'
                '    vulnerability_id: CVE-2026-112366\n'
                '    package: picomatch\n'
                '    version: 4.0.7\n'
                '    scope: sdks/node/package-lock.json\n'
                '    reason: merge-source regression fixture\n')
        tail = ('    scanner: dep_audit\n'
                '    expires: "2026-11-30"\n'
                '    development: true\n')
        defects = {
            "direct-scalar-tagged-mapping": '    <<: !!str {owner: yabanin}\n',
            "scalar-tagged-sequence-member": '    <<: [!!str {owner: yabanin}]\n',
            "seq-tagged-sequence-member": '    <<: [!!seq {owner: yabanin}]\n',
        }
        for label, merge_line in defects.items():
            with self.subTest(defect=label):
                self.policy.write_text(head + merge_line + tail)
                status, details = self.scan()
                self.assertEqual(status, "error", details)
                self.assertIn("could not load dependency exceptions", details)
                self.assertIn("merge operand", details)
        sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                       "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                       "_paths": ["node_modules/picomatch"]}
        lock = [("node_modules/picomatch", "4.0.7", True)]
        with self.subTest(shape="sequence-merge-valid"):
            self.policy.write_text(
                head + '    <<: [&left {owner: yabanin}, '
                '&right {scanner: dep_audit, expires: "2026-11-30"}]\n'
                '    development: true\n')
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True, lock_instances=lock)
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)
        with self.subTest(shape="valid-registry-preserved"):
            self.policy.write_text(head + '    owner: yabanin\n' + tail)
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True, lock_instances=lock)
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_lookalike_lockfile_basename_fail_closed(self):
        # NPM-BASENAME-01: only a final path component of exactly
        # package-lock.json identifies an npm lockfile result. A lookalike
        # suffix such as backup-package-lock.json must never be opened and
        # its HIGH finding stays unexcepted; the read boundary is asserted
        # by recording every lockfile read, not just the fail summary.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/picomatch"]}
        lock = [("node_modules/picomatch", "4.0.7", True)]
        reads = []
        real_read_bytes = Path.read_bytes

        def recording_read_bytes(path_self):
            reads.append(str(path_self))
            return real_read_bytes(path_self)

        with self.subTest(defect="lookalike-suffix-not-read"):
            with patch.object(Path, "read_bytes", recording_read_bytes):
                status, details, _ = self._run_scan(
                    audit, "sdks/node/backup-package-lock.json", [finding],
                    serve_always=True, lock_instances=lock)
            self.assertEqual(status, "fail", details)
            self.assertIn("uncovered_paths=no physical lockfile binding", details)
            self.assertIn("exact_exceptions_applied=0", details)
            self.assertFalse(
                [p for p in reads if "backup-package-lock.json" in p],
                "lookalike lockfile was opened: %s" % reads)
        with self.subTest(shape="ordinary-target-still-read"):
            reads.clear()
            with patch.object(Path, "read_bytes", recording_read_bytes):
                status, details, _ = self._run_scan(
                    audit, "sdks/node/package-lock.json", [finding],
                    serve_always=True, lock_instances=lock)
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)
            self.assertTrue(
                any(p.endswith("sdks/node/package-lock.json") for p in reads),
                "ordinary lockfile was not read: %s" % reads)

    def test_registry_merge_keys_fail_closed(self):
        # YAML-MERGE-01: SafeLoader merge keys (`<<`) are valid registry
        # YAML. Inherited fields work when they do not collide; an
        # inherited field colliding with a direct one is a duplicate-key
        # policy error, not a last-wins merge or a rejected merge.
        head = ('schema: 1\n'
                'exceptions:\n'
                '  - id: merge-development\n'
                '    path: node_modules/picomatch\n'
                '    vulnerability_id: CVE-2026-112366\n'
                '    package: picomatch\n'
                '    version: 4.0.7\n'
                '    scope: sdks/node/package-lock.json\n'
                '    reason: merge-key regression fixture\n')
        inherited = ('    <<: &common\n'
                     '      owner: yabanin\n'
                     '      scanner: dep_audit\n'
                     '      expires: "2026-11-30"\n')
        sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                       "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                       "_paths": ["node_modules/picomatch"]}
        with self.subTest(shape="valid-inherited-owner"):
            self.policy.write_text(head + inherited + '    development: true\n')
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)
        with self.subTest(defect="inherited-direct-development-conflict"):
            self.policy.write_text(head + inherited
                                   + '      development: false\n'
                                   + '    development: true\n')
            status, details = self.scan()
            self.assertEqual(status, "error", details)
            self.assertIn("could not load dependency exceptions", details)
            self.assertIn("duplicate YAML mapping key: development", details)
            self.assertNotIn("merge", details)

    def test_raw_report_duplicate_keys_fail_closed(self):
        # RAW-REPORT-DUPLICATES-01: json decoding keeps the last value of
        # a repeated key, so a finding repeating Severity HIGH then MEDIUM
        # reached validation as MEDIUM while a separate excepted HIGH
        # finding satisfied the exit-code check. Raw scanner stdout with
        # any duplicated key is invalid scanner JSON; valid raw JSON is
        # served through unchanged.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/picomatch"]}
        # Same excepted identity; a distinct serialization (the extra
        # PrimaryURL field Trivy emits) keeps the splice single-target.
        second = dict(finding, PrimaryURL="https://cve.example/CVE-2026-112366")
        lock = [("node_modules/picomatch", "2.3.2", True)]
        body = self._trivy_report("web/site/package-lock.json", [finding, second],
                                  "npm", _UNSET, False, (), lock, 0, (), None, None,
                                  _UNSET, False)
        serialized = json.dumps(body)
        second_json = json.dumps(body["Results"][0]["Vulnerabilities"][1])
        self.assertEqual(serialized.count(second_json), 1)
        duplicated = serialized.replace(second_json,
                                        second_json[:-1] + ', "Severity": "MEDIUM"}')
        with self.subTest(defect="repeated-severity-beside-excepted"):
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [finding, second],
                serve_always=True, lock_instances=lock, raw_stdout=duplicated)
            self.assertEqual(status, "error", details)
            self.assertIn("Trivy returned invalid JSON", details)
        with self.subTest(shape="valid-raw-json-preserved"):
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [finding, second],
                serve_always=True, lock_instances=lock, raw_stdout=serialized)
            self.assertEqual(status, "ok", details)
            # Both excepted findings bind through the same registry entry.
            self.assertIn("high_critical_findings=0", details)
            self.assertIn("exact_exceptions_applied=2", details)

    def test_registry_duplicate_keys_fail_closed(self):
        # REGISTRY-DUPLICATES-01: yaml resolves repeated keys last-wins,
        # so a literal duplicate development field could turn a
        # development-only waiver into one matching runtime entries (or
        # the reverse). Both orders are policy errors; a single
        # development field keeps matching its dev-tree instances.
        base = ('schema: 1\n'
                'exceptions:\n'
                '  - id: dup-development\n'
                '    path: node_modules/picomatch\n'
                '    vulnerability_id: CVE-2026-112366\n'
                '    package: picomatch\n'
                '    version: 4.0.7\n'
                '    scope: sdks/node/package-lock.json\n'
                '    reason: duplicate-key regression fixture\n'
                '    owner: yabanin\n'
                '    expires: "2026-11-30"\n'
                '    scanner: dep_audit\n')
        for label, first, second in (("false-then-true", "false", "true"),
                                     ("true-then-false", "true", "false")):
            with self.subTest(defect=label):
                self.policy.write_text(base
                                       + '    development: ' + first + '\n'
                                       + '    development: ' + second + '\n')
                status, details = self.scan()
                self.assertEqual(status, "error", details)
                self.assertIn("could not load dependency exceptions", details)
                self.assertIn("duplicate YAML mapping key: development", details)
        with self.subTest(shape="single-development-preserved"):
            self.policy.write_text(base + '    development: true\n')
            sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                           "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                           "_paths": ["node_modules/picomatch"]}
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_target_confinement_fail_closed(self):
        # TARGET-CONFINEMENT-01: a scanner-reported Target is untrusted
        # input. Absolute, parent-traversing and symlink-escaping targets
        # are refused before any file is read; the ordinary
        # repository-relative SDK lockfile keeps binding normally.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/picomatch"]}
        lock = [("node_modules/picomatch", "2.3.2", True)]
        outside = tempfile.TemporaryDirectory(prefix="confinement-")
        self.addCleanup(outside.cleanup)
        outside_path = Path(outside.name)
        (self.root / "sdks/node").mkdir(parents=True, exist_ok=True)
        (self.root / "sdks/node/evil").symlink_to(outside_path)
        cases = {
            "absolute": str(outside_path / "package-lock.json"),
            "parent-traversal": "../" + outside_path.name + "/package-lock.json",
            "symlink-escape": "sdks/node/evil/package-lock.json",
        }
        for label, target in cases.items():
            with self.subTest(defect=label):
                status, details, _ = self._run_scan(
                    audit, target, [finding], serve_always=True,
                    lock_instances=lock)
                self.assertEqual(status, "error", details)
                self.assertIn("not confined to the repository", details)
        with self.subTest(shape="ordinary-target-binds"):
            sdk_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                           "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                           "_paths": ["node_modules/picomatch"]}
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [sdk_finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_duplicate_binding_fields_fail_closed(self):
        # DUPLICATE-BINDING-FIELDS-01: JSON collapses duplicate
        # name/version/dev fields inside one entry to its last winner, so
        # the composed nodes must reject them before the json view chooses.
        # A conflicting dev must fail closed in either order; duplicates
        # are rejected even when the values coincide, while a single
        # dev:true entry keeps its development-only exception.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/picomatch"]}
        cases = {
            "dev-false-then-true":
                '{"version": "4.0.7", "dev": false, "dev": true}',
            "dev-true-then-false":
                '{"version": "4.0.7", "dev": true, "dev": false}',
            "name-coinciding":
                '{"version": "4.0.7", "name": "picomatch", "name": "picomatch"}',
            "version-coinciding":
                '{"version": "4.0.7", "version": "4.0.7", "dev": true}',
        }
        for label, entry in cases.items():
            with self.subTest(defect=label):
                raw = ('{"packages": {\n'
                       '    "node_modules/picomatch": ' + entry + '\n'
                       '}}\n')
                status, details, _ = self._run_scan(
                    audit, "sdks/node/package-lock.json", [finding],
                    serve_always=True,
                    lock_instances=[("node_modules/picomatch", "4.0.7", True)],
                    lock_raw=raw, lock_raw_lines={"node_modules/picomatch": 2})
                self.assertEqual(status, "error", details)
                self.assertIn("ambiguous lockfile member metadata", details)
        with self.subTest(shape="single-dev-true"):
            status, details, _ = self._run_scan(
                audit, "sdks/node/package-lock.json", [finding],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "4.0.7", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_severity_enum_fail_closed(self):
        # SEVERITY-ENUM-01: a padded or unrecognized Severity is a scanner
        # error even beside a recognized excepted finding and scanner
        # exit 1; a valid MEDIUM stays ignored by the HIGH/CRITICAL gate.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/picomatch"]}
        for label, severity in (("padded", "HIGH "), ("lowercase", "critical")):
            with self.subTest(defect=label + "-severity-beside-excepted"):
                status, details, _ = self._run_scan(
                    audit, "web/site/package-lock.json",
                    [finding, dict(finding, Severity=severity, VulnerabilityID="CVE-2026-1")],
                    serve_always=True,
                    lock_instances=[("node_modules/picomatch", "2.3.2", True)])
                self.assertEqual(status, "error", details)
                self.assertIn("invalid Severity", details)
        with self.subTest(shape="valid-medium-ignored"):
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json",
                [finding, dict(finding, Severity="MEDIUM", VulnerabilityID="CVE-2026-2")],
                serve_always=True,
                lock_instances=[("node_modules/picomatch", "2.3.2", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("high_critical_findings=0", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_scalar_vulnerabilities_field_fail_closed(self):
        # TEST-DOUBLE-SCALAR-01: a truthy scalar Vulnerabilities payload
        # must reach production validation and fail closed, not raise a
        # harness TypeError before trivy_audit() runs.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/picomatch"]}
        for label, payload in (("number", 7), ("boolean", True)):
            with self.subTest(defect=label + "-vulnerabilities-field"):
                status, details, _ = self._run_scan(
                    audit, "web/site/package-lock.json", [finding],
                    serve_always=True, vulns_override=payload,
                    lock_instances=[("node_modules/picomatch", "2.3.2", True)])
                self.assertEqual(status, "error", details)
                self.assertIn("invalid Vulnerabilities field", details)

    def test_u2028_same_physical_line_is_ambiguous(self):
        # PHYSICAL-LINE-01: a literal U+2028 inside a JSON string is a
        # line break to the YAML parser but not to the physical LF
        # framing Trivy's StartLine counts. Two package keys sharing one
        # physical line must therefore stay ambiguous, and non-ASCII
        # text before a key must not shift the line arithmetic.
        raw = ('{"packages": {\n'
               '    "node_modules/picomatch": '
               '{"version": "2.3.2", "note": "split\u2028here"}, '
               '"node_modules/tinyglobby/node_modules/picomatch": '
               '{"version": "4.0.5"}\n'
               '}}\n')
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/picomatch"]}
        lock = [("node_modules/picomatch", "2.3.2", True),
                ("node_modules/tinyglobby/node_modules/picomatch", "4.0.5", True)]
        status, details, _ = self._run_scan(
            audit, "web/site/package-lock.json", [finding], serve_always=True,
            lock_instances=lock, lock_raw=raw,
            lock_raw_lines={"node_modules/picomatch": 2,
                            "node_modules/tinyglobby/node_modules/picomatch": 2})
        self.assertEqual(status, "error", details)
        self.assertIn("does not resolve to exactly one matching lockfile entry", details)
        with self.subTest(shape="non-ascii-before-unique-key"):
            # Multibyte text and a literal U+2028 in an earlier line keep
            # the character-index line arithmetic correct for a later,
            # line-unique key; a splitlines-style count would drift.
            unique = ('{"lockfileVersion": 3, '
                      '"note": "h\u00e9llo\u2192\u4e16\u754c split\u2028here",\n'
                      ' "packages": {\n'
                      '  "node_modules/picomatch": {"version": "2.3.2"}\n'
              '}}\n')
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [finding], serve_always=True,
                lock_instances=[("node_modules/picomatch", "2.3.2", True)],
                lock_raw=unique,
                lock_raw_lines={"node_modules/picomatch": 3})
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_bare_cr_same_physical_line_is_ambiguous(self):
        # BARE-CR-PHYSICAL-LINE-01: a bare CR is JSON whitespace between
        # members, but universal-newline translation would fold it to LF,
        # splitting one physical line in two and handing the first key a
        # unique location. Physical lines stay LF-delimited; CRLF locks
        # keep their real lines.
        raw = ('{"packages": {\n'
               '    "node_modules/picomatch": {"version": "2.3.2"},\r'
               '    "node_modules/tinyglobby/node_modules/picomatch": '
               '{"version": "4.0.5"}\n'
               '}}\n')
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": ["node_modules/picomatch"]}
        lock = [("node_modules/picomatch", "2.3.2", True),
                ("node_modules/tinyglobby/node_modules/picomatch", "4.0.5", True)]
        status, details, _ = self._run_scan(
            audit, "web/site/package-lock.json", [finding], serve_always=True,
            lock_instances=lock, lock_raw=raw,
            lock_raw_lines={"node_modules/picomatch": 2,
                            "node_modules/tinyglobby/node_modules/picomatch": 2})
        self.assertEqual(status, "error", details)
        self.assertIn("does not resolve to exactly one matching lockfile entry", details)
        with self.subTest(shape="crlf-unique-location"):
            crlf = ('{"packages": {\r\n'
                    '    "node_modules/picomatch": {"version": "2.3.2"}\r\n'
                    '}}\r\n')
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [finding], serve_always=True,
                lock_instances=[("node_modules/picomatch", "2.3.2", True)],
                lock_raw=crlf,
                lock_raw_lines={"node_modules/picomatch": 2})
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_empty_findings_supplied_metadata_fail_closed(self):
        # EMPTY-FINDINGS-METADATA-01: an npm result with no HIGH/CRITICAL
        # findings still validates the Packages metadata it supplies.
        # The pinned scanner's clean empty shapes — Packages omitted or
        # an empty list — and well-formed supplied records stay ok.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": ""}
        with self.subTest(defect="malformed-locations-no-findings"):
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json",
                [dict(finding, _locations=7)], serve_always=True, vulns_override=[])
            self.assertEqual(status, "error", details)
            self.assertIn("has a malformed Locations field", details)
            self.assertNotIn("Is a directory", details)
        for label, locations in (("boolean", [{"StartLine": True}]),
                                 ("string", [{"StartLine": "3"}])):
            with self.subTest(defect=label + "-startline-no-findings"):
                status, details, _ = self._run_scan(
                    audit, "web/site/package-lock.json",
                    [dict(finding, _locations=locations)], serve_always=True,
                    vulns_override=[])
                self.assertEqual(status, "error", details)
                self.assertIn("has an invalid StartLine", details)
                self.assertNotIn("Is a directory", details)
        with self.subTest(defect="packages-wrong-type-no-findings"):
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [finding], serve_always=True,
                vulns_override=[], packages_override="not-a-list")
            self.assertEqual(status, "error", details)
            self.assertIn("invalid Packages array", details)
        with self.subTest(defect="packages-explicit-null-no-findings"):
            # An explicit Packages null is a supplied broken shape, not an
            # omitted field; omission and [] stay clean.
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [finding], serve_always=True,
                vulns_override=[], packages_override=None)
            self.assertEqual(status, "error", details)
            self.assertIn("invalid Packages array", details)
        with self.subTest(defect="malformed-override-alone-no-findings"):
            # An explicit Packages override alone must reach validation,
            # not fall back to a clean non-npm result.
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [], serve_always=True,
                packages_override="not-a-list")
            self.assertEqual(status, "error", details)
            self.assertIn("invalid Packages array", details)
        with self.subTest(defect="shared-uid-conflicting-identities-no-findings"):
            # Two individually valid records assigning one UID to
            # different identities conflict even without findings.
            shared_uid = "picomatch@2.3.2"
            records = [
                {"ID": shared_uid, "Name": "picomatch", "Version": "2.3.2",
                 "Identifier": {"UID": shared_uid},
                 "Locations": [{"StartLine": 2}]},
                {"ID": shared_uid, "Name": "picomatch", "Version": "4.0.5",
                 "Identifier": {"UID": shared_uid},
                 "Locations": [{"StartLine": 3}]},
            ]
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [], serve_always=True,
                packages_override=records,
                lock_instances=[("node_modules/picomatch", "2.3.2", True),
                                ("node_modules/tinyglobby/node_modules/picomatch",
                                 "4.0.5", True)])
            self.assertEqual(status, "error", details)
            self.assertIn("has conflicting locations", details)
        with self.subTest(defect="invalid-package-entry-no-findings"):
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [finding], serve_always=True,
                vulns_override=[], packages_override=[7])
            self.assertEqual(status, "error", details)
            self.assertIn("invalid package entry", details)
            self.assertNotIn("Is a directory", details)
        for label, kwargs in (("omitted", {"drop_packages": True}),
                              ("empty-list", {"packages_override": []})):
            with self.subTest(shape="clean-" + label + "-packages"):
                status, details, _ = self._run_scan(
                    audit, "web/site/package-lock.json", [finding], serve_always=True,
                    vulns_override=[], **kwargs)
                self.assertEqual(status, "ok", details)
                self.assertIn("exact_exceptions_applied=0", details)
        with self.subTest(shape="well-formed-supplied-packages"):
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [finding], serve_always=True,
                vulns_override=[])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=0", details)
        with self.subTest(shape="explicit-supplied-record"):
            # A literal supplied Packages record with empty
            # Vulnerabilities validates against the lockfile named by
            # the result's own Target, not the scanned root.
            supplied = self._trivy_report(
                "web/site/package-lock.json", [finding])["Results"][0]["Packages"]
            status, details, _ = self._run_scan(
                audit, "web/site/package-lock.json", [], serve_always=True,
                vulns_override=[], packages_override=supplied,
                lock_instances=[("node_modules/picomatch", "2.3.2", True)])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=0", details)





    def test_mapping_blind_variant_accepts_incomplete_policy(self):
        # Negative control: the isolated path-blind matcher (the pre-fix
        # semantics) accepts the policy missing the vite instance. The
        # refusal above must fail for exactly this reason, not because of
        # harness or compile setup.
        module = self.load_path_blind_module()
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "4.0.5", "Severity": "HIGH", "FixedVersion": "",
                   "_paths": DASHBOARD_V4_KEYS}
        policy = yaml.safe_load(self.policy.read_text())
        policy["exceptions"] = [entry for entry in policy["exceptions"]
                                if entry.get("id") != "dashboard-picomatch-v4-vite-extglob-redos"]
        self.policy.write_text(yaml.safe_dump(policy))
        status, details, _ = self._run_scan(module, "web/dashboard/package-lock.json",
                                            [finding], serve_always=True)
        self.assertEqual(status, "ok", details)

    def test_non_npm_result_type_does_not_inherit_exceptions(self):
        # NPM-IDENTITY-01: exception binding needs a positive npm result
        # identity (Type == "npm"), not just a package-lock.json target.
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": ""}]
        status, details, _ = self._run_scan(audit, "sdks/node/package-lock.json",
                                            self.findings, serve_always=True,
                                            result_type="gobinary")
        self.assertEqual(status, "fail", details)
        self.assertIn("exact_exceptions_applied=0", details)
        self.assertIn("no physical lockfile binding", details)

    def test_malformed_vulnerabilities_field_fails_closed(self):
        # MALFORMED-VULNERABILITIES-01: missing or explicit null is the
        # clean-scanner shape; any other present non-list value (including
        # a false-y object) is a scanner error, never a clean result.
        for label, kwargs in (
            ("empty-object", {"vulns_override": {}}),
            ("string-value", {"vulns_override": "not-a-list"}),
            ("explicit-null", {"vulns_override": None}),
            ("missing", {"drop_vulns": True}),
        ):
            with self.subTest(defect=label):
                status, details, _ = self._run_scan(audit, "sdks/node/package-lock.json",
                                                    [], serve_always=True, **kwargs)
                if label in ("empty-object", "string-value"):
                    self.assertEqual(status, "error", details)
                    self.assertIn("invalid Vulnerabilities field", details)
                else:
                    self.assertEqual(status, "ok", details)
                    self.assertIn("exact_exceptions_applied=0", details)

    def test_malformed_vulnerability_entries_fail_closed(self):
        # MALFORMED-VULNERABILITIES-02: a present Vulnerabilities list must
        # contain object findings whose Severity is one of the pinned
        # scanner's recognized values (CRITICAL, HIGH, MEDIUM, LOW,
        # UNKNOWN); malformed or unrecognized values error. Missing or
        # null stays a clean result, valid non-HIGH/CRITICAL entries stay
        # ignored by the HIGH/CRITICAL gate, and one valid HIGH entry
        # still reaches the existing physical binding behavior.
        finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                   "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": ""}
        for defect, vulns in (
            ("entry-none", [None]),
            ("entry-empty-object", [{}]),
            ("severity-null", [dict(finding, Severity=None)]),
            ("severity-missing", [{k: v for k, v in finding.items() if k != "Severity"}]),
            ("severity-empty-string", [dict(finding, Severity="")]),
            ("severity-non-string", [dict(finding, Severity=3)]),
        ):
            with self.subTest(defect=defect):
                status, details, _ = self._run_scan(audit, "web/dashboard/package-lock.json",
                                                    [], serve_always=True, vulns_override=vulns)
                self.assertEqual(status, "error", details)
                self.assertIn("Trivy JSON contains an invalid", details)
        with self.subTest(defect="valid-medium-ignored"):
            status, details, _ = self._run_scan(audit, "web/dashboard/package-lock.json",
                                                [], serve_always=True,
                                                vulns_override=[dict(finding, Severity="MEDIUM")])
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=0", details)
        with self.subTest(defect="valid-high-reaches-binding"):
            # The unbound entry rides alongside a bound finding so the
            # Packages array itself stays well-formed and the rejection
            # comes from the missing finding-to-package binding.
            status, details, _ = self._run_scan(
                audit, "web/dashboard/package-lock.json",
                [finding, dict(finding, _unbound=True)], serve_always=True)
            self.assertEqual(status, "error", details)
            self.assertIn("no physical lockfile binding", details)
        with self.subTest(defect="valid-high-applies-exception"):
            status, details, _ = self._run_scan(audit, "web/dashboard/package-lock.json",
                                                [finding], serve_always=True)
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)

    def test_dashboard_dep_audit_exceptions_reject_mismatched_finding(self):
        base = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                "Severity": "HIGH", "FixedVersion": ""}
        for label, mismatched, target in (
            ("package", {**base, "PkgName": "micromatch", "InstalledVersion": "2.3.2"},
             "web/dashboard/package-lock.json"),
            ("v2-version", {**base, "InstalledVersion": "2.3.1"},
             "web/dashboard/package-lock.json"),
            ("v4-version", {**base, "InstalledVersion": "4.0.4",
                            "_paths": DASHBOARD_V4_KEYS},
             "web/dashboard/package-lock.json"),
            # 4.0.5 is not covered by the site exception (2.3.2 only), and
            # the dashboard entries do not apply at the site lockfile.
            ("scope", {**base, "InstalledVersion": "4.0.5"},
             "web/site/package-lock.json"),
        ):
            with self.subTest(mismatch=label):
                self.findings = [mismatched]
                status, details = self.scan(target=target)
                self.assertEqual(status, "fail", details)
                self.assertIn("CVE-2026-112366", details)
                self.assertIn("exact_exceptions_applied=0", details)

    def test_expired_dep_audit_exception_fails_closed(self):
        policy = yaml.safe_load(self.policy.read_text())
        dep_entries = [entry for entry in policy["exceptions"]
                       if entry.get("scanner") == "dep_audit"]
        self.assertTrue(dep_entries, "dep_audit exception must be registered")
        # Expired relative to the frozen audit clock (2026-11-18), which
        # itself predates the registered 2026-11-30 expiry: no wall-clock
        # assumption anywhere.
        for entry in dep_entries:
            entry["expires"] = "2026-11-17"
        self.policy.write_text(yaml.safe_dump(policy))
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": ""}]
        status, details = self.scan(target="web/site/package-lock.json")
        self.assertEqual(status, "fail", details)
        self.assertIn("expired_dependency_exceptions="
                      + ",".join(sorted(entry["id"] for entry in dep_entries)), details)
        self.assertIn("exact_exceptions_applied=0", details)

    def test_dep_audit_exception_rejects_date_typed_expiry(self):
        # An unquoted YAML date parses to datetime.date; the scanner must
        # reject the non-string field as not exact-scoped rather than
        # type-coerce it. The scanner reports the first invalid entry in
        # registry order; holds for any number of dep_audit entries.
        for phase, targeted, expected_id in (
            ("all-entries", None, "picomatch-single-branch-extglob-redos"),
            ("single-nested-entry", {"dashboard-picomatch-v4-vite-extglob-redos"},
             "dashboard-picomatch-v4-vite-extglob-redos"),
        ):
            with self.subTest(phase=phase):
                policy = yaml.safe_load(
                    (ROOT / "scripts/quality/security-exceptions.yaml").read_text())
                dep_entries = [entry for entry in policy["exceptions"]
                               if entry.get("scanner") == "dep_audit"]
                self.assertGreaterEqual(len(dep_entries), 2)
                # Registry-order guard: the site entry is first, so the
                # all-entries phase must report it (first invalid wins).
                self.assertEqual(dep_entries[0]["id"],
                                 "picomatch-single-branch-extglob-redos")
                for entry in dep_entries:
                    if targeted is None or entry["id"] in targeted:
                        entry["expires"] = dt.date(2026, 11, 30)
                self.policy.write_text(yaml.safe_dump(policy))
                status, details = self.scan(target="web/dashboard/package-lock.json")
                self.assertEqual(status, "error", details)
                self.assertIn("not exact-scoped", details)
                self.assertIn(f"dependency exception {expected_id}", details)
    def test_malformed_expiry_strings_are_policy_errors(self):
        # EXPIRY-CANONICAL-01: expires must be a calendar-valid canonical
        # YYYY-MM-DD string; basic digit runs, impossible dates and free
        # text are policy errors. Expiry and coverage compare parsed
        # dates; the owner-approved 2026-11-30 registry values stay
        # canonical and an expiry equal to the audit date stays active.
        site_finding = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                        "InstalledVersion": "2.3.2", "Severity": "HIGH", "FixedVersion": ""}

        def rewrite(expires):
            policy = yaml.safe_load(self.policy.read_text())
            for entry in policy["exceptions"]:
                if entry.get("scanner") == "dep_audit":
                    entry["expires"] = expires
            self.policy.write_text(yaml.safe_dump(policy))

        for expires in ("never", "20261130", "2026-02-30", "30-11-2026",
                        "2026-11-3", "2026-11-30 ", "31-12-26"):
            with self.subTest(expires=expires):
                rewrite(expires)
                self.findings = [site_finding]
                status, details = self.scan(target="web/site/package-lock.json")
                self.assertEqual(status, "error", details)
                self.assertIn("invalid canonical expires date", details)
        with self.subTest(expires="today-boundary-active"):
            rewrite(FROZEN_TODAY.isoformat())
            self.findings = [site_finding]
            status, details = self.scan(target="web/site/package-lock.json")
            self.assertEqual(status, "ok", details)
            self.assertIn("exact_exceptions_applied=1", details)


    def test_sdk_dep_audit_exception_applies_to_exact_instance(self):
        # The one owner-option-B SDK exception: picomatch 4.0.7 at the
        # single hoisted SDK lockfile key. Positive development matching:
        # the lock entry is dev-classified and the entry declares
        # development: true (Kimi-confirmed build/test-only reachability;
        # sole repaired-tree HIGH).
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                          "_lock_dev": True}]
        status, details = self.scan(target="sdks/node/package-lock.json")
        self.assertEqual(status, "ok", details)
        self.assertIn("exact_exceptions_applied=1", details)

    def test_sdk_dep_audit_exception_rejects_mismatched_finding(self):
        base = {"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                "Severity": "HIGH", "FixedVersion": ""}
        for label, mismatched, target in (
            # The SDK entry covers only node_modules/picomatch; a nested
            # key is a different physical instance.
            ("path", {**base, "InstalledVersion": "4.0.7",
                      "_paths": ["node_modules/tinyglobby/node_modules/picomatch"]},
             "sdks/node/package-lock.json"),
            ("version", {**base, "InstalledVersion": "4.0.6"},
             "sdks/node/package-lock.json"),
            # 4.0.7 at the dashboard is not covered by any dashboard entry
            # (2.3.2 / 4.0.5) and the SDK entry does not apply there.
            ("scope", {**base, "InstalledVersion": "4.0.7"},
             "web/dashboard/package-lock.json"),
        ):
            with self.subTest(mismatch=label):
                self.findings = [mismatched]
                status, details = self.scan(target=target)
                self.assertEqual(status, "fail", details)
                self.assertIn("CVE-2026-112366", details)
                self.assertIn("exact_exceptions_applied=0", details)

    def test_sdk_exception_requires_matching_dev_classification(self):
        # LOCK-DEV-01: the build/test-only SDK exception inherits only to
        # instances the lockfile classifies as dev. A runtime (dev false),
        # unknown (missing) or wrongly-typed classification at the same
        # path/version/scope stays uncovered.
        for label, dev in (("runtime-dev-false", False),
                           ("unknown-dev-missing", None),
                           ("wrong-type-dev", "true")):
            with self.subTest(defect=label):
                self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                                  "InstalledVersion": "4.0.7", "Severity": "HIGH",
                                  "FixedVersion": "", "_lock_dev": dev}]
                status, details = self.scan(target="sdks/node/package-lock.json")
                self.assertEqual(status, "fail", details)
                self.assertIn("uncovered_paths=node_modules/picomatch", details)
                self.assertIn("exact_exceptions_applied=0", details)

    def test_exception_entry_development_field_type_fails_closed(self):
        # The optional development classification must be boolean; any
        # other type is a policy error, never a silent mismatch.
        policy = yaml.safe_load(self.policy.read_text())
        entry = next(item for item in policy["exceptions"]
                     if item.get("id") == "sdk-picomatch-v4-extglob-redos")
        entry["development"] = "true"
        self.policy.write_text(yaml.safe_dump(policy))
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": ""}]
        status, details = self.scan(target="sdks/node/package-lock.json")
        self.assertEqual(status, "error", details)
        self.assertIn("invalid development classification", details)

    def test_registry_declares_development_for_dev_tree_exceptions(self):
        # The dashboard/SDK entries claim build/test-only scope, so each
        # must declare its boolean development classification (all real
        # covered lock entries are dev: true). The site entry predates the
        # field and keeps its established semantics untouched.
        policy = yaml.safe_load(self.policy.read_text())
        entries = {entry["id"]: entry for entry in policy["exceptions"]}
        for entry_id in ("dashboard-picomatch-v2-extglob-redos",
                         "dashboard-picomatch-v4-extglob-redos",
                         "dashboard-picomatch-v4-vite-extglob-redos",
                         "sdk-picomatch-v4-extglob-redos"):
            self.assertIs(entries[entry_id]["development"], True, entry_id)
        self.assertNotIn("development",
                         entries["picomatch-single-branch-extglob-redos"])

    def test_sdk_dep_audit_exception_expires_fail_closed(self):
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": ""}]
        policy = yaml.safe_load(self.policy.read_text())
        entry = next(item for item in policy["exceptions"]
                     if item.get("id") == "sdk-picomatch-v4-extglob-redos")
        # Expired at the frozen audit clock (2026-11-18).
        entry["expires"] = "2026-11-17"
        self.policy.write_text(yaml.safe_dump(policy))
        status, details = self.scan(target="sdks/node/package-lock.json")
        self.assertEqual(status, "fail", details)
        self.assertIn("expired_dependency_exceptions=sdk-picomatch-v4-extglob-redos", details)
        self.assertIn("exact_exceptions_applied=0", details)

    def test_sdk_binding_metadata_defect_fails_closed(self):
        # Unknown or ambiguous identity metadata must not widen the SDK
        # exception into a lockfile-wide waiver.
        self.findings = [{"VulnerabilityID": "CVE-2026-112366", "PkgName": "picomatch",
                          "InstalledVersion": "4.0.7", "Severity": "HIGH", "FixedVersion": "",
                          "_unbound": True}]
        status, details = self.scan(target="sdks/node/package-lock.json")
        self.assertEqual(status, "error", details)

    def test_malformed_policy_fails_closed(self):
        for content in ("[]", "schema: 2\nexceptions: []", "schema: 1\nexceptions: null"):
            with self.subTest(content=content):
                self.policy.write_text(content)
                self.assertEqual(self.scan()[0], "error")

    def test_exceptions_registry_license_entries_are_scoped(self):
        policy = yaml.safe_load(self.policy.read_text())
        self.assertEqual(policy["schema"], 1)
        entries = policy["exceptions"]
        # The registry is shared by scanner-tagged consumers; only the
        # license_check entries form the public license policy.
        license_entries = [entry for entry in entries
                           if entry.get("scanner") == "license_check"]
        self.assertEqual(len(license_entries), 3)
        for entry in license_entries:
            for key in ("id", "path", "scope", "version", "reason", "owner", "expires"):
                self.assertTrue(entry[key], key)
        # Every entry must name its scanner: untagged entries are silently
        # honored by the secret scanner (secret_scan.py).
        for entry in entries:
            self.assertIn(entry.get("scanner"),
                          ("license_check", "secret_scan", "dep_audit"))
            for key in ("id", "path", "reason", "owner", "expires"):
                self.assertTrue(entry.get(key), key)


if __name__ == "__main__":
    unittest.main()
