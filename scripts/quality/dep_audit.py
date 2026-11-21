#!/usr/bin/env python3
"""Local dependency audit: reachable Go advisories and lockfile CVEs.

No registry receives a copy of package manifests. Vulnerability databases are
updated separately (`make security-db-update`); a missing/stale database is an
error, never a clean result.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
import argparse
import datetime as dt
from functools import lru_cache
from fnmatch import fnmatchcase

ROOT = Path(__file__).resolve().parent.parent.parent
TRIVY = os.environ.get("TRIVY", str(Path.home() / "go" / "bin" / "trivy"))
GOVULNCHECK = os.environ.get("GOVULNCHECK", str(Path.home() / "go" / "bin" / "govulncheck"))
CACHE = Path(os.environ.get("YABANIN_SECURITY_CACHE",
                            Path.home() / ".cache" / "yabanin-security"))
GO_DB = CACHE / "govuln"
ROOT_GO_VERSION = next((line.split()[1] for line in (ROOT / "go.mod").read_text().splitlines()
                        if line.startswith("go ")), "")


def database_fresh(metadata_path: Path) -> bool:
    try:
        metadata = json.loads(metadata_path.read_text())
        fetched = datetime.fromisoformat(metadata["fetched_at"])
        return (fetched.tzinfo is not None
                and timedelta(0) <= datetime.now(timezone.utc) - fetched.astimezone(timezone.utc)
                <= timedelta(hours=24))
    except (OSError, ValueError, KeyError, TypeError):
        return False


@lru_cache(maxsize=1)
def indexed_paths() -> list[str]:
    """Read the tracked path list once; index enumeration is deterministic."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT,
            capture_output=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"git could not enumerate tracked paths: {exc}") from exc
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def tracked_paths(pattern: str) -> list[str]:
    """Match basenames and explicit path globs across root and nested modules."""
    if "/" in pattern:
        return [path for path in indexed_paths() if fnmatchcase(path, pattern)]
    return [path for path in indexed_paths() if fnmatchcase(Path(path).name, pattern)]


def go_modules() -> list[Path]:
    return sorted({(ROOT / path).parent for path in tracked_paths("go.mod")})


def parse_json_stream(payload: str) -> list[object]:
    """Decode govulncheck's stream of JSON values, including pretty JSON."""
    decoder = json.JSONDecoder()
    values = []
    offset = 0
    while offset < len(payload):
        while offset < len(payload) and payload[offset].isspace():
            offset += 1
        if offset == len(payload):
            break
        try:
            value, offset = decoder.raw_decode(payload, offset)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid govulncheck JSON at byte {exc.pos}") from exc
        values.append(value)
    return values


def go_vuln(module: Path) -> tuple[str, str]:
    """Run symbol-reachability scan; malformed/incomplete output is an error."""
    try:
        proc = subprocess.run(
            [GOVULNCHECK, "-db", GO_DB.resolve().as_uri(), "-json", "./..."], cwd=module,
            capture_output=True, text=True, timeout=600,
            env={**os.environ, "GOTOOLCHAIN": "go" + ROOT_GO_VERSION},
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return "error", f"govulncheck unavailable or timed out: {exc}"
    try:
        events = parse_json_stream(proc.stdout)
    except ValueError as exc:
        return "error", str(exc)
    if not events or not all(isinstance(event, dict) for event in events):
        return "error", "govulncheck returned an empty or invalid event stream"
    if not any("config" in event for event in events):
        return "error", "govulncheck stream has no config event (incomplete scan)"
    findings = []
    for event in events:
        if "finding" not in event:
            continue
        finding = event["finding"]
        if (not isinstance(finding, dict) or not isinstance(finding.get("osv"), str)
                or not isinstance(finding.get("trace"), list)):
            return "error", "govulncheck returned a malformed finding event"
        findings.append(finding)
    # govulncheck also emits one module-only trace for a vulnerable module
    # present in the build list. It is not evidence that vulnerable code is
    # called. A function frame in the trace is the reachability signal.
    reachable = [finding for finding in findings
                 if any(isinstance(frame, dict) and isinstance(frame.get("function"), str)
                        and frame["function"] for frame in finding["trace"])]
    if proc.returncode:
        # Preserve the security finding while also classifying a nonzero
        # scanner exit as an execution failure at the caller.
        return "error", f"govulncheck exit {proc.returncode}; findings={len(findings)}"
    return ("fail" if reachable else "ok"), (
        f"reachable_findings={len(reachable)}; module_only_findings={len(findings) - len(reachable)}")


_ABSENT = object()


_SEVERITIES = frozenset(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"))
_BINDING_FIELDS = frozenset(("name", "version", "dev"))


def _has_duplicate_binding_fields(fields: object, mapping_node) -> bool:
    """Whether one lock entry repeats a binding field.

    JSON collapses duplicate keys to its last winner, so a repeated
    name/version/dev — even with coinciding values — leaves the entry's
    identity or dev classification ambiguous; other fields may repeat
    freely.
    """
    if not isinstance(fields, mapping_node):
        return False
    names = [key.value for key, _ in fields.value if key.value in _BINDING_FIELDS]
    return len(names) != len(set(names))


def _package_start_lines(document, mapping_node, text: str) -> dict[str, int] | None:
    """1-based physical start line of every packages member.

    Lines follow the original text's LF framing, the convention Trivy's
    StartLine uses, derived from each key's character index: the YAML
    line counter also breaks on a literal U+2028 inside a JSON string,
    which would hand two keys on one physical line different lines. A
    second `packages` block, duplicate member keys, or duplicate
    name/version/dev fields inside one entry would leave the mapping or
    the entry's binding identity ambiguous — including which duplicate
    the json view kept — so all are refused instead of collapsing to one
    winner. Returns None when no unambiguous packages map exists.
    """
    line_of = None
    for key_node, value_node in getattr(document, "value", []):
        if getattr(key_node, "value", None) != "packages":
            continue
        if line_of is not None or not isinstance(value_node, mapping_node):
            return None
        members = {}
        for member, fields in value_node.value:
            if (member.value in members
                    or _has_duplicate_binding_fields(fields, mapping_node)):
                return None
            members[member.value] = text.count("\n", 0, member.start_mark.index) + 1
        line_of = members
    return line_of


def _confined_target_path(target: str) -> Path | None:
    """Repository-relative path for a scanner-reported lockfile target.

    The Target string in a scanner report is untrusted input: absolute
    paths, Windows drive letters, backslashes, parent traversal and
    symlink escapes are refused before any file is opened.
    """
    if (not isinstance(target, str) or not target
            or target.startswith("/") or "\\" in target
            or target[1:2] == ":"
            or any(part in ("", "..") for part in target.split("/"))):
        return None
    try:
        resolved = (ROOT / target).resolve()
        resolved.relative_to(ROOT.resolve())
    except (OSError, ValueError):
        return None
    return resolved


def _load_lockfile(target: str) -> tuple[dict[str, int], dict, str | None]:
    """Return (entry start lines, lockfile package keys) for a scanned npm lockfile."""
    path = _confined_target_path(target)
    if path is None:
        return {}, {}, (f"scanner target is not confined to the repository "
                        f"and will not be read: {target}")
    try:
        # Read bytes and decode explicitly: universal-newline translation
        # would fold a bare CR into LF and corrupt physical-line counting.
        text = path.read_bytes().decode("utf-8")
        lock = json.loads(text)
    except (OSError, ValueError) as exc:
        return {}, {}, f"cannot read lockfile {target} for exception scoping: {exc}"
    keys = lock.get("packages") if isinstance(lock, dict) else None
    if not isinstance(keys, dict):
        return {}, {}, f"{target} has no packages map for exception scoping"
    try:
        import yaml
    except ImportError as exc:
        return {}, {}, f"cannot parse lock entry locations for {target}: {exc}"
    try:
        line_of = _package_start_lines(yaml.compose(text), yaml.MappingNode, text)
    except yaml.YAMLError as exc:
        return {}, {}, f"cannot parse lock entry locations for {target}: {exc}"
    if line_of is None or set(line_of) != set(keys):
        return {}, {}, f"{target} has ambiguous lockfile member metadata for exception scoping"
    return line_of, keys, None


def _entry_identity(key: str, entry, name: str) -> tuple[bool, str | None]:
    """Relevance of one lock entry to a package identity.

    An explicit `name` field is authoritative whenever present: only
    entries naming this package are relevant, whatever their install
    path, so a conflicting explicit identity can never inherit this
    package's exception. Without the field, relevance falls back to the
    install-path suffix. Malformed identity metadata fails closed.
    """
    explicit = entry.get("name", _ABSENT) if isinstance(entry, dict) else _ABSENT
    if explicit is not _ABSENT:
        if not isinstance(explicit, str) or not explicit.strip():
            return False, f"lockfile entry {key} has malformed identity for exception scoping"
        return explicit == name, None
    suffix = f"node_modules/{name}"
    if not (key == suffix or key.endswith(f"/{suffix}")):
        return False, None
    if not isinstance(entry, dict):
        return False, f"lockfile entry {key} has malformed metadata for exception scoping"
    return True, None


def _lock_package_instances(keys: dict, name: str, version: str) -> tuple[list[tuple[str, bool | None]], str | None]:
    """Physical lockfile entries for one package identity, with dev class.

    Identity follows `_entry_identity`: explicit names outrank install
    paths. Every relevant entry needs a usable nonempty string version:
    missing, non-string or blank (including whitespace-only) versions
    leave that physical instance ambiguous and are an error, so
    incomplete coverage cannot hide behind broken lock metadata. A dev
    field that is not a boolean leaves the classification unknown.
    """
    instances = []
    for key, entry in keys.items():
        relevant, identity_error = _entry_identity(key, entry, name)
        if identity_error:
            return [], identity_error
        if not relevant:
            continue
        version_field = entry.get("version")
        if not isinstance(version_field, str) or not version_field.strip():
            return [], f"lockfile entry {key} has no usable version for exception scoping"
        if version_field == version:
            dev = entry.get("dev")
            instances.append((key, dev if isinstance(dev, bool) else None))
    return instances, None


def _location_start_lines(uid: str, package: dict,
                          target: str) -> tuple[list[int], str | None]:
    """Validated StartLine values from a package record's Locations."""
    locations = package.get("Locations")
    if locations is not None and not isinstance(locations, list):
        return [], f"Trivy package {uid} in {target} has a malformed Locations field"
    starts = []
    for location in locations or []:
        start = location.get("StartLine") if isinstance(location, dict) else None
        if isinstance(start, bool) or not isinstance(start, int) or start < 1:
            return [], f"Trivy location for {uid} in {target} has an invalid StartLine"
        starts.append(start)
    return starts, None


def _reported_lock_keys(uid: str, package: dict, line_of: dict[str, int], keys: dict,
                        instances: list[tuple[str, bool | None]],
                        target: str) -> tuple[list[str], str | None]:
    """Lockfile keys named by the package record's reported locations.

    Each reported start line resolves against the parsed start lines of
    the full lockfile map first: it must begin exactly one entry of any
    version, whatever the JSON spacing, and that entry must be a
    physical instance of this package version. Same-line entries of
    different versions therefore cannot masquerade as a unique match.
    """
    by_key = dict(instances)
    starts, location_error = _location_start_lines(uid, package, target)
    if location_error:
        return [], location_error
    reported = []
    for start in starts:
        matches = [key for key, line in line_of.items() if line == start]
        if len(matches) != 1:
            return [], (f"Trivy location for {uid} in {target} does not "
                        "resolve to exactly one matching lockfile entry")
        if matches[0] not in by_key:
            return [], (f"Trivy location for {uid} in {target} resolves to "
                        "a lockfile entry that is not this package version")
        reported.append(matches[0])
    if not reported:
        return [], f"Trivy package {uid} has no lockfile locations for {target}"
    return reported, None


def _resolve_package_keys(package: dict, line_of: dict[str, int], keys: dict,
                          target: str) -> tuple[tuple[str, tuple[str, str, list[tuple[str, bool | None]]]], None] | tuple[None, str]:
    """Resolve one Trivy package record to identity plus physical instances.

    Reported lockfile locations are reconciled against the lockfile's own
    entries for the same name@version: every reported location must resolve
    to exactly one real matching entry, and together they must cover every
    real instance. An under-reporting scan can therefore never narrow an
    exception to the instances it happened to mention.
    """
    identifier = package.get("Identifier")
    uid = identifier.get("UID") if isinstance(identifier, dict) else None
    if not isinstance(uid, str) or not uid:
        return None, f"Trivy package without identifier UID for {target}"
    name, version = package.get("Name"), package.get("Version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None, f"Trivy package {uid} has no usable name/version for {target}"
    instances, lock_error = _lock_package_instances(keys, name, version)
    if lock_error:
        return None, lock_error
    if not instances:
        return None, f"Trivy package {uid} has no lockfile entries for {target}"
    reported, error = _reported_lock_keys(uid, package, line_of, keys, instances, target)
    if error:
        return None, error
    instance_keys = set(dict(instances))
    if set(reported) != instance_keys:
        return None, (f"Trivy package {uid} in {target} reports {len(set(reported))} "
                      f"of {len(instance_keys)} physical instances")
    return (uid, (name, version, instances)), None


def _check_finding_binding(finding: dict, bindings: dict, target: str) -> str | None:
    """Reject findings whose identity does not match the bound package."""
    identifier = finding.get("PkgIdentifier")
    uid = identifier.get("UID") if isinstance(identifier, dict) else None
    bound = bindings.get(uid) if isinstance(uid, str) else None
    if bound is None:
        return (f"finding {finding.get('VulnerabilityID')} on "
                f"{finding.get('PkgName')} has no physical lockfile "
                f"binding in {target}")
    name, version, _ = bound
    if finding.get("PkgName") != name or finding.get("InstalledVersion") != version:
        return (f"finding {finding.get('VulnerabilityID')} identity does not "
                f"match Trivy package {uid} ({name}@{version}) in {target}")
    return None


def _bind_lock_keys(result: dict, result_findings: list[dict]) -> tuple[dict | None, str | None]:
    """Bind findings to physical lockfile instances from Trivy metadata.

    Trivy aggregates one finding per package version; Packages[] carries the
    physical instances as lockfile line locations, selected through
    PkgIdentifier/Packages Identifier UIDs. Missing, conflicting or
    ambiguous metadata is an error so an exception can never broaden
    because a binding could not be established.
    """
    target = result.get("Target", "")
    line_of, keys, error = _load_lockfile(target)
    if error:
        return None, error
    packages = result.get("Packages")
    if not isinstance(packages, list) or not packages:
        return None, f"Trivy JSON has no Packages array for {target}"
    bindings: dict[str, tuple[str, str, list[tuple[str, bool | None]]]] = {}
    for package in packages:
        if not isinstance(package, dict):
            return None, f"Trivy JSON contains an invalid package entry for {target}"
        bound, error = _resolve_package_keys(package, line_of, keys, target)
        if error:
            return None, error
        uid, identity = bound
        if uid in bindings and bindings[uid] != identity:
            return None, f"Trivy package {uid} has conflicting locations for {target}"
        bindings[uid] = identity
    for finding in result_findings:
        error = _check_finding_binding(finding, bindings, target)
        if error:
            return None, error
    return bindings, None


def _uncovered_lock_keys(finding: dict, instances: list[tuple[str, bool | None]],
                         dependency_exceptions: list[dict], today: dt.date) -> list[str]:
    """Physical lockfile instances no exact-path exception covers.

    An entry that declares a development classification matches only
    instances carrying the same lock-entry dev flag; an unknown lock
    classification never inherits a build/test-only exception.
    """
    return [key for key, dev in instances
            if not any(item.get("vulnerability_id") == finding.get("VulnerabilityID")
                       and item.get("package") == finding.get("PkgName")
                       and item.get("version") == finding.get("InstalledVersion")
                       and item.get("scope") == finding.get("target")
                       and item.get("path") == key
                       and dt.date.fromisoformat(item["expires"]) >= today
                       and ("development" not in item or item["development"] is dev)
                       for item in dependency_exceptions)]


def _tracked_lockfiles() -> list[str]:
    """Tracked dependency lockfiles across supported ecosystems."""
    return [path for pattern in ("package-lock.json", "pnpm-lock.yaml",
                                 "yarn.lock", "Pipfile.lock")
            for path in tracked_paths(pattern)]


def _exact_scoped_exceptions(exceptions: list, today: dt.date
                             ) -> tuple[list[dict] | None, list[str] | None, str | None]:
    """Validate dep_audit entries: exact string scope and typed extras."""
    required_fields = ("id", "vulnerability_id", "package", "version", "scope", "path",
                       "reason", "owner", "expires")
    dependency_exceptions, expired = [], []
    for item in exceptions:
        if not isinstance(item, dict) or item.get("scanner") != "dep_audit":
            continue
        if not all(isinstance(item.get(field), str) and item[field].strip()
                   for field in required_fields):
            return None, None, f"dependency exception {item.get('id', 'unknown')} is not exact-scoped"
        if "development" in item and not isinstance(item["development"], bool):
            return None, None, (f"dependency exception {item.get('id', 'unknown')} has "
                                "an invalid development classification")
        invalid_expiry = (f"dependency exception {item.get('id', 'unknown')} has an "
                          "invalid canonical expires date")
        try:
            expires_on = dt.date.fromisoformat(item["expires"])
        except ValueError:
            return None, None, invalid_expiry
        if expires_on.isoformat() != item["expires"]:
            return None, None, invalid_expiry
        dependency_exceptions.append(item)
        if expires_on < today:
            expired.append(item["id"])
    return dependency_exceptions, expired, None


def _reject_merge_operand(operand) -> None:
    """Reject a `<<` operand that is not exactly a map or a seq of maps.

    Base flatten_mapping consumes structural kinds and never checks
    tags, so a mistagged mapping (or sequence member) still injects its
    fields. Every merge source must be a MappingNode with the YAML map
    tag; a sequence merge must be a SequenceNode with the YAML seq tag
    whose members all satisfy the merge-source rule. Scalar operands
    already fail in base flattening. Node types are imported locally
    to preserve the module's lazy yaml dependency.
    """
    from yaml import YAMLError
    from yaml.nodes import MappingNode, SequenceNode

    map_tag, seq_tag = "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq"
    if isinstance(operand, MappingNode):
        kind, expected, sources = "mapping", map_tag, [operand]
    elif isinstance(operand, SequenceNode):
        kind, expected, sources = "sequence", seq_tag, operand.value
    else:
        return
    if operand.tag != expected:
        raise YAMLError(f"YAML merge operand tagged {operand.tag} is not a {kind}")
    for source in sources:
        if source.tag != map_tag or not isinstance(source, MappingNode):
            raise YAMLError(f"YAML merge operand tagged {source.tag} is not a mapping")


def _strict_registry_loader():
    """Build a SafeLoader that refuses duplicate mapping keys.

    yaml resolves repeated keys last-wins, which could quietly change
    which lockfile instances an exception matches; duplicates anywhere
    in the small registry document are rejected instead.
    """
    import yaml

    class _UniqueKeyLoader(yaml.SafeLoader):
        def flatten_mapping(self, node):
            # Two merge keys in one mapping are ambiguous even when their
            # fields are disjoint: base flattening silently combines them
            # before duplicate checking. Inspect before flattening; base
            # recursion calls back here, so nested merge sources are
            # checked too.
            operands = [value_node for key_node, value_node in node.value
                        if key_node.tag == "tag:yaml.org,2002:merge"]
            if len(operands) > 1:
                raise yaml.YAMLError("repeated YAML merge key in one mapping")
            for operand in operands:
                _reject_merge_operand(operand)
            super().flatten_mapping(node)

    def _unique_mapping(loader, node, deep=False):
        # An explicitly tagged node (an empty sequence tagged !!map)
        # must not construct as an empty mapping: that would silently
        # skip registry validation for malformed content.
        if not isinstance(node, yaml.MappingNode):
            raise yaml.YAMLError(f"YAML node tagged {node.tag} is not a mapping")
        # Preserve SafeLoader merge-key semantics first: flatten_mapping
        # expands `<<` into the node's own pairs so inherited fields work,
        # and the collision check below then also catches an inherited
        # field colliding with a direct one.
        loader.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise yaml.YAMLError(f"unhashable YAML mapping key: {exc}")
            if duplicate:
                raise yaml.YAMLError(f"duplicate YAML mapping key: {key}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    _UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)
    return _UniqueKeyLoader


def _load_exception_policy(today: dt.date
                           ) -> tuple[list[dict] | None, list[str] | None, str | None]:
    """Load the shared exception registry from its YAML source."""
    try:
        import yaml
    except ImportError as exc:
        return None, None, f"PyYAML is required to load security exceptions: {exc}"
    try:
        document = yaml.load((ROOT / "scripts/quality/security-exceptions.yaml").read_text(),
                             Loader=_strict_registry_loader())
        if not isinstance(document, dict) or document.get("schema") != 1:
            return None, None, "security-exceptions.yaml has an unsupported schema"
        exceptions = document.get("exceptions")
        if not isinstance(exceptions, list):
            return None, None, "security-exceptions.yaml has no exceptions list"
    except (OSError, yaml.YAMLError, ValueError, TypeError, KeyError,
            AttributeError, IndexError) as exc:
        # Constructor errors must surface as a policy error, not escape
        # the audit: an unquoted invalid expiry parses as a timestamp
        # and raises ValueError, an explicit !!bool with an
        # unrecognized scalar raises KeyError, !!timestamp on an
        # unmatchable scalar raises AttributeError, and !!int on an
        # empty scalar raises IndexError.
        return None, None, f"could not load dependency exceptions: {exc}"
    return _exact_scoped_exceptions(exceptions, today)


def _check_trivy_version() -> str | None:
    """Refuse to audit with a scanner that is not the pinned one."""
    try:
        lock = json.loads((ROOT / "scripts/security/scanner-lock.json").read_text())
        expected = lock["scanners"]["trivy"]["version"]
        version = subprocess.run([TRIVY, "--version"], capture_output=True, text=True,
                                 timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
        return f"Trivy version check failed: {exc}"
    if f"Version: {expected}" not in version:
        return "Trivy version does not match scripts/security/scanner-lock.json"
    return None


def _reject_duplicate_keys(pairs):
    """object_pairs_hook refusing duplicate keys in scanner JSON.

    Plain decoding keeps the last value of a repeated key, so a finding
    repeating Severity from HIGH to MEDIUM would reach validation as
    MEDIUM and hide the HIGH finding; duplicated keys at any level are
    invalid scanner JSON instead.
    """
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate key in scanner JSON: {key}")
        document[key] = value
    return document


def _scan_target(target: str) -> tuple[tuple[object, list] | None, str | None]:
    """Run one offline trivy filesystem scan and decode its JSON report."""
    try:
        # Include development dependencies so test/build-tool findings
        # cannot be silently omitted.
        proc = subprocess.run(
            [TRIVY, "fs", "--scanners", "vuln", "--severity", "HIGH,CRITICAL",
             "--exit-code", "1", "--skip-db-update", "--skip-check-update",
             "--skip-version-check", "--offline-scan", "--include-dev-deps",
             "--format", "json", target],
            cwd=ROOT, capture_output=True, text=True, timeout=900,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return None, f"Trivy unavailable or timed out for {target}: {exc}"
    try:
        document = json.loads(proc.stdout, object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, TypeError):
        return None, f"Trivy returned invalid JSON for {target}; scanner/database failure"
    results = document.get("Results") if isinstance(document, dict) else None
    if not isinstance(results, list):
        return None, f"Trivy JSON has no Results array for {target}"
    return (proc, results), None


def _result_vulnerabilities(result: dict, target: str) -> tuple[list | None, str | None]:
    """A clean result may omit Vulnerabilities; other defects are errors.

    Missing or explicit null is the legitimate clean-scanner shape. A
    present non-list, a non-object entry, or an entry without a nonempty
    string Severity means the report is malformed and must not be treated
    as a clean result. Every Severity must be one of the pinned
    scanner's recognized values — a padded or unrecognized severity is a
    scanner error, never a silently dropped finding — while well-formed
    non-HIGH/CRITICAL entries stay ignored by the HIGH/CRITICAL gate.
    """
    items = result.get("Vulnerabilities")
    if items is None:
        return [], None
    if not isinstance(items, list):
        return None, f"Trivy JSON contains an invalid Vulnerabilities field for {target}"
    for finding in items:
        if not isinstance(finding, dict):
            return None, f"Trivy JSON contains an invalid vulnerability entry for {target}"
        severity = finding.get("Severity")
        if not isinstance(severity, str) or severity not in _SEVERITIES:
            return None, f"Trivy JSON contains an invalid Severity for {target}"
    return items, None


def _is_npm_lockfile_result(result: dict) -> bool:
    """Positive npm lockfile identity, not just a matching filename.

    The final path component must equal `package-lock.json` exactly, so
    lookalike suffixes such as `backup-package-lock.json` never reach
    binding or lockfile reads.
    """
    target = str(result.get("Target", ""))
    return (target.split("/")[-1] == "package-lock.json"
            and result.get("Type") == "npm")


def _validate_supplied_packages(result: dict, target: str) -> str | None:
    """Validate an npm result's supplied package records without findings.

    An empty report is not a license to serve broken binding metadata:
    a nonempty Packages list must resolve exactly like a bound one, and
    a present wrong-type Packages field is an error. The pinned
    scanner's legitimate empty shapes — Packages omitted or an empty
    list — stay accepted, as do non-npm results. The lockfile comes
    from the result's own Target — the scanned root, not a lockfile
    path, is what the caller holds — exactly as binding resolves it.
    """
    if not _is_npm_lockfile_result(result):
        return None
    if "Packages" not in result or result["Packages"] == []:
        return None
    result_target = result.get("Target", target)
    if result["Packages"] is None or not isinstance(result["Packages"], list):
        return f"Trivy JSON has an invalid Packages array for {result_target}"
    _, error = _bind_lock_keys(result, [])
    return error


def _collect_target_findings(target: str, results: list
                             ) -> tuple[list[tuple[dict, list[tuple[str, bool | None]]]] | None, str | None]:
    """Validate one scan's results and bind npm findings to lockfile instances."""
    findings = []
    for result in results:
        if not isinstance(result, dict):
            return None, f"Trivy JSON contains an invalid result for {target}"
        items, error = _result_vulnerabilities(result, target)
        if error:
            return None, error
        result_findings = [
            {**finding, "target": result.get("Target", target)}
            for finding in items
            if isinstance(finding, dict) and finding.get("Severity") in ("HIGH", "CRITICAL")]
        if result_findings and _is_npm_lockfile_result(result):
            bindings, bind_error = _bind_lock_keys(result, result_findings)
            if bind_error:
                return None, bind_error
            findings.extend(
                (finding, bindings[finding["PkgIdentifier"]["UID"]][2])
                for finding in result_findings)
        elif result_findings:
            # Only npm lockfile results have physical-key exceptions;
            # findings from other targets stay unexcepted and fail closed.
            findings.extend((finding, []) for finding in result_findings)
        else:
            error = _validate_supplied_packages(result, target)
            if error:
                return None, error
    return findings, None


def _aggregate_gate(findings: list, dependency_exceptions: list[dict],
                    expired: list[str], today: dt.date, targets: list[str]) -> tuple[str, str]:
    """Apply exact exceptions and render the gate verdict."""
    unresolved = []
    for finding, instances in findings:
        uncovered = (_uncovered_lock_keys(finding, instances, dependency_exceptions, today)
                     if instances else ["no physical lockfile binding"])
        if uncovered:
            unresolved.append((finding, uncovered))
    details = [f"high_critical_findings={len(unresolved)}; lockfile_directories={len(targets)}"]
    details.extend(f"{item.get('VulnerabilityID')} {item.get('PkgName')}@{item.get('InstalledVersion')} "
                   f"{item.get('Severity')} target={item.get('target')} "
                   f"fixed={item.get('FixedVersion') or 'none-listed'} "
                   f"uncovered_paths={','.join(paths)}"
                   for item, paths in unresolved)
    details.append(f"exact_exceptions_applied={len(findings) - len(unresolved)}")
    if expired:
        details.append("expired_dependency_exceptions=" + ",".join(sorted(expired)))
    return ("fail" if unresolved or expired else "ok"), "; ".join(details)


def trivy_audit() -> tuple[str, str]:
    """Scan tracked dependency manifests with the pre-fetched local DB."""
    if not _tracked_lockfiles():
        return "error", "no tracked dependency lockfiles found"
    today = dt.date.today()
    dependency_exceptions, expired, error = _load_exception_policy(today)
    if error:
        return "error", error
    error = _check_trivy_version()
    if error:
        return "error", error
    # Trivy recursively finds nested lockfiles from one target. Passing the
    # root plus each package directory double-counts nested findings, and it
    # accepts one filesystem target per invocation.
    targets = ["."]
    findings = []
    for target in targets:
        scanned, error = _scan_target(target)
        if error:
            return "error", error
        proc, results = scanned
        collected, error = _collect_target_findings(target, results)
        if error:
            return "error", error
        findings.extend(collected)
        if proc.returncode not in (0, 1):
            return "error", f"Trivy exit {proc.returncode} for {target}"
        if proc.returncode == 1 and not collected:
            return "error", f"Trivy returned failure without a recognized finding for {target}"
    return _aggregate_gate(findings, dependency_exceptions, expired, today, targets)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-root", action="store_true",
                        help="root Go module was already checked by make analyze-security")
    args = parser.parse_args(argv)
    if not database_fresh(CACHE / "govuln-metadata.json"):
        print("dependency audit: ERROR: local Go vulnerability DB is missing or older than 24 hours; "
              "run make security-db-update", file=sys.stderr)
        return 2
    if not database_fresh(CACHE / "trivy-db-metadata.json"):
        print("dependency audit: ERROR: local Trivy DB is missing or older than 24 hours; "
              "run make security-db-update", file=sys.stderr)
        return 2
    results = []
    modules = go_modules()
    if args.skip_root:
        modules = [module for module in modules if module.resolve() != ROOT.resolve()]
    if not modules:
        print("dependency audit: ERROR: no tracked Go modules found", file=sys.stderr)
        return 2
    for module in modules:
        status, detail = go_vuln(module)
        relative = module.relative_to(ROOT).as_posix() or "."
        results.append((status, f"govulncheck {relative}: {detail}"))
    status, detail = trivy_audit()
    results.append((status, f"trivy: {detail}"))
    print("local dependency audit:")
    for status, detail in results:
        print(f"  [{status:5s}] {detail}")
    if any(status == "error" for status, _ in results):
        print("dependency audit: scanner error (not a pass)", file=sys.stderr)
        return 2
    if any(status == "fail" for status, _ in results):
        return 1
    print("dependency audit: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
