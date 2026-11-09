#!/usr/bin/env bash
# Release gate check — N17-P03-T05 (negative scenario).
#
# One command in which an unverified or missing mandatory asset BLOCKS:
#   * every mandatory asset exists (recipe targets, SHA256SUMS(-FULL),
#     notice bundle, SBOM subjects, dependency map, consolidated SPDX,
#     normalized SBOM set, license bundle, handoff);
#   * every SHA256SUMS-FULL entry matches the bytes on disk and covers all
#     mandatory assets (stale sums, missing asset -> BLOCK);
#   * every SBOM subject binds to its delivered bytes (stale/foreign SBOM,
#     swapped payload -> BLOCK);
#   * every image subject binds to an asset-inventory record whose layers
#     are all diff_id-verified — a source-only scan has no such layer
#     records and cannot pass as a docker-layer proof (-> BLOCK);
#   * the inventory generator is syft with buildinfo_is_full_sbom=false and
#     source_only_scan_is_layer_proof=false — the `go version -m` buildinfo
#     fallback is NOT a full SBOM (-> BLOCK);
#   * NOTICE/THIRD-PARTY-NOTICES/NOTICE-litellm digests recorded in the
#     handoff match the bytes on disk (swapped NOTICE -> BLOCK);
#   * coverage-report ok=true, missing_from_disk=0, digest_drift=0;
#   * handoff self-consistency: consolidated SPDX + license-bundle manifest
#     digests match.
#
# The violation list is printed in full; nothing is hidden or retried.
# Exit codes: 0 gate green; 1 BLOCK (violations listed); 2 usage error.

set -euo pipefail

usage() {
    cat <<'USAGE'
usage: release_gate_check.sh --release-dir DIR
  --release-dir DIR  release set with a delivered-inventory/ subdir
Exit codes: 0 ok; 1 BLOCK; 2 usage error.
USAGE
}

die() { echo "FAIL: gate: $*" >&2; exit 1; }
# F-E (T11 review): the usage text promises exit 2 for usage errors;
# argument-parse failures print the usage and exit 2 (file/dir
# existence checks downstream remain invariant failures, exit 1).
usage_die() { usage >&2; echo "FAIL: gate: $*" >&2; exit 2; }

RELEASE_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --release-dir) RELEASE_DIR="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage_die "unknown argument: $1" ;;
    esac
done
[ -n "$RELEASE_DIR" ] || usage_die "--release-dir is required"
[ -d "$RELEASE_DIR" ] || die "release dir not found: $RELEASE_DIR"
command -v python3 > /dev/null 2>&1 || die "python3 is required"

python3 - "$(cd "$RELEASE_DIR" && pwd -P)" <<'PYEOF'
import hashlib, json, os, sys

release = sys.argv[1]
inv = os.path.join(release, "delivered-inventory")
violations = []

def fsha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load(p):
    # Boundary teeth (T07): malformed/unreadable JSON is a hard stop naming
    # the file — never a bare traceback that hides which binding failed.
    try:
        with open(p) as fh:
            return json.load(fh)
    except (OSError, ValueError) as e:
        raise SystemExit("FAIL: gate: malformed/unreadable JSON %s: %s" % (p, e))

# ------------------------------------------------- mandatory assets exist
targets = []
if os.path.isfile(os.path.join(release, "recipe.json")):
    raw_targets = load(os.path.join(release, "recipe.json")).get("targets", [])
    if not isinstance(raw_targets, list) or any(not isinstance(t, str) for t in raw_targets):
        raise SystemExit("FAIL: gate: recipe.json targets must be a list of strings")
    targets = [t.split("=", 1)[0] for t in raw_targets]
    # Boundary tooth (T07): a recipe that declares no targets means the
    # payload list is empty — the gate would silently verify only the
    # fixed mandatory set and let a zero-payload release through as GREEN.
    if not targets:
        violations.append("recipe.json declares no targets (payload list empty)")
mandate = (targets or ["yabanin"]) + [
    "SHA256SUMS", "SHA256SUMS-FULL", "THIRD-PARTY-NOTICES.md",
    "delivered-inventory/SBOM-SUBJECTS.json",
    "delivered-inventory/asset-inventory.json",
    "delivered-inventory/cache-scan.json",
    "delivered-inventory/coverage-report.json",
    "delivered-inventory/runtime-dependency-map.json",
    "delivered-inventory/sbom-normalized",
    "delivered-inventory/sbom-normalization-receipt.json",
    "delivered-inventory/sbom-delivered-consolidated.spdx.json",
    "delivered-inventory/license-bundle/THIRD-PARTY-LICENSES-FULL.md",
    "delivered-inventory/license-bundle/license-bundle-manifest.json",
    "delivered-inventory/sbom-handoff.json"]
for rel in mandate:
    if not os.path.exists(os.path.join(release, rel)):
        violations.append("missing mandatory asset: %s" % rel)
if violations:
    print("gate: BLOCK")
    for v in violations:
        print("  " + v)
    raise SystemExit(1)

# ------------------------------------------------------ SHA256SUMS-FULL
full = {}
# Boundary teeth (T07): same signed-sums parsing rules as the composition
# verifier — duplicates are ambiguous, malformed lines mean hand-edited or
# truncated sums, entries outside the release set do not describe this tree.
for lineno, line in enumerate(open(os.path.join(release, "SHA256SUMS-FULL")), 1):
    line = line.strip()
    if not line:
        continue
    if "  " not in line:
        violations.append("malformed SHA256SUMS-FULL line %d (expected "
                          "'<sha256>  <path>' with a two-space separator): %s"
                          % (lineno, line[:80]))
        continue
    digest, name = line.split("  ", 1)
    norm = os.path.normpath(name)
    if os.path.isabs(norm) or norm == ".." or norm.startswith("../"):
        violations.append("SHA256SUMS-FULL entry outside the release set: %s" % name)
        continue
    if name in full:
        violations.append("duplicate SHA256SUMS-FULL entry: %s (the signed sums "
                          "must be unambiguous)" % name)
        continue
    full[name] = digest
# sbom-handoff.json is deliberately NOT in SHA256SUMS-FULL (the bundle
# refresh excludes it): N17-P04 signs the handoff itself, per the packet
# order assets -> SHA256SUMS -> signatures/bundles.
for rel in mandate:
    if rel in ("SHA256SUMS-FULL", "delivered-inventory/sbom-handoff.json"):
        continue
    if os.path.isdir(os.path.join(release, rel)):
        under = [os.path.join(dp, f) for dp, _, fns in os.walk(os.path.join(release, rel))
                 for f in fns]
        for p in under:
            if os.path.relpath(p, release) not in full:
                violations.append("file under mandatory dir NOT covered by SHA256SUMS-FULL: %s"
                                  % os.path.relpath(p, release))
    elif rel not in full:
        violations.append("mandatory asset NOT covered by SHA256SUMS-FULL: %s" % rel)
for name, digest in sorted(full.items()):
    p = os.path.join(release, name)
    if not os.path.isfile(p):
        violations.append("SHA256SUMS-FULL covers missing file: %s" % name)
    elif fsha(p) != digest:
        violations.append("SHA256SUMS-FULL digest drift: %s" % name)

# --------------------------------------------------------- subject binds
subjects = load(os.path.join(inv, "SBOM-SUBJECTS.json"))
# Boundary teeth (T07): a missing subjects array or an empty inventory or an
# unbound recipe target means the SBOM does not actually describe the
# payload — all must BLOCK.
subject_list = subjects.get("subjects", [])
if "subjects" not in subjects:
    violations.append("SBOM-SUBJECTS.json has no subjects array")
elif not isinstance(subject_list, list):
    violations.append("SBOM-SUBJECTS.json subjects is not a list")
    subject_list = []
if not subject_list:
    violations.append("SBOM-SUBJECTS.json binds no subjects (empty inventory)")
meta = subjects.get("metadata", {})
if not isinstance(meta, dict):
    violations.append("SBOM-SUBJECTS.json metadata is not an object")
    meta = {}
if targets:
    subject_names = {s["subject"] for s in subject_list}
    for t in targets:
        if t not in subject_names:
            violations.append("recipe target has no SBOM subject binding: %s" % t)
if meta.get("generator") != "syft":
    violations.append("SBOM generator is %r, not syft — buildinfo fallback is NOT a full SBOM"
                      % meta.get("generator"))
if meta.get("buildinfo_is_full_sbom") is not False:
    violations.append("buildinfo_is_full_sbom must be explicitly false")
if meta.get("source_only_scan_is_layer_proof") is not False:
    violations.append("source_only_scan_is_layer_proof must be explicitly false")
for s in subject_list:
    ref = s["reference"]
    if not os.path.isfile(ref) or fsha(ref) != s["subject_sha256"]:
        violations.append("subject bytes drifted/foreign: %s" % s["subject"])
    for key in ("sbom_spdx", "sbom_cdx"):
        p = os.path.join(inv, s[key])
        if not os.path.isfile(p) or fsha(p) != s[key + "_sha256"]:
            violations.append("stale/foreign SBOM for subject %s: %s" % (s["subject"], s[key]))

# ---------------------------------------------------- image layer proof
img_records = {}
for rec in load(os.path.join(inv, "asset-inventory.json")).get("images", []):
    # Attestation manifests legitimately carry zero layers (unknown/unknown
    # platform); a layer proof requires ANY payload image whose layers are
    # ALL diff_id-verified against the config. An empty set proves nothing.
    img_records[rec.get("tar")] = any(
        bool(i.get("layers"))
        and all(l.get("diff_id_match") for l in i.get("layers", []))
        for i in rec.get("images", []))
for s in subject_list:
    if s["kind"] == "image" and not img_records.get(s["reference"]):
        violations.append("no image-layer proof: subject %s has no diff_id-verified layer "
                          "record (a source-only scan cannot pass as a docker-layer proof)"
                          % s["subject"])

# ------------------------------------------------------ coverage report
cov = load(os.path.join(inv, "coverage-report.json"))
if not cov.get("ok"):
    violations.append("coverage report not ok")
if cov.get("missing_from_disk"):
    violations.append("coverage missing assets: %s" % cov["missing_from_disk"])
if cov.get("digest_drift"):
    violations.append("coverage digest drift: %s" % cov["digest_drift"])

# --------------------------------------------------- handoff + notice swap
h = load(os.path.join(inv, "sbom-handoff.json"))
for rel, digest in sorted(h.get("notice_bundle", {}).items()):
    p = os.path.join(release, rel)
    if not os.path.isfile(p):
        violations.append("notice bundle asset missing: %s" % rel)
    elif fsha(p) != digest:
        violations.append("swapped/altered NOTICE: %s (handoff digest mismatch)" % rel)
cpath = os.path.join(inv, h.get("consolidated_spdx",
                                "sbom-delivered-consolidated.spdx.json"))
if not os.path.isfile(cpath) or fsha(cpath) != h.get("consolidated_spdx_sha256"):
    violations.append("consolidated SPDX digest mismatch")
lb = h.get("license_bundle", {})
mpath = os.path.join(inv, lb.get("root", "license-bundle"), "license-bundle-manifest.json")
if not os.path.isfile(mpath) or fsha(mpath) != lb.get("manifest_sha256"):
    violations.append("license bundle manifest digest mismatch")

if violations:
    print("gate: BLOCK")
    for v in violations:
        print("  " + v)
    raise SystemExit(1)
img_subj = sum(1 for s in subject_list if s["kind"] == "image")
print("gate: GREEN — %d mandatory assets verified, %d SHA256SUMS-FULL entries match, "
      "%d SBOM subjects bound, %d image %s layer-proven, coverage ok, notices bound"
      % (len(mandate), len(full), len(subject_list), img_subj,
         "subject" if img_subj == 1 else "subjects"))
PYEOF
