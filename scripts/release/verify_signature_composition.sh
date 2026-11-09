#!/usr/bin/env bash
# Signature composition verification — N17-P03-T06 (joint user scenario).
#
# Maps every SBOM subject to the actual delivered bytes, checks the
# composition of the to-be-signed SHA256SUMS, and verifies signature
# sidecars cryptographically:
#
#   A. subject <-> digest: every SBOM-SUBJECTS entry re-hashes its reference
#      bytes and both per-subject SBOMs (stale/foreign -> BLOCK);
#   B. SHA256SUMS composition: EVERY file in the release set is covered,
#      except exactly the rule set: SHA256SUMS-FULL itself,
#      delivered-inventory/sbom-handoff.json (P04 signs it), the composition
#      report itself (derived output, produced after the sums — assemble
#      refreshes exclude it so a stale report is never baked into the sums),
#      and signature sidecars (*.sig/*.bundle/*.pem) — SIGNATURE SIDECARS DO
#      NOT HASH THEMSELVES; every payload binary and every subject must be
#      covered BEFORE signing;
#   C. handoff sanity: handoff sbom_subjects digests equal SBOM-SUBJECTS
#      digests and the handoff asset list equals the sums composition;
#   D. sidecar binding (only when a signatures dir is given): for each
#      target with sidecars, `cosign verify-blob` must verify the content
#      binding against the delivered bytes — the cryptographic check runs
#      with real cosign; unit tests use the deterministic FAKE cosign, and
#      the JSON output records which binding mode ran.
#
# Exit codes: 0 green; 1 BLOCK (violations listed); 2 usage error.

set -euo pipefail

usage() {
    cat <<'USAGE'
usage: verify_signature_composition.sh --release-dir DIR [--signatures-dir DIR]
                                      [--key KEYFILE] [--out FILE]
Exit codes: 0 ok; 1 BLOCK; 2 usage error.
USAGE
}

die() { echo "FAIL: composition: $*" >&2; exit 1; }
# F-E (T11 review): the usage text promises exit 2 for usage errors;
# argument-parse failures print the usage and exit 2 (file/dir
# existence checks downstream remain invariant failures, exit 1).
usage_die() { usage >&2; echo "FAIL: composition: $*" >&2; exit 2; }

RELEASE_DIR=""; SIG_DIR=""; KEY=""; OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --release-dir) RELEASE_DIR="${2:-}"; shift 2 ;;
        --signatures-dir) SIG_DIR="${2:-}"; shift 2 ;;
        --key) KEY="${2:-}"; shift 2 ;;
        --out) OUT="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage_die "unknown argument: $1" ;;
    esac
done
[ -n "$RELEASE_DIR" ] || usage_die "--release-dir is required"
[ -d "$RELEASE_DIR" ] || die "release dir not found: $RELEASE_DIR"
if [ -n "$SIG_DIR" ]; then
    [ -d "$SIG_DIR" ] || die "signatures dir not found: $SIG_DIR"
    command -v cosign > /dev/null 2>&1 || die "cosign required for cryptographic sidecar binding"
    [ -n "$KEY" ] || usage_die "--key is required with --signatures-dir"
    [ -f "$KEY" ] || die "key file not found: $KEY"
fi
command -v python3 > /dev/null 2>&1 || die "python3 is required"

python3 - "$(cd "$RELEASE_DIR" && pwd -P)" \
    "$([ -n "$SIG_DIR" ] && cd "$SIG_DIR" && pwd -P || echo "")" \
    "$KEY" "$OUT" <<'PYEOF'
import base64, hashlib, json, os, subprocess, sys

release, sig_dir, key, out_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
inv = os.path.join(release, "delivered-inventory")
violations = []
report = {"ok": False, "subjects": [], "sums": {}, "handoff": {}, "sidecars": {},
          "binding_mode": "composition-only (no signatures dir given)" if not sig_dir
          else "cosign verify-blob (tool on PATH: test fixtures use a deterministic"
               " content-binding fake; production runs real cosign)"}

def fsha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load(p):
    # Boundary teeth (T07): a malformed or unreadable JSON input is a hard
    # stop with a named file — never a bare traceback that hides which
    # binding could not be evaluated.
    try:
        with open(p) as fh:
            return json.load(fh)
    except (OSError, ValueError) as e:
        raise SystemExit("FAIL: composition: malformed/unreadable JSON %s: %s" % (p, e))

def fail(msg):
    violations.append(msg)

# ---------------------------------------------------- A. subject <-> digest
subjects = load(os.path.join(inv, "SBOM-SUBJECTS.json"))
if not isinstance(subjects, dict):
    fail("SBOM-SUBJECTS.json is not a JSON object")
    subjects = {}
subject_list = subjects.get("subjects")
if not isinstance(subject_list, list):
    # F-C (T11 review): a wrong-shaped subjects value must be a named
    # refusal, not a raw TypeError — reset to an empty list so the rest of
    # the checks keep running and the BLOCK report still prints.
    fail("SBOM-SUBJECTS.json has no subjects array (wrong type)")
    subject_list = []
for s in subject_list:
    ref = s["reference"]
    entry = {"subject": s["subject"], "kind": s["kind"]}
    if not os.path.isfile(ref):
        fail("subject file missing: %s" % s["subject"])
        entry["bound"] = False
    elif fsha(ref) != s["subject_sha256"]:
        fail("subject bytes drifted/foreign: %s" % s["subject"])
        entry["bound"] = False
    else:
        entry["bound"] = True
        entry["subject_sha256"] = s["subject_sha256"]
    sb_ok = True
    for k in ("sbom_spdx", "sbom_cdx"):
        p = os.path.join(inv, s[k])
        if not os.path.isfile(p) or fsha(p) != s[k + "_sha256"]:
            fail("stale/foreign SBOM for subject %s: %s" % (s["subject"], s[k]))
            sb_ok = False
        else:
            entry[k + "_sha256"] = s[k + "_sha256"]
    entry["sbom_bound"] = sb_ok
    report["subjects"].append(entry)

# --------------------------------------------- B. SHA256SUMS composition
SIDECAR_EXTS = (".sig", ".bundle", ".pem")
full = {}
# Boundary teeth (T07): the signed sums must parse cleanly and be
# unambiguous. A duplicate entry makes "what was signed" ambiguous, a
# malformed line means the sums were hand-edited or truncated, and an entry
# outside the release set means the signed set does not describe this tree.
# Each is a hard violation with a specific message — previously a duplicate
# silently resolved last-entry-wins and a malformed line escaped as a bare
# ValueError traceback.
sums_path = os.path.join(release, "SHA256SUMS-FULL")
if os.path.isfile(sums_path):
    with open(sums_path) as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            if "  " not in line:
                fail("malformed SHA256SUMS-FULL line %d (expected "
                     "'<sha256>  <path>' with a two-space separator): %s"
                     % (lineno, line[:80]))
                continue
            digest, name = line.split("  ", 1)
            norm = os.path.normpath(name)
            if os.path.isabs(norm) or norm == ".." or norm.startswith("../"):
                fail("SHA256SUMS-FULL entry outside the release set: %s" % name)
                continue
            if name in full:
                fail("duplicate SHA256SUMS-FULL entry: %s (the signed sums "
                     "must be unambiguous)" % name)
                continue
            full[name] = digest
else:
    fail("SHA256SUMS-FULL missing (composition unverifiable)")

def sidecar_files():
    found = set()
    if sig_dir:
        for root, _, files in os.walk(sig_dir):
            for f in files:
                found.add(os.path.relpath(os.path.join(root, f), sig_dir))
    return found

sidecars = sidecar_files()
out_rel = os.path.relpath(out_path, release) if out_path else None

# every file in the release walk must be covered unless it is an exclusion:
# sums-full itself, the handoff (P04 signs it), the report being produced
# now, and signature sidecars ANYWHERE in the tree (sidecars do not hash
# themselves)
on_disk = set()
for dp, _, fns in os.walk(release):
    for f in fns:
        on_disk.add(os.path.relpath(os.path.join(dp, f), release))
excluded = set()
excluded_report = []
for rel in sorted(on_disk):
    is_sidecar = rel.endswith(SIDECAR_EXTS)
    if rel in ("SHA256SUMS-FULL", "delivered-inventory/sbom-handoff.json",
               "delivered-inventory/signature-composition.json") or \
       rel == out_rel or is_sidecar:
        excluded.add(rel)
        if rel in full:
            if is_sidecar:
                fail("signature sidecar must NOT be hashed by SHA256SUMS-FULL "
                     "(signature sidecars do not hash themselves): %s" % rel)
            else:
                fail("excluded artifact must NOT be hashed by SHA256SUMS-FULL "
                     "(never part of the signed set): %s" % rel)
        continue
    if rel not in full:
        fail("asset NOT covered by SHA256SUMS-FULL (must cover before signing): %s" % rel)
    elif fsha(os.path.join(release, rel)) != full[rel]:
        fail("SHA256SUMS-FULL digest drift: %s" % rel)
for name in sorted(full):
    if name not in on_disk:
        fail("SHA256SUMS-FULL covers missing file: %s" % name)
report["sums"] = {"covered": len(full), "on_disk": len(on_disk),
                  "excluded": sorted(excluded),
                  "rule": "all payload+metadata covered pre-signing; sums-full, "
                          "handoff (P04 signs) and signature sidecars excluded"}

# ------------------------------------------------------- C. handoff sanity
# The handoff ENRICHES each SBOM-SUBJECTS entry: sbom_spdx(_sha256) is
# split into sbom_spdx_original(_sha256) (== the SBOM-SUBJECTS binding)
# plus sbom_spdx_normalized(_sha256) (SDE-normalized copy), and records
# fields_normalized. Everything else must match verbatim.
h = load(os.path.join(inv, "sbom-handoff.json"))
if not isinstance(h, dict):
    fail("sbom-handoff.json is not a JSON object")
    h = {}
handoff_subjects = h.get("sbom_subjects", [])
if not isinstance(handoff_subjects, list):
    fail("sbom-handoff.json sbom_subjects is not a list")
    # F-C (T11 review): named refusal instead of a TypeError from the
    # dict comprehension below; continue with an empty list.
    handoff_subjects = []
hs = {s["subject"]: s for s in handoff_subjects}
if set(hs) != {s["subject"] for s in subject_list}:
    fail("handoff sbom_subjects subjects differ from SBOM-SUBJECTS.json")
for s in subject_list:
    e = hs.get(s["subject"])
    if not e:
        continue
    expect_common = {k: v for k, v in s.items()
                     if k not in ("sbom_spdx", "sbom_spdx_sha256")}
    got_common = {k: v for k, v in e.items()
                  if k not in ("sbom_spdx_original", "sbom_spdx_original_sha256",
                               "sbom_spdx_normalized", "sbom_spdx_normalized_sha256",
                               "fields_normalized")}
    if got_common != expect_common:
        fail("handoff entry fields differ for subject %s" % s["subject"])
    if e.get("sbom_spdx_original") != s["sbom_spdx"] or \
       e.get("sbom_spdx_original_sha256") != s["sbom_spdx_sha256"]:
        fail("handoff original-SPDX binding differs for subject %s" % s["subject"])
    np = os.path.join(inv, e.get("sbom_spdx_normalized", ""))
    if not os.path.isfile(np) or fsha(np) != e.get("sbom_spdx_normalized_sha256"):
        fail("handoff normalized SPDX missing/drifted for subject %s" % s["subject"])
assets = {a["path"]: a.get("sha256") for a in h.get("assets", [])
          if isinstance(a, dict) and "path" in a}
covered = on_disk - excluded
if set(assets) != covered:
    miss = sorted(covered - set(assets))
    extra = sorted(set(assets) - covered)
    if miss:
        fail("handoff assets missing entries: %s" % miss[:5])
    if extra:
        fail("handoff assets list stale entries: %s" % extra[:5])
for path, digest in sorted(assets.items()):
    p = os.path.join(release, path)
    if os.path.isfile(p) and fsha(p) != digest:
        fail("handoff asset digest drift: %s" % path)
report["handoff"] = {"sbom_subjects_match": not any("handoff sbom_subjects" in v or
                                                    "handoff entry fields" in v or
                                                    "handoff original-SPDX" in v or
                                                    "handoff normalized SPDX" in v
                                                    for v in violations),
                     "assets_match_sums_composition": set(assets) == covered}

# ------------------------------------------- D. sidecar crypto binding
side_report = {"state": "absent (signing owner-gated, pending N17-P04)",
               "targets": []}
if sig_dir:
    targets = sorted({f[:-len(ext)] for f in sidecars
                      for ext in SIDECAR_EXTS if f.endswith(ext)})
    if not targets:
        fail("signatures dir given but no sidecars (*.sig/*.bundle/*.pem) found")
    side_report["state"] = "verified"
    for t in targets:
        blob = os.path.join(release, t)
        entry = {"target": t}
        if not os.path.isfile(blob):
            fail("sidecar target missing in release set: %s" % t)
            side_report["targets"].append({**entry, "ok": False})
            continue
        if t not in full or fsha(blob) != full[t]:
            fail("sidecar target not digest-covered by SHA256SUMS-FULL: %s" % t)
        sigp = os.path.join(sig_dir, t + ".sig")
        bundp = os.path.join(sig_dir, t + ".bundle")
        args = ["cosign", "verify-blob", "--key", key]
        if os.path.isfile(bundp):
            args += ["--bundle", bundp]
        elif os.path.isfile(sigp):
            args += ["--signature", sigp]
        else:
            fail("no .sig/.bundle sidecar for target %s" % t)
            side_report["targets"].append({**entry, "ok": False})
            continue
        args += [blob]
        proc = subprocess.run(args, capture_output=True, text=True)
        if proc.returncode != 0:
            fail("signature verification FAILED for %s (cryptographic binding broken)"
                 % t)
            entry["ok"] = False
            entry["error"] = (proc.stderr or proc.stdout).strip()[:400]
        else:
            entry["ok"] = True
        side_report["targets"].append(entry)
    if all(t.get("ok") for t in side_report["targets"]) and side_report["targets"]:
        side_report["state"] = "verified"
    elif side_report["targets"]:
        side_report["state"] = "failed"
report["sidecars"] = side_report

if violations:
    report["ok"] = False
    report["violations"] = violations
    print("composition: BLOCK")
    for v in violations:
        print("  " + v)
else:
    report["ok"] = True
    print("composition: GREEN — %d subjects bound (%d with SBOM digests), "
          "%d SHA256SUMS-FULL entries cover %d on-disk assets, handoff matches, "
          "sidecars: %s"
          % (sum(1 for x in report["subjects"] if x.get("bound")),
             sum(1 for x in report["subjects"] if x.get("sbom_bound")),
             len(full), len(on_disk), side_report["state"]))

if out_path:
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.chmod(out_path, 0o644)
raise SystemExit(1 if violations else 0)
PYEOF
