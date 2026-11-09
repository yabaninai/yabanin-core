#!/usr/bin/env bash
# Run in the exact source checkout used to build this distribution.
# This is a verification entry point, not authorization to publish.
set -euo pipefail
if [ "$#" -ne 5 ]; then
    echo 'usage: check-distribution.sh QUALITY_MANIFEST REVIEW_JSON RELEASE_DIR TRUSTED_PUBLIC_KEY SIGNATURES_DIR' >&2
    exit 2
fi
manifest=$1
review=$2
release_dir=$3
trusted_key=$4
signatures_dir=$5
[ -z "$(git status --porcelain --untracked-files=all)" ] || { echo 'BLOCK: source checkout is dirty' >&2; exit 1; }
[ -f "$trusted_key" ] || { echo 'BLOCK: trusted public key missing' >&2; exit 1; }
[ -d "$signatures_dir" ] || { echo 'BLOCK: signatures directory missing' >&2; exit 1; }
python3 scripts/quality/quality.py evidence "$manifest" --require full
python3 - "$release_dir/recipe.json" "$(git rev-parse HEAD)" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    recipe = json.load(f)
if recipe.get('git_commit') != sys.argv[2]:
    raise SystemExit('BLOCK: artifacts were built from a different source commit')
PY
python3 scripts/quality/license_check.py --release --release-evidence "$review" \
    --json-report artifacts/licenses/release-audit.json
bash scripts/release/release_gate_check.sh --release-dir "$release_dir"
bash scripts/release/verify_signature_composition.sh --release-dir "$release_dir" \
    --signatures-dir "$signatures_dir" --key "$trusted_key"
# Composition verifies supplied sidecars; require the full checksum manifest
# signature explicitly so an incomplete sidecar set cannot stand in for it.
if [ -f "$signatures_dir/SHA256SUMS-FULL.bundle" ]; then
    cosign verify-blob --key "$trusted_key" --bundle "$signatures_dir/SHA256SUMS-FULL.bundle" "$release_dir/SHA256SUMS-FULL"
else
    cosign verify-blob --key "$trusted_key" --signature "$signatures_dir/SHA256SUMS-FULL.sig" "$release_dir/SHA256SUMS-FULL"
fi
echo 'Distribution checks passed. Independent rebuild, offline installation and release authorization remain separate acceptance checks.'
