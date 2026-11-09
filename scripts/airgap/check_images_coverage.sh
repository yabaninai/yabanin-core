#!/usr/bin/env bash
#
# list covers everything the onprem chart + compose + vLLM subchart values
# reference — every referenced image must be either
#   (a) present in scripts/airgap/images.txt (shipped in the bundle), or
#   (b) explicitly classified BUYER-SUPPLIED below (documented in
#       docs/onprem/airgap-checklist.md as the buyer's task).
# The reverse direction (orphans in images.txt) is reported as a warning:
# an image nobody references bloats the bundle but is not a coverage gap.
#
# Usage: bash scripts/airgap/check_images_coverage.sh   (from repo root)
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGES_FILE="scripts/airgap/images.txt"

# Explicit buyer-supplied classification (NOT in the vendor bundle):
#  - vllm/vllm-openai: the vLLM inference server for the local-model path
#    (deploy/onprem/vllm-*-values.yaml). Buyers with GPU nodes load it from
#    their own artifact store; the checklist documents the prefill of model
#    weights (200Gi PVC) as a buyer task. Do NOT add it to images.txt
#    without also updating the checklist classification.
BUYER_SUPPLIED="vllm/vllm-openai"

fail=0
[ -f "$IMAGES_FILE" ] || { echo "FAIL: $IMAGES_FILE missing" >&2; exit 1; }

# ---- collect referenced images ----------------------------------------------
# 1) onprem chart values: postgres.image / redis.image (full image:tag)
# 2) onprem chart templates: image.repository defaults (`default "yabanin"`)
#    and registry-qualified values-airgap repositories — these map to the
#    yabanin-* multi-service images (one unified binary, selected by
#    subcommand), which is what images.txt ships.
# 3) airgap compose: every `image:` line.
# 4) vLLM subchart values: image.repository.
refs="$( {
  grep -hE '^\s*(postgres|redis)\.image:' deploy/helm/yabanin-onprem/values*.yaml || true
  grep -hoE 'image:[[:space:]]+[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+' deploy/onprem/airgap-compose.yml \
    | awk '{print $2}' || true
  grep -hA1 '^image:' deploy/onprem/vllm-*.yaml | grep 'repository:' | awk '{print $2}' || true
  # chart templates: the app image default (`| default "yabanin"`)
  grep -hoE 'default "yabanin"' deploy/helm/yabanin-onprem/templates/*.yaml \
    | sed 's/default "yabanin"/yabanin/' | sort -u || true
} | sed 's/[[:space:]]*$//' | sort -u )"

# Chart app-image defaults ("yabanin", "localhost:5000/yabanin") normalize to
# the yabanin multi-service image set shipped in images.txt.
normalize() {
  case "$1" in
    yabanin|*/yabanin|yabanin:*) echo "yabanin-app-image" ;;
    *) echo "$1" ;;
  esac
}

covered() { # covered <image> -> 0 if in images.txt (or the app-image set)
  local img="$1" line
  [ "$img" = "yabanin-app-image" ] && return 0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    # images.txt entries carry their tag when not :latest (pgvector/pgvector:pg16)
    if [ "$line" = "$img" ] || [ "${line%%:*}" = "$img" ] || [ "$line" = "${img%%:*}" ]; then
      return 0
    fi
  done < "$IMAGES_FILE"
  return 1
}

echo "== R057 images.txt coverage check =="
echo "-- referenced images:"
checked=0
while IFS= read -r ref; do
  [ -z "$ref" ] && continue
  checked=$((checked+1))
  norm="$(normalize "$ref")"
  echo "   $ref"
  if [ "$norm" = "yabanin-app-image" ]; then
    echo "PASS: $ref -> yabanin multi-service image (images.txt: yabanin-gateway/-loggerd/-admin)"
  elif covered "$ref"; then
    echo "PASS: $ref -> covered by $IMAGES_FILE"
  elif grep -qx "$ref" <<< "$BUYER_SUPPLIED"; then
    echo "PASS: $ref -> BUYER-SUPPLIED (classified; see airgap-checklist.md)"
  else
    echo "FAIL: $ref referenced by chart/compose but NOT in $IMAGES_FILE and not classified buyer-supplied" >&2
    fail=1
  fi
done <<< "$refs"

# reverse direction: orphans
echo "-- images.txt entries (orphan = warning):"
while IFS= read -r line; do
  [ -z "$line" ] && continue
  echo "   $line"
done < "$IMAGES_FILE"

# completeness of the core set: the three yabanin service images + PG + Redis
# are the minimum viable air-gap install (airgap-compose + onprem chart).
for required in yabanin-gateway yabanin-loggerd yabanin-admin; do
  if ! grep -qx "$required" "$IMAGES_FILE"; then
    echo "FAIL: $required missing from $IMAGES_FILE (onprem chart deploys it)" >&2
    fail=1
  else
    echo "PASS: $required present (onprem chart)"
  fi
done
for required_third in pgvector/pgvector:pg16 redis:7-alpine; do
  if ! grep -qx "$required_third" "$IMAGES_FILE"; then
    echo "FAIL: $required_third missing from $IMAGES_FILE (bundled postgres/redis)" >&2
    fail=1
  else
    echo "PASS: $required_third present (bundled dependency)"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "== RESULT: FAIL" >&2
  exit 1
fi
echo "== RESULT: PASS ($checked references checked)"
