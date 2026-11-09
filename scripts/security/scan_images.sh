#!/usr/bin/env bash
# Build the hardened image and run trivy for HIGH/CRITICAL CVEs on every
# published service tag (gateway/loggerd/admin). One unified binary,
# subcommand-selected — Dockerfile.hardened has no SERVICE build arg, so the
# single build is tagged three ways (same pattern as the air-gap drill).
set -euo pipefail
TAG="${1:-hardened}"
fail=0

# Dockerfile.hardened fails the build loudly without SOURCE_DATE_EPOCH (it
# stamps image timestamps for reproducible rebuilds, same recipe as
# scripts/release/release-artifacts.sh): default to the last commit time,
# let an explicit caller value win, reject a non-integer value before any
# docker work starts.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git log -1 --pretty=format:%ct 2>/dev/null || true)
fi
case "$SOURCE_DATE_EPOCH" in
    '' | *[!0-9]*)
        echo "FAIL: SOURCE_DATE_EPOCH must be an integer unix timestamp (got: '$SOURCE_DATE_EPOCH')" >&2
        exit 1
        ;;
esac

docker build -f Dockerfile.hardened --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
    -t "yabanin:${TAG}" . || { echo "BUILD FAIL yabanin:${TAG}"; exit 1; }

for svc in gateway loggerd admin; do
    img="yabanin-${svc}:${TAG}"
    docker tag "yabanin:${TAG}" "${img}"
    echo "=== scanning ${img} ==="
    if command -v trivy >/dev/null 2>&1; then
        trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed "${img}" \
            || { echo "VULN FAIL ${img}"; fail=1; }
    else
        echo "trivy not found — skipping vuln scan"
    fi
    if command -v cosign >/dev/null 2>&1; then
        COSIGN_EXPERIMENTAL=1 cosign sign --yes "${img}" || true
    fi
done

exit ${fail}
