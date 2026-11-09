#!/usr/bin/env bash
# Build an air-gap bundle: pull all images, save to tarballs, generate a
# per-image SBOM, record image digests and sign them with the cosign key-pair
# signatures via `cosign sign` when reachable). Everything — tars, SBOMs,
# digests, NOTICE materials, install materials (compose profile + app-role
# bootstrap SQL + Helm charts incl. values.schema.json schemas) and any
# DECLARED mlpack model packs (verified before copy) — is covered by
# manifest.sha256.
#
# A08 signed inventory (BUILD29-CONTRACT C-12/Q5): the FULL inventory manifest
# (manifest.sha256 — every tar, SBOM, digest list, NOTICE and the bundle-info
# format marker) is signed with cosign sign-blob as a detached sidecar
# (manifest.sha256.sig, or the v3 sigstore-bundle form). A swapped SBOM or a
# tampered tar plus a recomputed manifest no longer verifies: the stale
# signature fails cosign verify-blob. load_bundle.sh refuses to install
# anything whose manifest signature does not verify against a pinned external
# --pubkey; RELEASE_ALLOW_UNSIGNED cannot make unsigned format-2 bundles
# installable.
#
# the NOTICE materials; failures are NOT swallowed. Unsigned bundles are only
# possible through RELEASE_ALLOW_UNSIGNED=true, recorded in the output and in
# UNSIGNED-RELEASE-DISCLOSURE.md for the release notes.
#
# usage: build_bundle.sh <tag> [bundle_dir]
set -euo pipefail

TAG="${1:?usage: build_bundle.sh <tag> [bundle_dir]}"
BUNDLE_DIR="${2:-dist/airgap}"
REGISTRY_PREFIX="${REGISTRY_PREFIX:-}"   # e.g. ghcr.io/reireirei/
IMAGES_FILE="${IMAGES_FILE:-$(dirname "$0")/images.txt}"
RELEASE_DIR="${RELEASE_DIR:-dist/release}"

strict() { [ "${RELEASE_STRICT:-0}" = "1" ] || [ "${RELEASE_STRICT:-}" = "true" ]; }
allow_unsigned() { [ "${RELEASE_ALLOW_UNSIGNED:-}" = "true" ] || [ "${RELEASE_ALLOW_UNSIGNED:-}" = "1" ]; }

if command -v sha256sum >/dev/null 2>&1; then
    HASH="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    HASH="shasum -a 256"
else
    echo "FAIL: no sha256sum or shasum on PATH" >&2
    exit 1
fi

if strict; then
    missing=""
    command -v syft > /dev/null 2>&1 || missing="syft (per-image SPDX SBOM)"
    if [ -n "${COSIGN_KEY:-}" ]; then
        command -v cosign > /dev/null 2>&1 || missing="${missing:+$missing, }cosign (COSIGN_KEY is set)"
    elif ! allow_unsigned; then
        missing="${missing:+$missing, }COSIGN_KEY (RELEASE_ALLOW_UNSIGNED=true is the only unsigned path, D-D)"
    fi
    [ -f "$RELEASE_DIR/THIRD-PARTY-NOTICES.md" ] || missing="${missing:+$missing, }$RELEASE_DIR/THIRD-PARTY-NOTICES.md (run 'make release-artifacts' first)"
    if [ -n "$missing" ]; then
        echo "FAIL: incomplete bundle (RELEASE_STRICT=1): missing $missing" >&2
        exit 1
    fi
fi

mkdir -p "$BUNDLE_DIR/images"
DIGESTS_FILE="$BUNDLE_DIR/images/image-digests.txt"
: > "$DIGESTS_FILE"

unsigned_disclosure() { # unsigned_disclosure <reason>
    cat > "$BUNDLE_DIR/UNSIGNED-RELEASE-DISCLOSURE.md" <<EOF
# UNSIGNED AIR-GAP BUNDLE — release-notes disclosure (required)

This air-gap bundle is UNSIGNED. Reason: $1.

- Decision D-D (owner, DECISIONS.md 2026-10-16): strict release mode is
  implemented; the 2026-10-31 release may ship unsigned only through the
  explicit RELEASE_ALLOW_UNSIGNED=true override with this disclosure in the
  release notes. Post-release, strict signing is mandatory.
- Integrity of the tarballs is still checkable via manifest.sha256, but there
  is no signature binding the image digests (image-digests.txt.sig absent)
  and none binding the inventory manifest (manifest.sha256.sig absent).
- A08 install policy: this is a format-2 bundle (bundle-info.txt marker) and
  UNSIGNED format-2 bundles are NOT installable — scripts/airgap/
  load_bundle.sh fails closed regardless of RELEASE_ALLOW_UNSIGNED. Only
  pre-A08 (legacy) bundles qualify for the explicit --allow-legacy-unsigned
  compatibility path.
EOF
    # non-strict unsigned bundle is a legacy skip, not an owner override.
    if allow_unsigned; then
        echo "OVERRIDE: RELEASE_ALLOW_UNSIGNED=true — bundle stays UNSIGNED; UNSIGNED-RELEASE-DISCLOSURE.md written; disclose in release notes" >&2
    else
        echo "unsigned: COSIGN_KEY not set and RELEASE_STRICT is not active — no override used; UNSIGNED-RELEASE-DISCLOSURE.md written; disclose in release notes" >&2
    fi
}

echo "=== Building air-gap bundle (tag=$TAG) ==="
while IFS= read -r img; do
    [ -z "$img" ] && continue
    name="$(echo "$img" | tr '/:' '__')"
    full="${REGISTRY_PREFIX}${img}"
    # (pgvector/pgvector:pg16, redis:7-alpine) must not get ":$TAG" appended —
    # `docker save host/pgvector/pgvector:pg16:$TAG` is an invalid reference
    # and aborted the whole bundle build. Untagged entries keep the bundle
    # tag. A colon in the basename (after the last slash) means "has tag".
    base="${img##*/}"
    case "$base" in
        *:*) ref="$full" ;;
        *)   ref="$full:$TAG" ;;
    esac
    echo "--- pulling $ref ---"
    docker pull "$ref"
    docker save "$ref" -o "$BUNDLE_DIR/images/${name}.tar"
    # --- image digest (D-B signing subject; never a hash of raw manifest JSON)
    digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$ref" 2>/dev/null || true)"
    if [ -n "$digest" ]; then
        printf '%s\t%s\n' "$name" "$digest" >> "$DIGESTS_FILE"
        echo "digest recorded: $digest"
    else
        # docker save/load do not preserve RepoDigests; a missing digest must
        # be visible, never invented.
        printf '%s\tDIGEST-UNAVAILABLE\n' "$name" >> "$DIGESTS_FILE"
        if strict; then
            echo "FAIL: incomplete bundle (RELEASE_STRICT=1): no RepoDigest for $ref" >&2
            exit 1
        fi
        echo "WARN: no RepoDigest for $ref (pulled-by-tag only)" >&2
    fi
    # --- per-image SBOM (syft; honest fallbacks, never faked syft output)
    tmpbin=""
    cid=""
    if command -v syft > /dev/null 2>&1; then
        syft "$ref" -o spdx-json > "$BUNDLE_DIR/images/sbom-${name}.spdx.json" \
            || { echo "FAIL: syft SBOM generation failed for $ref" >&2; exit 1; }
        echo "sbom: sbom-${name}.spdx.json (syft)"
    else
        tmpbin=$(mktemp)
        cid=$(docker create "$ref" 2>/dev/null || true)
        if [ -n "$cid" ] && docker cp "$cid:/app/yabanin" "$tmpbin" 2>/dev/null; then
            # Yabanin images: extract the static binary and fingerprint its Go
            # build metadata — honest buildinfo fallback, explicitly marked.
            if go version -m "$tmpbin" > "$BUNDLE_DIR/images/sbom-${name}.buildinfo" 2>/dev/null \
                    && [ -s "$BUNDLE_DIR/images/sbom-${name}.buildinfo" ]; then
                echo "go-version-m buildinfo fallback (NOT a full SPDX SBOM)" > "$BUNDLE_DIR/images/sbom-${name}.source"
                echo "sbom: sbom-${name}.buildinfo (go buildinfo fallback; syft not installed)"
            else
                rm -f "$BUNDLE_DIR/images/sbom-${name}.buildinfo"
                { echo "SBOM NOT GENERATED: extracted /app/yabanin has no Go build metadata."
                  echo "Regenerate with: syft $ref -o spdx-json > sbom-${name}.spdx.json"
                } > "$BUNDLE_DIR/images/sbom-${name}.UNAVAILABLE.txt"
                if strict; then
                    echo "FAIL: incomplete bundle (RELEASE_STRICT=1): no SBOM for $ref and syft is not installed" >&2
                    exit 1
                fi
                echo "sbom: sbom-${name}.UNAVAILABLE.txt (honest marker; syft required)" >&2
            fi
        else
            { echo "SBOM NOT GENERATED: syft is not installed and the image has no"
              echo "extractable Go binary (/app/yabanin). Regenerate with:"
              echo "  syft $ref -o spdx-json > sbom-${name}.spdx.json"
            } > "$BUNDLE_DIR/images/sbom-${name}.UNAVAILABLE.txt"
            if strict; then
                echo "FAIL: incomplete bundle (RELEASE_STRICT=1): no SBOM for $ref and syft is not installed" >&2
                exit 1
            fi
            echo "sbom: sbom-${name}.UNAVAILABLE.txt (honest marker; syft required)" >&2
        fi
    fi
    if [ -n "$cid" ]; then docker rm "$cid" > /dev/null 2>&1 || true; fi
    [ -n "$tmpbin" ] && rm -f "$tmpbin"
    # --- registry signature (cosign key-pair, D-A); failures are not swallowed
    if [ -n "${COSIGN_KEY:-}" ] && command -v cosign > /dev/null 2>&1; then
        if [ -n "$digest" ]; then
            if cosign sign --key "$COSIGN_KEY" --yes "$digest" 2>&1; then
                echo "cosign: registry signature stored for $digest"
            elif strict; then
                echo "FAIL: cosign sign failed for $digest (RELEASE_STRICT=1; previously swallowed by '|| true')" >&2
                exit 1
            else
                echo "WARN: cosign sign failed for $digest (bundle continues; blob signature below still binds the digest list)" >&2
            fi
        fi
    fi
done < "$IMAGES_FILE"

# --- NOTICE materials into the bundle (checked by airgap-verify.sh) ----------
if [ -f "$RELEASE_DIR/THIRD-PARTY-NOTICES.md" ]; then
    cp "$RELEASE_DIR/THIRD-PARTY-NOTICES.md" "$BUNDLE_DIR/"
    [ -f "$RELEASE_DIR/NOTICE" ] && cp "$RELEASE_DIR/NOTICE" "$BUNDLE_DIR/"
    echo "NOTICE materials copied from $RELEASE_DIR"
elif strict; then
    echo "FAIL: incomplete bundle (RELEASE_STRICT=1): $RELEASE_DIR/THIRD-PARTY-NOTICES.md missing" >&2
    exit 1
else
    echo "notice: SKIPPED — no THIRD-PARTY-NOTICES.md in $RELEASE_DIR (run 'make release-artifacts')" >&2
fi

# --- install materials into the bundle (N11-P03-T02) --------------------------
# An offline install needs more than images: the compose install profile (with
# its required-secrets .env contract and the app-role bootstrap), the
# bootstrap SQL, and the Helm charts — the charts carry the values.schema.json
# config schemas, so baking the charts IS the schema delivery. Sources are
# env-overridable for custom packaging layouts; a missing source is a HARD
# failure in every mode: a bundle without install materials is incomplete and
# the producer refuses rather than letting the consumer detect it. Files are
# COPIED verbatim — this script never edits deploy/ content (charts are
# n11p02t04 territory; the compose and SQL are owned by their packet cards).
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE_SRC="${AIRGAP_COMPOSE_SRC:-$REPO_ROOT/deploy/onprem/airgap-compose.yml}"
BOOTSTRAP_SQL_SRC="${AIRGAP_BOOTSTRAP_SQL_SRC:-$REPO_ROOT/deploy/quickstart/bootstrap-app-role.sql}"
CHARTS_SRC="${AIRGAP_CHARTS_SRC:-$REPO_ROOT/deploy/helm}"
mkdir -p "$BUNDLE_DIR/install/compose" "$BUNDLE_DIR/install/charts"
[ -f "$COMPOSE_SRC" ] || { echo "FAIL: install material missing: $COMPOSE_SRC (override with AIRGAP_COMPOSE_SRC)" >&2; exit 1; }
[ -f "$BOOTSTRAP_SQL_SRC" ] || { echo "FAIL: install material missing: $BOOTSTRAP_SQL_SRC (override with AIRGAP_BOOTSTRAP_SQL_SRC)" >&2; exit 1; }
cp "$COMPOSE_SRC" "$BUNDLE_DIR/install/compose/airgap-compose.yml"
cp "$BOOTSTRAP_SQL_SRC" "$BUNDLE_DIR/install/compose/bootstrap-app-role.sql"
echo "install materials: compose profile + app-role bootstrap SQL copied (pair kept: compose mounts ./bootstrap-app-role.sql)"
chart_count=0
for chart_dir in "$CHARTS_SRC"/*/; do
    [ -f "${chart_dir}Chart.yaml" ] || continue
    chart_name="$(basename "${chart_dir}")"
    cp -R "$chart_dir" "$BUNDLE_DIR/install/charts/$chart_name"
    chart_count=$((chart_count + 1))
done
if [ "$chart_count" -eq 0 ]; then
    echo "FAIL: no Helm charts found under $CHARTS_SRC (override with AIRGAP_CHARTS_SRC)" >&2
    exit 1
fi
echo "charts baked: $chart_count ($(cd "$BUNDLE_DIR/install/charts" && ls | tr '\n' ' ')— values.schema.json schemas included)"

# --- model packs into the bundle (N11-P03-T02; mlpack layer N11-P04) ----------
# The core never downloads models (pkg/mlpack: "deliberately no download
# path"). Packs enter the bundle ONLY when the builder declares them via
# MLPACK_PACKS_DIR=<dir whose immediate subdirectories are pack dirs built by
# mlpack_manifest.sh (each contains pack.json). Every pack is verified
# fail-closed by scripts/airgap/mlpack_manifest.sh verify BEFORE it is
# copied; a declared-but-broken pack aborts the bundle in every mode (a
# declaration that silently bakes nothing would be a lie in the release
# notes). With nothing declared the bundle records an honest marker — it
# never fakes models. TEI/vLLM serving images remain BUYER_SUPPLIED
# (scripts/airgap/check_images_coverage.sh); scripts/airgap/images.txt is
# frozen per the image-matrix policy and is never
# extended by this script.
MLPACK_MANIFEST="${MLPACK_MANIFEST:-$(dirname "$0")/mlpack_manifest.sh}"
PACKS_ROOT="${MLPACK_PACKS_DIR:-}"
mkdir -p "$BUNDLE_DIR/models"
if [ -z "$PACKS_ROOT" ]; then
    {
        echo "MODELS NOT BAKED: MLPACK_PACKS_DIR was not declared at build time."
        echo "This bundle carries no model packs. Operators attach packs separately"
        echo "(YABANIN_ML_PACK_DIR — verified on disk before anything is served)"
        echo "or rebuild the bundle with MLPACK_PACKS_DIR set. The core never"
        echo "downloads models; TEI/vLLM serving images stay BUYER_SUPPLIED"
        echo "(docs/onprem/install-guide.md)."
    } > "$BUNDLE_DIR/models/MODELS-UNAVAILABLE.txt"
    echo "models: SKIPPED — MLPACK_PACKS_DIR not declared (honest marker written, never faked)"
else
    [ -d "$PACKS_ROOT" ] || { echo "FAIL: MLPACK_PACKS_DIR is not a directory: $PACKS_ROOT" >&2; exit 1; }
    [ -f "$MLPACK_MANIFEST" ] || { echo "FAIL: mlpack verifier missing: $MLPACK_MANIFEST" >&2; exit 1; }
    pack_count=0
    for pack in "$PACKS_ROOT"/*/; do
        [ -d "$pack" ] || continue
        [ -f "${pack}pack.json" ] || { echo "FAIL: declared pack has no pack.json — build it with mlpack_manifest.sh build first: $pack" >&2; exit 1; }
        "$MLPACK_MANIFEST" verify "$pack" || { echo "FAIL: pack verification failed — pack NOT baked: $pack" >&2; exit 1; }
        pack_name="$(basename "${pack}")"
        cp -R "${pack}" "$BUNDLE_DIR/models/$pack_name"
        pack_count=$((pack_count + 1))
        echo "pack baked: $pack_name (verified by mlpack_manifest.sh verify before copy)"
    done
    if [ "$pack_count" -eq 0 ]; then
        echo "FAIL: MLPACK_PACKS_DIR declared but contains no pack subdirectories: $PACKS_ROOT" >&2
        exit 1
    fi
    {
        echo "models baked: $pack_count pack(s)"
        echo "verification: scripts/airgap/mlpack_manifest.sh verify per pack, fail-closed, BEFORE copy"
        echo "declaration: MLPACK_PACKS_DIR=$PACKS_ROOT"
        echo "no wall-clock metadata; per-file digests are covered by manifest.sha256 and"
        echo "per-artifact digests by each pack's own pack.json (canonical mlpack schema)."
        echo "attach at runtime via YABANIN_ML_PACK_DIR; the core never downloads."
    } > "$BUNDLE_DIR/models/MODELS-INFO.txt"
    echo "models baked: $pack_count pack(s) from $PACKS_ROOT (all verified before copy)"
fi

# --- offline-verifiable signature over the image digests (D-B subject) -------
if [ -n "${COSIGN_KEY:-}" ] && command -v cosign > /dev/null 2>&1; then
    # v2 cosign: detached signature + --tlog-upload=false (no Rekor entry).
    # v3 cosign: sigstore bundle (tlog upload may happen on the connected
    # build machine; air-gap verification ignores tlog via offline flags).
    if cosign sign-blob --key "$COSIGN_KEY" --tlog-upload=false \
            --output-signature "$DIGESTS_FILE.sig" "$DIGESTS_FILE" 2>/dev/null; then
        echo "signature written: image-digests.txt.sig (detached, v2 flag set; subject: image digests, D-B)"
    elif cosign sign-blob --key "$COSIGN_KEY" \
            --bundle "$DIGESTS_FILE.sig.bundle" "$DIGESTS_FILE"; then
        echo "signature written: image-digests.txt.sig.bundle (sigstore bundle, v3; subject: image digests, D-B)"
    else
        echo "FAIL: cosign sign-blob over image digests failed" >&2
        exit 1
    fi
elif strict && ! allow_unsigned; then
    echo "FAIL: incomplete bundle (RELEASE_STRICT=1): no usable cosign key-pair — image digests unsigned" >&2
    exit 1
else
    reason="COSIGN_KEY was not set at bundle build time"
    [ -n "${COSIGN_KEY:-}" ] && reason="cosign is not installed (COSIGN_KEY is set)"
    echo "cosign: SKIPPED — no COSIGN_KEY/cosign (unsigned bundle; record in release notes)" >&2
    unsigned_disclosure "$reason"
fi

# --- bundle identity / format marker (A08) -----------------------------------
# Written BEFORE the manifest so it is covered by the signed inventory. The
# installer (load_bundle.sh) treats the presence of bundle-info.txt with
# bundle_format=2 as the new-format contract: install requires a signature
# over manifest.sha256 verified against an external --pubkey; RELEASE_ALLOW_
# UNSIGNED never makes a format-2 bundle installable. No wall-clock time is
# embedded (BUILD29-CONTRACT C-3): source identity comes from git only.
n_images="$(grep -c . "$IMAGES_FILE" 2>/dev/null || true)"
commit_id="$(git describe --tags --always --dirty 2>/dev/null || echo unknown)"
{
    echo "bundle_format=2"
    echo "bundle_tag=$TAG"
    echo "source=$commit_id"
    echo "images_entries=$n_images"
} > "$BUNDLE_DIR/bundle-info.txt"
echo "bundle marker: bundle-info.txt (format 2, tag=$TAG, source=$commit_id)"

echo "=== Generating manifest ==="
# shellcheck disable=SC2086  # $HASH may be "shasum -a 256"
# Stale signature sidecars from a previous run are removed first and excluded
# from the listing: a leftover sidecar would be hashed into the new manifest
# and then overwritten, guaranteeing a verify failure. manifest.sha256 and
# its sidecars never cover themselves; the packed tarball is excluded.
rm -f "$BUNDLE_DIR/manifest.sha256.sig" "$BUNDLE_DIR/manifest.sha256.sig.bundle"
( cd "$BUNDLE_DIR" && find . -type f ! -name manifest.sha256 \
    ! -name 'manifest.sha256.tmp' ! -name 'manifest.sha256.sig' \
    ! -name 'manifest.sha256.sig.bundle' ! -name 'yabanin-airgap-*.tar.gz' -print0 \
    | LC_ALL=C sort -z \
    | LC_ALL=C xargs -0 $HASH > manifest.sha256.tmp && mv manifest.sha256.tmp manifest.sha256 )

# --- signed inventory manifest (A08/Q5, C-12) --------------------------------
# The manifest is the bundle's root of trust on the install path: it binds
# every payload byte (tars, SBOMs, digest list, NOTICE, format marker), and
# its detached signature binds the manifest itself. Signed whenever a usable
# cosign key-pair exists; failure is fatal, never swallowed — an installer
# would refuse the bundle, so shipping it silently unsigned helps nobody.
if [ -n "${COSIGN_KEY:-}" ] && command -v cosign > /dev/null 2>&1; then
    if cosign sign-blob --key "$COSIGN_KEY" --tlog-upload=false \
            --output-signature "$BUNDLE_DIR/manifest.sha256.sig" "$BUNDLE_DIR/manifest.sha256" 2>/dev/null; then
        echo "signature written: manifest.sha256.sig (detached, v2 flag set; subject: full inventory manifest, A08)"
    elif cosign sign-blob --key "$COSIGN_KEY" \
            --bundle "$BUNDLE_DIR/manifest.sha256.sig.bundle" "$BUNDLE_DIR/manifest.sha256"; then
        echo "signature written: manifest.sha256.sig.bundle (sigstore bundle, v3; subject: full inventory manifest, A08)"
    else
        echo "FAIL: cosign sign-blob over the inventory manifest failed" >&2
        exit 1
    fi
fi

echo "=== Packing bundle ==="
# Pack to a temp SIBLING outside the directory being read, then move it into
# place: writing the archive into the packed tree makes GNU tar see the
# growing tar.gz as a member and abort with "file changed as we read it"
# (nonzero exit under set -e; Q6), and a mktemp -d under /tmp would leave
# residue on failure under set -e and make the final mv potentially
# cross-device/non-atomic. The temp sibling lives in the bundle dir's PARENT:
# same filesystem, atomic mv; the EXIT trap removes a partial temp.
# The --exclude mirrors the manifest rule above: bundle tarballs are build
# OUTPUT, never bundle CONTENT — a stale tarball from any previous tag (or a
# rerun over a dirty bundle dir) is never packed into a new bundle, so the
# archive content always equals the manifest content. Nothing is excluded
# beyond that declared rule.
TARBALL="$BUNDLE_DIR/yabanin-airgap-$TAG.tar.gz"
pack_tmp="$(dirname "$BUNDLE_DIR")/.tmp-yabanin-airgap-$TAG.tar.gz"
rm -f "$pack_tmp"
trap 'rm -rf "$pack_tmp"' EXIT
tar -czf "$pack_tmp" -C "$BUNDLE_DIR" --exclude 'yabanin-airgap-*.tar.gz' .
mv "$pack_tmp" "$TARBALL"
trap - EXIT
echo "Bundle ready: $TARBALL"
