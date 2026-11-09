#!/usr/bin/env bash
# S08: release artifacts (supply-chain safety).
# Builds the release binaries reproducibly (-trimpath, CGO off, GOOS pinned,
# no VCS stamping, env-normalized) into $RELEASE_DIR, emits SHA256SUMS, an
# SBOM (syft when installed, otherwise a `go version -m` build manifest per
# binary), NOTICE materials (THIRD-PARTY-NOTICES.md draft from the license
# audit), and — when COSIGN_KEY is set — a cosign key-pair signature (D-A)
# over the checksum file plus the matching public key. Smoke: each artifact is
# copied into a fresh temp dir, its checksum re-verified, its embedded build
# info read, and the gateway binary executed with a deliberately invalid
# config (fast local failure, no network) to prove it runs as a static binary.
#
# The set has two kinds of subjects:
#   - "yabanin": the unified entry point, built from ./cmd/yabanin with the
#     SAME flags as the Dockerfile / Dockerfile.hardened builder stages, so
#     sha256($RELEASE_DIR/yabanin) equals the binary inside the OCI image for
#     the same source commit (one public source, one recipe).
#   - "yabanin-gateway/-loggerd/-admin/-mcp": standalone wrapper binaries from
#     services/*/cmd, additional subjects with the same flags.
#
# Generated file bytes are a function of the source commit and pinned inputs
# only: NOTICE generation stamps SOURCE_DATE_EPOCH (defaulting here to the
# last commit time) and manifest ordering is LC_ALL=C. VERSION/COMMIT are
# release-notes metadata (unsigned disclosure text); they are NOT embedded in
# the binaries.
#
# Pinned-inputs record (contract C-5): every run writes $RELEASE_DIR/recipe.json
# — go toolchain, module hashes, the canonical build recipe, target list and
# the digest/apk pins extracted from both image recipes — so the future A/B
# verifier can compare independent rebuilds; any recipe.json difference is a
# mismatch and blocks the reproducible claim. `--print-recipe` writes ONLY that
# record (no builds, no signing) for inspection and testing.
#
# Without syft, COSIGN_KEY or the license audit the artifact set would be
# incomplete. The 2026-10-31 release ships unsigned ONLY through the explicit
# RELEASE_ALLOW_UNSIGNED=true override, which is recorded in the output and in
# UNSIGNED-RELEASE-DISCLOSURE.md for the release notes; post-release, strict
# without the override is mandatory.
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

RELEASE_DIR="${RELEASE_DIR:-dist/release}"
LICENSE_AUDIT="${LICENSE_AUDIT:-artifacts/licenses/audit.json}"
# Path-invariant NOTICE bytes (C-3): the generator embeds the audit path as
# provenance, so an absolute LICENSE_AUDIT under the build root is normalized
# to the equivalent root-relative path; audits outside the tree keep their
# absolute path as honest external-input provenance.
case "$LICENSE_AUDIT" in
    "$ROOT"/*) LICENSE_AUDIT="${LICENSE_AUDIT#"$ROOT"/}" ;;
esac
# The unified subject first; the standalone wrappers follow with the same flags.
UNIFIED="yabanin=cmd/yabanin"
SERVICES="yabanin-gateway=services/gateway/cmd yabanin-loggerd=services/loggerd/cmd yabanin-admin=services/admin/cmd yabanin-mcp=services/mcp/cmd"

strict() { [ "${RELEASE_STRICT:-0}" = "1" ] || [ "${RELEASE_STRICT:-}" = "true" ]; }
allow_unsigned() { [ "${RELEASE_ALLOW_UNSIGNED:-}" = "true" ] || [ "${RELEASE_ALLOW_UNSIGNED:-}" = "1" ]; }

# --- C-5: pinned-inputs record helpers ---------------------------------------
# The record must be a deterministic function of the inputs: fixed key order,
# no wall-clock time, locale-normalized sort. The future A/B verifier compares
# recipe.json between independent rebuilds byte-for-byte; mismatch blocks.
BUILD_RECIPE='CGO_ENABLED=0 GOOS=linux GOFLAGS= GOWORK=off go build -trimpath -buildvcs=false -ldflags "-s -w"'

json_str() { # json_str <value>: print the value as a JSON string literal
    printf '"%s"' "${1//\"/\\\"}"
}

json_array() { # stdin: one value per line -> JSON array of strings
    local out="[" first=1 line
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        if [ "$first" = "1" ]; then first=0; else out="$out,"; fi
        out="$out$(json_str "$line")"
    done
    printf '%s]' "$out"
}

dockerfile_pins() { # <dockerfile>: "base <ref>" / "apk <name=ver>" lines, sorted
    awk '
        { lines[NR] = $0 }
        END {
            for (i = 1; i <= NR; i++) {
                line = lines[i]
                while (line ~ /\\$/ && i < NR) { sub(/\\$/, "", line); i++; line = line " " lines[i] }
                if (line ~ /^FROM /) {
                    n = split(line, tok, /[ \t]+/)
                    for (t = 2; t <= n; t++)
                        if (tok[t] ~ /@sha256:[0-9a-f]{64}$/) print "base\t" tok[t]
                }
                if (line ~ /apk add --no-cache/) {
                    n = split(line, tok, /[ \t]+/)
                    for (t = 1; t <= n; t++)
                        if (tok[t] ~ /^[A-Za-z0-9][A-Za-z0-9._+-]*=[A-Za-z0-9][A-Za-z0-9._+-]*$/) print "apk\t" tok[t]
                }
            }
        }' "$1" | sort
}

write_recipe_json() { # record this build's pinned inputs -> $RELEASE_DIR/recipe.json
    local commit_full go_ver go_arch mod_sha sum_sha df bases apks first=1
    commit_full=$(git rev-parse HEAD 2>/dev/null || echo unknown)
    go_ver=$(go env GOVERSION 2>/dev/null || echo unknown)
    go_arch=$(go env GOARCH 2>/dev/null || echo unknown)
    mod_sha=$(shasum -a 256 go.mod | awk '{print $1}')
    sum_sha=$(shasum -a 256 go.sum | awk '{print $1}')
    local targets="[" entry
    for entry in $UNIFIED $SERVICES; do
        if [ "$first" = "1" ]; then first=0; else targets="$targets,"; fi
        targets="$targets$(json_str "$entry")"
    done
    targets="$targets]"
    {
        printf '{\n'
        printf '  "schema": %s,\n' "$(json_str "yabanin.release-recipe/1")"
        printf '  "purpose": %s,\n' "$(json_str "pinned-inputs record (contract C-5): an independent A/B verifier compares this file between rebuilds; any difference is a mismatch and blocks the reproducible claim")"
        printf '  "git_commit": %s,\n' "$(json_str "$commit_full")"
        printf '  "git_describe": %s,\n' "$(json_str "$VERSION")"
        printf '  "source_date_epoch": %s,\n' "$SOURCE_DATE_EPOCH"
        printf '  "go_version": %s,\n' "$(json_str "$go_ver")"
        printf '  "go_os": "linux",\n'
        printf '  "go_arch": %s,\n' "$(json_str "$go_arch")"
        printf '  "go_mod_sha256": %s,\n' "$(json_str "$mod_sha")"
        printf '  "go_sum_sha256": %s,\n' "$(json_str "$sum_sha")"
        printf '  "build_recipe": %s,\n' "$(json_str "$BUILD_RECIPE")"
        printf '  "targets": %s,\n' "$targets"
        printf '  "image_inputs": {\n'
        first=1
        for df in Dockerfile Dockerfile.hardened; do
            if [ "$first" = "1" ]; then first=0; else printf ',\n'; fi
            bases=$(dockerfile_pins "$df" | awk -F '\t' '$1 == "base" { print $2 }')
            apks=$(dockerfile_pins "$df" | awk -F '\t' '$1 == "apk" { print $2 }')
            printf '    %s: {"bases": %s, "apk": %s}' "$(json_str "$df")" \
                "$(printf '%s\n' "$bases" | json_array)" "$(printf '%s\n' "$apks" | json_array)"
        done
        printf '\n  }\n}\n'
    } > "$RELEASE_DIR/recipe.json"
    echo "recipe recorded: $RELEASE_DIR/recipe.json (go=$go_ver arch=$go_arch)"
}

# The script takes no positional arguments except the inspection mode below;
# the Makefile knob is the RELEASE_DIR environment variable only.
PRINT_RECIPE_ONLY=0
for arg in "$@"; do
    case "$arg" in
    --print-recipe) PRINT_RECIPE_ONLY=1 ;;
    *) echo "usage error: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

unsigned_disclosure() { # unsigned_disclosure <reason>
    cat > "$RELEASE_DIR/UNSIGNED-RELEASE-DISCLOSURE.md" <<EOF
# UNSIGNED RELEASE — release-notes disclosure (required)

This release artifact set is UNSIGNED. Reason: $1.

- Decision D-D (owner, DECISIONS.md 2026-10-16): strict release mode is
  implemented; the 2026-10-31 release may ship unsigned only through the
  explicit RELEASE_ALLOW_UNSIGNED=true override with this disclosure in the
  release notes. Post-release, strict signing is mandatory.
- version: ${VERSION:-unknown}  commit: ${COMMIT:-unknown}
- Include this file's text in the release notes. Consumers verify integrity
  via SHA256SUMS only; there is no signature to check against yabanin-release.pub.
EOF
    # The OVERRIDE line may only be claimed when the override is
    # actually set (strict + RELEASE_ALLOW_UNSIGNED=true). A plain non-strict
    # unsigned build is a legacy skip — honest line, no false override claim.
    if allow_unsigned; then
        echo "OVERRIDE: RELEASE_ALLOW_UNSIGNED=true — release stays UNSIGNED; UNSIGNED-RELEASE-DISCLOSURE.md written; disclose in release notes" >&2
    else
        echo "unsigned: COSIGN_KEY not set and RELEASE_STRICT is not active — no override used; UNSIGNED-RELEASE-DISCLOSURE.md written; disclose in release notes" >&2
    fi
}

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

# Deterministic generation timestamps: NOTICE and other generated files stamp
# SOURCE_DATE_EPOCH instead of wall-clock time. Default to the last commit
# time so two builds of the same commit emit identical bytes without operator
# setup; an explicit caller-provided value wins. A non-integer explicit value
# is a build-input error, not something to silently fall back from.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git log -1 --pretty=format:%ct 2>/dev/null || echo 0)
fi
case "$SOURCE_DATE_EPOCH" in
    '' | *[!0-9]*)
        echo "FAIL: SOURCE_DATE_EPOCH must be an integer unix timestamp (got: $SOURCE_DATE_EPOCH)" >&2
        exit 1
        ;;
esac
export SOURCE_DATE_EPOCH

# Inspection/testing mode: write ONLY the C-5 pinned-inputs record and exit.
# No strict preflight, no builds, no signing — recipe.json describes inputs,
# not artifacts.
if [ "$PRINT_RECIPE_ONLY" = "1" ]; then
    mkdir -p "$RELEASE_DIR"
    write_recipe_json
    exit 0
fi

# --- Strict preflight (fail before building, not after) ----------------------
if strict; then
    missing=""
    command -v syft > /dev/null 2>&1 || missing="syft (SPDX SBOM)"
    if [ -n "${COSIGN_KEY:-}" ]; then
        command -v cosign > /dev/null 2>&1 || missing="${missing:+$missing, }cosign (COSIGN_KEY is set)"
    elif ! allow_unsigned; then
        missing="${missing:+$missing, }COSIGN_KEY (signing key; RELEASE_ALLOW_UNSIGNED=true is the only unsigned path, D-D)"
    fi
    [ -f "$LICENSE_AUDIT" ] || missing="${missing:+$missing, }$LICENSE_AUDIT (run 'make licenses-report')"
    if [ -n "$missing" ]; then
        echo "FAIL: incomplete release artifacts (RELEASE_STRICT=1): missing $missing" >&2
        exit 1
    fi
    [ -z "${COSIGN_KEY:-}" ] && echo "strict mode: unsigned build allowed by explicit RELEASE_ALLOW_UNSIGNED=true (D-D override)"
fi

mkdir -p "$RELEASE_DIR"
rm -f "$RELEASE_DIR"/yabanin "$RELEASE_DIR"/yabanin-* "$RELEASE_DIR"/SHA256SUMS "$RELEASE_DIR"/SHA256SUMS.sig \
    "$RELEASE_DIR"/SHA256SUMS.sig.bundle "$RELEASE_DIR"/sbom-* "$RELEASE_DIR"/*.buildinfo "$RELEASE_DIR"/sbom.source \
    "$RELEASE_DIR"/THIRD-PARTY-NOTICES.md "$RELEASE_DIR"/NOTICE "$RELEASE_DIR"/NOTICE-litellm.txt \
    "$RELEASE_DIR"/yabanin-release.pub "$RELEASE_DIR"/UNSIGNED-RELEASE-DISCLOSURE.md \
    "$RELEASE_DIR"/recipe.json
# C-5: record the pinned inputs of THIS build before building, so even a
# failed run leaves the exact input record and a completed release dir always
# carries the A/B-verifier record.
write_recipe_json || exit 1
for entry in $UNIFIED $SERVICES; do
    name=${entry%%=*}; dir=${entry#*=}
    echo "building $RELEASE_DIR/$name ($dir)"
    # Same flag set as the Dockerfile / Dockerfile.hardened builder stages:
    # one public source with one recipe must give the byte-identical unified
    # subject in the release set and inside the OCI image. GOFLAGS/GOWORK are
    # normalized so operator environment cannot silently change the bytes.
    CGO_ENABLED=0 GOOS=linux GOFLAGS= GOWORK=off go build \
        -trimpath -buildvcs=false -ldflags "-s -w" \
        -o "$RELEASE_DIR/$name" "./$dir" || exit 1
done
echo "computing SHA256SUMS"
(cd "$RELEASE_DIR" && shasum -a 256 yabanin yabanin-* > SHA256SUMS && cat SHA256SUMS)
echo "generating SBOM"
if command -v syft > /dev/null 2>&1; then
    syft dir:"$RELEASE_DIR" -o spdx-json > "$RELEASE_DIR/sbom.spdx.json" && echo "syft SPDX SBOM written"
    echo "syft spdx-json" > "$RELEASE_DIR/sbom.source"
else
    if strict; then
        echo "FAIL: incomplete release artifacts (RELEASE_STRICT=1): syft is not installed; the go version -m fallback is not a full SPDX SBOM" >&2
        exit 1
    fi
    echo "syft not installed — writing go version -m build manifests instead"
    for bin in "$RELEASE_DIR/yabanin" "$RELEASE_DIR"/yabanin-*; do
        go version -m "$bin" > "$bin.buildinfo" || exit 1
    done
    echo "go-version-m buildinfo fallback (syft not installed; NOT a full SPDX SBOM)" > "$RELEASE_DIR/sbom.source"
fi
echo "assembling NOTICE materials"
if bash scripts/release/notice_bundle.sh --audit "$LICENSE_AUDIT" --out "$RELEASE_DIR/THIRD-PARTY-NOTICES.md"; then
    cp NOTICE "$RELEASE_DIR/NOTICE" 2>/dev/null || echo "notice: root NOTICE missing (non-fatal)"
    cp pkg/pricing/NOTICE-litellm.txt "$RELEASE_DIR/NOTICE-litellm.txt" 2>/dev/null || echo "notice: pkg/pricing/NOTICE-litellm.txt missing (non-fatal)"
else
    if strict; then
        echo "FAIL: incomplete release artifacts (RELEASE_STRICT=1): NOTICE draft generation failed" >&2
        exit 1
    fi
    echo "notice: SKIPPED — no THIRD-PARTY-NOTICES.md in this artifact set (record in release notes)"
fi
if [ -n "${COSIGN_KEY:-}" ]; then
    echo "signing SHA256SUMS with cosign key-pair (D-A; key from COSIGN_KEY)"
    # v2 cosign (pinned in CI): raw detached signature, no tlog. v3 cosign
    # removed --tlog-upload/--output-signature and writes a sigstore bundle.
    if cosign sign-blob --key "$COSIGN_KEY" --tlog-upload=false \
            --output-signature "$RELEASE_DIR/SHA256SUMS.sig" "$RELEASE_DIR/SHA256SUMS" 2>/dev/null; then
        echo "signature written: SHA256SUMS.sig (detached, v2 flag set)"
    elif cosign sign-blob --key "$COSIGN_KEY" \
            --bundle "$RELEASE_DIR/SHA256SUMS.sig.bundle" "$RELEASE_DIR/SHA256SUMS"; then
        echo "signature written: SHA256SUMS.sig.bundle (sigstore bundle, v3)"
    else
        echo "FAIL: cosign sign-blob failed for SHA256SUMS" >&2
        exit 1
    fi
    cosign public-key --key "$COSIGN_KEY" > "$RELEASE_DIR/yabanin-release.pub" \
        || { echo "FAIL: signed, but exporting the matching public key failed — bundle would be unverifiable" >&2; exit 1; }
    echo "public key exported to $RELEASE_DIR/yabanin-release.pub (public material only)"
else
    echo "cosign: SKIPPED — COSIGN_KEY is not set (unsigned release; record this in the release notes)"
    unsigned_disclosure "COSIGN_KEY was not set at build time$(strict && echo ' (RELEASE_STRICT=1 with RELEASE_ALLOW_UNSIGNED=true override)' || true)"
fi
echo "smoke: clean-temp-dir install + checksum + build info (no network)"
smoke_dir=$(mktemp -d /tmp/yabanin-release-smoke.XXXXXX)
trap 'rm -rf "$smoke_dir"' EXIT INT TERM
for bin in "$RELEASE_DIR/yabanin" "$RELEASE_DIR/yabanin-gateway" "$RELEASE_DIR/yabanin-loggerd" "$RELEASE_DIR/yabanin-admin" "$RELEASE_DIR/yabanin-mcp"; do
    name=$(basename "$bin")
    cp "$bin" "$smoke_dir/$name" || exit 1
    expected=$(awk -v n="$name" '$2 == n { print $1 }' "$RELEASE_DIR/SHA256SUMS")
    [ -n "$expected" ] || { echo "smoke FAIL: no SHA256SUMS entry for $name"; exit 1; }
    echo "$expected  $smoke_dir/$name" | shasum -a 256 -c - > /dev/null || { echo "smoke FAIL: checksum mismatch for $name"; exit 1; }
    go version -m "$smoke_dir/$name" | grep -q "github.com/reireirei/yabanin" || { echo "smoke FAIL: $name has no module build info"; exit 1; }
    echo "smoke OK: $name installed in clean dir, checksum + build info verified"
done
if [ "$(uname -s)" = "Linux" ]; then
    echo "smoke: exec gateway with an invalid config (must fail fast, no network)"
    set +e
    YABANIN_CONFIG=/nonexistent-config.yaml "$smoke_dir/yabanin-gateway" > /dev/null 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then echo "smoke FAIL: gateway exited 0 with an invalid config"; exit 1; fi
    echo "smoke OK: gateway executes and exits fast on bad config (exit $rc)"
else
    echo "smoke: exec check SKIPPED on non-Linux host (release binaries are GOOS=linux); checksum + build info still verified above"
fi
echo "release artifacts ready in $RELEASE_DIR"
