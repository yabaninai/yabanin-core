#!/usr/bin/env bash
# airgap-verify.sh — verify a Yabanin offline bundle on a machine WITHOUT network.
#
# Uses only local files and never fetches anything:
#   1. sha256 verification of release artifacts (SHA256SUMS) and, optionally,
#      a bundle-level manifest (manifest.sha256).
#   2. cosign signature over SHA256SUMS, when the bundle is signed and a
#      public key is provided (offline flags used; transparency log ignored).
#      Signature MISMATCH always FAILs (fail closed).
#   3. SBOM presence: sbom.spdx.json (syft) or *.buildinfo fallback manifests.
#   5. after all inventory, signature and SBOM checks succeed: docker load
#      the checksum-listed image tarball, then run with --network none to
#      prove the image works without connectivity (--pull=never guard).
#   6. compose file: `docker compose config` validation; FAILS if the file
#      contains `build:` or references images that are not present locally.
#   7. bundle image SBOMs (sbom-*.spdx.json per saved tar) and the signature
#      manifest is provided.
#
# above into a FAIL — unsigned or incomplete artifact sets do not verify.
# The ONLY unsigned path is RELEASE_ALLOW_UNSIGNED=true, which is recorded
# verbatim in the output (and must be disclosed in the release notes).
#
# Usage:
#   airgap-verify.sh [--artifacts DIR] [--manifest FILE] [--pubkey FILE]
#                    [--image-tar FILE --image TAG] [--compose FILE] [--strict]
#
# Defaults: --artifacts dist/release; all optional stages are skipped when the
# corresponding input is not provided. Exit codes: 0 all executed stages PASS,
# 1 at least one FAIL (or a strict-mode incompleteness), 2 usage error.

set -u -o pipefail

ARTIFACTS="dist/release"
MANIFEST=""
PUBKEY=""
IMAGE_TAR=""
IMAGE=""
COMPOSE=""
STRICT=0
if [ "${RELEASE_STRICT:-0}" = "1" ] || [ "${RELEASE_STRICT:-}" = "true" ]; then
	STRICT=1
fi

usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
	case "$1" in
	--artifacts) ARTIFACTS="$2"; shift 2 ;;
	--manifest) MANIFEST="$2"; shift 2 ;;
	--pubkey) PUBKEY="$2"; shift 2 ;;
	--image-tar) IMAGE_TAR="$2"; shift 2 ;;
	--image) IMAGE="$2"; shift 2 ;;
	--compose) COMPOSE="$2"; shift 2 ;;
	--strict) STRICT=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "usage error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
	esac
done

if [ -n "$IMAGE_TAR" ] && [ -z "$IMAGE" ]; then
	echo "usage error: --image-tar requires --image TAG" >&2
	exit 2
fi

allow_unsigned() { [ "${RELEASE_ALLOW_UNSIGNED:-}" = "true" ] || [ "${RELEASE_ALLOW_UNSIGNED:-}" = "1" ]; }

RESULTS=0
report() { # report <PASS|SKIP|FAIL> <stage> <detail>
	printf '%-4s %-14s %s\n' "$1" "$2" "$3"
	if [ "$1" = "FAIL" ]; then RESULTS=1; fi
}

# Unsigned handling for strict mode (D-D): FAIL unless the explicit owner
# override is set; when it is set, the allowance is recorded verbatim.
strict_unsigned() { # strict_unsigned <stage> <detail>
	if allow_unsigned; then
		report PASS "$1" "$2 — allowed by explicit RELEASE_ALLOW_UNSIGNED=true (owner decision D-D, 2026-10-31 release); MUST be disclosed in the release notes"
		echo "OVERRIDE recorded: RELEASE_ALLOW_UNSIGNED=true — $1 unsigned by owner decision; this line belongs in the release notes" >&2
	else
		report FAIL "$1" "$2 — strict mode requires a signed bundle (set a --pubkey and ship signatures, or the owner-authorized RELEASE_ALLOW_UNSIGNED=true)"
	fi
}

HASH=""
if command -v sha256sum >/dev/null 2>&1; then
	HASH="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
	HASH="shasum -a 256"
else
	report FAIL tooling "no sha256sum or shasum on PATH"
fi

check_manifest() { # check_manifest <stage> <manifest-file>
	stage="$1"
	file="$2"
	if [ -z "$HASH" ]; then report FAIL "$stage" "no hash tool available"; return; fi
	if [ ! -f "$file" ]; then
		if [ "$STRICT" -eq 1 ]; then
			report FAIL "$stage" "manifest not found: $file (strict mode)"
		else
			report SKIP "$stage" "manifest not found: $file"
		fi
		return
	fi
	dir=$(cd "$(dirname "$file")" && pwd)
	if out=$(cd "$dir" && $HASH -c "$(basename "$file")" 2>&1); then
		total=$(printf '%s\n' "$out" | grep -c ': OK$')
		if [ "$total" -eq 0 ]; then
			# (e.g. a tampered digest field) — "verified zero files" is not a
			# pass, it is an unfalsifiable manifest. Fail closed.
			report FAIL "$stage" "checksum manifest verified ZERO files — empty or malformed $(basename "$file") (possible tampering; raw output follows)"
			printf '%s\n' "$out" | sed 's/^/       /'
		elif printf '%s\n' "$out" | grep -Eq 'improperly formatted|no properly formatted|FAILED'; then
			# malformed — the tampered file is silently skipped, the rest
			# verify. A partially-ignored manifest is not a pass either (the
			# unsigned path relies on checksums alone).
			report FAIL "$stage" "checksum manifest has malformed/failed lines — not every listed file was verified (raw output follows)"
			printf '%s\n' "$out" | grep -E 'improperly formatted|no properly formatted|FAILED' | sed 's/^/       /'
		else
			report PASS "$stage" "$total file(s) verified against $(basename "$file")"
		fi
	else
		report FAIL "$stage" "checksum mismatch:"
		printf '%s\n' "$out" | grep -v ': OK$' | sed 's/^/       /'
	fi
}

# Bind the requested executable archive to the inventory already verified by
# check_manifest. Matching only its bytes against some unrelated inventory is
# insufficient: the selected tarball itself must have a checked entry.
image_in_manifest() { # image_in_manifest <verified-checksum-file>
	local inventory="$1" inventory_dir line candidate
	local checksum_line='^[[:xdigit:]]{64} [ *](.+)$'
	[ -f "$inventory" ] || return 1
	inventory_dir=$(cd "$(dirname "$inventory")" && pwd -P) || return 1
	while IFS= read -r line || [ -n "$line" ]; do
		if [[ "$line" =~ $checksum_line ]]; then
			candidate="${BASH_REMATCH[1]}"
			case "$candidate" in
				/*) ;;
				*) candidate="$inventory_dir/$candidate" ;;
			esac
			[ "$candidate" -ef "$IMAGE_TAR" ] && return 0
		fi
	done < "$inventory"
	return 1
}

# Resolve only an image reported by this successful load, and return its
# immutable ID. A preexisting tag unrelated to the verified archive is not proof
# of a successful load, and executing by ID avoids a later tag reassignment.
loaded_image_id() { # loaded_image_id <docker-load-output>
	local output="$1" requested_id line ref loaded_id
	requested_id=$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null) || return 1
	[[ "$requested_id" =~ ^sha256:[[:xdigit:]]{64}$ ]] || return 1
	while IFS= read -r line; do
		case "$line" in
			'Loaded image: '*) ref="${line#Loaded image: }" ;;
			'Loaded image ID: '*) ref="${line#Loaded image ID: }" ;;
			*) continue ;;
		esac
		[ -n "$ref" ] || continue
		loaded_id=$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null) || continue
		if [ "$loaded_id" = "$requested_id" ]; then
			printf '%s\n' "$loaded_id"
			return 0
		fi
	done <<< "$output"
	return 1
}

# Offline cosign blob verification; a mismatch is ALWAYS a FAIL (fail closed),
# regardless of strict mode. Accepts a raw detached signature (v2 cosign,
# --signature) or a sigstore bundle file (v3 cosign, --bundle).
verify_blob_sig() { # verify_blob_sig <stage> <sig-or-bundle> <target> <subject-desc>
	stage="$1"; sig="$2"; target="$3"; subject="$4"
	if ! command -v cosign >/dev/null 2>&1; then
		report FAIL "$stage" "signature present but cosign is not installed (prerequisite)"
		return
	fi
	if [ -z "$PUBKEY" ]; then
		report FAIL "$stage" "signature present but --pubkey FILE was not given"
		return
	fi
	flags=""
	help=$(cosign verify-blob --help 2>&1 || true)
	if printf '%s\n' "$help" | grep -q -- '--insecure-ignore-tlog'; then
		flags="--insecure-ignore-tlog"
	elif printf '%s\n' "$help" | grep -q -- '--offline'; then
		flags="--offline"
	else
		report SKIP signature-flags "cosign has no offline flag — it may try to reach the transparency log; continuing"
	fi
	if head -c 1 "$sig" 2>/dev/null | grep -q '{'; then
		sigflag=(--bundle "$sig")
	else
		sigflag=(--signature "$sig")
	fi
	# shellcheck disable=SC2086
	if cosign verify-blob --key "$PUBKEY" "${sigflag[@]}" $flags "$target" >/dev/null 2>&1; then
		report PASS "$stage" "cosign verified $subject with $PUBKEY (offline flags: ${flags:-none})"
	else
		report FAIL "$stage" "cosign verify-blob failed for $subject (wrong key, corrupted signature, or cosign needed network — check flag support)"
	fi
}

# --- Stage 1: release artifacts (SHA256SUMS) --------------------------------
check_manifest artifacts "$ARTIFACTS/SHA256SUMS"

# --- Stage 2: bundle-level manifest (manifest.sha256), when provided --------
[ -n "$MANIFEST" ] && check_manifest bundle "$MANIFEST"

# --- Stage 2b: signature over the inventory manifest (A08/Q5) ----------------
# The manifest is the bundle's root of trust: it lists every payload byte and
# (format-2 bundles) carries a detached cosign signature. Verify it whenever a
# signature sidecar is present — mismatch is ALWAYS a FAIL. A missing sidecar
# is an honest SKIP outside strict mode (legacy pre-A08 bundle) and a FAIL in
# strict mode; the install path (load_bundle.sh) additionally enforces the
# format-2 policy itself before anything is loaded.
if [ -n "$MANIFEST" ] && [ -f "$MANIFEST" ]; then
	MSIG="$MANIFEST.sig"
	MSIGB="$MANIFEST.sig.bundle"
	if [ -f "$MSIG" ]; then
		verify_blob_sig manifest-sig "$MSIG" "$MANIFEST" "inventory manifest (manifest.sha256)"
	elif [ -f "$MSIGB" ]; then
		verify_blob_sig manifest-sig "$MSIGB" "$MANIFEST" "inventory manifest (manifest.sha256, sigstore bundle)"
	elif [ "$STRICT" -eq 1 ]; then
		report FAIL manifest-sig "manifest.sha256 has no signature sidecar — strict mode requires the signed inventory manifest (format-2 contract)"
	else
		report SKIP manifest-sig "no manifest.sha256.sig/.sig.bundle next to the manifest — pre-A08 (legacy) bundle; inventory authenticity is not cryptographically provable"
	fi
fi

# --- Stage 3: cosign signature over SHA256SUMS ------------------------------
SIG="$ARTIFACTS/SHA256SUMS.sig"
SIGB="$ARTIFACTS/SHA256SUMS.sig.bundle"
if [ -f "$SIG" ]; then
	verify_blob_sig signature "$SIG" "$ARTIFACTS/SHA256SUMS" "SHA256SUMS"
elif [ -f "$SIGB" ]; then
	verify_blob_sig signature "$SIGB" "$ARTIFACTS/SHA256SUMS" "SHA256SUMS (sigstore bundle)"
elif [ "$STRICT" -eq 1 ]; then
	strict_unsigned signature "no SHA256SUMS.sig in $ARTIFACTS — bundle unsigned (COSIGN_KEY was not set at build time)"
else
	report SKIP signature "no SHA256SUMS.sig in $ARTIFACTS — bundle unsigned (COSIGN_KEY was not set at build time)"
fi

# --- Stage 4: SBOM ----------------------------------------------------------
if [ -f "$ARTIFACTS/sbom.spdx.json" ]; then
	report PASS sbom "SPDX SBOM found: $ARTIFACTS/sbom.spdx.json (syft)"
elif ls "$ARTIFACTS"/*.buildinfo >/dev/null 2>&1; then
	n_buildinfo=$(find "$ARTIFACTS" -maxdepth 1 -name '*.buildinfo' -type f | wc -l | tr -d ' ')
	if [ "$STRICT" -eq 1 ]; then
		report FAIL sbom "only go version -m build manifests found ($n_buildinfo files) — strict mode requires a full SPDX SBOM (install syft at build time)"
	else
		report PASS sbom "go version -m build manifests found ($n_buildinfo files; syft was not installed at build time)"
	fi
elif [ "$STRICT" -eq 1 ]; then
	report FAIL sbom "no sbom.spdx.json or *.buildinfo in $ARTIFACTS (strict mode)"
else
	report SKIP sbom "no sbom.spdx.json or *.buildinfo in $ARTIFACTS"
fi

if [ -f "$ARTIFACTS/THIRD-PARTY-NOTICES.md" ]; then
	report PASS notice "THIRD-PARTY-NOTICES.md found in $ARTIFACTS ($(wc -c < "$ARTIFACTS/THIRD-PARTY-NOTICES.md" | tr -d ' ') bytes; draft — full license texts still required per standards/license-compliance.md)"
elif [ "$STRICT" -eq 1 ]; then
	report FAIL notice "no THIRD-PARTY-NOTICES.md in $ARTIFACTS (strict mode requires the delivery NOTICE draft)"
else
	report SKIP notice "no THIRD-PARTY-NOTICES.md in $ARTIFACTS (draft is generated by 'make release-artifacts' from the license audit)"
fi

if [ -n "$MANIFEST" ] && [ -f "$MANIFEST" ]; then
	bundle_dir=$(cd "$(dirname "$MANIFEST")" && pwd)
	images_dir="$bundle_dir/images"
	if [ -d "$images_dir" ]; then
		total_tars=0; spdx=0; fallback=0; unavailable=0
		for tarball in "$images_dir"/*.tar; do
			[ -f "$tarball" ] || continue
			total_tars=$((total_tars + 1))
			n=$(basename "$tarball" .tar)
			if [ -f "$images_dir/sbom-${n}.spdx.json" ]; then
				spdx=$((spdx + 1))
			elif [ -f "$images_dir/sbom-${n}.buildinfo" ]; then
				fallback=$((fallback + 1))
			elif [ -f "$images_dir/sbom-${n}.UNAVAILABLE.txt" ]; then
				unavailable=$((unavailable + 1))
			fi
		done
		if [ "$total_tars" -eq 0 ]; then
			report SKIP image-sbom "no image tarballs next to $MANIFEST"
		elif [ "$spdx" -eq "$total_tars" ]; then
			report PASS image-sbom "syft SPDX SBOM present for all $total_tars image(s)"
		elif [ "$STRICT" -eq 1 ]; then
			report FAIL image-sbom "incomplete image SBOM set: $spdx/$total_tars SPDX, $fallback buildinfo-fallback, $unavailable unavailable — strict mode requires syft SPDX for every image"
		else
			report SKIP image-sbom "incomplete image SBOM set: $spdx/$total_tars SPDX, $fallback buildinfo-fallback, $unavailable unavailable (honest fallback markers; install syft at build time)"
		fi
		digests="$images_dir/image-digests.txt"
		if [ -f "$digests" ] && grep -q 'DIGEST-UNAVAILABLE' "$digests"; then
			report FAIL image-digests "image-digests.txt contains DIGEST-UNAVAILABLE entries — digests were not provable at build time"
		elif [ -f "$digests.sig" ]; then
			verify_blob_sig image-digests "$digests.sig" "$digests" "image digests (image-digests.txt)"
		elif [ -f "$digests.sig.bundle" ]; then
			verify_blob_sig image-digests "$digests.sig.bundle" "$digests" "image digests (image-digests.txt, sigstore bundle)"
		elif [ -f "$digests" ]; then
			if [ "$STRICT" -eq 1 ]; then
				strict_unsigned image-digests "image-digests.txt present but unsigned (no image-digests.txt.sig)"
			else
				report SKIP image-digests "image-digests.txt present but unsigned (COSIGN_KEY was not set at build time)"
			fi
		else
			report SKIP image-digests "no image-digests.txt in $images_dir (pre-R078 bundle)"
		fi
	fi
fi

# No image is loaded or executed until every verification-only stage above has
# completed. Keep reporting all verification failures rather than exiting early.
# --- Stage 6: image tarball -------------------------------------------------
if [ -n "$IMAGE_TAR" ]; then
	image_inventory="${MANIFEST:-$ARTIFACTS/SHA256SUMS}"
	if [ "$RESULTS" -ne 0 ]; then
		report FAIL image "refusing docker load/run because bundle verification failed"
	elif [ ! -f "$IMAGE_TAR" ]; then
		report FAIL image "image tarball not found: $IMAGE_TAR"
	elif ! image_in_manifest "$image_inventory"; then
		report FAIL image "image tarball is not listed in the verified checksum inventory: $IMAGE_TAR"
	elif ! command -v docker >/dev/null 2>&1; then
		report FAIL image "docker not installed (prerequisite)"
	else
		if load_out=$(docker load -i "$IMAGE_TAR" 2>&1); then
			report PASS image "docker load OK: $(printf '%s' "$load_out" | tr '\n' '; ')"
			if image_id=$(loaded_image_id "$load_out"); then
				if docker run --rm --pull=never --network none "$image_id" --help >/dev/null 2>&1; then
					report PASS image "$IMAGE ($image_id) runs with --network none; --help exits 0 (no 'version' subcommand exists — use --help)"
				else
					report FAIL image "$IMAGE failed to run --help offline"
				fi
			else
				report FAIL image "$IMAGE does not resolve to an image reported by this verified archive load"
			fi
		else
			report FAIL image "docker load failed: $load_out; refusing to run any existing image"
		fi
	fi
fi

# --- Stage 7: compose file (no network, no build) ----------------------------
if [ -n "$COMPOSE" ]; then
	if [ "$RESULTS" -ne 0 ]; then
		report FAIL compose "refusing Docker compose checks because prior verification or image checks failed"
	elif ! command -v docker >/dev/null 2>&1; then
		report FAIL compose "docker not installed (prerequisite)"
	elif [ ! -f "$COMPOSE" ]; then
		report FAIL compose "compose file not found: $COMPOSE"
	elif grep -Eq '^[[:space:]]*build:' "$COMPOSE"; then
		report FAIL compose "compose contains 'build:' — not air-gap safe (ready images only)"
	else
		if docker compose -f "$COMPOSE" config -q >/dev/null 2>&1; then
			report PASS compose "docker compose config validates"
		else
			report FAIL compose "docker compose config failed"
		fi
		if images=$(docker compose -f "$COMPOSE" config --images 2>/dev/null | sort -u); then
			missing=""
			for img in $images; do
				docker image inspect "$img" >/dev/null 2>&1 || missing="$missing $img"
			done
			if [ -z "$missing" ]; then
				report PASS compose "all referenced images already present locally (no pull needed)"
			else
				report FAIL compose "images missing locally (compose would pull):$missing"
			fi
		else
			report SKIP compose-images "docker compose config --images unsupported by this compose version"
		fi
	fi
fi

if [ "$RESULTS" -eq 0 ]; then
	echo "airgap-verify: PASS (skips above are reported honestly, not hidden; strict=$STRICT)"
else
	echo "airgap-verify: FAIL — do not install this bundle (strict=$STRICT)"
fi
exit "$RESULTS"
