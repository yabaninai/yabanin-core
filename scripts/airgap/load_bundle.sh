#!/usr/bin/env bash
# Load an air-gap bundle into a local registry (localhost:5000 by default).
#
# A08 pre-install verification — fail-closed BEFORE any docker load/push:
#   1. The bundle's inventory manifest (manifest.sha256) must be covered by a
#      cosign signature verified against the EXPLICIT --pubkey trust root.
#      The pinned key comes from an independent channel (BUILD29-CONTRACT
#      C-11): a key file found inside the unverified bundle is refused, and
#      the bundle-embedded yabanin-release.pub is never trust.
#   2. The manifest must cover EVERY actual file in the bundle (no unlisted
#      payload) and every listed hash must match. Tamper set: a replaced tar
#      with a recomputed manifest still fails — the old signature no longer
#      matches the recomputed manifest bytes. AUDIT-P1-01 (2026-11-04): the
#      manifest is also the ONLY consume set. Every archive member is
#      validated before extraction (absolute/.. paths refused); after
#      extraction every bundle entry must be a regular file (symlinks and
#      special entries refused — the old find -type f inventory never saw
#      them, while the images/*.tar load glob handed symlinks to docker
#      load, which follows them); the manifest parses strictly (one
#      '<sha256>  ./path' entry per line, escaping paths refused); sidecar
#      exemptions apply at the bundle ROOT only; and image loading consumes
#      exactly the manifest's ./images/*.tar entries — never a directory
#      glob, which is a different file set than the verified inventory.
#   3. Format policy: format-2 bundles (bundle-info.txt marker, produced by
#      build_bundle.sh since A08) are NEVER installable unsigned —
#      RELEASE_ALLOW_UNSIGNED does not accept new bundles. Legacy pre-A08
#      bundles (no marker) install only through the explicit
#      --allow-legacy-unsigned flag with loud warnings (compat per
#      BUILD29-CONTRACT C-10; never the default).
#
# The verifier pass delegates the whole-directory checksum and the image
# digest-list signature to scripts/release/airgap-verify.sh (the consumer
# verifier, C-10) and enforces the manifest-signature + inventory checks on
# the install path itself.
#
# usage: load_bundle.sh [--pubkey FILE] [--allow-legacy-unsigned] [--retain DIR] <bundle.tar.gz> [registry]
#   --retain DIR: after verification passes, copy the VERIFIED install/
#     materials (offline compose files etc.) to DIR before any image is
#     loaded. Without it the extracted bundle tree — install/ included —
#     is removed when the script exits. The target must be OUTSIDE the
#     extracted tree and must not already contain an install/ directory.
# Exit codes: 0 verified + loaded; 1 verification FAIL (nothing installed);
# 2 usage error.
set -euo pipefail

WORKDIR="${WORKDIR:-/tmp/airgap}"
case "$WORKDIR" in "" | "/") WORKDIR="/tmp/airgap" ;; esac

usage() { sed -n '/^# usage:/,/^# Exit codes:/p' "$0" | sed 's/^# \{0,1\}//'; }

fail() { # fail <reason...>: verification failure, exit nonzero, nothing installed
	echo "FAIL: $*" >&2
	exit 1
}

usage_error() {
	echo "usage error: $1" >&2
	usage >&2
	exit 2
}

allow_unsigned() {
	[ "${RELEASE_ALLOW_UNSIGNED:-}" = "true" ] || [ "${RELEASE_ALLOW_UNSIGNED:-}" = "1" ]
}

BUNDLE=""
REGISTRY=""
PUBKEY=""
RETAIN=""
LEGACY_OK=0
POSITIONAL=0
while [ $# -gt 0 ]; do
	case "$1" in
	--pubkey)
		[ $# -ge 2 ] || usage_error "--pubkey requires FILE"
		[ -n "$2" ] || usage_error "--pubkey requires FILE"
		PUBKEY="$2"
		shift 2
		;;
	--retain)
		[ $# -ge 2 ] || usage_error "--retain requires DIR"
		[ -n "$2" ] || usage_error "--retain requires DIR"
		RETAIN="$2"
		shift 2
		;;
	--allow-legacy-unsigned)
		LEGACY_OK=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		usage_error "unknown argument: $1"
		;;
	*)
		POSITIONAL=$((POSITIONAL + 1))
		case "$POSITIONAL" in
		1) BUNDLE="$1" ;;
		2) REGISTRY="$1" ;;
		*) usage_error "too many positional arguments (bundle.tar.gz and registry only)" ;;
		esac
		shift
		;;
	esac
done

[ -n "$BUNDLE" ] || usage_error "bundle.tar.gz is required"
[ -f "$BUNDLE" ] || fail "bundle not found: $BUNDLE"
REGISTRY="${REGISTRY:-localhost:5000}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_VERIFY="$SCRIPT_DIR/../release/airgap-verify.sh"
[ -f "$REAL_VERIFY" ] || fail "real offline verifier not found: $REAL_VERIFY — cannot verify anything"

if command -v sha256sum >/dev/null 2>&1; then
	HASH="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
	HASH="shasum -a 256"
else
	echo "FAIL: no sha256sum or shasum on PATH" >&2
	exit 1
fi

# --- extract into a FRESH, deterministic directory ---------------------------
# The deterministic name (documented scratch semantics of WORKDIR) also lets
# the trust-root check below detect a --pubkey that resolves inside the
# extracted bundle.
EXTRACT="$WORKDIR/verified"
rm -rf "$EXTRACT"
mkdir -p "$EXTRACT"
MEMBERS="$WORKDIR/bundle-members.txt"
trap 'rm -rf "$EXTRACT" "$MEMBERS"' EXIT

echo "=== Validating archive members ==="
# AUDIT-P1-01: validate every member path BEFORE extraction — an archive
# with absolute paths or '..' path components must not be extracted at all
# (belt behind the post-extraction checks; tar itself would contain the
# escape to the extraction target's parent).
tar -tzf "$BUNDLE" >"$MEMBERS" || fail "bundle archive unreadable (tar -tzf failed) — refusing to extract"
while IFS= read -r member; do
	[ -n "$member" ] || continue
	case "$member" in
	/*) fail "archive member with ABSOLUTE path refused: $member" ;;
	esac
	remainder="$member"
	while [ -n "$remainder" ]; do
		component="${remainder%%/*}"
		if [ "$component" = ".." ]; then
			fail "archive member with '..' path component refused: $member — every bundle entry must stay inside the bundle"
		fi
		if [ "$component" = "$remainder" ]; then remainder=""; else remainder="${remainder#*/}"; fi
	done
done <"$MEMBERS"

echo "=== Extracting bundle ==="
# --no-same-owner/--no-same-permissions: the bundle never grants ownership
# or permission bits to local accounts; everything is owned by the invoking
# user with umask-applied permissions.
tar -xzf "$BUNDLE" --no-same-owner --no-same-permissions -C "$EXTRACT"

EXTRACT_CANON="$(cd "$EXTRACT" && pwd -P)"

# AUDIT-P1-01: every bundle entry must be a verifiable REGULAR file. The old
# inventory used find -type f (symlinks and special entries invisible) while
# image loading globbed images/*.tar and FOLLOWED symlinks — a symlink named
# *.tar added to the archive after signing reached docker load with this
# script exiting 0. Non-regular entries are refused outright, before any
# manifest or signature logic.
echo "=== Scanning for non-regular entries ==="
nonregular="$(cd "$EXTRACT" && find . -mindepth 1 ! -type d ! -type f -print | LC_ALL=C sort)"
if [ -n "$nonregular" ]; then
	printf 'non-regular bundle entry (symlink or special file — never verifiable) refused:\n%s\n' "$nonregular" >&2
	fail "bundle contains non-regular entries (symlinks, fifos, sockets, devices) — every bundle entry must be a regular file (AUDIT-P1-01)"
fi

MANIFEST="$EXTRACT/manifest.sha256"
MSIG="$MANIFEST.sig"
MSIGB="$MANIFEST.sig.bundle"
INFO="$EXTRACT/bundle-info.txt"

[ -f "$MANIFEST" ] || fail "bundle manifest not found: $MANIFEST — no bundle byte can be verified"

# --- trust root: explicit, existing, OUTSIDE the unverified bundle (C-11) ----
if [ -n "$PUBKEY" ]; then
	[ -f "$PUBKEY" ] || fail "--pubkey file not found: $PUBKEY"
	# pwd -P canonicalizes through symlinks: the containment decision must
	# compare PHYSICAL paths on both sides, or a --pubkey whose logical path
	# differs from its canonical one could dodge the check when WORKDIR is
	# itself reached through a symlink (review F4; C-11 enforcement point).
	# EXTRACT_CANON is computed right after extraction (shared with the
	# retain containment and the image-entry resolution below).
	PUBKEY_DIR="$(cd "$(dirname "$PUBKEY")" && pwd -P)"
	PUBKEY_REAL="$PUBKEY_DIR/$(basename "$PUBKEY")"
	case "$PUBKEY_REAL" in
	"$EXTRACT_CANON" | "$EXTRACT_CANON"/*)
		fail "refusing a trust root found INSIDE the unverified bundle (--pubkey $PUBKEY resolves into the extracted bundle); the pinned public key must come from an independent channel (BUILD29-CONTRACT C-11)"
		;;
	esac
fi

# --- format detection ---------------------------------------------------------
FORMAT="legacy"
if [ -f "$INFO" ]; then
	declared="$(sed -n 's/^bundle_format=//p' "$INFO" | head -1)"
	[ "$declared" = "2" ] || fail "unknown bundle format (bundle-info.txt declares '$declared', expected '2') — refusing to install"
	FORMAT="2"
fi

# --- signature over the inventory manifest (fail-closed) ----------------------
verify_manifest_sig() {
	command -v cosign >/dev/null 2>&1 ||
		fail "inventory-manifest signature present but cosign is not installed (prerequisite)"
	if [ -f "$MSIG" ]; then
		sig="$MSIG"
		subject="manifest.sha256 (detached signature)"
	else
		sig="$MSIGB"
		subject="manifest.sha256 (sigstore bundle)"
	fi
	flags=""
	help="$(cosign verify-blob --help 2>&1 || true)"
	if printf '%s\n' "$help" | grep -q -- '--insecure-ignore-tlog'; then
		flags="--insecure-ignore-tlog"
	elif printf '%s\n' "$help" | grep -q -- '--offline'; then
		flags="--offline"
	else
		echo "WARN: cosign has no offline flag — it may try to reach the transparency log; continuing" >&2
	fi
	if head -c 1 "$sig" 2>/dev/null | grep -q '{'; then
		sigflag=(--bundle "$sig")
	else
		sigflag=(--signature "$sig")
	fi
	# shellcheck disable=SC2086
	if cosign verify-blob --key "$PUBKEY" "${sigflag[@]}" $flags "$MANIFEST" >/dev/null 2>&1; then
		echo "PASS: inventory manifest signature verified with $PUBKEY ($subject; offline flags: ${flags:-none})"
	else
		fail "inventory-manifest signature verification FAILED for $subject (wrong key, stale signature over different manifest bytes — e.g. tampered payload + recomputed manifest — corrupted signature, or cosign needed network)"
	fi
}

if [ "$FORMAT" = "2" ]; then
	if [ ! -f "$MSIG" ] && [ ! -f "$MSIGB" ]; then
		if allow_unsigned; then
			fail "format-2 bundle is UNSIGNED and RELEASE_ALLOW_UNSIGNED cannot accept new bundles (A08): the override applies to legacy bundles only — rebuild with COSIGN_KEY or obtain a signed bundle"
		fi
		fail "format-2 bundle has no inventory-manifest signature (neither manifest.sha256.sig nor manifest.sha256.sig.bundle) — unsigned new-format bundles are never installable"
	fi
	[ -n "$PUBKEY" ] ||
		fail "format-2 bundle requires --pubkey FILE: the manifest signature must be verified against a trust root from OUTSIDE the bundle (a key shipped inside the bundle is never trust, C-11)"
	verify_manifest_sig
else
	if [ "$LEGACY_OK" = "1" ]; then
		# A manifest signature sidecar in a bundle WITHOUT the format-2
		# marker is never silently ignored (review F3): a genuine pre-A08
		# bundle cannot carry one — manifest signing shipped with A08 — so
		# this is either a hand-made hybrid or a stripped/downgraded
		# format-2 bundle (a tamper indicator). With a pinned trust root the
		# signature is verified right here and an inconsistency refuses the
		# install; without a pubkey it is called out as loudly as the
		# unverifiable image-digest signature further below.
		if [ -f "$MSIG" ] || [ -f "$MSIGB" ]; then
			if [ -n "$PUBKEY" ]; then
				verify_manifest_sig
			else
				echo "WARNING: bundle carries an inventory-manifest signature (manifest.sha256.sig or .sig.bundle) but no --pubkey was given: the signature is NOT verified (legacy checksum-only install; a signed manifest without the format-2 marker is also a downgrade indicator — pass a pinned --pubkey to verify it)" >&2
			fi
		fi
		echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
		echo "WARNING: LEGACY BUNDLE (pre-A08 format: no bundle-info.txt marker)." >&2
		echo "WARNING: --allow-legacy-unsigned was passed explicitly: inventory" >&2
		echo "WARNING: authenticity is NOT cryptographically verified; integrity" >&2
		echo "WARNING: rests on manifest.sha256 checksums alone. Prefer a signed" >&2
		echo "WARNING: format-2 bundle." >&2
		echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
	else
		fail "legacy bundle (pre-A08 format, no bundle-info.txt marker): unsigned installs are never the default — pass --allow-legacy-unsigned explicitly to accept checksum-only integrity with a loud warning (compat per BUILD29-CONTRACT C-10)"
	fi
fi

# --- canonical manifest: strict parse + structural path validation -----------
# AUDIT-P1-01: the manifest is the single source of truth for everything the
# loader consumes. The parse is strict — EVERY line must be exactly
#   <64 hex chars><space><space>./<path>
# The old parse silently DROPPED non-conforming lines while sha256sum -c
# below still read them: a manifest line 'hash  ../../outside' pointed the
# checksum stage at files OUTSIDE the bundle (outside-read oracle). Refuse
# anything that does not parse exactly.
echo "=== Validating manifest entries ==="
strict_lines="$(grep -Ec '^[0-9a-fA-F]{64}  \./' "$MANIFEST")" || strict_lines=0
total_lines="$(grep -Ec '.' "$MANIFEST")" || total_lines=0
if [ "$strict_lines" -ne "$total_lines" ] || [ "$strict_lines" -eq 0 ]; then
	echo "manifest line(s) not matching '<sha256>  ./path':" >&2
	grep -Evn '^[0-9a-fA-F]{64}  \./' "$MANIFEST" | head -20 >&2 || true
	fail "malformed manifest: every line must be '<sha256>  ./path' — refusing to consume a manifest that cannot be parsed exactly (AUDIT-P1-01)"
fi

check_entry_path() { # check_entry_path <path-without-./-prefix>: refuse escapes
	_remainder="$1"
	case "$_remainder" in
	"" | .) fail "manifest entry is not a regular-file path: ./" ;;
	*/) fail "manifest entry is not a regular-file path: $1 (directory entries are never inventoried)" ;;
	/*) fail "manifest entry is absolute: ./$1" ;;
	esac
	while [ -n "$_remainder" ]; do
		_component="${_remainder%%/*}"
		if [ "$_component" = ".." ]; then
			fail "manifest entry escapes the bundle root: ./$1 — path components may not contain '..' (AUDIT-P1-01)"
		fi
		if [ "$_component" = "$_remainder" ]; then _remainder=""; else _remainder="${_remainder#*/}"; fi
	done
}
while IFS= read -r entry; do
	[ -n "$entry" ] || continue
	check_entry_path "${entry#*  ./}"
done < <(sed -n 's/^[0-9a-fA-F]\{64\}  \(\.\/.*\)$/\1/p' "$MANIFEST")

# --- inventory completeness: the manifest must cover EVERY actual file -------
# sha256sum -c proves listed files match; this proves nothing outside the
# (signed) manifest was smuggled into the bundle — in BOTH directions.
# AUDIT-P1-01: sidecar exemptions are exact, ROOT-level paths only. The old
# `find ! -name manifest.sha256` excluded those BASENAMES in every
# subdirectory: a file named manifest.sha256 planted in install/ was
# invisible to the inventory.
echo "=== Inventory completeness ==="
actual="$(cd "$EXTRACT" && find . -type f -print |
	sed '/^\.\/manifest\.sha256$/d; /^\.\/manifest\.sha256\.sig$/d; /^\.\/manifest\.sha256\.sig\.bundle$/d' |
	LC_ALL=C sort)"
listed="$(sed -n 's/^[0-9a-fA-F]\{64\}  \.\//.\//p' "$MANIFEST" | LC_ALL=C sort)"
actual_list="$(printf '%s\n' "$actual" | sed '/^$/d')"
listed_list="$(printf '%s\n' "$listed" | sed '/^$/d')"
unlisted="$(comm -23 <(printf '%s\n' "$actual_list") <(printf '%s\n' "$listed_list") || true)"
if [ -n "$unlisted" ]; then
	printf '%s\n' "$unlisted" >&2
	fail "bundle contains file(s) NOT covered by the manifest — unlisted payload is refused (added or smuggled content)"
fi
missing_listed="$(comm -13 <(printf '%s\n' "$actual_list") <(printf '%s\n' "$listed_list") || true)"
if [ -n "$missing_listed" ]; then
	printf '%s\n' "$missing_listed" >&2
	fail "manifest lists file(s) absent from the bundle — incomplete payload is refused"
fi

echo "=== Verifying manifest hashes ==="
# shellcheck disable=SC2086  # $HASH may be "shasum -a 256"
if ! (cd "$EXTRACT" && $HASH -c manifest.sha256); then
	fail "manifest checksum verification failed — refusing to install (tampered or missing payload listed above)"
fi

# --- delegate to the consumer verifier (C-10) --------------------------------
# Format-2: ALWAYS delegate with the (mandatory) pubkey — whole-directory
# checksum verdict, image digest-list signature, honest per-image SBOM report.
#   Its nonzero exit is the verdict; nothing has been loaded yet.
# Legacy: delegate only when a pubkey was supplied (then the old-style image
# digest signature is verified strictly). Without a pubkey there is no trust
# root for any signature stage; the pre-A08 install semantics (checksum-only)
# are preserved under the explicit flag, with the unverifiable signature
# called out loudly instead of silently ignored.
delegate_verify() {
	echo "=== Delegating full offline verification ==="
	VERIFY_ARGS=(--manifest "$MANIFEST" --artifacts "$EXTRACT")
	[ -n "$PUBKEY" ] && VERIFY_ARGS+=(--pubkey "$PUBKEY")
	bash "$REAL_VERIFY" "${VERIFY_ARGS[@]}"
}

if [ "$FORMAT" = "2" ]; then
	if ! delegate_verify; then
		fail "pre-install verification failed — nothing was loaded (verifier verdict above)"
	fi
else
	if [ -n "$PUBKEY" ]; then
		if ! delegate_verify; then
			fail "pre-install verification failed — nothing was loaded (verifier verdict above)"
		fi
	else
		if [ -f "$EXTRACT/images/image-digests.txt.sig" ] || [ -f "$EXTRACT/images/image-digests.txt.sig.bundle" ]; then
			echo "WARNING: bundle carries an image-digest signature but no --pubkey was given: the signature is NOT verified (legacy checksum-only install; pass a pinned --pubkey to verify it)" >&2
		fi
		echo "legacy install: inventory completeness + manifest hashes verified inline; verifier delegation skipped (no --pubkey trust root)"
	fi
fi

# --- retain verified install/ materials (AUDIT-P1-01 gap d) ------------------
# The EXIT trap removes the extracted tree; without --retain the verified
# install/ materials (documented onprem install inputs) were discarded along
# with it. --retain copies them OUT to a durable location after ALL
# verification passed but BEFORE any image is loaded — retained content is
# verified content by construction.
if [ -n "$RETAIN" ]; then
	RETAIN_CANON="$(mkdir -p "$RETAIN" && cd "$RETAIN" && pwd -P)" ||
		fail "--retain target not usable: $RETAIN"
	case "$RETAIN_CANON" in
	"$EXTRACT_CANON" | "$EXTRACT_CANON"/*)
		fail "--retain target $RETAIN is inside the extracted bundle tree ($EXTRACT_CANON) which is removed on exit — pick a durable location outside it" ;;
	esac
	if [ -e "$RETAIN_CANON/install" ]; then
		fail "--retain target already contains an install/ directory: $RETAIN_CANON/install — refusing to overwrite (remove it or choose another directory)"
	fi
	if [ -d "$EXTRACT/install" ]; then
		cp -R "$EXTRACT/install" "$RETAIN_CANON/install"
		echo "retained verified install/ materials at $RETAIN_CANON/install"
	else
		echo "WARN: bundle has no install/ directory — nothing retained to $RETAIN_CANON" >&2
	fi
fi

echo "=== Loading + pushing images to $REGISTRY ==="
# AUDIT-P1-01: the consume set is EXACTLY the verified manifest's image
# entries — any depth under ./images/, resolved inside the canonical extract.
# The old `for tar_img in "$EXTRACT"/images/*.tar` glob was a DIFFERENT file
# set than the verified inventory and followed post-sign symlinks into
# attacker bytes. An empty verified image set fails loud instead of silently
# "succeeding" with zero images loaded.
image_entries="$(sed -n 's/^[0-9a-fA-F]\{64\}  \(\.\/images\/.*\.tar\)$/\1/p' "$MANIFEST" | LC_ALL=C sort)"
if [ -z "$image_entries" ]; then
	fail "no image tarballs listed in the verified manifest (./images/*.tar) — refusing to load: the consume set is the verified manifest, not a directory glob (AUDIT-P1-01)"
fi
while IFS= read -r image_entry; do
	[ -n "$image_entry" ] || continue
	image_path="$EXTRACT_CANON/${image_entry#./}"
	# Belt behind the tree scan: a verified image entry must be a real
	# regular file right before docker load follows the path.
	if [ -L "$image_path" ] || [ ! -f "$image_path" ]; then
		fail "verified image entry is not a regular file at load time: $image_entry"
	fi
	name="$(docker load -i "$image_path" | sed -n 's/Loaded image: //p' | head -1)"
	echo "loaded: $name"
	# registry-qualified names (e.g. localhost:5001/yabanin-gateway:t) —
	# prefixing those again produced REGISTRY/REGISTRY/... and aborted the
	# push. Only add the offline-registry prefix to unprefixed names.
	case "$name" in
	"$REGISTRY"/*) target="$name" ;;
	*) target="$REGISTRY/$name" ;;
	esac
	docker tag "$name" "$target"
	docker push "$target"
done <<<"$image_entries"
echo "=== Done. Use --set image.registry=$REGISTRY with helm install ==="
