#!/usr/bin/env bash
# Verify the cosign signatures of an air-gap bundle directory — fail closed.
#
# Signature PRESENCE is not verification: this entry point delegates every
# cryptographic decision to scripts/release/airgap-verify.sh (the real
# offline verifier: checksum manifests, cosign verify-blob with offline
# flags, honest SKIP reporting) and adds the bundle-scope strictness the
# consumer policy requires, so the legacy bundle path can no longer pass
# an unsigned, garbage-signed or incomplete bundle:
#
#   - the bundle must carry manifest.sha256 and images/image-digests.txt;
#   - the image digest list must be signed (image-digests.txt.sig or the
#     sigstore-bundle .sig.bundle form). Unsigned bundles FAIL unless the
#     explicit owner override RELEASE_ALLOW_UNSIGNED=true is set (D-D);
#     the override is recorded verbatim for the release notes;
#   - every digest entry must be well-formed "name<TAB>repo@sha256:<64
#     lowercase hex>". A signature over malformed bytes does not make the
#     bytes valid: empty digests and DIGEST-UNAVAILABLE markers FAIL;
#   - every image tarball in the bundle must be covered by the digest
#     list (missing/unlisted payload FAILs before anything is installed);
#   - with --expected-digests, the recorded digests must match the
#     consumer-pinned set exactly: wrong source/version, missing images
#     and old validly-signed releases (rollback/substitution) FAIL;
#   - garbage signatures, wrong keys and tampered bytes FAIL through the
#     delegated verification (checksum mismatch or cosign verify-blob).
#
# The pinned public key must come from the consumer via --pubkey; a key
# file found inside the unverified bundle is never used as trust root.
# Verification only: this script performs no install steps, so every
# failure above is reported before any install could happen. Full
# artifact-set verification (SHA256SUMS, SBOM, NOTICE, compose) remains
# airgap-verify.sh directly.
#
# Usage:
#   verify_signatures.sh <bundle_dir> [--pubkey FILE] [--expected-digests FILE]
#
# Exit codes: 0 all executed stages PASS; 1 verification FAIL (with the
# reason on stderr); 2 usage error.
set -euo pipefail

usage() { sed -n '/^# Usage:$/,/^# Exit codes:/p' "$0" | sed 's/^# \{0,1\}//'; }

fail() { # fail <reason...>: verification failure, exit nonzero, loud reason
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

BUNDLE_DIR=""
PUBKEY=""
EXPECTED=""
while [ $# -gt 0 ]; do
	case "$1" in
	--pubkey)
		[ $# -ge 2 ] || usage_error "--pubkey requires FILE"
		[ -n "$2" ] || usage_error "--pubkey requires FILE"
		PUBKEY="$2"
		shift 2
		;;
	--expected-digests)
		[ $# -ge 2 ] || usage_error "--expected-digests requires FILE"
		[ -n "$2" ] || usage_error "--expected-digests requires FILE"
		EXPECTED="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	--)
		shift
		while [ $# -gt 0 ]; do
			[ -z "$BUNDLE_DIR" ] || usage_error "exactly one bundle_dir is allowed"
			BUNDLE_DIR="$1"
			shift
		done
		;;
	-*)
		usage_error "unknown argument: $1"
		;;
	*)
		[ -z "$BUNDLE_DIR" ] || usage_error "exactly one bundle_dir is allowed (got both $BUNDLE_DIR and $1)"
		BUNDLE_DIR="$1"
		shift
		;;
	esac
done

[ -n "$BUNDLE_DIR" ] || usage_error "bundle_dir is required"
[ -d "$BUNDLE_DIR" ] || usage_error "bundle_dir is not a directory: $BUNDLE_DIR"

# Resolve the real verifier relative to this script so the wrapper works
# from any working directory; a missing verifier is a hard failure, never
# a silent downgrade to presence-only checks.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_VERIFY="$SCRIPT_DIR/../release/airgap-verify.sh"
[ -f "$REAL_VERIFY" ] || fail "real offline verifier not found: $REAL_VERIFY — cannot verify anything"

MANIFEST="$BUNDLE_DIR/manifest.sha256"
DIGESTS="$BUNDLE_DIR/images/image-digests.txt"
SIG="$DIGESTS.sig"
SIGBUNDLE="$DIGESTS.sig.bundle"

[ -f "$MANIFEST" ] || fail "bundle manifest not found: $MANIFEST — no bundle byte can be verified"
[ -f "$DIGESTS" ] || fail "image digest list not found: $DIGESTS — the bundle carries no verifiable image identity"
[ -s "$DIGESTS" ] || fail "image digest list is empty: $DIGESTS"

# Well-formed digest entries only. Validated with plain awk string
# operations (no regex intervals) so the check behaves identically on
# gawk/mawk/busybox awk across air-gap hosts.
digest_problems="$(awk -F '\t' '
	{
		if (NF != 2) {
			printf "line %d: expected name<TAB>digest, found %d field(s): %s\n", NR, NF, $0
			bad = 1
			next
		}
		if ($2 == "DIGEST-UNAVAILABLE") {
			printf "line %d: digest was not provable at build time (DIGEST-UNAVAILABLE): %s\n", NR, $1
			bad = 1
			next
		}
		marker = index($2, "@sha256:")
		if (marker <= 1) {
			printf "line %d: digest is not repo@sha256:<64 hex>: %s\n", NR, $2
			bad = 1
			next
		}
		hex = substr($2, marker + 8)
		repo = substr($2, 1, marker - 1)
		if (length(hex) != 64 || hex ~ /[^0-9a-f]/) {
			printf "line %d: digest is not repo@sha256:<64 lowercase hex>: %s\n", NR, $2
			bad = 1
			next
		}
		if (repo == "") {
			printf "line %d: empty repository in digest: %s\n", NR, $2
			bad = 1
		}
	}
	END { exit bad ? 1 : 0 }
' "$DIGESTS")" || {
	printf '%s\n' "$digest_problems" >&2
	fail "image digest list is malformed: $DIGESTS — a signature over malformed bytes does not make a digest real"
}

# One digest entry per image tarball, and every tarball listed: an
# unlisted payload would be loaded by the installer with no verifiable
# identity, and a missing payload means the digests describe images the
# bundle does not actually deliver.
n_tars=0
tar_names=""
for tar in "$BUNDLE_DIR"/images/*.tar; do
	[ -f "$tar" ] || continue
	n_tars=$((n_tars + 1))
	name="${tar##*/}"
	tar_names="$tar_names${name%.tar}"$'\n'
done
n_digests="$(wc -l < "$DIGESTS" | tr -d ' ')"
[ "$n_tars" -gt 0 ] || fail "bundle contains no image tarballs — nothing to install, digests describe absent payload"
[ "$n_tars" -eq "$n_digests" ] || fail "payload/digest count mismatch: $n_tars image tarball(s) but $n_digests digest entr(ies) — missing or unlisted payload"

unlisted="$(printf '%s' "$tar_names" | awk -F '\t' '
	NR == FNR { listed[$1] = 1; next }
	!($0 in listed) { print $0 }
' "$DIGESTS" -)" || fail "cannot compare payload against the digest list"
if [ -n "$unlisted" ]; then
	printf '%s\n' "$unlisted" >&2
	fail "bundle contains image payload with no digest entry — missing/unlisted payload is refused"
fi

# Expected-identity pin (anti-rollback): compare the recorded digests
# against the consumer-pinned set. Exact set equality, so an old but
# validly-signed release fails as loudly as a wrong digest.
if [ -n "$EXPECTED" ]; then
	[ -f "$EXPECTED" ] || fail "expected-digests file not found: $EXPECTED"
	[ -s "$EXPECTED" ] || fail "expected-digests file is empty: $EXPECTED — a pin expecting nothing verifies nothing"
	expected_problems="$(awk -F '\t' '
		{
			if (NF != 2 || $1 == "" || $2 !~ /@/) {
				printf "line %d: expected pin must be name<TAB>repo@sha256:<64 hex>, got: %s\n", NR, $0
				bad = 1
			}
		}
		END { exit bad ? 1 : 0 }
	' "$EXPECTED")" || {
		printf '%s\n' "$expected_problems" >&2
		fail "expected-digests file is malformed: $EXPECTED"
	}
	conflict="$(awk -F '\t' '
		NR == FNR { expected[$1] = $2; next }
		{ recorded[$1] = $2 }
		END {
			for (name in expected) {
				if (!(name in recorded))
					printf "MISSING   %s — pinned image is not in the bundle\n", name
				else if (expected[name] != recorded[name])
					printf "MISMATCH  %s — expected %s, bundle has %s\n", name, expected[name], recorded[name]
			}
			for (name in recorded) {
				if (!(name in expected))
					printf "EXTRA     %s — bundle carries an image outside the pinned set\n", name
			}
		}
	' "$EXPECTED" "$DIGESTS" | LC_ALL=C sort)" || fail "cannot compare expected digests with the bundle"
	if [ -n "$conflict" ]; then
		printf '%s\n' "$conflict" >&2
		fail "recorded image digests do not match the expected set — wrong source/version or substituted (old) release"
	fi
	echo "expected digests: all $(wc -l < "$EXPECTED" | tr -d ' ') pinned image(s) match the bundle"
fi

# Unsigned bundles are refused here: delegation alone would only SKIP the
# signature stage outside strict mode. The only unsigned path is the
# explicit owner override, which is recorded verbatim for disclosure.
if [ -f "$SIG" ]; then
	echo "bundle signature file present: $SIG (verification delegated to the offline verifier)"
elif [ -f "$SIGBUNDLE" ]; then
	echo "bundle signature bundle present: $SIGBUNDLE (verification delegated to the offline verifier)"
elif allow_unsigned; then
	echo "OVERRIDE recorded: RELEASE_ALLOW_UNSIGNED=true — bundle is UNSIGNED by owner decision; this line belongs in the release notes" >&2
else
	fail "no signature for the image digest list (neither $SIG nor $SIGBUNDLE) — an unsigned bundle is not verifiable (only RELEASE_ALLOW_UNSIGNED=true, recorded and disclosed, allows unsigned)"
fi

# Delegate: real checksum verification of the whole bundle (catches any
# tampered byte, including swapped SBOMs) plus cosign verify-blob over
# the digest list (catches garbage and wrong-key signatures). Its exit
# code is the verdict; no install step exists on this path.
echo "delegating to the offline verifier: $REAL_VERIFY"
VERIFY_ARGS=(--manifest "$MANIFEST")
if [ -n "$PUBKEY" ]; then
	VERIFY_ARGS+=(--pubkey "$PUBKEY")
fi
exec bash "$REAL_VERIFY" "${VERIFY_ARGS[@]}"
