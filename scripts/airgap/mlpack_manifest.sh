#!/usr/bin/env bash
# mlpack_manifest.sh — JSON digest manifest machinery for Yabanin ML model
# packs. A pack is the air-gap alternative to hub
# downloads: the core never downloads, and an explicitly attached pack
# (YABANIN_ML_PACK_DIR) is verified on disk before anything is served from
# it. This script is the producer/verifier side of that contract:
#
#   build  <pack_dir> --id ID --version VERSION --revision 40HEX
#          --license LICENSE [--out FILE]
#       Walk <pack_dir> deterministically (LC_ALL=C byte order, regular
#       files only), write the canonical pack.json next to the weights:
#       schema_version, provenance (id/version/revision/license) and one
#       {"path","sha256"} entry per artifact. The same directory always
#       yields byte-identical output (reproducible bundles).
#
#   verify <pack_dir>
#       Recompute every declared digest and compare. ANY problem — missing
#       manifest, unsupported schema, unpinned revision, traversal path,
#       missing weight, digest mismatch — is a refusal: explicit FAIL lines,
#       exit 1. Fail-closed: a wrong digest or a missing runtime artifact
#       never yields a ready verdict.
#
# Canonical format: verify accepts exactly the serialization `build` writes
# (one file entry per line). The gateway loader (pkg/mlpack) is the runtime
# authority and structurally validates any JSON manifest; this verifier is
# the stricter offline gate, so a manifest it refuses can never be silently
# upgraded to ready.
#
# Exit codes: 0 ok; 1 refusal (fail-closed); 2 usage error.
set -u -o pipefail

LC_ALL=C
export LC_ALL

MANIFEST_NAME="pack.json"
SCHEMA_VERSION=1
TMP_FILES=""

usage() { sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; }

fail() { echo "FAIL: $*" >&2; }
die() { fail "$*"; exit 1; }

cleanup() {
    # shellcheck disable=SC2086  # mktemp paths contain no spaces
    [ -n "$TMP_FILES" ] && rm -f $TMP_FILES
    return 0
}
trap cleanup EXIT

if command -v sha256sum >/dev/null 2>&1; then
    HASH=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
    HASH=(shasum -a 256)
else
    echo "FAIL: no sha256sum or shasum on PATH" >&2
    exit 1
fi

digest_of() { # digest_of <file> — lowercase 64-hex sha256 of file contents
    "${HASH[@]}" "$1" | awk '{print $1}'
}

is_40hex() { # pinned git revision: exactly 40 lowercase hex chars
    case "$1" in
        "" | *[!0-9a-f]*) return 1 ;;
    esac
    [ ${#1} -eq 40 ]
}

check_scalar() { # check_scalar <value> <what> — canonical-JSON representable
    case "$1" in
        *'"'* | *'\'*)
            die "$2 contains a quote or backslash — not representable in the canonical manifest; rename it" ;;
    esac
    case "$1" in
        *[[:cntrl:]]*)
            die "$2 contains a control character — not representable in the canonical manifest; rename it" ;;
    esac
}

cmd_build() {
    [ $# -ge 1 ] || { echo "usage error: build requires a pack directory" >&2; usage >&2; exit 2; }
    DIR="$1"
    shift
    ID="" VERSION="" REVISION="" LICENSE="" OUT=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --id) [ $# -ge 2 ] || { echo "usage error: --id requires a value" >&2; exit 2; }; ID="$2"; shift 2 ;;
            --version) [ $# -ge 2 ] || { echo "usage error: --version requires a value" >&2; exit 2; }; VERSION="$2"; shift 2 ;;
            --revision) [ $# -ge 2 ] || { echo "usage error: --revision requires a value" >&2; exit 2; }; REVISION="$2"; shift 2 ;;
            --license) [ $# -ge 2 ] || { echo "usage error: --license requires a value" >&2; exit 2; }; LICENSE="$2"; shift 2 ;;
            --out) [ $# -ge 2 ] || { echo "usage error: --out requires a value" >&2; exit 2; }; OUT="$2"; shift 2 ;;
            *) echo "usage error: unknown build argument: $1" >&2; usage >&2; exit 2 ;;
        esac
    done
    if [ -z "$ID" ] || [ -z "$VERSION" ] || [ -z "$REVISION" ] || [ -z "$LICENSE" ]; then
        echo "usage error: build requires --id, --version, --revision, --license" >&2
        usage >&2
        exit 2
    fi
    [ -d "$DIR" ] || die "pack dir \"$DIR\" is not a directory"
    DIR="$(CDPATH= cd -- "$DIR" && pwd -P)"
    OUT="${OUT:-$DIR/$MANIFEST_NAME}"

    check_scalar "$ID" "pack id"
    check_scalar "$VERSION" "pack version"
    check_scalar "$LICENSE" "license"
    if ! is_40hex "$REVISION"; then
        die "revision must be a pinned 40-hex git commit, got \"$REVISION\" (floating refs like \"main\" are rejected)"
    fi

    # Deterministic walk: LC_ALL=C byte order; regular files only. A symlink
    # is refused, never followed — a symlinked weight would silently swap the
    # artifact the digest claims to pin.
    ENTRIES="$(mktemp)"
    TMP_FILES="$TMP_FILES $ENTRIES"
    : > "$ENTRIES"
    count=0
    while IFS= read -r -d '' rel; do
        path="${rel#./}"
        [ "$path" = "$MANIFEST_NAME" ] && continue
        full="$DIR/$path"
        if [ -L "$full" ]; then
            die "pack entry \"$path\" is a symlink — packs ship regular files only; a symlinked weight would silently swap the digested artifact"
        elif [ -d "$full" ]; then
            continue
        elif [ -f "$full" ]; then
            check_scalar "$path" "file path \"$path\""
            d="$(digest_of "$full")" || die "cannot hash \"$path\""
            printf '%s\t%s\n' "$path" "$d" >> "$ENTRIES"
            count=$((count + 1))
        else
            die "pack entry \"$path\" is not a regular file — refused"
        fi
    done < <(cd "$DIR" && find . -mindepth 1 -print0 | LC_ALL=C sort -z)
    if [ "$count" -eq 0 ]; then
        die "pack declares no files (weights missing) — an empty pack must not enter the distribution"
    fi

    TMP_OUT="$(mktemp "$DIR/.${MANIFEST_NAME}.tmp.XXXXXX")"
    TMP_FILES="$TMP_FILES $TMP_OUT"
    {
        printf '{\n'
        printf '  "schema_version": %d,\n' "$SCHEMA_VERSION"
        printf '  "id": "%s",\n' "$ID"
        printf '  "version": "%s",\n' "$VERSION"
        printf '  "revision": "%s",\n' "$REVISION"
        printf '  "license": "%s",\n' "$LICENSE"
        printf '  "files": [\n'
        first=1
        while IFS=$'\t' read -r path d; do
            [ -n "$path" ] || continue
            if [ "$first" -eq 1 ]; then first=0; else printf ',\n'; fi
            printf '    {"path": "%s", "sha256": "%s"}' "$path" "$d"
        done < "$ENTRIES"
        printf '\n  ]\n}\n'
    } > "$TMP_OUT"
    mv "$TMP_OUT" "$OUT"
    echo "manifest written: $OUT ($count files, schema_version=$SCHEMA_VERSION)"
}

cmd_verify() {
    [ $# -eq 1 ] || { echo "usage error: verify takes exactly one pack directory" >&2; usage >&2; exit 2; }
    DIR="$1"
    [ -d "$DIR" ] || die "pack dir \"$DIR\" is not a directory"
    DIR="$(CDPATH= cd -- "$DIR" && pwd -P)"
    MAN="$DIR/$MANIFEST_NAME"
    [ -f "$MAN" ] || die "$MANIFEST_NAME missing in \"$DIR\" — the JSON digest manifest is required; regenerate with: mlpack_manifest.sh build \"$DIR\" --id ... --version ... --revision ... --license ..."

    canonic() { # canonic <line-no> <detail> — refusal for non-canonical input
        fail "$MANIFEST_NAME in \"$DIR\" is not in the canonical format produced by mlpack_manifest.sh build (line $1: $2)"
        exit 1
    }
    missing_field() { # missing_field <name> — canonical manifests always carry all fields
        fail "$MANIFEST_NAME in \"$DIR\" is not canonical: missing \"$1\" field"
        exit 1
    }

    schema_seen="" id_seen="" version_seen="" revision_seen="" license_seen=""
    ID="" VERSION="" REVISION="" LICENSE=""
    in_files=0 closed=0 count=0
    problems=()
    re_entry='^    \{"path": "([^"]*)", "sha256": "([0-9a-f]{64})"\},?$'
    lineno=0
    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))
        if [ "$closed" -eq 1 ]; then
            canonic "$lineno" "content after the closing brace"
        fi
        if [ "$lineno" -eq 1 ]; then
            [ "$line" = "{" ] || canonic "$lineno" "expected '{'"
            continue
        fi
        if [ "$in_files" -eq 0 ]; then
            case "$line" in
                '  "files": [')
                    in_files=1
                    continue
                    ;;
                '  "schema_version": '*)
                    v="${line#  \"schema_version\": }"
                    v="${v%,}"
                    if [ "$v" != "$SCHEMA_VERSION" ]; then
                        fail "unsupported manifest schema_version: $v (this tool writes schema_version=$SCHEMA_VERSION) — refuse, do not guess"
                        exit 1
                    fi
                    schema_seen=1
                    ;;
                '  "id": '*)
                    ID="${line#  \"id\": \"}"
                    ID="${ID%\",}"
                    id_seen=1
                    ;;
                '  "version": '*)
                    VERSION="${line#  \"version\": \"}"
                    VERSION="${VERSION%\",}"
                    version_seen=1
                    ;;
                '  "revision": '*)
                    REVISION="${line#  \"revision\": \"}"
                    REVISION="${REVISION%\",}"
                    revision_seen=1
                    ;;
                '  "license": '*)
                    LICENSE="${line#  \"license\": \"}"
                    LICENSE="${LICENSE%\",}"
                    license_seen=1
                    ;;
                '}')
                    canonic "$lineno" "manifest ends before the files array"
                    ;;
                *)
                    canonic "$lineno" "$line"
                    ;;
            esac
            continue
        fi
        if [ "$in_files" -eq 1 ]; then
            if [ "$line" = "  ]" ]; then
                in_files=2
                continue
            fi
            if [[ "$line" =~ $re_entry ]]; then
                path="${BASH_REMATCH[1]}"
                d="${BASH_REMATCH[2]}"
                count=$((count + 1))
                # Safe relative path only (mirrors pkg/mlpack unsafePackPath):
                # no absolute paths, no traversal, no empty segments.
                unsafe=""
                case "$path" in
                    "") unsafe="path is empty" ;;
                    /*) unsafe="absolute paths are not allowed" ;;
                    *'\'*) unsafe="backslash is not allowed in pack paths" ;;
                esac
                if [ -z "$unsafe" ]; then
                    seg="$path"
                    while [ -n "$seg" ]; do
                        case "$seg" in
                            */*)
                                item="${seg%%/*}"
                                seg="${seg#*/}"
                                ;;
                            *)
                                item="$seg"
                                seg=""
                                ;;
                        esac
                        if [ -z "$item" ] || [ "$item" = "." ] || [ "$item" = ".." ]; then
                            unsafe="parent traversal is not allowed"
                            break
                        fi
                    done
                fi
                if [ -n "$unsafe" ]; then
                    problems+=("file \"$path\": unsafe path: $unsafe")
                    continue
                fi
                full="$DIR/$path"
                if [ -L "$full" ]; then
                    problems+=("file \"$path\" is a symlink — packs ship regular files only")
                    continue
                fi
                if [ ! -e "$full" ]; then
                    problems+=("file \"$path\" declared by $MANIFEST_NAME is missing (weights missing)")
                    continue
                fi
                if [ ! -f "$full" ]; then
                    problems+=("file \"$path\" is not a regular file")
                    continue
                fi
                actual="$(digest_of "$full")"
                if [ -z "$actual" ]; then
                    problems+=("file \"$path\" cannot be hashed")
                    continue
                fi
                if [ "$actual" != "$d" ]; then
                    problems+=("file \"$path\" digest mismatch: manifest $d, actual $actual — must not enter the distribution")
                fi
            else
                canonic "$lineno" "$line"
            fi
            continue
        fi
        # in_files == 2: only the closing brace may follow the files array
        if [ "$line" = "}" ]; then
            closed=1
        else
            canonic "$lineno" "expected '}'"
        fi
    done < "$MAN"

    [ "$schema_seen" = 1 ] || missing_field "schema_version"
    [ "$id_seen" = 1 ] || missing_field "id"
    [ "$version_seen" = 1 ] || missing_field "version"
    [ "$revision_seen" = 1 ] || missing_field "revision"
    [ "$license_seen" = 1 ] || missing_field "license"
    if [ "$count" -eq 0 ]; then
        problems+=("pack declares no files (weights missing)")
    fi
    if ! is_40hex "$REVISION"; then
        problems+=("revision must be a pinned 40-hex git commit, got \"$REVISION\" (floating refs like \"main\" are rejected)")
    fi
    [ -n "$ID" ] || problems+=("pack id is empty")
    [ -n "$VERSION" ] || problems+=("pack version is empty (packs are versioned)")
    [ -n "$LICENSE" ] || problems+=("license is unconfirmed (not recorded)")

    if [ "${#problems[@]}" -gt 0 ]; then
        for p in "${problems[@]}"; do
            fail "$p"
        done
        fail "pack \"$DIR\" did not verify — NOT ready; nothing may be served from this pack"
        exit 1
    fi
    echo "OK: $MANIFEST_NAME verified in \"$DIR\" (id=$ID version=$VERSION files=$count) — all digests match"
}

case "${1-}" in
    build)
        shift
        cmd_build "$@"
        ;;
    verify)
        shift
        cmd_verify "$@"
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    "")
        echo "usage error: missing command (build|verify)" >&2
        usage >&2
        exit 2
        ;;
    *)
        echo "usage error: unknown command: $1" >&2
        usage >&2
        exit 2
        ;;
esac
