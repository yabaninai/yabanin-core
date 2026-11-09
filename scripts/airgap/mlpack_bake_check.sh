#!/usr/bin/env bash
# mlpack_bake_check.sh — baked-TEI serve-readiness check for Yabanin ML model
# packs. The serving mode for packs is a baked serving image: the pack is
# mounted read-only into an offline embedder/classifier image, and the
# gateway verifies only the pack directory that image mounts.
#
# A pack can pass the digest layer (pack.json canonical, every declared file
# present with a matching sha256 — see mlpack_manifest.sh verify) and still
# be unserveable: the TEI runtime pointed at a local model directory
# (--model-id /pack) needs the model config, a tokenizer and the weight file
# at the model root. A bake that cannot start TEI — or that lets TEI read a
# file the manifest does not digest-protect — must be caught OFFLINE, before
# deployment: a wrong digest or a missing runtime prerequisite must never
# yield a ready verdict (the gateway refusal cannot see this gap, because it
# only judges the files the manifest declares).
#
#   check <pack_dir> [--expect-id ID]
#       Layer 1 (digest): run mlpack_manifest.sh verify <pack_dir>; any
#       refusal aborts the bake check.
#       Layer 2 (serve): the TEI serving prerequisites must be DECLARED in
#       pack.json (the digest protects only declared files) and PRESENT:
#         config.json                                        (model config)
#         tokenizer.json  OR spiece.model               (TEI tokenization)
#         model.safetensors / pytorch_model.bin / model.bin  (weights)
#       A required serving file present on disk but NOT declared in the
#       manifest is a refusal — its bytes would reach the runtime unverified.
#       Extra undeclared regular files are a warning (bloat/drift), never a
#       pass/fail. On success the exact serving contract is printed: the
#       documented pack-mode wiring (read-only /pack mount, --model-id /pack,
#       YABANIN_ML_PACK_DIR at the gateway, embedder model = pack id).
#       --expect-id refuses a pack whose manifest id differs from the model
#       the operator intends to serve (predictable attach).
#
# Exit codes: 0 bake-ready; 1 refusal (fail-closed); 2 usage error.
set -u -o pipefail

LC_ALL=C
export LC_ALL

MANIFEST_NAME="pack.json"
SELF_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
VERIFY="$SELF_DIR/mlpack_manifest.sh"

usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; }

fail() { echo "FAIL: $*" >&2; }

cleanup() { return 0; }
trap cleanup EXIT

if [ ! -f "$VERIFY" ]; then
    echo "FAIL: digest verifier not found next to this script: $VERIFY" >&2
    exit 1
fi

# pack_manifest_field <manifest> <field> — top-level scalar string field from
# the canonical manifest (the caller has already passed the digest layer, so
# the canonical serialization is guaranteed).
pack_manifest_field() {
    awk -v f="$2" '
        $1 == "\"" f "\":" {
            v = $0
            sub("^  \"" f "\": \"", "", v)
            sub("\",?$", "", v)
            print v
            exit
        }
    ' "$1"
}

cmd_check() {
    if [ $# -lt 1 ]; then
        echo "usage error: check requires a pack directory" >&2
        usage >&2
        exit 2
    fi
    case "$1" in
        -h | --help) usage; exit 0 ;;
        -*) echo "usage error: check requires a pack directory before flags" >&2; usage >&2; exit 2 ;;
    esac
    DIR="$1"
    shift
    EXPECT_ID=""
    WEIGHT_USED=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --expect-id) [ $# -ge 2 ] || { echo "usage error: --expect-id requires a value" >&2; exit 2; }; EXPECT_ID="$2"; shift 2 ;;
            *) echo "usage error: unknown check argument: $1" >&2; usage >&2; exit 2 ;;
        esac
    done

    if [ ! -d "$DIR" ]; then
        fail "pack dir \"$DIR\" is not a directory — NOT ready; nothing may be served from this pack"
        exit 1
    fi
    DIR="$(CDPATH= cd -- "$DIR" && pwd -P)"

    # ---- Layer 1: the digest contract (single source of truth) --------------
    if ! "$VERIFY" verify "$DIR"; then
        fail "bake check aborted at the digest layer — NOT ready; nothing may be served from this pack"
        exit 1
    fi

    MAN="$DIR/$MANIFEST_NAME"
    PACK_ID="$(pack_manifest_field "$MAN" id)"
    PACK_VERSION="$(pack_manifest_field "$MAN" version)"

    # ---- Layer 2: the TEI local-dir serving prerequisites -------------------
    declared=()
    DECL_PFX='    {"path": "'
    DECL_SFX='", "sha256": "'
    while IFS= read -r line; do
        case "$line" in
            '    {"path": "'*)
                p="${line#"$DECL_PFX"}"
                p="${p%%"$DECL_SFX"*}"
                declared+=("$p")
                ;;
        esac
    done < "$MAN"

    is_declared() { # is_declared <path> — path is in the declared files array
        local p
        for p in ${declared[@]+"${declared[@]}"}; do
            [ "$p" = "$1" ] && return 0
        done
        return 1
    }

    problems=()
    warns=()

    # prereq <path>... — an all-or-nothing prerequisite set (a file and its
    # format variants, e.g. tokenizer.json / spiece.model). Each variant must
    # be declared; declared implies present (layer 1 recomputed every digest).
    # Present-but-undeclared is a digest hole; wholly absent is a missing
    # runtime prerequisite.
    prereq() {
        local any_declared=0 any_present=0 p out
        for p in "$@"; do
            if is_declared "$p"; then
                any_declared=1
            elif [ -e "$DIR/$p" ]; then
                any_present=1
                problems+=("serving file \"$p\" is present in the pack but NOT declared in $MANIFEST_NAME — the digest protects only declared files; rebuild the manifest")
            fi
        done
        if [ "$any_declared" -eq 0 ] && [ "$any_present" -eq 0 ]; then
            out=""
            for p in "$@"; do out="$out \"$p\""; done
            problems+=("serving prerequisite missing: none of${out} is in the pack — the baked TEI runtime would not start; a missing runtime must not yield a ready verdict")
        fi
    }

    prereq "config.json"
    prereq "tokenizer.json" "spiece.model"

    weights_declared=0
    wfirst=1
    for w in model.safetensors pytorch_model.bin model.bin; do
        if is_declared "$w"; then
            weights_declared=$((weights_declared + 1))
            if [ "$wfirst" -eq 1 ]; then
                WEIGHT_USED="$w"
                wfirst=0
            fi
        elif [ -e "$DIR/$w" ]; then
            problems+=("serving file \"$w\" is present in the pack but NOT declared in $MANIFEST_NAME — the digest protects only declared files; rebuild the manifest")
        fi
    done
    if [ "$weights_declared" -eq 0 ]; then
        problems+=("no weights file declared (model.safetensors, pytorch_model.bin or model.bin) — the baked TEI runtime would not start (weights missing); a missing runtime must not yield a ready verdict")
    elif [ "$weights_declared" -gt 1 ]; then
        warns+=("multiple weights files declared — TEI prefers model.safetensors; the extra weight file bloats the bake")
    fi

    # Generic drift scan: undeclared regular files that are not serving
    # prerequisites (already reported above) and not the manifest itself.
    while IFS= read -r -d '' rel; do
        path="${rel#./}"
        [ "$path" = "$MANIFEST_NAME" ] && continue
        full="$DIR/$path"
        [ -d "$full" ] && continue
        case "$path" in
            config.json | tokenizer.json | spiece.model | model.safetensors | pytorch_model.bin | model.bin) continue ;;
        esac
        if ! is_declared "$path"; then
            warns+=("file \"$path\" is in the pack dir but not declared in $MANIFEST_NAME — it ships unverified; rebuild the manifest or remove it")
        fi
    done < <(cd "$DIR" && find . -mindepth 1 -print0 | LC_ALL=C sort -z)

    # ---- Predictable attach: the operator's intended model ------------------
    if [ -n "$EXPECT_ID" ] && [ "$EXPECT_ID" != "$PACK_ID" ]; then
        problems+=("pack id \"$PACK_ID\" does not match the expected model \"$EXPECT_ID\" — attaching a different model than configured must not happen silently")
    fi

    for w in ${warns[@]+"${warns[@]}"}; do
        echo "WARN: $w" >&2
    done
    if [ "${#problems[@]}" -gt 0 ]; then
        for p in ${problems[@]+"${problems[@]}"}; do
            fail "$p"
        done
        fail "pack \"$DIR\" did not pass the baked-TEI bake check — NOT ready; serving this pack would not start or would not be digest-protected"
        exit 1
    fi

    # ---- The serving contract (compose-documented pack mode, D4) ------------
    echo "OK: bake check passed for \"$DIR\" (id=$PACK_ID version=$PACK_VERSION weights=$WEIGHT_USED)"
    echo "serve (baked TEI, compose-documented pack mode):"
    echo "  mount:   $DIR:/pack:ro              (read-only; TEI reads exactly the bytes the digests pin)"
    echo "  tei:     --model-id /pack           (local-dir serving; nothing downloaded)"
    echo "  gateway: YABANIN_ML_PACK_DIR=/pack  (gateway verifies pack.json + per-file sha256 at startup and refuses on any mismatch)"
    echo "  model:   $PACK_ID                   (gateway embedder/classifier model must equal the pack id)"
    echo "bake ready — wrong digest or missing runtime never yields ready"
}

case "${1-}" in
    check)
        shift
        cmd_check "$@"
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    "")
        echo "usage error: missing command (check)" >&2
        usage >&2
        exit 2
        ;;
    *)
        echo "usage error: unknown command: $1" >&2
        usage >&2
        exit 2
        ;;
esac
