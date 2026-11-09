#!/usr/bin/env bash
#
# fetch-local-model.sh — one-time fetch of the demo's local LLM weights.
#
# Downloads the pinned Qwen2.5-0.5B-Instruct GGUF (Apache-2.0) and its license
# into demo/models/ and verifies the sha256 BEFORE the file is considered
# usable. The compose override demo/local-llm-override.yml bind-mounts the
# verified file read-only into the llama.cpp server container, so the demo
# contour runs fully offline after this fetch.
#
# Model provenance (full model card in docs/preview/DEMO.md, local-LLM section):
#   repo     : https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF
#   revision : 9217f5db79a29953eb74d5343926648285ec7e67
#   file     : qwen2.5-0.5b-instruct-q4_k_m.gguf (491,400,032 bytes)
#   license  : Apache-2.0 (Qwen) + MIT (llama.cpp runtime)
#   params   : 0.5B (owner constraint: <=1B)
#
# Usage: scripts/demo/fetch-local-model.sh
# Re-runs are no-ops when the verified file is already present.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODEL_DIR="$ROOT/demo/models"
FILE="$MODEL_DIR/qwen2.5-0.5b-instruct-q4_k_m.gguf"
LICENSE="$MODEL_DIR/LICENSE-qwen2.5-0.5b-instruct"

# Pinned provenance. Changing ANY of these is a new model decision and must be
# re-recorded (license compliance gates: make quality-licenses +
# scripts/quality/license_check.py).
BASE_URL="https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/9217f5db79a29953eb74d5343926648285ec7e67"
WEIGHTS_SHA256="74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
LICENSE_SHA256="832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e"

log()  { printf '\033[1;34m[fetch-model]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[fetch-model] FAIL: %s\033[0m\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl not found in PATH"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum not found in PATH"

mkdir -p "$MODEL_DIR"

verify() { # verify <file> <expected-sha256> <label>
  local actual
  actual="$(sha256sum "$1" | cut -d' ' -f1)"
  [[ "$actual" == "$2" ]] || fail "$3 sha256 mismatch: got $actual, want $2"
}

if [[ -f "$FILE" ]]; then
  log "weights already present; verifying sha256"
  verify "$FILE" "$WEIGHTS_SHA256" "qwen2.5-0.5b-instruct-q4_k_m.gguf"
  log "weights verified (cached): $FILE"
else
  log "downloading pinned GGUF (~491 MB) from $BASE_URL"
  # -f: fail on HTTP errors so a partial/proxy error page never passes verify.
  curl -fL --retry 3 -o "$FILE.part" "$BASE_URL/qwen2.5-0.5b-instruct-q4_k_m.gguf" \
    || fail "download failed"
  verify "$FILE.part" "$WEIGHTS_SHA256" "downloaded GGUF"
  mv "$FILE.part" "$FILE"
  log "weights verified (fresh download): $FILE"
fi

if [[ -f "$LICENSE" ]]; then
  verify "$LICENSE" "$LICENSE_SHA256" "Qwen LICENSE" || rm -f "$LICENSE"
fi
if [[ ! -f "$LICENSE" ]]; then
  curl -fL --retry 3 -o "$LICENSE" "$BASE_URL/LICENSE" || fail "license download failed"
  verify "$LICENSE" "$LICENSE_SHA256" "Qwen LICENSE"
fi
log "license copy verified: $LICENSE"

# The .gitignore keeps the weights out of git; the tracked provenance lives in
# this script + docs/preview/DEMO.md.
log "done. Start the local-mode demo with: scripts/demo/local-llm.sh enable"
