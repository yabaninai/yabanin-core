#!/usr/bin/env bash
# N18-P01-T02 — validate the pinned competitor versions/configs.
#
# Two modes:
#   ./validate-configs.sh --static-only   # pin-drift teeth, no Docker needed
#   ./validate-configs.sh                 # static + live: boot the pinned
#                                         # images, probe JSON+SSE, run small
#                                         # bench cells, record RSS
#
# Static teeth (exit 1 on drift):
#   - compose image digests must equal the VERSIONS.md pin row
#   - bifrost config.json must parse as JSON (stdlib; YAML config is validated
#     by the live boot — no PyYAML dependency is invented for this)
#   - compose files must bind loopback only
#   - reserved run-benchmark.sh ports 14651–14655 must not appear anywhere
#   - no `latest`/`main` floating image tags
#
# Live teeth (exit 1 on failure):
#   - gateway boot readiness probes check the mock reply itself (an HTTP 200
#     carrying a Bifrost error object is not readiness)
#   - every bench cell must print a RESULT line with errs=0 — a red run is
#     never a green receipt (same honesty rule as run-benchmark.sh)
#
# This script is pin/config validation only. The identical-conditions
# comparison runner is N18-P01-T03's deliverable; do not grow this into it.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATIC_ONLY=0
[[ "${1:-}" == "--static-only" ]] && STATIC_ONLY=1

BIFROST_DIGEST="sha256:a1c90607dcfd13c1fb2f9476ceb3bb24407a50ade7fdf3e61a59fb42b09e5c57"
LITELLM_DIGEST="sha256:c560d317136880ea92d62334d4367ab10955b1af189dd3ea24f6551290b1d6c1"
MOCK_PORT=14650
BIFROST_PORT=14660
LITELLM_PORT=14661

fail() { echo "FAIL: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing prerequisite: $1"; }

need python3
need docker
need curl
[[ $STATIC_ONLY -eq 1 ]] || need go

# ---- static: VERSIONS.md is the single source of truth -------------------
grep -q -- "$BIFROST_DIGEST" "$DIR/VERSIONS.md" || fail "Bifrost digest missing from VERSIONS.md"
grep -q -- "$LITELLM_DIGEST" "$DIR/VERSIONS.md" || fail "LiteLLM digest missing from VERSIONS.md"
grep -qF "maximhq/bifrost@$BIFROST_DIGEST" "$DIR/bifrost/docker-compose.yml" \
  || fail "bifrost/docker-compose.yml does not pin the VERSIONS.md digest"
grep -qF "ghcr.io/berriai/litellm@$LITELLM_DIGEST" "$DIR/litellm/docker-compose.yml" \
  || fail "litellm/docker-compose.yml does not pin the VERSIONS.md digest"
grep -qF 'APP_HOST: "127.0.0.1"' "$DIR/bifrost/docker-compose.yml" \
  || fail "bifrost compose must bind 127.0.0.1 (APP_HOST)"
grep -qF '"127.0.0.1"' "$DIR/litellm/docker-compose.yml" \
  || fail "litellm compose must bind 127.0.0.1 (--host)"

if grep -E "image:.*:(latest|main)([[:space:]]*)$" "$DIR"/*/docker-compose.yml | grep -q .; then
  fail "floating image tags are not allowed in competitor pins"
fi

python3 - "$DIR" << 'EOF'
import json, pathlib, sys
d = pathlib.Path(sys.argv[1])
mock, bif, lit = "14650", "14660", "14661"

cfg = json.loads((d / "bifrost" / "config.json").read_text())
nc = cfg["providers"]["openai"]["network_config"]
assert nc["base_url"] == f"http://127.0.0.1:{mock}", nc["base_url"]
assert nc.get("allow_private_network") is True, "loopback mock needs allow_private_network"
assert cfg["config_store"]["enabled"] is False, "file-only mode is the pinned posture"
key = cfg["providers"]["openai"]["keys"][0]
assert key["value"] == "env.BIFROST_BENCH_UPSTREAM_KEY", "keys must come from env, never literal"
assert key["aliases"] == {"bench-model": "openai/bench-model"}, key["aliases"]

yml = (d / "litellm" / "config.yaml").read_text()
assert f"api_base: http://127.0.0.1:{mock}/v1" in yml
assert "os.environ/LITELLM_BENCH_UPSTREAM_KEY" in yml

bc = (d / "bifrost" / "docker-compose.yml").read_text()
lc = (d / "litellm" / "docker-compose.yml").read_text()
assert 'APP_PORT: "' + bif + '"' in bc, "bifrost compose must declare the pinned port"
assert '"--port"' in lc and '"' + lit + '"' in lc, "litellm compose must declare the pinned port"
artifacts = [d / "bifrost" / "config.json", d / "litellm" / "config.yaml",
             d / "bifrost" / "docker-compose.yml", d / "litellm" / "docker-compose.yml"]
everything = "".join(p.read_text() for p in artifacts)
for reserved in ("14651", "14652", "14653", "14654", "14655"):
    assert reserved not in everything, f"reserved port {reserved} must not appear in competitor pins"
print(f"static config checks OK (mock={mock} bifrost={bif} litellm={lit})")
EOF

echo "static pin-drift checks passed"
[[ $STATIC_ONLY -eq 1 ]] && { echo "--static-only requested; skipping live validation"; exit 0; }

# ---- live: boot mock + both pinned gateways, probe, bench, RSS ------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/yb-competitor-val.XXXXXX")"
MOCK_PID=""
BIFROST_CID=""
LITELLM_CID=""
cleanup() {
  rc=$?
  [[ -n "$BIFROST_CID" ]] && docker rm -f "$BIFROST_CID" >/dev/null 2>&1 || true
  [[ -n "$LITELLM_CID" ]] && docker rm -f "$LITELLM_CID" >/dev/null 2>&1 || true
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" >/dev/null 2>&1 || true
  exit $rc
}
trap cleanup EXIT

for p in "$MOCK_PORT" "$BIFROST_PORT" "$LITELLM_PORT"; do
  if curl -s -m 1 "http://127.0.0.1:$p/" >/dev/null 2>&1; then
    fail "port $p already has a listener — refusing to start"
  fi
done

(cd "$DIR/../gatewayoverhead" && go build -o "$WORK/gatewayoverhead" .)
"$WORK/gatewayoverhead" mock -addr "127.0.0.1:$MOCK_PORT" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
for i in $(seq 1 30); do
  curl -sf -m 1 "http://127.0.0.1:$MOCK_PORT/healthz" >/dev/null 2>&1 && break
  [[ $i -eq 30 ]] && fail "mock never became ready"
  sleep 0.3
done

export BIFROST_BENCH_UPSTREAM_KEY=bench-local-dummy
export LITELLM_MASTER_KEY=sk-bench-local-dummy
export LITELLM_BENCH_UPSTREAM_KEY=bench-local-dummy
docker compose -f "$DIR/bifrost/docker-compose.yml" up -d >/dev/null \
  || fail "bifrost compose up failed"
docker compose -f "$DIR/litellm/docker-compose.yml" up -d >/dev/null \
  || fail "litellm compose up failed"
BIFROST_CID="$(docker compose -f "$DIR/bifrost/docker-compose.yml" ps -q)"
LITELLM_CID="$(docker compose -f "$DIR/litellm/docker-compose.yml" ps -q)"
[[ -n "$BIFROST_CID" ]] || fail "bifrost container id not found after up"
[[ -n "$LITELLM_CID" ]] || fail "litellm container id not found after up"

ready() { # url name extra_curl_args... — readiness = mock reply present (not a bare HTTP 200)
  local url=$1 name=$2; shift 2
  local tries=${BENCH_READY_TRIES:-120}
  for i in $(seq 1 "$tries"); do
    if curl -s -m 2 -X POST "$url/v1/chat/completions" \
      -H 'Content-Type: application/json' "$@" \
      -d '{"model":"bench-model","messages":[{"role":"user","content":"ready-probe"}]}' \
      2>/dev/null | grep -q "Deterministic benchmark reply."; then
      echo "$name ready after ${i} probes"
      return 0
    fi
    sleep 1
  done
  fail "$name never became ready ($url)"
}
ready "http://127.0.0.1:$BIFROST_PORT" bifrost
ready "http://127.0.0.1:$LITELLM_PORT" litellm -H "Authorization: Bearer sk-bench-local-dummy"

probe() { # port name extra_curl_args...
  local port=$1 name=$2; shift 2
  local j s
  j=$(curl -s -m 5 -X POST "http://127.0.0.1:$port/v1/chat/completions" \
    -H 'Content-Type: application/json' "$@" \
    -d '{"model":"bench-model","messages":[{"role":"user","content":"probe"}]}')
  echo "$j" | grep -q "Deterministic benchmark reply." \
    || fail "$name JSON probe: mock reply not present: $j"
  s=$(curl -s -N -m 5 -X POST "http://127.0.0.1:$port/v1/chat/completions" \
    -H 'Content-Type: application/json' "$@" \
    -d '{"model":"bench-model","stream":true,"messages":[{"role":"user","content":"probe"}]}' \
    | grep -v '^[[:space:]]*$' | tail -1)
  [[ "$s" == "data: [DONE]" ]] || fail "$name SSE probe: stream did not end with [DONE]: $s"
  echo "$name probes OK (json reply + SSE [DONE])"
}
probe "$BIFROST_PORT" bifrost
probe "$LITELLM_PORT" litellm -H "Authorization: Bearer sk-bench-local-dummy"

cell() { # target mode name extra_bench_args...
  local target=$1 mode=$2 name=$3; shift 3
  local out
  out=$("$WORK/gatewayoverhead" bench -target "$target" -mode "$mode" \
    -n "${BENCH_N:-20}" -c "${BENCH_C:-2}" -warmup "${BENCH_WARMUP:-2}" "$@" 2>&1) \
    || { echo "$out"; fail "$name $mode bench exited non-zero"; }
  echo "$out" | grep -q "RESULT mode=$mode" \
    || { echo "$out"; fail "$name $mode bench printed no RESULT line"; }
  echo "$out" | grep -E "RESULT mode=$mode" | sed "s/^/$name /"
  echo "$out" | grep -E "RESULT mode=$mode" | grep -q "errs=0 " \
    || fail "$name $mode bench reported errors"
}

echo "--- bench cells (validation examples, NOT comparison receipts; n=${BENCH_N:-20}) ---"
cell "http://127.0.0.1:$MOCK_PORT" json direct-mock
cell "http://127.0.0.1:$MOCK_PORT" sse direct-mock
cell "http://127.0.0.1:$BIFROST_PORT" json bifrost
cell "http://127.0.0.1:$BIFROST_PORT" sse bifrost
cell "http://127.0.0.1:$LITELLM_PORT" json litellm -api-key sk-bench-local-dummy
cell "http://127.0.0.1:$LITELLM_PORT" sse litellm -api-key sk-bench-local-dummy

echo "--- RSS snapshot (docker stats cgroup view) ---"
docker stats --no-stream --format '{{.Name}} mem={{.MemUsage}} cpu={{.CPUPerc}}' \
  "$BIFROST_CID" "$LITELLM_CID" 2>/dev/null \
  || echo "RSS snapshot unavailable (docker stats drift) — not a pin failure"

echo "VALIDATION OK — pinned versions/configs serve the shared mock end-to-end"
