#!/usr/bin/env bash
#
# N12-P04-T03 profile runner: 30 s synthetic responses, 100 RPS bursts × 60 s,
# and the separate 120 s long-response profile (PRODUCT-CONTRACT §15 lines
# 129–136; T01 inventory gaps G3 + burst stage of G4) against a REAL stack for
# REAL wall-clock.
#
# Brings up the mock-profile stack (docker-compose.prod.yml + e2e overlay)
# under an ISOLATED compose project (-p profiles, ports 36xxx/3919x, subnet
# 10.208.0.0/24 — deliberately disjoint from the soak stand's 3xxxx ports and
# 10.207.0.0/24 so the sibling lane's stand can coexist), builds the
# duration-tunable slowmock upstream (tests/load/slowmock), seeds a throwaway
# org whose model routes to slowmock, applies the sovereign-default policy
# pack in shadow mode (contract profile), captures a pre-load backlog
# baseline per profile, runs the measured k6 profile, and:
#   burst  → watches the settlement backlog return to the baseline range
#            within 5 min (§15 line 136; a miss is recorded, not hidden);
#   long30/long120 → short settle watch as sanity.
#
# Honesty rules (packet negative criteria):
#   - NO time acceleration exists: k6 and the stack run on real wall-clock;
#     reports FAIL unless actual elapsed >= nominal arrival span.
#   - Generator/VU shortfall cannot pass as a sustained rate: the profiles'
#     thresholds (dropped_iterations==0, exact completed-iterations count)
#     turn shortfall into a loud failure (G1+G2).
#
# Usage: run-profiles.sh [--profile burst|long30|long120|all] [--label ...]
#                        [--policy off|shadow|enforce] [--keep]
# Requirements: docker + compose, go (builds ./yb when policy != off), python3,
#               openssl, curl. k6 runs inside the grafana/k6:0.53.0 image.
#
# Run outputs land in artifacts/profiles/<run-id>/ (gitignored — never commit).
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

# --- configuration -------------------------------------------------------------
PROJECT="profiles"
LABEL="profiles"
PROFILE="all"
POLICY="${PROFILES_POLICY:-shadow}"
KEEP=0
ORG_SLUG="profiles"
ORG_NAME="Profiles"
SEED_EMAIL="profiles@yabanin.internal"
SEED_MODEL="profile-model"
K6_IMAGE="${K6_IMAGE:-grafana/k6:0.53.0}"
# Profiles-safe host ports (disjoint from the soak stand's 35432/39090 block).
PG_HOST_PORT="${PG_HOST_PORT:-36432}"
PROM_HOST_PORT="${PROM_HOST_PORT:-39190}"
# IP pins in OUR subnet (slowmock doubles as the provider addr, which seeds
# the gateway's egress allowlist — see the overlay comment below).
SLOWMOCK_IP="10.208.0.10"
MOCKEMBEDDER_IP="10.208.0.11"
export K6_IMAGE LABEL PROFILE_MODEL="$SEED_MODEL"

usage() { sed -n '2,32p' "$0"; exit 0; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --policy) POLICY="$2"; shift 2 ;;
    --keep|--skip-teardown) KEEP=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown flag: $1" >&2; usage ;;
  esac
done

RUN_ID="$(date -u +%Y%m%d-%H%M%S)-profiles-$(git rev-parse --short HEAD)"
OUT="$ROOT/artifacts/profiles/$RUN_ID"
mkdir -p "$OUT"
LOG="$OUT/run.log"
exec > >(tee -a "$LOG") 2>&1

log()  { printf '\n[profiles] %s\n' "$*"; }
API_KEY=""
redact_key() { # the minted key is a throwaway stand credential; artifacts must not carry it
  [[ -n "$API_KEY" ]] || return 0
  sed -i "s|$API_KEY|[REDACTED_PROFILES_KEY]|g" "$LOG" 2>/dev/null || true
  [[ -f "$OUT/seed.log" ]] && sed -i "s|$API_KEY|[REDACTED_PROFILES_KEY]|g" "$OUT/seed.log" 2>/dev/null || true
}
fail() { printf '\n[profiles] FATAL: %s\n' "$*" >&2; redact_key; exit 1; }

duration_seconds() { # 45s / 10m / 1h -> seconds
  python3 - "$1" <<'PY'
import re, sys
m = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|s|m|h)", sys.argv[1].strip())
unit = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[m.group(2)]
print(float(m.group(1)) * unit)
PY
}

COMPOSE_FILES=(-f deploy/docker-compose.prod.yml -f deploy/docker-compose.e2e.yml)
RENDERED="$OUT/compose-rendered.yml"
remap_ports() { # $1 = src file, $2 = dst file — rewrite published host ports
  sed \
    -e 's/published: "5432"/published: "'"$PG_HOST_PORT"'"/' \
    -e 's/published: "6379"/published: "36479"/' \
    -e 's/published: "9090"/published: "'"$PROM_HOST_PORT"'"/' \
    -e 's/published: "9091"/published: "39191"/' \
    -e 's/published: "9093"/published: "39193"/' \
    -e 's/published: "9100"/published: "39200"/' \
    -e 's/published: "3001"/published: "33201"/' \
    -e 's/published: "18093"/published: "38193"/' \
    -e 's/published: "18094"/published: "38194"/' \
    -e 's/published: "80"/published: "31080"/' \
    -e 's/published: "443"/published: "31443"/' \
    "$1" > "$2"
}
render_compose() {
  docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" -f "$OUT/gateway-overlay.yml" config > "$RENDERED.raw"
  remap_ports "$RENDERED.raw" "$RENDERED"
}
compose() { docker compose -p "$PROJECT" -f "$RENDERED" "$@"; }

# --- preflight -----------------------------------------------------------------
log "N12-P04-T03 profiles run $RUN_ID (label=$LABEL profile=$PROFILE policy=$POLICY out=$OUT)"

command -v docker >/dev/null || fail "docker not found"
docker info >/dev/null 2>&1 || fail "docker daemon unreachable"
command -v python3 >/dev/null || fail "python3 not found"
command -v openssl >/dev/null || fail "openssl not found"
command -v curl >/dev/null || fail "curl not found"

# Remove leftovers of OUR OWN previous (possibly aborted) runs first — they
# hold the profiles host ports. Foreign projects are never touched.
log "removing leftovers of previous '$PROJECT' runs (own project only)"
docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

# Never touch foreign stands: refuse to start if any profiles-safe port is taken.
for port in "$PG_HOST_PORT" "$PROM_HOST_PORT" 36479 39191 39193 39200 33201 38193 38194 31080 31443; do
  if python3 -c "
import socket, sys
s = socket.socket(); s.settimeout(0.3)
try:
    s.connect(('127.0.0.1', $port)); sys.exit(1)
except OSError:
    sys.exit(0)
finally:
    s.close()
"; then :; else
    fail "127.0.0.1:$port is busy — another stand owns it; refusing to interfere"
  fi
done

if [[ ! -f deploy/.env || ! -f deploy/secrets/pg_uri ]]; then
  log "bootstrapping deploy secrets (init-secrets.sh)"
  bash scripts/deploy/init-secrets.sh
fi

# Linux hosts only: service images run as the container user "yabanin" and
# the prometheus image as "nobody", none of whom can read the mode-600
# secret files init-secrets.sh writes (same step as the demo/soak stands).
chmod 644 deploy/secrets/pg_uri deploy/secrets/cache_hmac deploy/secrets/session_key \
          deploy/secrets/kms_local_key deploy/secrets/metrics-bearer.key

# --- fresh stand ---------------------------------------------------------------
write_overlay() { # $1 = policy mode
  cat > "$OUT/gateway-overlay.yml" <<YAML
# Generated by tests/load/run-profiles.sh (run $RUN_ID) — do not edit.
#
# Dedicated subnet 10.208.0.0/24 (the soak stand uses 10.207.0.0/24 — the two
# must be able to coexist). The gateway's D-4 egress posture waives the
# reserved-range refusal ONLY for exact IP-literal pins, so both mock
# providers and slowmock are pinned and the seeded model URL uses the same
# literal.
services:
  gateway:
    environment:
      YABANIN_POLICY_MODE: "$1"
      # The PROVIDER ADDR is ALSO the egress allowlist seed (pkg/gateway
      # allowedUpstreamsForGateway: empty operator list → allowlist =
      # [provider] exactly; allowed_upstreams is a YAML-only knob). The
      # seeded model routes to slowmock, so slowmock MUST be the provider —
      # the quickstart composes the same invariant (provider == seed URL).
      YABANIN_PROVIDER_ADDR: "http://${SLOWMOCK_IP}:8081"
      YABANIN_EMBEDDER_BASE_URL: "http://${MOCKEMBEDDER_IP}:8082"
    deploy:
      resources:
        limits:
          # §15 line 129 burst peak ≈3000 concurrent 30 s SSE streams.
          # Measured: ~160 MB RSS at 600 streams (long30 smoke), so the peak
          # needs ~800 MB — the prod default 512M is cgroup-OOM-killed at
          # the peak (reproduced in both failure runs).
          # The dedicated profiles stand budgets 1280M; production compose
          # must be re-sized before real 100 RPS bursts (ops recommendation).
          memory: 1280M
  mock-embedder:
    networks:
      default:
        ipv4_address: ${MOCKEMBEDDER_IP}
  slowmock:
    image: yabanin-slowmock:latest
    networks:
      default:
        ipv4_address: ${SLOWMOCK_IP}
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:8081/healthz || exit 1"]
      interval: 5s
      timeout: 3s
      start_period: 5s
      retries: 3
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
networks:
  default:
    ipam:
      config:
        - subnet: 10.208.0.0/24
YAML
}

write_overlay "$POLICY"
log "rendering merged compose config with profiles-safe host ports"
render_compose
log "tearing down any previous '$PROJECT' stand (fresh volumes for honest numbers)"
compose down -v --remove-orphans >/dev/null 2>&1 || true

STAND_STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

log "building the duration-tunable slowmock image (tests/load/slowmock)"
docker build -q -t yabanin-slowmock:latest tests/load/slowmock > /dev/null

log "building ./yb (policy reconcile CLI; needed when policy != off)"
if [[ "$POLICY" != "off" ]]; then
  command -v go >/dev/null || fail "go not found (needed to build ./yb for policy reconcile)"
  go build -o yb ./cmd/yb
fi

log "pulling $K6_IMAGE"
docker pull -q "$K6_IMAGE" >/dev/null

log "building images + starting base services"
ensure_images() {
  local need=0 img
  for img in yabanin-gateway:latest yabanin-admin:latest yabanin-loggerd:latest; do
    docker image inspect "$img" >/dev/null 2>&1 || need=1
  done
  [[ "$need" -eq 1 ]] || { log "images present — skipping build (PROFILES_FORCE_BUILD=1 forces)"; return 0; }
  compose build gateway admin loggerd migrate seed mock-openai mock-embedder >/dev/null 2>&1 &
  local bpid=$!
  ( sleep "${BUILD_TIMEOUT:-900}"; kill "$bpid" 2>/dev/null ) &
  local wpid=$!
  wait "$bpid" || true
  kill "$wpid" 2>/dev/null || true
  for img in yabanin-gateway:latest yabanin-admin:latest yabanin-loggerd:latest; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "image $img missing and build did not produce it"
  done
}
ensure_images
for img in yabanin-gateway:latest yabanin-admin:latest yabanin-loggerd:latest; do
  docker image inspect "$img" --format '{{.Id}}' >> "$OUT/image-digests.txt"
done
compose up -d --wait postgres redis mock-openai mock-embedder slowmock

log "migrate"
compose up -d migrate
MIGRATE_CID=$(compose ps -q migrate)
st="unknown"
for _ in $(seq 1 60); do
  st=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$MIGRATE_CID" 2>/dev/null || echo "unknown 1")
  [[ "$st" == "exited 0" ]] && break
  case "$st" in exited*) compose logs migrate; fail "migrate failed ($st)" ;; esac
  sleep 2
done
[[ "$st" == "exited 0" ]] || fail "migrate did not finish in time"

PG_USER=$(sed -n 's|postgres://\([^:]*\):.*|\1|p' deploy/secrets/pg_uri)
PG_DB=$(sed -n 's|postgres://[^/]*/\([^?]*\).*|\1|p' deploy/secrets/pg_uri)
log "bootstrapping app role yabanin_app (db=$PG_DB)"
compose exec -T postgres psql -U "${PG_USER:-yabanin}" -d "${PG_DB:-yabanin}" \
  -v ON_ERROR_STOP=1 < deploy/quickstart/bootstrap-app-role.sql >/dev/null

log "seed (mock profile, org=$ORG_NAME, model=$SEED_MODEL → slowmock $SLOWMOCK_IP)"
openssl rand -hex 16 > "$OUT/admin-password"
compose run --rm --no-deps \
  -v "$OUT/admin-password:/run/secrets/profiles_admin_pw:ro" \
  -e YABANIN_ADMIN_PASSWORD_FILE=/run/secrets/profiles_admin_pw \
  -e SEED_PROFILE=mock \
  -e SEED_UPSTREAM_URL="http://${SLOWMOCK_IP}:8081" \
  -e SEED_ADMIN_EMAIL="$SEED_EMAIL" \
  -e SEED_ORG_NAME="$ORG_NAME" \
  -e SEED_MODEL="$SEED_MODEL" \
  seed 2>&1 | tee "$OUT/seed.log"
API_KEY=$(sed -n 's/.*API key (shown once, store it now): //p' "$OUT/seed.log" | head -1 | awk '{print $1}')
[[ -n "$API_KEY" ]] || fail "seed did not mint an API key (see $OUT/seed.log)"
rm -f "$OUT/admin-password"

log "starting serving plane"
compose up -d --wait gateway admin loggerd prometheus node-exporter
NETWORK=$(docker inspect -f '{{range $k,$_ := .NetworkSettings.Networks}}{{$k}}{{end}}' "$(compose ps -q gateway)")
[[ -n "$NETWORK" ]] || fail "profiles network not found"

wait_gateway() {
  for _ in $(seq 1 60); do
    if compose exec -T gateway wget -qO- http://localhost:8082/healthz 2>/dev/null | grep -q ok; then
      return 0
    fi
    sleep 2
  done
  return 1
}
wait_gateway || fail "gateway never became healthy"
sleep 5

chat_timed() { # measures a marker round-trip through the full stack; rc!=0 on any non-200
  local delay="$1" content="$2" start elapsed
  start=$(date +%s.%N)
  if ! compose exec -T gateway wget -qO- --header='Content-Type: application/json' \
    --header="Authorization: Bearer $API_KEY" \
    --post-data="{\"model\":\"$SEED_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"$content\"}],\"stream\":true}" \
    http://localhost:8082/v1/chat/completions 2>/dev/null | grep -q '"choices"'; then
    return 1
  fi
  elapsed=$(python3 -c "print(f'{$(date +%s.%N) - $start:.1f}')")
  echo "$elapsed"
}

log "sanity: instant round-trip"
t0=$(chat_timed "0s" "profiles sanity ping instant") \
  || fail "instant sanity round-trip failed (non-200 or no choices — see gateway logs; run with --keep to inspect)"
log "sanity OK (instant round-trip ${t0}s)"
log "sanity: [delay=2s] marker round-trip through slowmock (must take ≈2s wall-clock)"
t2=$(chat_timed "2s" "[delay=2s] profiles sanity ping delayed") \
  || fail "delay-marker sanity round-trip failed (non-200 — see gateway logs; run with --keep to inspect)"
python3 - "$t2" <<'PY' || fail "delay marker not honored end-to-end (2s round-trip took ${t2}s)"
import sys
v = float(sys.argv[1])
sys.exit(0 if 1.8 <= v <= 6.0 else 1)
PY
log "marker round-trip took ${t2}s (window honored)"

psql() { compose exec -T postgres psql -U yabanin -d yabanin -tAc "$1"; }

# --- policy pack (contract profile: local policies enabled) ---------------------
apply_policy() { # $1 = shadow|enforce
  local pm="$1" dir="$OUT/policies" file pg_uri nanos
  mkdir -p "$dir/$ORG_SLUG"
  file="$dir/$ORG_SLUG/sovereign-default.yaml"
  # Profiles adaptation of the shipped pack (repo file untouched): singular
  # builtin categories + conjunction-only decide DSL (bench/soak precedent).
  python3 - "$pm" deploy/policies/_pack/sovereign-default.yaml "$file" <<'PY'
import sys
pm, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src).read()
text = text.replace("mode: shadow", "mode: %s" % pm, 1)
text = text.replace("enabled: false", "enabled: true", 1)
old = "      deny  if findings.any(f -> f.category matches 'secrets.*' and f.severity == 'high')"
new = ("      deny  if findings.any(f -> f.category matches 'secret*' and f.severity == 'high')\n"
       "      deny  if findings.any(f -> f.category matches 'credential*' and f.severity == 'high')")
assert old in text, "pack decide line drifted; adapt apply_policy"
text = text.replace(old, new, 1)
open(dst, "w").write(text)
PY
  [[ "$(grep -c "^mode: $pm$" "$file")" == "1" && "$(grep -c '^enabled: true$' "$file")" == "1" ]] \
    || fail "policy file generation failed ($file)"
  pg_uri=$(sed "s|@postgres:5432|@127.0.0.1:$PG_HOST_PORT|" deploy/secrets/pg_uri)
  ./yb policies reconcile --pg-uri "$pg_uri" --dir "$dir" --org "$ORG_SLUG" \
    --apply --git-sha "profiles-$RUN_ID" --created-by "n12p04t03-profiles" 2>&1 | tee "$OUT/policy-reconcile-$pm.txt"
  nanos=$(python3 -c 'import time; print(time.time_ns())')
  compose exec -T redis redis-cli SET "policystore:ver:$(psql "SELECT id::text FROM organizations WHERE slug='$ORG_SLUG'")" "$nanos" EX 604800 >/dev/null
  sleep 2
}

case "$POLICY" in
  off) log "policy pipeline OFF (disclosed in report)" ;;
  shadow|enforce)
    apply_policy "$POLICY"
    if [[ "$POLICY" == "shadow" ]]; then
      t=$(chat_timed "0s" "profiles policy probe instant")
      log "shadow policy active: probe 200 OK in ${t}s (flag-only)"
    fi
    ;;
  *) fail "unknown policy mode: $POLICY" ;;
esac

# --- k6 helpers ------------------------------------------------------------------
PROM_URL="http://127.0.0.1:$PROM_HOST_PORT"
LAST_RECOVER_RC=0

run_k6() { # $1 script, $2 out name, $3 out env-var, $4... extra env "K=V"
  local script="$1" name="$2" outvar="$3"; shift 3
  local -a cmd=(docker run --rm --network "$NETWORK"
    --user "$(id -u):$(id -g)"
    -v "$ROOT/tests/load:/t:ro" -v "$OUT:/out"
    -e BASE_URL="http://gateway:8082"
    -e API_KEY="$API_KEY"
    -e PROFILE_MODEL="$SEED_MODEL"
    -e "$outvar=/out/$name.summary.json")
  local e
  for e in "$@"; do cmd+=(-e "$e"); done
  cmd+=("$K6_IMAGE" "run" "-q" "/t/$script")
  "${cmd[@]}" 2>&1 | tee "$OUT/$name.k6.log"
}

warmup_k6() { # 30s of instant 20-rps traffic via the burst profile file, discarded
  log "warmup: 30s × 20 rps instant responses (results discarded)"
  set +e
  run_k6 soak_burst.js warmup BURST_OUT \
    "BURST_RPS=20" "BURST_LEN=30s" "BURST_COUNT=1" "BURST_RESP=0" \
    "BURST_PRE_VUS=40" "BURST_MAX_VUS=60" > "$OUT/warmup.k6.log" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    log "WARNING: warmup rc=$rc (discarded, but the stand may be unhealthy — see $OUT/warmup.k6.log)"
    tail -5 "$OUT/warmup.k6.log" || true
  fi
  log "warmup done (rc=$rc, discarded)"
  sleep 5
}

capture_baseline() { # $1 = profile name
  log "capturing pre-load backlog baseline for $1"
  python3 tests/load/profile_collect.py --prom "$PROM_URL" baseline \
    --samples 5 --interval 3 --out "$OUT/$1.baseline.json" > /dev/null
  python3 -c "import json;b=json.load(open('$OUT/$1.baseline.json'));assert b['series_observed'],'backlog series absent';print('baseline',b['min'],'..',b['max'])"
}

recover_watch() { # $1 = profile name, $2 = timeout seconds; sets LAST_RECOVER_RC
  log "watching settlement backlog return to baseline (timeout ${2}s)"
  set +e
  python3 tests/load/profile_collect.py --prom "$PROM_URL" watch \
    --baseline-file "$OUT/$1.baseline.json" \
    --timeout "$2" --interval 10 --stable 2 \
    --out "$OUT/$1.recovery.json"
  LAST_RECOVER_RC=$?
  set -e
  [[ "$LAST_RECOVER_RC" -eq 0 ]] || log "$1: backlog did NOT return to baseline within ${2}s — recording the goal failure"
}

saturation_range() { # $1 = profile name, $2/$3 = epoch start/end
  python3 tests/load/profile_collect.py --prom "$PROM_URL" range \
    --start "$2" --end "$3" --step 15 --out "$OUT/$1.saturation.json" > /dev/null
}

declare -A PROFILE_RC

profile_burst() {
  log "=== PROFILE burst: 3 × 100 RPS × 60s bursts, 30s responses, 300s gaps (§15 line 129) ==="
  capture_baseline burst
  local start_s end_s
  start_s=$(date -u +%s)
  set +e
  # NOTE: optional overrides stay UNQUOTED — a quoted "${VAR:+word}" keeps an
  # empty array element when VAR is unset, and `docker run -e ""` dies (rc=125).
  run_k6 soak_burst.js burst BURST_OUT \
    ${BURST_RPS:+BURST_RPS=$BURST_RPS} ${BURST_LEN:+BURST_LEN=$BURST_LEN} \
    ${BURST_GAP:+BURST_GAP=$BURST_GAP} ${BURST_COUNT:+BURST_COUNT=$BURST_COUNT} \
    ${BURST_RESP:+BURST_RESP=$BURST_RESP} ${BURST_MAX_VUS:+BURST_MAX_VUS=$BURST_MAX_VUS}
  PROFILE_RC[burst]=$?
  set -e
  end_s=$(date -u +%s)
  log "burst k6 finished rc=${PROFILE_RC[burst]}"
  recover_watch burst 300
  if [[ "$LAST_RECOVER_RC" -gt "${PROFILE_RC[burst]:-0}" ]]; then
    PROFILE_RC[burst]=$LAST_RECOVER_RC
  fi
  saturation_range burst "$start_s" "$end_s"
}

profile_long() { # $1 = long30|long120
  local mode="$1"
  log "=== PROFILE $mode: 20 RPS × default window of ${mode#long} responses (contract §15 line 131) ==="
  capture_baseline "$mode"
  local start_s end_s
  start_s=$(date -u +%s)
  set +e
  run_k6 soak_longres.js "$mode" LONG_OUT \
    "LONG_MODE=$mode" \
    ${LONG_RATE:+LONG_RATE=$LONG_RATE} ${LONG_WINDOW:+LONG_WINDOW=$LONG_WINDOW} \
    ${LONG_MAX_VUS:+LONG_MAX_VUS=$LONG_MAX_VUS}
  PROFILE_RC[$mode]=$?
  set -e
  end_s=$(date -u +%s)
  log "$mode k6 finished rc=${PROFILE_RC[$mode]}"
  recover_watch "$mode" "$([ "$mode" = "long120" ] && echo 120 || echo 60)"
  saturation_range "$mode" "$start_s" "$end_s"
}

# --- warmup (unmeasured) + pre snapshot -------------------------------------------
warmup_k6
log "capturing pre-run metrics snapshot"
python3 tests/load/profile_collect.py --prom "$PROM_URL" snapshot --out "$OUT/pre.json" > /dev/null

# --- measured profiles -------------------------------------------------------------
case "$PROFILE" in
  burst)   profile_burst ;;
  long30)  profile_long long30 ;;
  long120) profile_long long120 ;;
  all)     profile_burst; profile_long long30; profile_long long120 ;;
  *) fail "unknown --profile: $PROFILE" ;;
esac

# --- post-run captures -------------------------------------------------------------
python3 tests/load/profile_collect.py --prom "$PROM_URL" snapshot --out "$OUT/post.json" > /dev/null

# --- report -----------------------------------------------------------------------
set +e
python3 - "$OUT" "$RUN_ID" "$LABEL" "$PROFILE" "$POLICY" <<'PY'
import json, os, platform, subprocess, sys

out, run_id, label, profile, policy = sys.argv[1:6]

def load(path, default=None):
    p = os.path.join(out, path)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    return default

def sh(c):
    try:
        return subprocess.check_output(c, shell=True, text=True).strip()
    except Exception:
        return ""

names = {
    "burst": {"title": "3×100 RPS × 60s bursts, 30s responses, 300s gaps (§15 line 129/136)", "goal_watch_s": 300},
    "long30": {"title": "20 RPS × 5m window of 30s responses — in-flight ≈600 (§15 line 131)", "goal_watch_s": 60},
    "long120": {"title": "20 RPS × 2m window of 120s responses — in-flight ≈2400 (§15 line 131, separate profile)", "goal_watch_s": 120},
}
if profile != "all":
    names = {k: v for k, v in names.items() if k == profile}

profiles = {}
overall_fail = False
for name, meta in names.items():
    summary = load(f"{name}.summary.json") or {}
    baseline = load(f"{name}.baseline.json") or {}
    recovery = load(f"{name}.recovery.json") or {}
    sat = load(f"{name}.saturation.json") or {}
    reasons = []
    raw = summary.get("raw_rates", {})
    wall = summary.get("wall_clock", {})
    if summary.get("wall_clock", {}).get("integrity") != "ok":
        reasons.append("wall-clock integrity FAIL (elapsed below nominal)")
    if raw.get("dropped_iterations") not in (None, 0):
        reasons.append(f"dropped_iterations={raw.get('dropped_iterations')} (generator/stack could not hold the arrival rate)")
    ratio = raw.get("completion_ratio")
    if ratio is not None and ratio < 0.999:
        reasons.append(f"completion ratio {ratio:.4f} < 1 (some launched iterations did not complete)")
    extras = raw.get("boundary_extras")
    allowance = raw.get("boundary_extras_allowance")
    if extras is not None and allowance is not None and extras > allowance:
        reasons.append(f"boundary_extras={extras} exceeds allowance {allowance} (arrival accounting anomaly)")
    errs = summary.get("errors", {})
    fail_rate = errs.get("http_req_failed_rate")
    budget = 0.01 if name == "burst" else 0.001
    if fail_rate is not None and fail_rate >= budget:
        reasons.append(f"http_req_failed rate {fail_rate:.4f} >= {budget} budget")
    if not recovery:
        reasons.append("recovery watch absent (backlog series missing — observability gap)")
    elif name == "burst":
        if not recovery.get("series_ever_observed", False):
            reasons.append("settlement backlog series never observed — backlog criterion inconclusive")
        elif not recovery.get("recovered", False):
            reasons.append(f"backlog did NOT return to baseline {recovery.get('baseline')} within the 5-min goal (§15 line 136 miss)")
    profiles[name] = {
        "title": meta["title"],
        "verdict": "PASS" if not reasons else "FAIL",
        "failure_reasons": reasons,
        "raw_rates": raw,
        "latency_ms": summary.get("latency_ms", {}),
        "errors": errs,
        "wall_clock": wall,
        "backlog_recovery": {
            "baseline_range": [baseline.get("min"), baseline.get("max")],
            "recovered": (recovery or {}).get("recovered"),
            "recovered_after_s": (recovery or {}).get("recovered_after_s"),
            "goal_s": meta["goal_watch_s"],
        },
        "saturation": {k: v for k, v in (sat.get("metrics") or {}).items() if not k.startswith("settlement")},
    }
    if profiles[name]["verdict"] == "FAIL":
        overall_fail = True

# silent-failure + pipeline deltas across the whole run (pre vs post snapshot)
pre = load("pre.json") or {}
post = load("post.json") or {}
def delta(metric):
    a = (pre.get("metrics", {}).get(metric) or {}).get("value")
    b = (post.get("metrics", {}).get(metric) or {}).get("value")
    if a is None or b is None:
        return None
    return b - a
counters = {m: delta(m) for m in (
    "gateway_http_requests_total", "gateway_reservations_denied_total",
    "gateway_reservations_would_deny_total", "gateway_key_ratelimit_denied_total",
    "gateway_upstream_requests_total", "gateway_upstream_tokens_total",
    "gateway_silent_failures_total", "gateway_loggerd_events_consumed_total")}
if counters.get("gateway_silent_failures_total"):
    overall_fail = True
    for name in profiles:
        profiles[name]["failure_reasons"].append(
            f"gateway_silent_failures_total increased by {counters['gateway_silent_failures_total']:.0f} during the run")

report = {
    "run_id": run_id,
    "card": "N12-P04-T03",
    "label": label,
    "profile": profile,
    "verdict": "FAIL" if overall_fail else "PASS",
    "profiles": profiles,
    "policy": policy,
    "counters_delta_during_run": counters,
    "provenance": {
        "git": {"sha": sh("git rev-parse HEAD"), "branch": sh("git rev-parse --abbrev-ref HEAD")},
        "host": {"sys": platform.platform(), "machine": platform.machine(), "cpus": os.cpu_count()},
        "docker": sh("docker version --format '{{.Server.Version}}'"),
        "k6_image": os.environ.get("K6_IMAGE", ""),
        "images": sh(f"cat {out}/image-digests.txt 2>/dev/null").splitlines(),
    },
    "note": "INTERNAL profiles stand. Machine-dependent numbers; publication is owner-gated. DO NOT publish.",
}
with open(os.path.join(out, "profiles-report.json"), "w") as fh:
    json.dump(report, fh, indent=2)

lines = [f"N12-P04-T03 profiles run {run_id} (label {label}, profile {profile})", ""]
for name, p in profiles.items():
    lines.append(f"[{name}] verdict {p['verdict']}")
    lines.append(f"  {p['title']}")
    raw = p["raw_rates"]
    lines.append(f"  dropped={raw.get('dropped_iterations')} completed={raw.get('completed_iterations')} (ratio {raw.get('completion_ratio', 0):.4f}, boundary extras {raw.get('boundary_extras')}/{raw.get('boundary_extras_allowance')})")
    lat = p.get("latency_ms") or {}
    lines.append(f"  p95 {(lat.get('p95') or 0):.0f} ms / p99 {(lat.get('p99') or 0):.0f} ms / max {(lat.get('max') or 0):.0f} ms")
    br = p["backlog_recovery"]
    lines.append(f"  backlog baseline {br['baseline_range']} → recovered={br['recovered']} (goal ≤{br['goal_s']}s)")
    if p["failure_reasons"]:
        for r in p["failure_reasons"]:
            lines.append(f"  FAIL: {r}")
    lines.append("")
txt = "\n".join(lines)
with open(os.path.join(out, "SUMMARY.txt"), "w") as fh:
    fh.write(txt + "\n")
print(txt)

gw_sat = profiles.get("burst", {}).get("saturation", {})
print("burst saturation (during measured window):")
rss = gw_sat.get("gateway_rss_bytes") or {}
cpu = gw_sat.get("gateway_cpu_seconds") or {}
go = gw_sat.get("gateway_goroutines") or {}
print(f"  gateway rss   min {(rss.get('min') or 0)/1e6:.1f} MB max {(rss.get('max') or 0)/1e6:.1f} MB")
print(f"  gateway cpu   {(cpu.get('first') or 0):.1f}s → {(cpu.get('last') or 0):.1f}s (Δ{(cpu.get('delta_last_minus_first') or 0):.1f}s)")
print(f"  goroutines    max {go.get('max') or 0:.0f}")
print("\nINTERNAL ONLY — machine-dependent, owner-gated publication.")

sys.exit(1 if overall_fail else 0)
PY
REPORT_RC=$?
set -e

# --- teardown ---------------------------------------------------------------------
if [[ "$KEEP" -eq 1 ]]; then
  log "--keep: stand left running (compose project '$PROJECT'); tear down with: docker compose -p $PROJECT -f deploy/docker-compose.prod.yml -f deploy/docker-compose.e2e.yml down -v"
else
  log "tearing down the profiles stand"
  compose down -v --remove-orphans >/dev/null 2>&1 || true
fi
redact_key

if [[ "$REPORT_RC" -ne 0 ]]; then
  fail "profiles run FAILED its acceptance criteria (see $OUT/SUMMARY.txt)"
fi
log "profiles run complete: artifacts in $OUT (gitignored — do not commit run outputs)"
