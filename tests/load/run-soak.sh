#!/usr/bin/env bash
#
# N12-P04-T02 soak/uptime runner: sustained open-arrival acceptance/soak at a
# fixed new-request rate (default 20 new req/s per the I48-proposed profile,
# PRODUCT-CONTRACT §15) against a REAL stack for a REAL wall-clock duration.
#
# Brings up the mock-profile stack (docker-compose.prod.yml + e2e overlay)
# under an ISOLATED compose project (-p soak — never touches other stands),
# seeds a throwaway soak org, applies the sovereign-default policy pack in
# shadow mode (contract profile: auth, budget, audit, history, local policies
# enabled), captures a pre-load backlog baseline, runs the warmup + measured
# k6 profile (soak_steady.js), watches the settlement backlog return to the
# baseline range (≤5 min proposed goal — a miss is recorded, not hidden),
# and emits a report whose wall-clock block proves actual elapsed >= nominal.
#
# Honesty rules (packet negative criteria):
#   - NO time acceleration exists anywhere in this harness: k6 and the stack
#     run on real wall-clock, and the report FAILS if actual elapsed < nominal.
#   - Generator/VU shortfall cannot pass as a sustained rate: the profile
#     thresholds dropped_iterations==0 and a completion-rate floor (G1+G2).
#
# Usage: run-soak.sh [--rps N] [--duration 1h|8h|...] [--label acceptance|soak|validation]
#                    [--warmup 120s] [--policy off|shadow|enforce]
#                    [--recover-watch 300s] [--keep]
# Requirements: docker + compose, go (builds ./yb when policy != off), python3, openssl, curl.
#
# Run outputs land in artifacts/soak/<run-id>/ (gitignored). Do not commit them.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

# --- configuration -------------------------------------------------------------
PROJECT="soak"
LABEL="acceptance"
RPS="${SOAK_RPS:-20}"
DURATION="${SOAK_DURATION:-1h}"
WARMUP="${SOAK_WARMUP:-120s}"
POLICY="${SOAK_POLICY:-shadow}"
RECOVER_WATCH="${SOAK_RECOVER_WATCH:-300s}"
KEEP=0
ORG_SLUG="soak"
ORG_NAME="Soak"
SEED_EMAIL="soak@yabanin.internal"
SEED_MODEL="soak-model"
K6_IMAGE="${K6_IMAGE:-grafana/k6:0.53.0}"
# Soak-safe host ports (3xxxx — disjoint from the bench stand's 2xxxx range).
PG_HOST_PORT="${PG_HOST_PORT:-35432}"
PROM_HOST_PORT="${PROM_HOST_PORT:-39090}"
export RPS DURATION K6_IMAGE

usage() { sed -n '2,24p' "$0"; exit 0; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rps) RPS="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --policy) POLICY="$2"; shift 2 ;;
    --recover-watch) RECOVER_WATCH="$2"; shift 2 ;;
    --keep|--skip-teardown) KEEP=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown flag: $1" >&2; usage ;;
  esac
done

RUN_ID="$(date -u +%Y%m%d-%H%M%S)-soak-$(git rev-parse --short HEAD)"
OUT="$ROOT/artifacts/soak/$RUN_ID"
mkdir -p "$OUT"
LOG="$OUT/run.log"
exec > >(tee -a "$LOG") 2>&1

log()  { printf '\n[soak] %s\n' "$*"; }
API_KEY=""
redact_key() { # the minted key is a throwaway stand credential; artifacts must not carry it
  [[ -n "$API_KEY" ]] || return 0
  sed -i "s|$API_KEY|[REDACTED_SOAK_KEY]|g" "$LOG" 2>/dev/null || true
  [[ -f "$OUT/seed.log" ]] && sed -i "s|$API_KEY|[REDACTED_SOAK_KEY]|g" "$OUT/seed.log" 2>/dev/null || true
}
fail() { printf '\n[soak] FATAL: %s\n' "$*" >&2; redact_key; exit 1; }

duration_seconds() { # 45s / 10m / 1h / 8h -> seconds
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
    -e 's/published: "6379"/published: "36379"/' \
    -e 's/published: "9090"/published: "'"$PROM_HOST_PORT"'"/' \
    -e 's/published: "9091"/published: "39091"/' \
    -e 's/published: "9093"/published: "39093"/' \
    -e 's/published: "9100"/published: "39100"/' \
    -e 's/published: "3001"/published: "33001"/' \
    -e 's/published: "18093"/published: "38093"/' \
    -e 's/published: "18094"/published: "38094"/' \
    -e 's/published: "80"/published: "30080"/' \
    -e 's/published: "443"/published: "30443"/' \
    "$1" > "$2"
}
render_compose() {
  docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" -f "$OUT/gateway-overlay.yml" config > "$RENDERED.raw"
  remap_ports "$RENDERED.raw" "$RENDERED"
}
compose() { docker compose -p "$PROJECT" -f "$RENDERED" "$@"; }

# --- preflight -----------------------------------------------------------------
log "N12-P04-T02 soak run $RUN_ID (label=$LABEL rps=$RPS duration=$DURATION policy=$POLICY out=$OUT)"

command -v docker >/dev/null || fail "docker not found"
docker info >/dev/null 2>&1 || fail "docker daemon unreachable"
command -v python3 >/dev/null || fail "python3 not found"
command -v openssl >/dev/null || fail "openssl not found"
command -v curl >/dev/null || fail "curl not found"

# Remove leftovers of OUR OWN previous (possibly aborted) runs first — they
# hold the soak host ports. Foreign projects are never touched.
log "removing leftovers of previous '$PROJECT' runs (own project only)"
docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

# Never touch foreign stands: refuse to start if any soak-safe port is taken.
for port in "$PG_HOST_PORT" "$PROM_HOST_PORT" 36379 39091 39093 39100 33001 38093 38094 30080 30443; do
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
# secret files init-secrets.sh writes (DEMO.md documents the same step for
# the demo stack). These file-read secrets hold only machine-local synthetic
# random values — make them group/other-readable (with 600 the gateway/
# migrate boot fails "pg_uri is required" and the prometheus gateway job
# 401s, leaving the packet's gateway/job series absent).
chmod 644 deploy/secrets/pg_uri deploy/secrets/cache_hmac deploy/secrets/session_key \
          deploy/secrets/kms_local_key deploy/secrets/metrics-bearer.key

# --- fresh stand ---------------------------------------------------------------
write_overlay() { # $1 = policy mode
  cat > "$OUT/gateway-overlay.yml" <<YAML
# Generated by tests/load/run-soak.sh (run $RUN_ID) — do not edit.
#
# The mock upstream is wired the canonical quickstart way (see the header of
# deploy/quickstart/docker-compose.yml): a dedicated 10.207.0.0/24 subnet
# pins mock-openai at the literal 10.207.0.9. The gateway's D-4 egress
# posture waives the reserved-range refusal ONLY for exact IP-literal pins —
# a compose DNS name in a private range is refused at dial time (pkg/ssrf
# anti-rebind guard), so provider origin and the seeded model URL must both
# use the same literal.
services:
  gateway:
    environment:
      YABANIN_POLICY_MODE: "$1"
      YABANIN_PROVIDER_ADDR: "http://10.207.0.9:8081"
  mock-openai:
    networks:
      default:
        ipv4_address: 10.207.0.9
networks:
  default:
    ipam:
      config:
        - subnet: 10.207.0.0/24
YAML
}

write_overlay "$POLICY"
log "rendering merged compose config with soak-safe host ports"
render_compose
log "tearing down any previous '$PROJECT' stand (fresh volumes for honest numbers)"
compose down -v --remove-orphans >/dev/null 2>&1 || true

STAND_STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

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
  [[ "$need" -eq 1 ]] || { log "images present — skipping build (SOAK_FORCE_BUILD=1 forces)"; return 0; }
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
compose up -d --wait postgres redis mock-openai mock-embedder

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

log "seed (mock profile, org=$ORG_NAME, model=$SEED_MODEL)"
openssl rand -hex 16 > "$OUT/admin-password"
compose run --rm --no-deps \
  -v "$OUT/admin-password:/run/secrets/soak_admin_pw:ro" \
  -e YABANIN_ADMIN_PASSWORD_FILE=/run/secrets/soak_admin_pw \
  -e SEED_PROFILE=mock \
  -e SEED_UPSTREAM_URL="http://10.207.0.9:8081" \
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
[[ -n "$NETWORK" ]] || fail "soak network not found"

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
sleep 5 # warmup

chat_ok() { # 0 when the model answers 200 with a choices body
  compose exec -T gateway wget -qO- --header='Content-Type: application/json' \
    --header="Authorization: Bearer $API_KEY" \
    --post-data="{\"model\":\"$1\",\"messages\":[{\"role\":\"user\",\"content\":\"$2\"}],\"max_tokens\":16}" \
    http://localhost:8082/v1/chat/completions 2>/dev/null | grep -q '"choices"'
}
log "sanity: seed model round-trip"
chat_ok "$SEED_MODEL" "soak sanity ping" || fail "seed model $SEED_MODEL does not serve 200 — aborting before load"
log "sanity OK"

psql() { compose exec -T postgres psql -U yabanin -d yabanin -tAc "$1"; }

# --- policy pack (contract profile: local policies enabled) ---------------------
apply_policy() { # $1 = shadow|enforce
  local pm="$1" dir="$OUT/policies" file pg_uri nanos
  mkdir -p "$dir/$ORG_SLUG"
  file="$dir/$ORG_SLUG/sovereign-default.yaml"
  # Bench adaptation of the shipped pack (repo file untouched): singular
  # builtin categories + conjunction-only decide DSL (see run-bench.sh).
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
    --apply --git-sha "soak-$RUN_ID" --created-by "n12p04t02-soak" 2>&1 | tee "$OUT/policy-reconcile-$pm.txt"
  nanos=$(python3 -c 'import time; print(time.time_ns())')
  compose exec -T redis redis-cli SET "policystore:ver:$(psql "SELECT id::text FROM organizations WHERE slug='$ORG_SLUG'")" "$nanos" EX 604800 >/dev/null
  sleep 2
}

case "$POLICY" in
  off) log "policy pipeline OFF (disclosed in report)" ;;
  shadow|enforce)
    apply_policy "$POLICY"
    if [[ "$POLICY" == "shadow" ]]; then
      chat_ok "$SEED_MODEL" "soak policy probe" || fail "shadow policy probe failed (shadow must never block)"
      log "shadow policy active: probe 200 OK (flag-only)"
    fi
    ;;
  *) fail "unknown policy mode: $POLICY" ;;
esac

# --- baselines ------------------------------------------------------------------
PROM_URL="http://127.0.0.1:$PROM_HOST_PORT"
log "capturing pre-load baseline (metrics snapshot + backlog range)"
python3 tests/load/soak_collect.py --prom "$PROM_URL" snapshot --out "$OUT/pre.json"
python3 tests/load/soak_collect.py --prom "$PROM_URL" baseline --samples 5 --interval 3 --out "$OUT/baseline.json"

run_k6() { # $1 out name, $2 duration, $3 extra env "K=V K2=V2" (may be empty)
  local name="$1" dur="$2" extra="${3:-}"
  log "k6: soak_steady (rps=$RPS, duration=$dur)"
  local -a cmd=(docker run --rm --network "$NETWORK"
    --user "$(id -u):$(id -g)"
    -v "$ROOT/tests/load:/t:ro" -v "$OUT:/out"
    -e BASE_URL="http://gateway:8082"
    -e API_KEY="$API_KEY"
    -e SOAK_MODEL="$SEED_MODEL"
    -e SOAK_RPS="$RPS" -e SOAK_DURATION="$dur"
    -e SOAK_OUT="/out/$name.summary.json")
  if [[ -n "$extra" ]]; then
    local e
    for e in $extra; do cmd+=(-e "$e"); done
  fi
  cmd+=("$K6_IMAGE" run -q "/t/soak_steady.js")
  "${cmd[@]}" 2>&1 | tee "$OUT/$name.k6.log"
}

# --- warmup (unmeasured) --------------------------------------------------------
if [[ "$WARMUP" != "0s" && "$WARMUP" != "0" ]]; then
  log "warmup ${WARMUP} at ${RPS} rps (results discarded)"
  set +e
  run_k6 warmup "$WARMUP" >/dev/null 2>&1
  warmup_rc=$?
  set -e
  log "warmup done (rc=$warmup_rc, discarded)"
  sleep 3
fi

# --- measured run ---------------------------------------------------------------
NOMINAL_S=$(duration_seconds "$DURATION")
WALL_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
WALL_START_S=$(date -u +%s)
log "MEASURED RUN: ${RPS} new req/s × ${DURATION} (real wall-clock), label=$LABEL"
set +e
run_k6 soak "$DURATION"
K6_RC=$?
set -e
WALL_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
WALL_END_S=$(date -u +%s)
HARNESS_ELAPSED=$((WALL_END_S - WALL_START_S))
log "measured run finished: k6 rc=$K6_RC, wall-clock elapsed ${HARNESS_ELAPSED}s (nominal ${NOMINAL_S}s)"

# --- backlog recovery watch (packet acceptance: ≤5 min to baseline, else FAIL) ---
log "watching settlement backlog return to baseline (timeout $RECOVER_WATCH)"
set +e
python3 tests/load/soak_collect.py --prom "$PROM_URL" watch \
  --baseline-file "$OUT/baseline.json" \
  --timeout "$(duration_seconds "$RECOVER_WATCH")" \
  --interval 10 --stable 2 \
  --out "$OUT/recovery.json"
WATCH_RC=$?
set -e
[[ "$WATCH_RC" -eq 0 ]] || log "backlog did NOT return to baseline within $RECOVER_WATCH — recording the goal failure"

# --- post-run captures ------------------------------------------------------------
set +e
python3 tests/load/soak_collect.py --prom "$PROM_URL" snapshot --out "$OUT/post.json"
python3 tests/load/soak_collect.py --prom "$PROM_URL" range \
  --start "$WALL_START_S" --end "$WALL_END_S" --step 30 --out "$OUT/saturation.json"
set -e

# --- report -----------------------------------------------------------------------
set +e
python3 - "$OUT" "$RUN_ID" "$LABEL" "$RPS" "$DURATION" "$WARMUP" "$POLICY" \
  "$WALL_START" "$WALL_END" "$K6_RC" "$WATCH_RC" "$HARNESS_ELAPSED" <<'PY'
import json, os, platform, re, subprocess, sys

out, run_id, label, rps, duration, warmup, policy = sys.argv[1:8]
wall_start, wall_end, k6_rc, watch_rc, harness_elapsed = sys.argv[8], sys.argv[9], int(sys.argv[10]), int(sys.argv[11]), int(sys.argv[12])
rps, harness_elapsed = int(rps), int(harness_elapsed)

def load(name, default=None):
    p = os.path.join(out, name)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    return default

def nominal_seconds(s):
    units = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|s|m|h)", s.strip())
    return float(m.group(1)) * units[m.group(2)]

summary = load("soak.summary.json") or {}
recovery = load("recovery.json") or {}
baseline = load("baseline.json") or {}
pre = load("pre.json") or {}
post = load("post.json") or {}
saturation = load("saturation.json") or {}
nominal = nominal_seconds(duration)

k6_wall = summary.get("wall_clock", {})
k6_integrity = k6_wall.get("integrity") == "ok"
harness_integrity = harness_elapsed >= nominal - 10
integrity_ok = k6_integrity and harness_integrity

raw = summary.get("raw_rates", {})
lat = summary.get("latency_ms", {})
errs = summary.get("errors", {})

def delta(metric):
    a = (pre.get("metrics", {}).get(metric) or {}).get("value")
    b = (post.get("metrics", {}).get(metric) or {}).get("value")
    if a is None or b is None:
        return None
    return b - a

deltas = {m: delta(m) for m in (
    "gateway_http_requests_total", "gateway_reservations_denied_total",
    "gateway_reservations_would_deny_total", "gateway_key_ratelimit_denied_total",
    "gateway_upstream_requests_total", "gateway_upstream_tokens_total",
    "gateway_silent_failures_total", "gateway_loggerd_events_consumed_total")}
sat_delta = {m: delta(m) for m in ("gateway_rss_bytes", "gateway_cpu_seconds", "gateway_goroutines", "loggerd_rss_bytes", "loggerd_goroutines")}

if not recovery:
    recovery_state = "metric_absent"
elif recovery.get("recovered"):
    recovery_state = "recovered"
elif not recovery.get("series_ever_observed", True):
    recovery_state = "metric_absent"
else:
    recovery_state = "NOT_RECOVERED"

def sh(c):
    try:
        return subprocess.check_output(c, shell=True, text=True).strip()
    except Exception:
        return ""

reasons = []
if k6_rc != 0:
    reasons.append(f"k6 thresholds failed (rc={k6_rc})")
if not integrity_ok:
    reasons.append(f"wall-clock integrity: k6={k6_wall.get('integrity')} harness_elapsed={harness_elapsed}s nominal={nominal:.0f}s")
if recovery_state == "NOT_RECOVERED":
    reasons.append(f"backlog did not return to baseline {baseline.get('min')}..{baseline.get('max')} within watch timeout")
if recovery_state == "metric_absent":
    reasons.append("settlement backlog series absent — backlog criterion inconclusive (observability gap)")
gw_series = ((pre.get("metrics", {}).get("gateway_http_requests_total") or {}).get("series") or {})
if not gw_series:
    reasons.append("gateway job series absent in prometheus — scrape never observed; all gateway counters inconclusive")
silent = deltas.get("gateway_silent_failures_total")
if silent:
    reasons.append(f"gateway_silent_failures_total increased by {silent:.0f} during the run")
up_delta = deltas.get("gateway_upstream_requests_total")
if not up_delta:
    reasons.append(f"gateway_upstream_requests_total delta {up_delta} — no upstream traffic observed despite load (pipeline or scrape gap)")
cons_delta = deltas.get("gateway_loggerd_events_consumed_total")
if not cons_delta:
    reasons.append(f"gateway_loggerd_events_consumed_total delta {cons_delta} — consumer did not process events during the run (pipeline or scrape gap)")

verdict = "PASS" if not reasons else "FAIL"

report = {
    "run_id": run_id,
    "card": "N12-P04-T02",
    "label": label,
    "verdict": verdict,
    "failure_reasons": reasons,
    "profile": {"rps": rps, "duration": duration, "nominal_seconds": nominal,
                "warmup": warmup, "policy": policy,
                "model": "soak-model", "scenario": "constant-arrival-rate open-arrival, unique prompts (cache-miss primary)"},
    "wall_clock": {
        "started_utc": wall_start, "finished_utc": wall_end,
        "harness_elapsed_s": harness_elapsed,
        "k6_elapsed_s": summary.get("wall_clock", {}).get("elapsed_s"),
        "integrity_ok": integrity_ok,
        "note": "no virtual/accelerated clock exists in this harness; integrity is proven both inside k6 and outside it",
    },
    "raw_rates": raw,
    "latency_ms": lat,
    "errors": errs,
    "dropped_iterations": raw.get("dropped_iterations"),
    "backlog_recovery": {
        "baseline_range": [baseline.get("min"), baseline.get("max")],
        "state": recovery_state,
        "recovered": recovery.get("recovered"),
        "elapsed_s": recovery.get("elapsed_s"),
        "timeline_points": len(recovery.get("timeline", [])),
    },
    "counters_delta_during_run": deltas,
    "saturation_delta_start_end": sat_delta,
    "saturation_timeline": (saturation.get("metrics") or {}),
    "provenance": {
        "git": {"sha": sh("git rev-parse HEAD"), "branch": sh("git rev-parse --abbrev-ref HEAD")},
        "host": {"sys": platform.platform(), "machine": platform.machine(), "cpus": os.cpu_count(),
                 "mem_bytes": sh("free -b | awk 'NR==2{print $7}'")},
        "docker": sh("docker version --format '{{.Server.Version}}'"),
        "k6_image": os.environ.get("K6_IMAGE", ""),
        "images": sh(f"cat {out}/image-digests.txt 2>/dev/null").splitlines(),
    },
    "note": "INTERNAL soak stand. Machine-dependent numbers; publication is owner-gated. DO NOT publish.",
}
with open(os.path.join(out, "soak-report.json"), "w") as fh:
    json.dump(report, fh, indent=2)

lines = [f"N12-P04-T02 soak run {run_id} (label {label})", ""]
lines.append(f"verdict        {verdict}" + (f" — {'; '.join(reasons)}" if reasons else ""))
lines.append(f"profile        {rps} new req/s × {duration} (policy {policy})")
lines.append(f"dropped iters  {raw.get('dropped_iterations')} (must be 0)")
lines.append(f"completed      {raw.get('completed_iterations')} ({(raw.get('completion_rps') or 0):.2f}/s vs configured {rps}/s)")
lines.append(f"latency p50/95 {(lat.get('p50') or 0):.1f} ms / {(lat.get('p95') or 0):.1f} ms   p99 {(lat.get('p99') or 0):.1f} ms")
lines.append(f"failed reqs    {(errs.get('http_req_failed_rate') or 0)*100:.3f} %   checks {(errs.get('checks_rate') or 0)*100:.2f} %")
lines.append(f"wall-clock     {harness_elapsed}s elapsed vs {nominal:.0f}s nominal → {'OK' if integrity_ok else 'FAIL'}")
br = report["backlog_recovery"]
lines.append(f"backlog        baseline {br['baseline_range']} → {br['state']}")
lines += ["", "INTERNAL ONLY — machine-dependent, owner-gated publication."]
txt = "\n".join(lines)
with open(os.path.join(out, "SUMMARY.txt"), "w") as fh:
    fh.write(txt + "\n")
print(txt)

sat = report["saturation_timeline"]
gw_rss = sat.get("gateway_rss_bytes") or {}
gw_cpu = sat.get("gateway_cpu_seconds") or {}
gw_go = sat.get("gateway_goroutines") or {}
print("\nsaturation (during measured window):")
print(f"  gateway rss   min {(gw_rss.get('min') or 0)/1e6:.1f} MB max {(gw_rss.get('max') or 0)/1e6:.1f} MB delta {(gw_rss.get('delta_last_minus_first') or 0)/1e6:+.1f} MB")
print(f"  gateway cpu   {(gw_cpu.get('first') or 0):.1f}s → {(gw_cpu.get('last') or 0):.1f}s (Δ{(gw_cpu.get('delta_last_minus_first') or 0):.1f}s)")
print(f"  goroutines    max {gw_go.get('max') or 0:.0f} delta {(gw_go.get('delta_last_minus_first') or 0):+.0f}")

if verdict != "PASS":
    sys.exit(1)
PY
REPORT_RC=$?
set -e

# --- teardown ---------------------------------------------------------------------
if [[ "$KEEP" -eq 1 ]]; then
  log "--keep: stand left running (compose project '$PROJECT'); tear down with: docker compose -p $PROJECT -f deploy/docker-compose.prod.yml -f deploy/docker-compose.e2e.yml down -v"
else
  log "tearing down the soak stand"
  compose down -v --remove-orphans >/dev/null 2>&1 || true
fi
redact_key

if [[ "$REPORT_RC" -ne 0 ]]; then
  fail "soak run FAILED its acceptance criteria (see $OUT/SUMMARY.txt)"
fi
log "soak run complete: artifacts in $OUT (gitignored — do not commit run outputs)"
