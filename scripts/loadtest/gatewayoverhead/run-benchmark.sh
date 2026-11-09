#!/usr/bin/env bash
#
# Measures p50/p95/p99 latency overhead the gateway adds in front of a
# deterministic mock upstream (JSON and SSE, TTFT for streams), across
# scenario toggles: cache on/off, guard hooks on/off, lineage on/off.
# Defaults mirror production config.yaml (cache_enabled: true, guard/lineage
# env defaults off, single gateway + Redis + Postgres).
#
# Everything runs on loopback ports 14650-14655 (verified free via lsof):
#   14650 mock upstream   14651 gateway   14652 gateway admin
#   14653 redis (docker)  14654 postgres (docker)   14655 reserved
#
# Usage: scripts/loadtest/gatewayoverhead/run-benchmark.sh
# Env knobs:
#   BENCH_REQUESTS=300  BENCH_CONCURRENCY=4  BENCH_WARMUP=30
#   BENCH_SCENARIOS="prod,no-cache,guards,lineage"
#   BENCH_UPSTREAM_DELAY=0s (fixed mock delay; cancels out in deltas)
#   BENCH_KEEP=1 (keep containers/processes for debugging)
# Results: artifacts/bench/gateway-overhead/run-<UTC timestamp>/
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"

MOCK_PORT=${BENCH_MOCK_PORT:-14650}
GW_PORT=${BENCH_GW_PORT:-14651}
ADMIN_PORT=${BENCH_ADMIN_PORT:-14652}
REDIS_PORT=${BENCH_REDIS_PORT:-14653}
PG_PORT=${BENCH_PG_PORT:-14654}
for p in 14650 14651 14652 14653 14654 14655; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN 2>/dev/null | grep -q .; then
    echo "port $p is already in use — refusing to start (lsof):" >&2
    lsof -nP -iTCP:"$p" -sTCP:LISTEN 2>/dev/null >&2
    exit 1
  fi
done

REQUESTS=${BENCH_REQUESTS:-300}
CONCURRENCY=${BENCH_CONCURRENCY:-4}
WARMUP=${BENCH_WARMUP:-30}
# Pacing target in requests/second. Must stay under the gateway's production
# per-IP limiter (50 rps, burst 100) — otherwise measured overhead includes
# self-inflicted 429s. The direct baseline is paced identically.
RPS=${BENCH_RPS:-40}
# Each cell (target × mode) is measured BENCH_REPEATS times; the median run
# by p50 lands in summary.tsv, every raw repeat is kept under results/.
REPEATS=${BENCH_REPEATS:-3}
UPSTREAM_DELAY=${BENCH_UPSTREAM_DELAY:-0s}
SCENARIOS=${BENCH_SCENARIOS:-"prod,no-cache,guards,lineage"}
KEEP=${BENCH_KEEP:-0}

for cmd in docker go openssl awk sed; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing prerequisite: $cmd" >&2; exit 1; }
done

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$ROOT/artifacts/bench/gateway-overhead/run-$TS"
mkdir -p "$OUT/results"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/yabanin-bench.XXXXXX")

PG_CONTAINER=yabanin-bench-pg
REDIS_CONTAINER=yabanin-bench-redis
for c in "$PG_CONTAINER" "$REDIS_CONTAINER"; do
  if docker container inspect "$c" >/dev/null 2>&1; then
    echo "container $c already exists — remove it first: docker rm -f $c" >&2
    exit 1
  fi
done

PIDS=()
cleanup() {
  if [[ "$KEEP" == "1" ]]; then
    echo "BENCH_KEEP=1: keeping gateway/mock processes (${PIDS[*]:-none}) and containers" >&2
    return
  fi
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  docker rm -f "$PG_CONTAINER" "$REDIS_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ---------- conditions record ----------
{
  echo "date_utc: $TS"
  echo "host: $(uname -a)"
  echo "cpu: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo)"
  echo "cores: $(sysctl -n hw.ncpu 2>/dev/null || nproc)"
  echo "memory_bytes: $(sysctl -n hw.memsize 2>/dev/null || grep -m1 MemTotal /proc/meminfo | awk '{print $2*1024}')"
  echo "go: $(go version)"
  echo "docker: $(docker --version)"
  echo "requests: $REQUESTS concurrency: $CONCURRENCY warmup: $WARMUP pacing_rps: $RPS repeats: $REPEATS"
  echo "upstream_delay: $UPSTREAM_DELAY"
  echo "scenarios: $SCENARIOS"
  echo "ports: mock=$MOCK_PORT gateway=$GW_PORT admin=$ADMIN_PORT redis=$REDIS_PORT postgres=$PG_PORT"
  echo "percentiles: nearest-rank on per-request samples; overhead = gateway_pX - direct_pX"
} >"$OUT/conditions.txt"

# ---------- build ----------
echo "== building gateway and bench tool =="
(cd "$ROOT" && go build -o "$WORK/yabanin" ./cmd/yabanin)
(cd "$ROOT/scripts/loadtest/gatewayoverhead" && go build -o "$WORK/gatewayoverhead" .)

# ---------- infrastructure ----------
echo "== starting postgres + redis (docker) =="
docker run -d --name "$PG_CONTAINER" -p "127.0.0.1:$PG_PORT:5432" \
  -e POSTGRES_USER=yabanin -e POSTGRES_PASSWORD=yabanin -e POSTGRES_DB=yabanin \
  pgvector/pgvector:pg16 >/dev/null
docker run -d --name "$REDIS_CONTAINER" -p "127.0.0.1:$REDIS_PORT:6379" \
  redis:7-alpine >/dev/null

PG_URI_OWNER="postgres://yabanin:yabanin@127.0.0.1:$PG_PORT/yabanin?sslmode=disable"
PG_URI_APP="postgres://yabanin_app:yabanin_app@127.0.0.1:$PG_PORT/yabanin?sslmode=disable"
for i in $(seq 1 60); do
  if docker exec "$PG_CONTAINER" pg_isready -U yabanin -d yabanin >/dev/null 2>&1; then break; fi
  [[ "$i" == 60 ]] && { echo "postgres did not become ready" >&2; exit 1; }
  sleep 1
done
for i in $(seq 1 30); do
  if docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null | grep -q PONG; then break; fi
  [[ "$i" == 30 ]] && { echo "redis did not become ready" >&2; exit 1; }
  sleep 1
done

echo "== migrating and seeding =="
YABANIN_PG_URI="$PG_URI_OWNER" YABANIN_REGION=sg "$WORK/yabanin" migrate
docker exec "$PG_CONTAINER" psql -U yabanin -d yabanin -c \
  "ALTER ROLE yabanin_app LOGIN PASSWORD 'yabanin_app'" >/dev/null

KEY="yb_bench_$(openssl rand -hex 16)"
if command -v sha256sum >/dev/null 2>&1; then
  KEY_HASH=$(printf '%s' "$KEY" | sha256sum | cut -d' ' -f1)
else
  KEY_HASH=$(printf '%s' "$KEY" | shasum -a 256 | cut -d' ' -f1)
fi

docker exec -i "$PG_CONTAINER" psql -v ON_ERROR_STOP=1 -U yabanin -d yabanin \
  -v key_hash="$KEY_HASH" \
  -v upstream_url="http://127.0.0.1:$MOCK_PORT" <<'SQL' >/dev/null
-- bench seed: one org (cache enabled, exact mode), team, wallet, key, model.
INSERT INTO organizations (id, name, slug, cache_enabled, cache_mode)
VALUES ('00000000-0000-4000-8000-00000000b105', 'Bench', 'bench', true, 'exact')
ON CONFLICT (id) DO NOTHING;

INSERT INTO organizations_teams (id, org_id, name, slug)
VALUES (
  '00000000-0000-4000-8000-00000000c105',
  '00000000-0000-4000-8000-00000000b105', 'Default', 'default'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
VALUES ('00000000-0000-4000-8000-00000000c105', 50, true)
ON CONFLICT (team_id) DO NOTHING;

INSERT INTO org_credits (org_id, balance_cents)
VALUES ('00000000-0000-4000-8000-00000000b105', 100000000)
ON CONFLICT (org_id) DO NOTHING;

INSERT INTO api_keys (key_hash, org_id, name, team_id)
VALUES (
  :'key_hash',
  '00000000-0000-4000-8000-00000000b105', 'bench',
  '00000000-0000-4000-8000-00000000c105'
);

INSERT INTO models_registry (model_name, display_name, tier, tier_pool, provider, upstream_url, enabled)
VALUES (
  'bench-model', 'bench-model', 'smart', '{easy,medium,hard}',
  'openai-compat', :'upstream_url', true
) ON CONFLICT (model_name) DO UPDATE
SET upstream_url = EXCLUDED.upstream_url, provider = EXCLUDED.provider,
    tier_pool = EXCLUDED.tier_pool, enabled = true;
SQL

# ---------- mock upstream ----------
"$WORK/gatewayoverhead" mock -addr "127.0.0.1:$MOCK_PORT" -delay "$UPSTREAM_DELAY" \
  >"$OUT/mock.log" 2>&1 &
MOCK_PID=$!
PIDS+=("$MOCK_PID")
for i in $(seq 1 30); do
  if curl -sf -m 1 "http://127.0.0.1:$MOCK_PORT/healthz" >/dev/null; then break; fi
  [[ "$i" == 30 ]] && { echo "mock upstream did not start" >&2; exit 1; }
  sleep 0.2
done

# ---------- benchmark primitives ----------
run_bench() { # target mode out_prefix — BENCH_REPEATS runs, median p50 to summary.tsv
  local target=$1 mode=$2 prefix=$3 r
  for r in $(seq 1 "$REPEATS"); do
    "$WORK/gatewayoverhead" bench -target "$target" -mode "$mode" \
      -n "$REQUESTS" -c "$CONCURRENCY" -warmup "$WARMUP" -rps "$RPS" -api-key "$KEY" \
      -out "$OUT/results/$prefix.repeat$r.json" 2>"$OUT/results/$prefix.repeat$r.line"
    grep 'RESULT' "$OUT/results/$prefix.repeat$r.line" | tail -1 \
      | sed -E 's/^[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9:]{8} //' \
      | sed "s/^RESULT/$prefix RESULT/" >>"$OUT/results/$prefix.lines"
  done
  awk -F'[= ]' '{for (i = 3; i <= NF; i += 2) if ($i == "p50") printf "%s %s\n", $(i + 1), $0}' \
    "$OUT/results/$prefix.lines" | sort -n \
    | awk 'NR == int((NR + 1) / 2) { sub(/^[0-9.]+ /, ""); print }' >>"$OUT/summary.tsv"
}

rss_kb() { ps -o rss= -p "$1" 2>/dev/null | tr -d ' ' || echo unknown; }

GW_PID=
start_gateway() { # scenario guard_mode lineage cache_enabled -> sets GW_PID
  local scenario=$1 guard=$2 lineage=$3 cache=$4
  cat >"$WORK/config-$scenario.yaml" <<EOF
# RM-105 benchmark scenario '$scenario'. Base fields mirror config.yaml
# (production) with endpoints moved to loopback bench ports; the regions map
# is omitted (single-region bench — see docs/gateway-performance.md).
gateway:
  listen_address: "127.0.0.1:$GW_PORT"
  admin_listen: "127.0.0.1:$ADMIN_PORT"
  provider: "http://127.0.0.1:$MOCK_PORT"
  redis_addr: "127.0.0.1:$REDIS_PORT"
  pg_uri: "$PG_URI_APP"
  log_level: "info"
  log_format: "json"
  fallback_model: "bench-model"
  event_stream: "events:queue"
  cache_enabled: $cache
  metrics_enabled: true
  region: sg
  home_region: SG
  kms_provider: local
EOF
  cp "$WORK/config-$scenario.yaml" "$OUT/config-$scenario.yaml"

  YABANIN_CONFIG="$WORK/config-$scenario.yaml" \
  YABANIN_PROVIDER_ADDR="http://127.0.0.1:$MOCK_PORT" \
  YABANIN_AUTH_MODE=header \
  YABANIN_API_KEY="$KEY" \
  YABANIN_CACHE_HMAC_SECRET="62656e63682d686d61632d303030300000000000000000000000000000000000" \
  YABANIN_GUARD_MODE="$guard" \
  YABANIN_LINEAGE_ENABLED="$lineage" \
    "$WORK/yabanin" gateway >"$OUT/gateway-$scenario.log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  for i in $(seq 1 100); do
    if curl -sf -m 1 "http://127.0.0.1:$GW_PORT/healthz" >/dev/null; then
      GW_PID=$pid
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || { echo "gateway $scenario exited early:" >&2; tail -5 "$OUT/gateway-$scenario.log" >&2; return 1; }
    sleep 0.2
  done
  echo "gateway $scenario not healthy in time" >&2
  return 1
}

stop_gateway() {
  kill "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
  # drop the pid from PIDS so cleanup does not re-kill a reaped pid
  local rest=() p
  for p in "${PIDS[@]}"; do
    [[ "$p" != "$1" ]] && rest+=("$p")
  done
  PIDS=("${rest[@]:-}")
}

# ---------- baseline: direct to mock ----------
echo "== baseline (direct to mock upstream) =="
run_bench "http://127.0.0.1:$MOCK_PORT" json "direct-json"
run_bench "http://127.0.0.1:$MOCK_PORT" sse "direct-sse"

# ---------- scenarios ----------
# scenario name: guard_mode lineage_enabled cache_enabled
scenario_args() {
  case "$1" in
    prod)     echo "off 0 true" ;;
    no-cache) echo "off 0 false" ;;
    guards)   echo "log 0 true" ;;
    lineage)  echo "off 1 true" ;;
    *)        echo "" ;;
  esac
}

for scenario in $(echo "$SCENARIOS" | tr ',' ' '); do
  args=$(scenario_args "$scenario")
  [[ -z "$args" ]] && { echo "unknown scenario: $scenario" >&2; exit 1; }
  read -r guard lineage cache <<<"$args"
  echo "== scenario $scenario (guard=$guard lineage=$lineage cache=$cache) =="
  start_gateway "$scenario" "$guard" "$lineage" "$cache"
  run_bench "http://127.0.0.1:$GW_PORT" json "$scenario-json"
  run_bench "http://127.0.0.1:$GW_PORT" sse "$scenario-sse"
  echo "scenario=$scenario gateway_rss_kb=$(rss_kb "$GW_PID")" >>"$OUT/summary.tsv"
  stop_gateway "$GW_PID"
  GW_PID=
done

# ---------- summary ----------
awk -F'[= ]' '
function collect(  i, p50, p95, p99, tp50, tp95, tp99, out) {
  p50 = 0; p95 = 0; p99 = 0; tp50 = ""; tp95 = ""; tp99 = ""
  for (i = 3; i <= NF; i += 2) {
    if ($i == "p50") p50 = $(i + 1)
    if ($i == "p95") p95 = $(i + 1)
    if ($i == "p99") p99 = $(i + 1)
    if ($i == "ttft_p50") tp50 = $(i + 1)
    if ($i == "ttft_p95") tp95 = $(i + 1)
    if ($i == "ttft_p99") tp99 = $(i + 1)
  }
  return sprintf("%s %s %s %s %s %s", p50, p95, p99, tp50, tp95, tp99)
}
function delta(a, b) { return sprintf("%.3f", a - b) }
/^direct-json RESULT/ { t = collect(); base["json"] = t }
/^direct-sse RESULT/  { t = collect(); base["sse"] = t }
/^prod-.* RESULT/     { t = collect(); res["prod" SUBSEP modeof($1, "prod")] = t }
/^no-cache-.* RESULT/ { t = collect(); res["no-cache" SUBSEP modeof($1, "no-cache")] = t }
/^guards-.* RESULT/   { t = collect(); res["guards" SUBSEP modeof($1, "guards")] = t }
/^lineage-.* RESULT/  { t = collect(); res["lineage" SUBSEP modeof($1, "lineage")] = t }
function modeof(prefix, sc) {
  return substr(prefix, length(sc) + 2, 99) # "prod-json" -> "json"
}
/^scenario=/ { scen_rss[$2] = $4 }
END {
  split("json sse", modes, " ")
  split("prod no-cache guards lineage", scens, " ")
  split(base["json"], bj, " "); split(base["sse"], bs, " ")
  printf "| Scenario | Mode | p50 ms | p95 ms | p99 ms | TTFT p50 | TTFT p95 | TTFT p99 |\n"
  printf "|---|---|---|---|---|---|---|---|\n"
  printf "| direct (mock upstream) | json | %s | %s | %s | — | — | — |\n", bj[1], bj[2], bj[3]
  printf "| direct (mock upstream) | sse | %s | %s | %s | %s | %s | %s |\n", bs[1], bs[2], bs[3], bs[4], bs[5], bs[6]
  for (s = 1; s <= 4; s++) {
    sc = scens[s]
    for (m = 1; m <= 2; m++) {
      key = sc SUBSEP modes[m]
      if (!(key in res)) continue
      split(res[key], v, " ")
      printf "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
        sc, modes[m], v[1], v[2], v[3],
        (v[4] == "" ? "—" : v[4]), (v[5] == "" ? "—" : v[5]), (v[6] == "" ? "—" : v[6])
    }
  }
  printf "\nOverhead = gateway minus direct baseline, same percentile, milliseconds.\n\n"
  printf "| Scenario | Mode | d p50 | d p95 | d p99 | d TTFT p50 | d TTFT p95 | d TTFT p99 |\n"
  printf "|---|---|---|---|---|---|---|---|\n"
  for (s = 1; s <= 4; s++) {
    sc = scens[s]
    for (m = 1; m <= 2; m++) {
      mode = modes[m]
      key = sc SUBSEP mode
      if (!(key in res)) continue
      split(res[key], v, " ")
      dv = (mode == "json") ? "—" : delta(v[4], bs[4])
      printf "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
        sc, mode, delta(v[1], bj[1]), delta(v[2], bj[2]), delta(v[3], bj[3]),
        dv,
        (mode == "json" ? "—" : delta(v[5], bs[5])),
        (mode == "json" ? "—" : delta(v[6], bs[6]))
    }
  }
  printf "\n"
  for (s = 1; s <= 4; s++) {
    sc = scens[s]
    if (!(sc in scen_rss)) continue
    printf "gateway RSS after %s measurements: %s kB\n", sc, scen_rss[sc]
  }
}
' "$OUT/summary.tsv" >"$OUT/summary.md"

echo
echo "== done =="
echo "results dir: $OUT"
cat "$OUT/summary.tsv"
echo
cat "$OUT/summary.md"
