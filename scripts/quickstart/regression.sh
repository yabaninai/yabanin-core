#!/usr/bin/env bash
# (Community clean install). Runs two isolated compose projects and never
# touches the default `yabanin-quickstart` project or any other stack.
#
#   S1 fresh Community install: exactly the documented services, no hidden
#      services, published ports bind 127.0.0.1 only
#   S2 canonical seed + documented first request (smoke.sh) on the clean stack
#   S3 empty DB: every embedded migration applied on the fresh volume,
#     against the pinned schema contract (head 0027, 26 pairs, 0023
#     reserved) — never a derived max()/count
#   S3b/S3c managed beta views (frozen): exactly the seven views with
#     content-minimized columns; per-org values pinned independently
#     (fixture 3 requests/1 error, DAU 3/3, ttfq 90s, byok provider,
#     p50/p95 200/290, cache 1/3) + org1 against raw rows; app-role reads
#     and a real 42501 negative; a revoked/dropped view is named degraded
#     readiness while the gateway serves; the migrate boundary self-heals
#     all seven and a fresh startup is ready
#   S4 restart (down, no -v): named pg_data volume survives; the same key
#      serves; seed rerun is a loud no-op; the seven views and the frozen
#      fixture survive
#   S5 broken-vs-fixed: a pre-fix anonymous-volume fixture must FAIL the
#      same restart-survival check the shipped stack passes. The fixture is
#      rewritten onto its own /24 (QS_FIXTURE_NET, default 10.208.0) so it
#      coexists with the still-running primary project, which keeps the
#      shipped D-4 pin 10.207.0.0/24; two pinned networks never overlap.
#   S6 wrong secrets: weak session key refuses production startup; a wrong
#      YABANIN_ENCRYPTION_KEY fails closed (503 model_registry_unavailable)
#   S7 documented command surface matches the repo (docs vs Makefile targets)
#
#   S8 documented five-command flow (make quickstart-up/seed/smoke) on a third
#      isolated project; fresh-install service-surface assertions re-checked on
#      the make-created stack
#   S9 empty DB through the same boundary: documented reset (down -v -> up),
#      migrate re-applies the full schema, old key -> 401, the seven beta
#      views exist before reseed, reseed -> first request 200 with a new key
#   S10 restart through the same boundary: make quickstart-down keeps pg_data;
#      up re-runs migrate as a no-op; the same key serves
#   S11 wrong secrets through the same boundary: half-set license env refuses
#      the dev process; admin plane rejects a wrong password and accepts the
#      seed-printed one (CSRF-protected POST /auth/login)
#   S12 linked deploy paths: dev/prod/prod+e2e compose configs render; a
#      missing required secret is rejected at config time; every compose
#      yabanin subcommand and env var is known to the binary/config layer
#
#   S0 preflight additions (F2): before touching anything, the suite detects a
#      FOREIGN stack holding one of its pinned subnets and fails fast naming
#      the holder (network, compose project, attached containers) with
#      remedies — evict it, or relocate this suite's quickstart projects
#      (primary and S8-S11 make flow alike) via QS_PRIMARY_NET (a counted,
#      asserted scratch rewrite honored end-to-end via QS_COMPOSE_FILE; the
#      shipped compose file is never edited, so the D-4 production pin stays).
#      QS_FIXTURE_NET already relocates the S5 fixture the same way.
#   Failure-output capture (F3): the S8-S10 make-flow invocations run under
#      run_bounded with RUN_BOUNDED_KEEP, so a stalled or failed
#      `make quickstart-up` no longer discards its output into /dev/null —
#      the last lines are dumped to stderr and the full build log is kept in
#      scratch for the run.
#
# Missing external prerequisites (docker, compose, python3, free ports) are
# hard failures, never skips: an absent prerequisite must not mask a green run.
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

compose_file=deploy/quickstart/docker-compose.yml
proj_fixed=yabanin-qs-r05504
proj_broken=yabanin-qs-r05504-broken
proj_integ=yabanin-qs-r05505
fixed_gw=28082 fixed_adm=28086 wrongkey_port=28099
broken_gw=28182 broken_adm=28186
integ_gw=28282 integ_adm=28286

fail() { echo "REGRESSION FAIL: $*" >&2; exit 1; }
step() { printf '\n=== %s ===\n' "$*"; }
note() { printf '    %s\n' "$*"; }

# S5 fixture networking. The broken fixture must coexist with the still
# running `fixed` project — that coexistence IS the multi-project regression
# this suite exercises — while the shipped compose keeps its D-4 pin
# (10.207.0.0/24) for the primary project. The fixture is therefore rewritten
# onto its own /24: same pinned-posture shape (static mock IP + literal-IP
# upstream URLs, see the compose header), zero subnet overlap. Override
# QS_FIXTURE_NET (first three octets of a /24 outside Docker's default
# auto-allocation pools, like the shipped 10.207 pin) only if the default
# range is occupied on the host.
fixture_net=${QS_FIXTURE_NET:-10.208.0}
if ! [[ "$fixture_net" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  fail "QS_FIXTURE_NET must be the first three octets of a /24 (got: $fixture_net)"
fi
IFS=. read -r _fx1 _fx2 _fx3 <<<"$fixture_net"
for _fxoct in "$_fx1" "$_fx2" "$_fx3"; do
  [[ "$_fxoct" -le 255 ]] || fail "QS_FIXTURE_NET octet out of range: $fixture_net"
done
fixture_subnet="$fixture_net.0/24"
fixture_mock_ip="$fixture_net.9"
fixture_mock_url="http://${fixture_mock_ip}:8081"

# S8 make-flow networking (F2 escape hatch). The S1-S6b primary project and
# the S8-S11 make flow share one compose source: the shipped file (claiming
# the production D-4 pin 10.207.0.0/24) unless QS_PRIMARY_NET relocates both
# onto another free /24. The override (first three octets of a /24, like the
# shipped 10.207 pin) is a counted, asserted scratch rewrite exported as
# QS_COMPOSE_FILE and honored by the Makefile quickstart targets and the
# quickstart scripts; the shipped file is never edited. Without an override
# a foreign holder of the shipped pin still fails the preflight below closed.
shipped_pin="10.207.0.0/24"
primary_net=${QS_PRIMARY_NET:-}
if [[ -n "$primary_net" ]]; then
  if ! [[ "$primary_net" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    fail "QS_PRIMARY_NET must be the first three octets of a /24 (got: $primary_net)"
  fi
  IFS=. read -r _pn1 _pn2 _pn3 <<<"$primary_net"
  for _pnoct in "$_pn1" "$_pn2" "$_pn3"; do
    [[ "$_pnoct" -le 255 ]] || fail "QS_PRIMARY_NET octet out of range: $primary_net"
  done
  [[ "$primary_net" != "$fixture_net" ]] \
    || fail "QS_PRIMARY_NET ($primary_net) must differ from QS_FIXTURE_NET ($fixture_net)"
fi
primary_mock_ip=${primary_net:+$primary_net.9}
pri_pin_subnet=${primary_net:+$primary_net.0/24}
pri_pin_subnet=${pri_pin_subnet:-$shipped_pin}
# The fixture must never share a /24 with the primary project — under its
# default (10.208.0 vs the shipped 10.207.0) that holds; guard overrides.
[[ "$fixture_net" != "${primary_net:-10.207.0}" ]] \
  || fail "QS_FIXTURE_NET ($fixture_net) collides with the primary pin (${primary_net:-10.207.0}.0/24)"

# --- S0 preflight: hard prerequisites ---------------------------------------
command -v docker  >/dev/null || fail "docker not found"
command -v python3 >/dev/null || fail "python3 not found"
command -v curl    >/dev/null || fail "curl not found"
command -v openssl >/dev/null || fail "openssl not found"
command -v sha256sum >/dev/null || fail "sha256sum not found"
docker compose version >/dev/null 2>&1 || fail "docker compose v2 not available"
docker info >/dev/null 2>&1         || fail "docker daemon not reachable"
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for p in "$fixed_gw" "$fixed_adm" "$wrongkey_port" "$broken_gw" "$broken_adm" \
         "$integ_gw" "$integ_adm"; do
  if port_busy "$p"; then fail "port $p busy; free it or override the *_PORT variables"; fi
done
[[ -f deploy/quickstart/.env ]] || bash scripts/quickstart/init-env.sh
[[ -s deploy/quickstart/.env ]] || fail "deploy/quickstart/.env missing after init-env.sh"

# Clean slate for this card's own projects only (never `yabanin-quickstart`).
docker compose -p "$proj_fixed"  -f "$compose_file" --profile mock down -v --remove-orphans >/dev/null 2>&1 || true
# The broken project may hold a named pg_data volume from an earlier run whose
# seed path leaked the shipped compose; clean it via the shipped file.
docker compose -p "$proj_broken" -f "$compose_file" --profile mock --profile seed down -v --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$proj_integ"  -f "$compose_file" --profile mock down -v --remove-orphans >/dev/null 2>&1 || true

# Scratch inside the checkout (git-ignored, removed on exit): this host's
# per-user TMPDIR has shown unreliable write visibility under heavy parallel
BRK_TMP="$root/.r05505-scratch"
rm -rf "$BRK_TMP"
mkdir -p "$BRK_TMP"
BRK_COMPOSE="$BRK_TMP/docker-compose-broken.yml"

# --- F2: foreign-holder preflight for the pinned subnets ---------------------
# A foreign stack holding one of this suite's pinned subnets is the exact
# failure shape that motivated the fixture re-subnet fix (two pinned
# projects claiming one /24) — except this holder is not ours to tear down. Name it, then fail
# fast with remedies (evict it, or relocate the primary project via
# QS_PRIMARY_NET). Runs after our own clean-slate downs, so anything found
# here is foreign by construction.
net_holders() {
  local want_subnet=$1
  local skip_re="^(${proj_fixed}|${proj_broken}|${proj_integ})_default\$"
  local net sub holders="" proj containers
  for net in $(docker network ls --format '{{.Name}}' 2>/dev/null || true); do
    [[ "$net" =~ $skip_re ]] && continue
    sub=$(docker network inspect "$net" \
      --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true)
    case " $sub " in
      *" $want_subnet "*)
        proj=$(docker network inspect "$net" \
          --format '{{index .Labels "com.docker.compose.project"}}' 2>/dev/null || true)
        containers=$(docker network inspect "$net" \
          --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null || true)
        holders+="$net (compose project: ${proj:-n/a}; containers: ${containers:-none})"$'\n'
        ;;
    esac
  done
  printf '%s' "$holders"
}
step "S0 preflight: pinned-subnet foreign-holder check"
# Byte-stability oracle: S8 re-checks this digest after the make flow to
# prove the override path never edited the shipped compose.
shipped_sha=$(sha256sum "$compose_file" | cut -d' ' -f1)
if [[ -n "$primary_net" ]]; then
  # Override active: every project in this run — the S1-S6b primary and the
  # S8-S11 make flow alike — is rewritten onto the override /24, so nothing
  # here needs the shipped pin; a foreign holder of it stays informational.
  shipped_holders=$(net_holders "$shipped_pin")
  if [[ -n "$shipped_holders" ]]; then
    echo "NOTE: a foreign stack still holds the shipped pin $shipped_pin; this run does not use it (all projects run on $pri_pin_subnet):" >&2
    printf '%s\n' "$shipped_holders" >&2
  fi
  primary_holders=$(net_holders "$pri_pin_subnet")
  if [[ -n "$primary_holders" ]]; then
    echo "REGRESSION FAIL: a foreign stack already holds the QS_PRIMARY_NET override subnet $pri_pin_subnet:" >&2
    printf '%s\n' "$primary_holders" >&2
    echo "Remedy: pick another free /24 triplet for QS_PRIMARY_NET (e.g. 10.211.0)." >&2
    rm -rf "$BRK_TMP"
    exit 1
  fi
else
  primary_holders=$(net_holders "$pri_pin_subnet")
  if [[ -n "$primary_holders" ]]; then
    echo "REGRESSION FAIL: a foreign stack already holds the primary pin $pri_pin_subnet:" >&2
    printf '%s\n' "$primary_holders" >&2
    cat >&2 <<'EOS'
This suite runs three isolated projects; without an override they all claim
the production D-4 pin 10.207.0.0/24 through the shipped compose. Remedies,
in order of preference:
  1. Evict the foreign stack listed above (it is not ours to touch):
       docker compose -p <compose project> down      # if compose-managed
       docker network rm <network>                   # otherwise
  2. Relocate this run's quickstart projects — primary and S8-S11 make flow
     alike — to another free /24 and rerun:
       QS_PRIMARY_NET=10.209.0 bash scripts/quickstart/regression.sh
     (a counted, asserted scratch rewrite honored end-to-end; the shipped
      compose file and its D-4 pin are never edited)
EOS
    rm -rf "$BRK_TMP"
    exit 1
  fi
fi
fixture_holders=$(net_holders "$fixture_subnet")
if [[ -n "$fixture_holders" ]]; then
  echo "REGRESSION FAIL: a foreign stack already holds the fixture subnet $fixture_subnet:" >&2
  printf '%s\n' "$fixture_holders" >&2
  echo "Remedy: rerun with QS_FIXTURE_NET set to another free /24 triplet (e.g. 10.210.0)." >&2
  rm -rf "$BRK_TMP"
  exit 1
fi

FX=(docker compose -p "$proj_fixed" -f "$compose_file" --profile mock)
INX=(docker compose -p "$proj_integ" -f "$compose_file" --profile mock)

# F2 escape hatch implementation: with QS_PRIMARY_NET set, rewrite a counted,
# asserted scratch copy of the shipped compose onto the override /24 (same
# posture as the S5 fixture rewrite; the production file is never edited).
if [[ -n "$primary_net" ]]; then
  PRI_COMPOSE="$BRK_TMP/docker-compose-primary.yml"
  FX_COMPOSE="$PRI_COMPOSE"
  FX_PD=(--project-directory deploy/quickstart)
  export QS_COMPOSE_FILE="$PRI_COMPOSE"
  python3 - "$compose_file" "$PRI_COMPOSE" "$pri_pin_subnet" "$primary_mock_ip" <<'PY'
import sys
src_path, dst_path = sys.argv[1], sys.argv[2]
subnet, mock_ip = sys.argv[3], sys.argv[4]
src = open(src_path).read()
primary_lit = "http://10.207.0.9:8081"
inter = "${QS_UPSTREAM_URL:-" + primary_lit + "}"
# 1. Bake the literal upstream URL (2 sites: seed + provider) re-pointed at
#    the override mock IP, before touching the pin (counted, like S5).
assert src.count(inter) == 2, \
    "QS_UPSTREAM_URL interpolation sites changed; QS_PRIMARY_NET rewrite needs update"
out = src.replace(inter, "http://" + mock_ip + ":8081")
# 2. Static mock-openai address -> the override subnet (must match 1).
assert out.count("ipv4_address: 10.207.0.9") == 1, \
    "mock-openai static IP site changed; QS_PRIMARY_NET rewrite needs update"
out = out.replace("ipv4_address: 10.207.0.9", "ipv4_address: " + mock_ip)
# 3. ipam subnet (config line + the explaining comment).
assert out.count("10.207.0.0/24") == 2, \
    "pinned subnet sites changed; QS_PRIMARY_NET rewrite needs update"
out = out.replace("10.207.0.0/24", subnet)
assert "10.207." not in out, "primary rewrite still references the shipped pin"
open(dst_path, "w").write(out)
PY
  docker compose -p "$proj_fixed" -f "$PRI_COMPOSE" --project-directory deploy/quickstart config -q \
    || fail "S0: QS_PRIMARY_NET rewrite does not render as a compose file"
  FX=(docker compose -p "$proj_fixed" -f "$PRI_COMPOSE" \
    --project-directory deploy/quickstart --profile mock)
  # The S8-S11 make flow (INX, seed/smoke via QS_COMPOSE_FILE) must run the
  # same rewritten compose as the primary, so the integ project claims the
  # override /24 — never the possibly foreign-held shipped pin.
  INX=(docker compose -p "$proj_integ" -f "$PRI_COMPOSE" \
    --project-directory deploy/quickstart --profile mock)
  note "QS_PRIMARY_NET active: primary project and S8-S11 make flow rewritten onto $pri_pin_subnet (mock at $primary_mock_ip); shipped file untouched"
fi

# Set when S12 generates deploy-side secrets in this checkout (they are
# removed again on exit; pre-existing files are never touched).
integ_env_created=0 integ_secrets_created=0

REG_FAILED=0
cleanup() {
  local code=$?
  if [[ $code -ne 0 ]]; then
    REG_FAILED=1
    echo "---- failure dump: compose ps (fixed) ----" >&2
    docker compose -p "$proj_fixed" -f "$compose_file" --profile mock ps -a >&2 || true
    echo "---- failure dump: yabanin logs (fixed, tail) ----" >&2
    docker logs "$proj_fixed-yabanin-1" 2>&1 | tail -30 >&2 || true
    echo "---- failure dump: compose ps (integ) ----" >&2
    docker compose -p "$proj_integ" -f "$compose_file" --profile mock ps -a >&2 || true
    echo "---- failure dump: yabanin logs (integ, tail) ----" >&2
    docker logs "$proj_integ-yabanin-1" 2>&1 | tail -30 >&2 || true
  fi
  docker compose -p "$proj_fixed" -f "${FX_COMPOSE:-$compose_file}" \
    ${FX_PD[@]+"${FX_PD[@]}"} --profile mock down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose -p "$proj_fixed"  -f "$compose_file" --profile mock down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose -p "$proj_broken" -f "$BRK_COMPOSE" --project-directory deploy/quickstart --profile mock --profile seed down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose -p "$proj_broken" -f "$compose_file" --profile mock --profile seed down -v --remove-orphans >/dev/null 2>&1 || true
  # INX carries the primary scratch compose under QS_PRIMARY_NET, so the
  # make-flow project is torn down through the file it was created from.
  "${INX[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker rm -f "$proj_fixed-wrongkey" >/dev/null 2>&1 || true
  if [[ "$integ_env_created" == 1 ]]; then
    rm -f deploy/.env
    if [[ "$integ_secrets_created" == 1 ]]; then rm -rf deploy/secrets; fi
  fi
  rm -rf "$BRK_TMP"
}
trap cleanup EXIT

# QS_COMPOSE_FILE routes the env-driven paths (seed.sh, smoke.sh, the make
# flow) at the active compose: the primary scratch rewrite when QS_PRIMARY_NET
# is set, the shipped file otherwise. use_broken drops it so the fixture
# project never inherits the primary's compose; use_fixed restores it after
# use_broken so S6b-onwards scripts keep targeting the primary project.
use_fixed() {
  export COMPOSE_PROJECT_NAME="$proj_fixed"
  export QS_GATEWAY_PORT="$fixed_gw" QS_ADMIN_PORT="$fixed_adm"
  export QS_BASE="http://127.0.0.1:${fixed_gw}"
  if [[ -n "$primary_net" ]]; then export QS_COMPOSE_FILE="$PRI_COMPOSE"; else unset QS_COMPOSE_FILE; fi
}
use_broken() {
  export COMPOSE_PROJECT_NAME="$proj_broken"
  export QS_GATEWAY_PORT="$broken_gw" QS_ADMIN_PORT="$broken_adm"
  export QS_BASE="http://127.0.0.1:${broken_gw}"
  unset QS_COMPOSE_FILE
}
use_integ() {
  export COMPOSE_PROJECT_NAME="$proj_integ"
  export QS_GATEWAY_PORT="$integ_gw" QS_ADMIN_PORT="$integ_adm"
  export QS_BASE="http://127.0.0.1:${integ_gw}"
  if [[ -n "$primary_net" ]]; then export QS_COMPOSE_FILE="$PRI_COMPOSE"; else unset QS_COMPOSE_FILE; fi
}

dbq()  { "${FX[@]}" exec -T postgres psql -U yabanin -d yabanin -tA -c "$1"; }
bdbq() { "${BRIX[@]}" exec -T postgres psql -U yabanin -d yabanin -tA -c "$1"; }
idbq() { "${INX[@]}" exec -T postgres psql -U yabanin -d yabanin -tA -c "$1"; }

extract_key() { sed -n 's/.*API key (shown once, store it now): \(yb_[0-9a-fA-F]*\).*/\1/p'; }
extract_admin_password() { sed -n 's/.*Admin password (shown once, store it now): \([0-9a-fA-F]*\).*/\1/p'; }

# App-role (yabanin_app) psql for the fixed and integ projects. ON_ERROR_STOP
# + verbose make a permission denial fail nonzero with SQLSTATE 42501 in the
# output, so the 42501 negative below is a real behavioral denial.
adbq()     { "${FX[@]}" exec -T postgres psql -U yabanin_app -d yabanin -v ON_ERROR_STOP=1 --verbosity=verbose -tA -c "$1"; }
idbq_app() { "${INX[@]}" exec -T postgres psql -U yabanin_app -d yabanin -v ON_ERROR_STOP=1 --verbosity=verbose -tA -c "$1"; }

# The seven managed beta views (pkg/feedback MetricsViewNames), pinned sorted.
BETA_VIEWS="beta_cache_hit_rate_daily beta_dau_daily beta_latency_daily beta_onboarding_ttfq beta_provider_distribution beta_provider_errors beta_requests_daily"

# gw_restart_wait: restart the fixed gateway and wait for /healthz (bounded).
gw_restart_wait() {
  "${FX[@]}" restart yabanin >/dev/null
  local i
  for i in $(seq 1 60); do
    curl -fsS "$QS_BASE/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# gw_log_wait TIMEOUT_SECS MARKER PATTERN...: bounded wait until the gateway
# container has logged every fixed-string PATTERN since MARKER. /healthz
# alone is not sufficient evidence — the readiness wiring logs after the
# listener is up, so a one-shot grep can race the message and false-fail.
# Prints the matched log window on stdout; on timeout dumps the actual log
# tail and returns nonzero.
gw_log_wait() {
  local timeout_secs=$1 marker=$2; shift 2
  local i log p ok
  for i in $(seq 1 "$timeout_secs"); do
    log=$(docker logs --since "$marker" "${proj_fixed}-yabanin-1" 2>&1)
    ok=1
    for p in "$@"; do
      grep -qF -- "$p" <<<"$log" || ok=0
    done
    if [[ $ok -eq 1 ]]; then
      printf '%s' "$log"
      return 0
    fi
    sleep 1
  done
  echo "---- gw_log_wait: expected log state not reached in ${timeout_secs}s (since $marker) ----" >&2
  docker logs --since "$marker" "${proj_fixed}-yabanin-1" 2>&1 | tail -40 >&2
  return 1
}

# gw_serve_200 PAYLOAD: bounded wait until the gateway answers a chat
# completion with 200 — degraded view readiness must never stop serving.
gw_serve_200() {
  local i code=000
  for i in $(seq 1 30); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" \
      -H 'Content-Type: application/json' -d "$1" "$QS_BASE/v1/chat/completions")
    [[ "$code" == "200" ]] && return 0
    sleep 1
  done
  echo "gw_serve_200: last HTTP status $code" >&2
  return 1
}

# beta_views_check QFN: exactly the seven managed views exist — no unexpected
# beta views, no beta materialized views.
beta_views_check() {
  local got mats
  got=$("$1" "SELECT COALESCE(string_agg(viewname, ' ' ORDER BY viewname), '') FROM pg_views WHERE schemaname = 'public' AND viewname LIKE 'beta\\_%'")
  [[ "$got" == "$BETA_VIEWS" ]] || fail "beta views are [$got], want exactly the seven managed names"
  mats=$("$1" "SELECT count(*) FROM pg_matviews WHERE schemaname = 'public' AND viewname LIKE 'beta\\_%'")
  [[ "$mats" == "0" ]] || fail "$mats unexpected beta materialized views present"
}

# beta_columns_check QFN: every managed view is content-minimized — exactly
# the pinned column set in pinned order (counts/percentiles/timestamps and
# org scoping only; any payload column fails here).
beta_columns_check() {
  local v got exp
  for v in $BETA_VIEWS; do
    got=$("$1" "SELECT COALESCE(string_agg(column_name, '|' ORDER BY ordinal_position), '') FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '$v'")
    case "$v" in
      beta_dau_daily)             exp='day|org_id|active_users|requests' ;;
      beta_requests_daily)        exp='day|org_id|requests|errors' ;;
      beta_onboarding_ttfq)       exp='org_id|onboarded_at|first_request_at|seconds_to_first_request' ;;
      beta_provider_distribution) exp='day|org_id|provider|byok|requests' ;;
      beta_provider_errors)       exp='day|org_id|provider|byok|requests|errors|error_rate' ;;
      beta_latency_daily)         exp='day|org_id|p50_ms|p95_ms|requests' ;;
      beta_cache_hit_rate_daily)  exp='day|org_id|hits|requests|hit_rate' ;;
    esac
    [[ "$got" == "$exp" ]] || fail "$v exposes [$got], want the content-minimized set [$exp]"
  done
}

# beta_fixture_values_check QFN: frozen fixture-org expectations — 3 requests/
# 1 error, DAU 3/3, onboarding pinned to FIX_T0/+90s/90s, BYOK provider
# attribution, p50/p95 200/290 (durations 200/200/300 under percentile_cont),
# cache 1/3. Numbers are pinned here, never derived from the implementation.
beta_fixture_values_check() {
  local q=$1 got
  got=$($q "SELECT active_users || '/' || requests FROM beta_dau_daily WHERE org_id = '$FIX_ORG'")
  [[ "$got" == "3/3" ]] || fail "fixture beta_dau_daily [$got] != 3/3"
  got=$($q "SELECT requests || '/' || errors FROM beta_requests_daily WHERE org_id = '$FIX_ORG'")
  [[ "$got" == "3/1" ]] || fail "fixture beta_requests_daily [$got] != 3/1"
  got=$($q "SELECT (onboarded_at - '$FIX_T0'::timestamptz) = interval '0' AND (first_request_at - ('$FIX_T0'::timestamptz + interval '90 seconds')) = interval '0' AND round(seconds_to_first_request::numeric) = 90 FROM beta_onboarding_ttfq WHERE org_id = '$FIX_ORG'")
  [[ "$got" == "t" ]] || fail "fixture beta_onboarding_ttfq [$got] != pinned t0/+90s/90s"
  got=$($q "SELECT provider || '/' || byok || '/' || requests FROM beta_provider_distribution WHERE org_id = '$FIX_ORG'")
  [[ "$got" == "qs-fixture-provider/t/3" ]] || fail "fixture beta_provider_distribution [$got] != qs-fixture-provider/t/3"
  got=$($q "SELECT requests || '/' || errors || '/' || round(error_rate::numeric, 4)::text FROM beta_provider_errors WHERE org_id = '$FIX_ORG'")
  [[ "$got" == "3/1/0.3333" ]] || fail "fixture beta_provider_errors [$got] != 3/1/0.3333"
  got=$($q "SELECT p50_ms::int || '/' || p95_ms::int || '/' || requests FROM beta_latency_daily WHERE org_id = '$FIX_ORG'")
  [[ "$got" == "200/290/3" ]] || fail "fixture beta_latency_daily [$got] != 200/290/3"
  got=$($q "SELECT hits || '/' || requests || '/' || round(hit_rate::numeric, 4)::text FROM beta_cache_hit_rate_daily WHERE org_id = '$FIX_ORG'")
  [[ "$got" == "1/3/0.3333" ]] || fail "fixture beta_cache_hit_rate_daily [$got] != 1/3/0.3333"
  got=$($q "SELECT count(*) FROM beta_requests_daily WHERE org_id = '$FIX_ORG' AND day = date_trunc('day', '$FIX_T0'::timestamptz AT TIME ZONE 'UTC')")
  [[ "$got" == "1" ]] || fail "fixture rows grouped into [$got] days, want the single pinned UTC day"
}

# up_wait TIMEOUT_SECS PROJECT build|nobuild COMPOSE_CMD...
# `compose up -d --wait` under a hard bound: compose v2.18 can poll a
# completed one-shot forever when the service_completed_successfully event
# races the waiter, so an unbounded --wait can hang the whole run. On timeout
# or failure: dump the project's container states and one-shot logs, then
# return non-zero (the caller's fail() turns that into a scenario failure).
up_wait() {
  local timeout_secs=$1 proj=$2 build=$3; shift 3
  local flags=(-d --wait --wait-timeout "$timeout_secs")
  [[ "$build" == "build" ]] && flags+=(--build)
  if ! "$@" up "${flags[@]}"; then
    echo "---- stall/failure dump: container states ($proj) ----" >&2
    docker ps -a --filter "label=com.docker.compose.project=$proj" \
      --format '{{.Names}} {{.Status}}' >&2 || true
    local svc
    for svc in migrate db-app-role yabanin; do
      echo "---- logs: $proj-$svc-1 (tail) ----" >&2
      docker logs "$proj-$svc-1" 2>&1 | tail -15 >&2 || true
    done
    return 1
  fi
}

# run_bounded TIMEOUT_SECS CMD... — run CMD with a wall-clock bound; on stall
# kill it (and its direct children) and dump its captured output to stderr.
# Output always goes to stdout, so callers may capture it as before.
# Bash points a non-interactive async command's stdin at /dev/null; callers
# that must feed the child (seed password) set RUN_BOUNDED_STDIN=<file>.
# Callers that discard stdout (>/dev/null) set RUN_BOUNDED_KEEP=<path> (F3):
# the log is copied to that path, so a failed or stalled `make quickstart-up`
# no longer vanishes — on failure the last lines are dumped to stderr (which
# lands in the run log) and the full output stays in scratch for inspection.
run_bounded() {
  local timeout_secs=$1; shift
  local log="$BRK_TMP/bounded.$$.$RANDOM.log"
  local tries=0
  until : >"$log" 2>/dev/null; do
    tries=$((tries + 1))
    if [[ $tries -ge 3 ]]; then
      echo "REGRESSION FAIL: cannot create scratch log $log (host write flake)" >&2
      return 1
    fi
    sleep 1
  done
  "$@" <"${RUN_BOUNDED_STDIN:-/dev/null}" >"$log" 2>&1 &
  local pid=$!
  local waited=0
  while kill -0 "$pid" 2>/dev/null && [[ $waited -lt $timeout_secs ]]; do
    sleep 5
    waited=$((waited + 5))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    pkill -P "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    if [[ -n "${RUN_BOUNDED_KEEP:-}" ]]; then cp "$log" "$RUN_BOUNDED_KEEP" 2>/dev/null || true; fi
    echo "---- stall dump: command exceeded ${timeout_secs}s; last output${RUN_BOUNDED_KEEP:+ (kept at $RUN_BOUNDED_KEEP)} ----" >&2
    tail -40 "$log" >&2 || true
    return 1
  fi
  local rc=0
  wait "$pid" || rc=$?
  cat "$log"
  if [[ -n "${RUN_BOUNDED_KEEP:-}" ]]; then cp "$log" "$RUN_BOUNDED_KEEP" 2>/dev/null || true; fi
  if [[ "$rc" -ne 0 ]]; then
    echo "---- failure dump: exit $rc; last output${RUN_BOUNDED_KEEP:+ (kept at $RUN_BOUNDED_KEEP)} ----" >&2
    tail -40 "$log" >&2 || true
  fi
  return $rc
}

# inventory_assert PROJECT [COMPOSE_FILE]: fresh Community install surface
# assertions — exactly the documented service set (no hidden services), only
# the gateway publishing, 127.0.0.1-only bindings, one-shot services
# Exited(0). COMPOSE_FILE defaults to the shipped file; callers under
# QS_PRIMARY_NET pass the scratch rewrite the project was created from.
inventory_assert() {
local cmp_file=${2:-deploy/quickstart/docker-compose.yml}
python3 - "$1" "$cmp_file" <<'PY'
import json, subprocess, sys
proj, cmp_file = sys.argv[1], sys.argv[2]
def run(*args):
    return subprocess.run(args, capture_output=True, text=True)
services = sorted(run("docker", "compose", "-p", proj, "-f", cmp_file,
                      "--project-directory", "deploy/quickstart", "--profile",
                      "mock", "ps", "--all", "--services").stdout.split())
expected = ["db-app-role", "migrate", "mock-openai", "postgres", "redis", "yabanin"]
assert services == expected, f"project services {services} != documented {expected}"
base = sorted(run("docker", "compose", "-p", proj, "-f", cmp_file,
                  "--project-directory", "deploy/quickstart",
                  "config", "--services").stdout.split())
assert base == ["db-app-role", "migrate", "postgres", "redis", "yabanin"], \
    f"default profile surface {base} hides or leaks services"
forbidden = ["prometheus", "grafana", "alertmanager", "dashboard", "classifier",
             "embedder", "llama", "caddy", "status-page", "backup", "node-exporter", "seed"]
leaked = [s for s in services for f in forbidden if f in s]
assert not leaked, f"hidden/undocumented services present: {leaked}"
names = run("docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={proj}",
            "--format", "{{.Names}}").stdout.split()
assert len(names) == 6, f"expected exactly 6 containers, got {names}"
for svc, want in [("postgres", "running"), ("redis", "running"),
                  ("yabanin", "running"), ("mock-openai", "running"),
                  ("migrate", "exited"), ("db-app-role", "exited")]:
    out = run("docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}",
              f"{proj}-{svc}-1").stdout.strip()
    status, code = out.split()
    assert status == want, f"{svc}: status {status}, want {want}"
    if want == "exited":
        assert code == "0", f"{svc}: exit code {code}, want 0"
data = json.loads(run("docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}",
                      f"{proj}-yabanin-1").stdout)
bindings = []
for _container_port, mappings in data.items():
    for m in mappings or []:
        bindings.append((m["HostIp"], m["HostPort"]))
assert bindings, "gateway publishes no host ports"
for ip, _port in bindings:
    assert ip == "127.0.0.1", f"non-localhost binding: {ip}"
print(f"inventory ok: services={services} bindings={sorted(bindings)} (127.0.0.1 only)")
PY
}

# --- S1 fresh Community install: inventory, no hidden services --------------
step "S1 fresh Community install: service inventory"
use_fixed
"${FX[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
# Documented build step (docs step 3 / demo.sh): the Dockerfile's epoch guard
# fails `up --build` without SOURCE_DATE_EPOCH, so build with the commit
# timestamp first, then the documented up --no-build --wait.
run_bounded 1200 "${FX[@]}" build \
  --build-arg "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)" \
  || fail "S1: reproducible compose build failed or stalled"
up_wait 1200 "$proj_fixed" nobuild "${FX[@]}" || fail "S1: up --wait failed or stalled"
note "reproducible build (SOURCE_DATE_EPOCH=commit time) + up -d --no-build --wait exit 0"

inventory_assert "$proj_fixed" "${QS_COMPOSE_FILE:-$compose_file}" || fail "S1 inventory assertions failed"

# --- S2 canonical seed + documented first request ----------------------------
step "S2 canonical seed + documented first request (clean environment)"
seed_out=$(bash scripts/quickstart/seed.sh 2>&1)
key=$(printf '%s' "$seed_out" | extract_key)
[[ -n "$key" ]] || fail "S2: seed did not print an API key"
note "seed printed key ${key:0:10}… and admin password (values redacted here)"
smoke_out=$(bash scripts/quickstart/smoke.sh "$key")
grep -q "^smoke ok (" <<<"$smoke_out" || fail "S2: smoke.sh output unexpected: $smoke_out"
note "$smoke_out"
reqs_after_first=$(dbq "SELECT count(*) FROM request_logs WHERE request_id IS NOT NULL")
[[ "$reqs_after_first" -ge 1 ]] || fail "S2: no request_logs row with request_id after smoke"
# negative control: a bogus key must be rejected (401)
bogus="yb_$(openssl rand -hex 32)"
code401=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $bogus" \
  "$QS_BASE/v1/chat/completions" -H 'Content-Type: application/json' \
  -d '{"model":"mock-model","stream":false,"messages":[{"role":"user","content":"ping"}]}' || true)
[[ "$code401" == "401" ]] || fail "S2: bogus key got HTTP $code401, want 401"
note "bogus key rejected with 401"

# --- schema contract (pinned; migrations/README.md "Current schema and
# numbering" + pkg/migrate numbering tests): head version 0027, exactly 26
# up/down pairs 0001-0022 + 0024-0027, 0023 permanently reserved unused.
# The expectation is pinned, never derived: deleting the head migration or
# renumbering must FAIL here instead of silently lowering a max()/count.
SCHEMA_HEAD=27
SCHEMA_UP_SET="0001 0002 0003 0004 0005 0006 0007 0008 0009 0010 0011 0012 0013 0014 0015 0016 0017 0018 0019 0020 0021 0022 0024 0025 0026 0027"

migration_versions() { # <up|down>: sorted embedded migration version numbers
  ls pkg/migrate/migrations/*."$1".sql \
    | sed 's#.*/\([0-9]\{4\}\)_[^/]*$#\1#' | sort | tr '\n' ' ' | sed 's/ $//'
}

schema_contract_violations() { # <version> <dirty> <up-set> <down-set>
  local ver=$1 dirty=$2 ups=$3 downs=$4
  [[ "$ver" == "$SCHEMA_HEAD" ]] || printf 'schema version %s != pinned head %s\n' "$ver" "$SCHEMA_HEAD"
  [[ "$dirty" == "f" ]] || printf 'schema_migrations.dirty=%s (want f)\n' "$dirty"
  [[ "$ups" == "$SCHEMA_UP_SET" ]] || printf 'up set mismatch\n  got:    %s\n  pinned: %s\n' "$ups" "$SCHEMA_UP_SET"
  [[ "$downs" == "$SCHEMA_UP_SET" ]] || printf 'down set mismatch\n  got:    %s\n  pinned: %s\n' "$downs" "$SCHEMA_UP_SET"
}

# --- S3 empty DB: full schema on the fresh volume ----------------------------
step "S3 empty DB: all embedded migrations applied"
ups=$(migration_versions up)
downs=$(migration_versions down)
dbver=$(dbq "SELECT version FROM schema_migrations")
dirty=$(dbq "SELECT dirty FROM schema_migrations")
viol=$(schema_contract_violations "$dbver" "$dirty" "$ups" "$downs")
[[ -z "$viol" ]] || fail "S3: schema contract violated (pinned head $SCHEMA_HEAD, 26 pairs, 0023 reserved): $viol"
counts=$(dbq "SELECT (SELECT count(*) FROM organizations)||'/'||(SELECT count(*) FROM api_keys)||'/'||(SELECT count(*) FROM admin_users)")
[[ "$counts" == "1/1/1" ]] || fail "S3: seeded counts $counts != 1/1/1"
credits=$(dbq "SELECT count(*) FROM org_credits WHERE balance_cents > 0")
[[ "$credits" -ge 1 ]] || fail "S3: no org credit balance > 0"
# Oracle negative controls: each synthetic breach the oracle itself must
# catch (lowered head, missing head migration file, dirty state) — otherwise
# the pinned check above could pass vacuously.
neg_head=$(schema_contract_violations 26 f "$ups" "$downs")
[[ "$neg_head" == *"26 != pinned head 27"* ]] || fail "S3: oracle missed lowered head: $neg_head"
neg_missing=$(schema_contract_violations "$dbver" f "$(printf '%s ' $SCHEMA_UP_SET | sed 's/0027 //; s/ $//')" "$downs")
[[ "$neg_missing" == *"up set mismatch"* ]] || fail "S3: oracle missed missing 0027: $neg_missing"
neg_dirty=$(schema_contract_violations "$dbver" t "$ups" "$downs")
[[ "$neg_dirty" == *"dirty=t"* ]] || fail "S3: oracle missed dirty schema_migrations: $neg_dirty"
note "schema head=$dbver (pinned $SCHEMA_HEAD), dirty=f, 26 up/down pairs (0023 reserved); oracle catches lowered head / missing 0027 / dirty"

# --- S3b managed beta views: seven names, content-minimized columns,
# frozen per-org values, app-role reads (expectations pinned, never
# derived from the implementation) ------------------------------------------
step "S3b beta views: exactly seven, content-minimized, frozen per-org values"
beta_views_check dbq
beta_columns_check dbq
note "seven managed views present (no extras, no materialized); columns content-minimized"

# Deterministic fixture org (fixed uuids/bigint ids; timestamps pinned to one
# UTC hour so day grouping is stable). Durations 200/200/300 yield the pinned
# p50/p95 200/290 under percentile_cont; row 2 is the only cache hit, row 3
# the only >=400. BYOK attribution is pinned via an org_custom_models row.
FIX_ORG='66666666-6666-4666-8666-666666666666'
FIX_T0=$(dbq "SELECT date_trunc('hour', now())::text")
dbq "DELETE FROM request_logs WHERE org_id = '$FIX_ORG';
DELETE FROM org_custom_models WHERE org_id = '$FIX_ORG';
DELETE FROM organizations WHERE id = '$FIX_ORG';
INSERT INTO organizations (id, name, slug, created_at) VALUES ('$FIX_ORG', 'qs-fixture-org', 'qs-fixture-org', '$FIX_T0');
INSERT INTO org_custom_models (id, org_id, model_name, provider, upstream_url) VALUES (987650001, '$FIX_ORG', 'mock-model', 'qs-fixture-provider', 'http://fixture.invalid');
INSERT INTO request_logs (id, org_id, model_requested, model_used, status_code, duration_ms, error, created_at, updated_at, request_id, cache_hit_type, user_id, home_region) VALUES
  (987650101, '$FIX_ORG', 'mock-model', 'mock-model', 200, 200, NULL, '$FIX_T0'::timestamptz + interval '90 seconds', '$FIX_T0'::timestamptz + interval '90 seconds', 'qs-fixture-req-1', NULL, '66666666-6666-4666-8666-000000000001', 'qs'),
  (987650102, '$FIX_ORG', 'mock-model', 'mock-model', 200, 200, NULL, '$FIX_T0'::timestamptz + interval '150 seconds', '$FIX_T0'::timestamptz + interval '150 seconds', 'qs-fixture-req-2', 'exact', '66666666-6666-4666-8666-000000000002', 'qs'),
  (987650103, '$FIX_ORG', 'mock-model', 'mock-model', 500, 300, 'fixture error', '$FIX_T0'::timestamptz + interval '180 seconds', '$FIX_T0'::timestamptz + interval '180 seconds', 'qs-fixture-req-3', NULL, '66666666-6666-4666-8666-000000000003', 'qs')" >/dev/null
beta_fixture_values_check dbq
note "fixture org pinned: 3 requests/1 error, DAU 3/3, ttfq t0/+90s/90s, byok provider, p50/p95 200/290, cache 1/3"

# org1 pinned to the actual S2 smoke rows: view aggregates must equal
# aggregates computed independently over raw request_logs for the seeded org.
org1=$(dbq "SELECT id FROM organizations WHERE id <> '$FIX_ORG' ORDER BY created_at LIMIT 1")
[[ -n "$org1" ]] || fail "S3b: seeded org missing"
raw_reqs=$(dbq "SELECT count(*) FROM request_logs WHERE org_id = '$org1'")
raw_errs=$(dbq "SELECT count(*) FROM request_logs WHERE org_id = '$org1' AND status_code >= 400")
raw_users=$(dbq "SELECT count(DISTINCT COALESCE(user_id::text, api_key_id::text, 'anon')) FROM request_logs WHERE org_id = '$org1'")
[[ "$raw_errs" == "0" ]] || fail "S3b: org1 smoke traffic unexpectedly has $raw_errs error rows"
got=$(dbq "SELECT requests || '/' || errors FROM beta_requests_daily WHERE org_id = '$org1'")
[[ "$got" == "$raw_reqs/0" ]] || fail "S3b: org1 beta_requests_daily [$got] != raw $raw_reqs/0"
got=$(dbq "SELECT active_users || '/' || requests FROM beta_dau_daily WHERE org_id = '$org1'")
[[ "$got" == "$raw_users/$raw_reqs" ]] || fail "S3b: org1 beta_dau_daily [$got] != raw $raw_users/$raw_reqs"
note "org1 view rows equal raw request_logs aggregates ($raw_reqs requests, 0 errors)"

# The app role reads every view (bootstrap grants; provisioning re-grants).
for v in $BETA_VIEWS; do
  got=$(adbq "SELECT count(*) FROM $v WHERE org_id = '$FIX_ORG'")
  [[ "$got" == "1" ]] || fail "S3b: app-role read of $v returned [$got], want 1 fixture row"
done
note "app role reads all seven views (1 fixture row each)"

# --- S3c degraded readiness: a revoked/dropped view is named degraded while
# the gateway still serves; the documented migrate boundary self-heals all
# seven; a fresh startup reports ready ---------------------------------------
step "S3c revoked view: app read denied 42501, named degraded readiness, gateway serves"
dbq "REVOKE SELECT ON public.beta_latency_daily FROM yabanin_app" >/dev/null
set +e
deny_out=$(adbq "SELECT count(*) FROM public.beta_latency_daily WHERE org_id = '$FIX_ORG'" 2>&1)
deny_rc=$?
set -e
if [[ $deny_rc -eq 0 ]] || ! grep -q '42501' <<<"$deny_out" || ! grep -q 'permission denied' <<<"$deny_out"; then
  fail "S3c: revoked-view read as yabanin_app rc=$deny_rc, want nonzero with SQLSTATE 42501: $deny_out"
fi
deg0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gw_restart_wait || fail "S3c: gateway did not come back after restart (revoked view)"
deg_log=$(gw_log_wait 90 "$deg0" "beta metrics views not ready" "beta_latency_daily") \
  || fail "S3c: named degraded readiness for beta_latency_daily not logged (dump above)"
if grep -qF 'msg="beta metrics views ready"' <<<"$deg_log"; then
  fail "S3c: ready line logged while beta_latency_daily is unreadable"
fi
gw_serve_200 '{"model":"mock-model","stream":false,"messages":[{"role":"user","content":"degraded"}]}' \
  || fail "S3c: gateway did not serve while degraded (status above)"
note "named degraded (unreadable beta_latency_daily) while still serving 200"

step "S3c migrate boundary self-heals the revoked view; fresh startup ready"
"${FX[@]}" run --rm migrate >/dev/null 2>&1 || fail "S3c: migrate re-run failed (revoked view)"
got=$(adbq "SELECT count(*) FROM public.beta_latency_daily WHERE org_id = '$FIX_ORG'")
[[ "$got" == "1" ]] || fail "S3c: app-role read not healed after migrate: [$got]"
heal0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gw_restart_wait || fail "S3c: gateway did not come back after restart (healed)"
heal_log=$(gw_log_wait 90 "$heal0" 'msg="beta metrics views ready"') \
  || fail "S3c: fresh startup did not report ready after heal (dump above)"
if grep -qF "beta metrics views not ready" <<<"$heal_log"; then
  fail "S3c: stale degraded line after heal"
fi
note "re-grant via migrate; fresh startup reports ready"

step "S3c dropped view: named degraded while serving; migrate recreates all seven"
dbq "DROP VIEW public.beta_cache_hit_rate_daily" >/dev/null
drop_views=$(dbq "SELECT count(*) FROM pg_views WHERE schemaname = 'public' AND viewname LIKE 'beta\\_%'")
[[ "$drop_views" == "6" ]] || fail "S3c: expected 6 beta views after drop, got $drop_views"
deg1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gw_restart_wait || fail "S3c: gateway did not come back after restart (dropped view)"
deg_log=$(gw_log_wait 90 "$deg1" "beta metrics views not ready" "beta_cache_hit_rate_daily") \
  || fail "S3c: named degraded readiness for the dropped view not logged (dump above)"
if grep -qF 'msg="beta metrics views ready"' <<<"$deg_log"; then
  fail "S3c: ready line logged while beta_cache_hit_rate_daily is dropped"
fi
gw_serve_200 '{"model":"mock-model","stream":false,"messages":[{"role":"user","content":"degraded2"}]}' \
  || fail "S3c: gateway did not serve while view dropped (status above)"
"${FX[@]}" run --rm migrate >/dev/null 2>&1 || fail "S3c: migrate re-run failed (dropped view)"
beta_views_check dbq
beta_fixture_values_check dbq
got=$(adbq "SELECT count(*) FROM public.beta_cache_hit_rate_daily WHERE org_id = '$FIX_ORG'")
[[ "$got" == "1" ]] || fail "S3c: app-role read of recreated view [$got] != 1"
ready0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gw_restart_wait || fail "S3c: gateway did not come back after restart (recreated view)"
ready_log=$(gw_log_wait 90 "$ready0" 'msg="beta metrics views ready"') \
  || fail "S3c: fresh startup did not report ready after recreate (dump above)"
note "dropped view recreated + re-granted by migrate; fresh startup ready"

# --- S4 restart: named volume survives down (no -v) --------------------------
step "S4 restart: down (no -v) -> up -> same key serves"
"${FX[@]}" down --remove-orphans
docker volume inspect "${proj_fixed}_pg_data" >/dev/null 2>&1 \
  || fail "S4: named volume ${proj_fixed}_pg_data dropped by down"
note "volume ${proj_fixed}_pg_data survived down"
up_wait 300 "$proj_fixed" nobuild "${FX[@]}" || fail "S4: up --wait failed or stalled"
mig_status=$(docker inspect -f '{{.State.Status}}/{{.State.ExitCode}}' "${proj_fixed}-migrate-1")
[[ "$mig_status" == "exited/0" ]] || fail "S4: migrate re-run state $mig_status, want exited/0"
seed_rerun=$(bash scripts/quickstart/seed.sh 2>&1)
grep -q "API key already exists" <<<"$seed_rerun" || fail "S4: seed rerun not a no-op: $seed_rerun"
if grep -q "shown once, store it now" <<<"$seed_rerun"; then
  fail "S4: seed rerun re-printed the plaintext key"
fi
note "seed rerun: loud no-op, plaintext not reprinted"
counts2=$(dbq "SELECT (SELECT count(*) FROM organizations)||'/'||(SELECT count(*) FROM api_keys)||'/'||(SELECT count(*) FROM admin_users)")
[[ "$counts2" == "1/1/1" ]] || fail "S4: counts after restart $counts2 != 1/1/1"
smoke_out2=$(bash scripts/quickstart/smoke.sh "$key")
grep -q "^smoke ok (" <<<"$smoke_out2" || fail "S4: smoke with same key after restart failed: $smoke_out2"
note "$smoke_out2 (same key as S2)"

# The seven managed views and the frozen fixture rows ride the named volume.
beta_views_check dbq
beta_fixture_values_check dbq
note "seven views + frozen fixture values intact after down/up"

# --- S6 wrong secrets (fixed stack still up) ---------------------------------
step "S6a wrong secret: weak session key refuses production startup"
set +e
weak_out=$("${FX[@]}" run --rm -T \
  -e YABANIN_ENV=production -e YABANIN_SESSION_KEY=changeme \
  yabanin dev 2>&1)
weak_code=$?
set -e
[[ "$weak_code" -eq 1 ]] || fail "S6a: weak-key dev run exit $weak_code, want 1"
grep -q "session secret rejected" <<<"$weak_out" \
  || fail "S6a: rejection message missing in: $weak_out"
note "exit 1, message: session secret rejected (production posture)"

step "S6b wrong secret: wrong YABANIN_ENCRYPTION_KEY fails closed on enc: credentials"
enc_material=$(openssl rand -hex 24)
enc_key_file="$BRK_TMP/enc-upstream.key"
printf '%s' "$enc_material" > "$enc_key_file"
enc_seed_out=$(run_bounded 300 "${FX[@]}" run --rm -T \
  --volume "$enc_key_file:/tmp/enc-upstream.key:ro" \
  seed --admin-email admin@localhost --profile provider --model enc-model \
  --upstream-key-file /tmp/enc-upstream.key 2>&1) \
  || fail "S6b: provider-profile seed one-shot failed or stalled: $enc_seed_out"
enc_row=$(dbq "SELECT count(*) FROM models_registry WHERE model_name='enc-model'")
[[ "$enc_row" == "1" ]] || fail "S6b: provider-profile seed did not register enc-model: $enc_seed_out"
stored=$(dbq "SELECT upstream_api_key FROM models_registry WHERE model_name='enc-model'")
grep -q "^enc:" <<<"$stored" || fail "S6b: upstream key not stored as enc: (prefix: ${stored:0:6}…)"
note "enc-model registered, upstream key stored as enc:… (plaintext only in --upstream-key-file)"
enc_ok=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" \
  -H 'Content-Type: application/json' \
  -d '{"model":"enc-model","stream":false,"messages":[{"role":"user","content":"ping"}]}' \
  "$QS_BASE/v1/chat/completions")
[[ "$enc_ok" == "200" ]] || fail "S6b: correct-key stack failed to serve enc-model (HTTP $enc_ok)"
note "contrast base: correct key decrypts enc-model, HTTP 200"
wk=$(openssl rand -hex 32)
"${FX[@]}" run -d --rm --name "$proj_fixed-wrongkey" \
  -p "127.0.0.1:${wrongkey_port}:8082" \
  -e "YABANIN_ENCRYPTION_KEY=$wk" yabanin >/dev/null
wk_base="http://127.0.0.1:${wrongkey_port}"
wk_up=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if curl -fsS "$wk_base/healthz" >/dev/null 2>&1; then wk_up=1; break; fi
  sleep 2
done
[[ "$wk_up" -eq 1 ]] || { docker logs "$proj_fixed-wrongkey" 2>&1 | tail -20 >&2; fail "S6b: wrong-key gateway never became healthy"; }
wk_body=$(curl -s -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
  -d '{"model":"enc-model","stream":false,"messages":[{"role":"user","content":"ping"}]}' \
  "$wk_base/v1/chat/completions")
grep -q "model_registry_unavailable" <<<"$wk_body" \
  || fail "S6b: wrong-key response for enc-model not fail-closed: $wk_body"
wk_mock_code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-model","stream":false,"messages":[{"role":"user","content":"ping"}]}' \
  "$wk_base/v1/chat/completions")
wk_decrypt_logs=$(docker logs "$proj_fixed-wrongkey" 2>&1 | grep -c "decrypt upstream_api_key" || true)
[[ "${wk_decrypt_logs:-0}" -ge 1 ]] || fail "S6b: no decrypt-failure log naming the cause"
docker rm -f "$proj_fixed-wrongkey" >/dev/null
note "wrong-key one-off: enc-model 503 model_registry_unavailable + decrypt-failure WARN (no silent global-key fallback); one-off removed"
note "observed, not asserted: NULL-upstream-key mock-model on the wrong-key gateway -> HTTP $wk_mock_code (nothing encrypted to decrypt)"
ok_code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-model","stream":false,"messages":[{"role":"user","content":"ping"}]}' \
  "$QS_BASE/v1/chat/completions")
[[ "$ok_code" == "200" ]] || fail "S6b contrast: correct stack returned $ok_code, want 200"
note "contrast: correct-key stack served the same request with 200"

# --- S5 broken-vs-fixed: anonymous-volume fixture vs shipped named volume ----
step "S5 broken-vs-fixed: pre-R055-03 anonymous-volume fixture must fail the restart check"
# shown transient ENOENT on a just-created mktemp dir; a fresh write succeeds.
fixture_ok=0
for _attempt in 1 2 3; do
  if python3 - "$compose_file" "$BRK_COMPOSE" "$fixture_subnet" "$fixture_mock_ip" "$fixture_mock_url" <<'PY'
import re, sys
src_path, dst_path = sys.argv[1], sys.argv[2]
subnet, mock_ip, mock_url = sys.argv[3], sys.argv[4], sys.argv[5]
src = open(src_path).read()
topvol = "\nvolumes:\n  pg_data:\n"
assert topvol in src, "shipped compose shape changed; fixture needs update"
# --- re-subnet the fixture (post-D-4 multi-project fix) ----------------------
# The shipped pin stays on the primary project (unchanged production file);
# the fixture is rewritten onto its own /24 so the still-running fixed
# project and the fixture never claim one subnet.
# 1. Bake the literal upstream URL (2 sites: seed + provider). The default is
#    interpolated from QS_UPSTREAM_URL, which deploy/quickstart/.env sets to
#    the primary pin — rewriting only the default would silently revert.
primary_lit = "http://10.207.0.9:8081"
inter = "${QS_UPSTREAM_URL:-" + primary_lit + "}"
assert src.count(inter) == 2, \
    "QS_UPSTREAM_URL interpolation sites changed; fixture needs update"
broken = src.replace(inter, mock_url)
# 2. Static mock-openai address -> the fixture subnet (must match 1).
assert broken.count("ipv4_address: 10.207.0.9") == 1, \
    "mock-openai static IP site changed; fixture needs update"
broken = broken.replace("ipv4_address: 10.207.0.9", "ipv4_address: " + mock_ip)
# 3. ipam subnet (config line + the explaining comment).
assert broken.count("10.207.0.0/24") == 2, \
    "pinned subnet sites changed; fixture needs update"
broken = broken.replace("10.207.0.0/24", subnet)
assert "10.207." not in broken, "fixture still references the primary pin"
# --- defect under test: anonymous postgres volume ----------------------------
broken, n = re.subn(
    r"    volumes:\n(?:[ ]*#[^\n]*\n)*      - pg_data:/var/lib/postgresql/data\n",
    "", broken, count=1)
assert n == 1, "postgres pg_data mount block not found; fixture needs update"
broken = broken.replace(topvol, "\n")
assert "pg_data" not in broken, "fixture still references pg_data"
open(dst_path, "w").write(broken)
PY
  then fixture_ok=1; break; fi
  sleep 1
done
[[ "$fixture_ok" == 1 ]] || fail "S5: fixture generation failed (3 attempts)"
note "fixture: postgres volume mount removed (PGDATA falls back to the image's anonymous volume)"
note "fixture: re-subnetted to $fixture_subnet (mock at $fixture_mock_ip, literal upstream baked) — no overlap with the primary $pri_pin_subnet pin"
docker compose -p "$proj_broken" -f "$BRK_COMPOSE" --project-directory deploy/quickstart config -q \
  || fail "S5: generated fixture does not render as a compose file"
BRIX=(docker compose -p "$proj_broken" -f "$BRK_COMPOSE" --project-directory deploy/quickstart --profile mock)
# Seed the broken fixture through the BROKEN compose itself. seed.sh resolves
# to the shipped file or the primary scratch override — both declare the
# named pg_data volume — so under this project name it would recreate
# postgres onto that volume and mask the anonymous-volume defect entirely.
BRIXS=(docker compose -p "$proj_broken" -f "$BRK_COMPOSE" --project-directory deploy/quickstart --profile mock --profile seed)
brk_seed() {
  local pw_file="$BRK_TMP/brk-seed-pw.$$"
  printf '%s\n' "$(openssl rand -hex 16)" >"$pw_file"
  local out rc=0
  out=$(RUN_BOUNDED_STDIN="$pw_file" run_bounded 300 "${BRIXS[@]}" run --rm -T seed \
    --admin-email admin@localhost --admin-password-stdin 2>&1) || rc=$?
  rm -f "$pw_file"
  printf '%s\n' "$out"
  return $rc
}
use_broken
"${BRIX[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
up_wait 300 "$proj_broken" nobuild "${BRIX[@]}" || fail "S5: fixture up failed or stalled"
# Multi-project regression, asserted explicitly: the pinned primary network
# and the re-subnetted fixture network must coexist. This is the exact
# mechanism the pre-fix suite died on — two pinned quickstart projects
# claiming one subnet.
brk_subnet=$(docker network inspect "${proj_broken}_default" \
  --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
[[ "$brk_subnet" == "$fixture_subnet" ]] \
  || fail "S5: fixture network subnet $brk_subnet != $fixture_subnet"
docker network inspect "${proj_fixed}_default" >/dev/null \
  || fail "S5: primary network vanished; pinned-primary coexistence scenario did not run"
fixed_subnet=$(docker network inspect "${proj_fixed}_default" \
  --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
[[ "$fixed_subnet" == "$pri_pin_subnet" ]] \
  || fail "S5: primary network subnet $fixed_subnet != $pri_pin_subnet"
[[ "$fixed_subnet" != "$brk_subnet" ]] \
  || fail "S5: primary and fixture networks share subnet $fixed_subnet; multi-project isolation did not hold"
note "coexistence: ${proj_fixed}_default ($fixed_subnet) + ${proj_broken}_default ($brk_subnet) both up, distinct subnets"
brk_type=$(docker inspect -f '{{range .Mounts}}{{.Type}} {{end}}' "${proj_broken}-postgres-1")
brk_names=$(docker inspect -f '{{range .Mounts}}{{.Name}} {{end}}' "${proj_broken}-postgres-1")
[[ "$brk_type" == *"volume"* ]] || fail "S5: fixture postgres has no volume mount: $brk_type"
if grep -qw "${proj_broken}_pg_data" <<<"$brk_names"; then
  fail "S5: fixture unexpectedly uses the named volume"
fi
note "postgres mount type(s): $brk_type; volume name(s): $brk_names (anonymous, image VOLUME fallback)"
seed_b_out=$(brk_seed) || fail "S5: fixture seed one-shot failed: $seed_b_out"
key_b=$(printf '%s' "$seed_b_out" | extract_key)
[[ -n "$key_b" ]] || fail "S5: fixture seed did not print a key: $seed_b_out"
if docker volume ls --format '{{.Name}}' | grep -qx "${proj_broken}_pg_data"; then
  fail "S5: broken project grew a pg_data volume (seed path leaked the shipped compose)"
fi
"${BRIX[@]}" down --remove-orphans
up_wait 300 "$proj_broken" nobuild "${BRIX[@]}" || fail "S5: fixture restart up failed or stalled"
code_b=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key_b" "$QS_BASE/v1/models" || true)
[[ "$code_b" == "401" ]] || fail "S5: BROKEN fixture unexpectedly survived restart (HTTP $code_b); check no longer distinguishes the defect"
note "broken: seeded key rejected after restart (HTTP 401) — defect reproduced"
seed_b2_out=$(brk_seed) || fail "S5: fixture reseed one-shot failed: $seed_b2_out"
key_b2=$(printf '%s' "$seed_b2_out" | extract_key)
[[ -n "$key_b2" && "$key_b2" != "$key_b" ]] || fail "S5: reseed on wiped DB did not mint a fresh key (data-loss signature missing): $seed_b2_out"
note "broken: reseed minted a second key — silent wipe signature confirmed"
use_fixed

# --- S7 documented command surface matches the repo ---------------------------
step "S7 docs vs repo: documented commands and links exist"
grep -q 'bash scripts/quickstart/init-env.sh' docs/quickstart.md || fail "S7: docs missing init-env step"
for t in quickstart-up quickstart-seed quickstart-smoke quickstart-down; do
  grep -q "^${t}:" Makefile || fail "S7: docs reference missing make target $t"
  grep -q "make ${t}" docs/quickstart.md || fail "S7: docs/Makefile mismatch for $t"
done
grep -q 'keeps the database volume' docs/quickstart.md \
  || fail "S7: docs restart claim missing (S4 verified it; docs must keep stating it)"
grep -q 'Nothing listens on `0.0.0.0`' docs/quickstart.md \
  || fail "S7: docs localhost-only claim missing (S1 verified it)"
[[ -f docs/ops/public-stand.md && -f docs/byok.md ]] || fail "S7: docs links point to missing files"
note "five-command flow + restart/localhost claims + links: consistent with verified behavior"

# --- S8 documented five-command flow via make targets (consumer entry point) -
step "S8 documented consumer flow (make targets) on an isolated clean stack"
use_integ
# The make flow honors QS_COMPOSE_FILE (exported by use_integ), so the integ
# project runs the same compose as the primary: the scratch rewrite under
# QS_PRIMARY_NET, the shipped file and its D-4 pin otherwise. Nothing reads
# the fixed stack after S6b, so retire it — volume included, cleanup removes
# leftovers anyway — to free the fixed stack's pinned subnet ($pri_pin_subnet)
# for the integ project's network.
"${FX[@]}" down -v --remove-orphans >/dev/null
RUN_BOUNDED_KEEP="$BRK_TMP/make-quickstart-up-s8.log" run_bounded 1200 make quickstart-up >/dev/null \
  || fail "S8: make quickstart-up failed or stalled (failure dump above; full output kept at $BRK_TMP/make-quickstart-up-s8.log)"
note "make quickstart-up exit 0 (init-env idempotence + reproducible build + up --no-build --wait; output kept at $BRK_TMP/make-quickstart-up-s8.log)"
# Executed F2 proof: the make-created project must sit on the primary pin
# ($pri_pin_subnet — the override /24 or, without one, the shipped pin),
# never on the fixture subnet; under the override its mock must hold the
# rewritten upstream address (the same one seed/smoke route through); and
# the shipped compose must stay byte-identical to the S0 digest.
integ_subnet=$(docker network inspect "${proj_integ}_default" \
  --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}') \
  || fail "S8: no ${proj_integ}_default network after make quickstart-up"
[[ "$integ_subnet" == "$pri_pin_subnet" ]] \
  || fail "S8: make-flow network ${proj_integ}_default is ${integ_subnet}, want the primary pin ${pri_pin_subnet} (QS_COMPOSE_FILE not honored by the make flow?)"
[[ "$integ_subnet" != "$fixture_subnet" ]] \
  || fail "S8: make-flow network sits on the fixture subnet ${fixture_subnet}; projects are not isolated"
if [[ -n "$primary_net" ]]; then
  integ_mock_ip=$(docker inspect "${proj_integ}-mock-openai-1" \
    -f '{{range .NetworkSettings.Networks}}{{.IPAMConfig.IPv4Address}}{{end}}' 2>/dev/null || true)
  [[ "$integ_mock_ip" == "$primary_mock_ip" ]] \
    || fail "S8: make-flow mock-openai is at ${integ_mock_ip:-no static address}, want the rewritten upstream ${primary_mock_ip}"
fi
shipped_now=$(sha256sum "$compose_file" | cut -d' ' -f1)
[[ "$shipped_now" == "$shipped_sha" ]] \
  || fail "S8: shipped compose bytes changed during the run (${shipped_now} != ${shipped_sha})"
note "make-flow network ${proj_integ}_default on ${integ_subnet} (fixture keeps ${fixture_subnet}); shipped compose sha256 unchanged (${shipped_now:0:12}…)"
inventory_assert "$proj_integ" "${QS_COMPOSE_FILE:-$compose_file}" || fail "S8: make-created stack fails the fresh-install inventory"
note "make-created stack: documented surface only, one-shots Exited(0), 127.0.0.1-only"
seed_out=$(make quickstart-seed 2>&1)
key=$(printf '%s' "$seed_out" | extract_key)
[[ -n "$key" ]] || fail "S8: make quickstart-seed did not print an API key"
admin_pass=$(printf '%s' "$seed_out" | extract_admin_password)
[[ -n "$admin_pass" ]] || fail "S8: make quickstart-seed did not print the admin password"
note "seed via the canonical binary one-shot: key ${key:0:10}… + admin password (redacted here)"
smoke_out=$(make -s quickstart-smoke KEY="$key")
grep -q "^smoke ok (" <<<"$smoke_out" || fail "S8: make quickstart-smoke failed: $smoke_out"
note "$smoke_out (documented first request through the make entry point)"

# --- S9 empty DB through the same boundary -----------------------------------
step "S9 empty DB: documented reset, full schema re-applied, old key refused"
"${INX[@]}" down -v --remove-orphans >/dev/null
if docker volume inspect "${proj_integ}_pg_data" >/dev/null 2>&1; then
  fail "S9: volume ${proj_integ}_pg_data still present after down -v"
fi
note "volume dropped: the database is truly empty for the next documented up"
RUN_BOUNDED_KEEP="$BRK_TMP/make-quickstart-up-s9.log" run_bounded 900 make quickstart-up >/dev/null \
  || fail "S9: make quickstart-up on the empty DB failed or stalled (failure dump above; full output kept at $BRK_TMP/make-quickstart-up-s9.log)"
mig_s=$(docker inspect -f '{{.State.Status}}/{{.State.ExitCode}}' "${proj_integ}-migrate-1")
[[ "$mig_s" == "exited/0" ]] || fail "S9: migrate on the wiped volume: $mig_s, want exited/0"
ups=$(migration_versions up)
downs=$(migration_versions down)
dbver=$(idbq "SELECT version FROM schema_migrations")
dirty=$(idbq "SELECT dirty FROM schema_migrations")
viol=$(schema_contract_violations "$dbver" "$dirty" "$ups" "$downs")
[[ -z "$viol" ]] || fail "S9: schema contract violated on the empty DB (pinned head $SCHEMA_HEAD, 26 pairs, 0023 reserved): $viol"
counts=$(idbq "SELECT (SELECT count(*) FROM organizations)||'/'||(SELECT count(*) FROM api_keys)||'/'||(SELECT count(*) FROM admin_users)")
[[ "$counts" == "0/0/0" ]] || fail "S9: wiped DB not empty: $counts"
empty_code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-model","stream":false,"messages":[{"role":"user","content":"ping"}]}' \
  "$QS_BASE/v1/chat/completions")
[[ "$empty_code" == "401" ]] || fail "S9: key from the wiped DB got HTTP $empty_code, want 401"
note "empty DB boundary: migrate applied version $dbver (dirty=f); wiped key refused 401"

# The documented reset provisions the seven managed views on the empty
# database before any seed runs, and the app role can read them.
beta_views_check idbq
got=$(idbq "SELECT (SELECT count(*) FROM beta_requests_daily) || '/' || (SELECT count(*) FROM beta_dau_daily) || '/' || (SELECT count(*) FROM beta_onboarding_ttfq)")
[[ "$got" == "0/0/0" ]] || fail "S9: beta views not empty on the fresh DB: $got"
got=$(idbq_app "SELECT count(*) FROM beta_requests_daily")
[[ "$got" == "0" ]] || fail "S9: app role cannot read the fresh beta views: [$got]"
note "seven views exist and are app-readable on the empty DB before seed"
seed_out=$(make quickstart-seed 2>&1)
key9=$(printf '%s' "$seed_out" | extract_key)
[[ -n "$key9" && "$key9" != "$key" ]] || fail "S9: reseed did not mint a fresh key: $seed_out"
admin_pass=$(printf '%s' "$seed_out" | extract_admin_password)
[[ -n "$admin_pass" ]] || fail "S9: reseed did not recreate the root admin password"
smoke_out=$(make -s quickstart-smoke KEY="$key9")
grep -q "^smoke ok (" <<<"$smoke_out" || fail "S9: first request after reseed failed: $smoke_out"
key="$key9"
note "$smoke_out (new key after the documented empty-DB reset)"

# --- S10 restart through the same boundary -----------------------------------
step "S10 restart: documented down/up via make targets, same key serves"
make quickstart-down >/dev/null
if ! docker volume inspect "${proj_integ}_pg_data" >/dev/null 2>&1; then
  fail "S10: documented quickstart-down dropped the pg_data volume"
fi
note "make quickstart-down kept the volume (docs restart claim holds at wrapper level)"
RUN_BOUNDED_KEEP="$BRK_TMP/make-quickstart-up-s10.log" run_bounded 900 make quickstart-up >/dev/null \
  || fail "S10: make quickstart-up after restart failed or stalled (failure dump above; full output kept at $BRK_TMP/make-quickstart-up-s10.log)"
mig_s=$(docker inspect -f '{{.State.Status}}/{{.State.ExitCode}}' "${proj_integ}-migrate-1")
[[ "$mig_s" == "exited/0" ]] || fail "S10: migrate re-run after restart: $mig_s, want exited/0"
counts=$(idbq "SELECT (SELECT count(*) FROM organizations)||'/'||(SELECT count(*) FROM api_keys)||'/'||(SELECT count(*) FROM admin_users)")
[[ "$counts" == "1/1/1" ]] || fail "S10: counts after restart $counts != 1/1/1"
smoke_out=$(make -s quickstart-smoke KEY="$key")
grep -q "^smoke ok (" <<<"$smoke_out" || fail "S10: same-key smoke after restart failed: $smoke_out"
note "$smoke_out (same key as S9 across a documented restart)"

# --- S11 wrong secrets through the same boundary ------------------------------
step "S11a wrong secret: half-set license env refuses the quickstart dev process"
lic_code=0
lic_out=$(run_bounded 180 "${INX[@]}" run --rm -T \
  -e YABANIN_LICENSE_FILE=/tmp/license.key yabanin dev 2>&1) || lic_code=$?
[[ "$lic_code" -eq 1 ]] || fail "S11a: half-set license env dev run exit $lic_code, want 1"
[[ "$lic_code" -eq 1 ]] || fail "S11a: half-set license env dev run exit $lic_code, want 1"
grep -q "FATAL: YABANIN_LICENSE_ROOT_PUBKEY is required" <<<"$lic_out" \
  || fail "S11a: license fail-closed message missing in: $lic_out"
note "exit 1, message: FATAL: YABANIN_LICENSE_ROOT_PUBKEY is required …"

step "S11b wrong secret: admin plane rejects a wrong password, accepts the seed password"
login_code=$(curl -s -D "$BRK_TMP/login.hdr" -o "$BRK_TMP/login.html" -w '%{http_code}' \
  "http://127.0.0.1:${integ_adm}/auth/login")
[[ "$login_code" == "200" ]] || fail "S11b: GET /auth/login returned $login_code, want 200"
csrf=$(sed -n 's/.*name="_csrf" value="\([0-9a-fA-F]*\)".*/\1/p' "$BRK_TMP/login.html" | head -1)
[[ -n "$csrf" ]] || fail "S11b: no _csrf token on the login page"
grep -q "yabanin_csrf_token=$csrf" "$BRK_TMP/login.hdr" \
  || fail "S11b: csrf cookie not issued alongside the form token"
wrong_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Cookie: yabanin_csrf_token=$csrf" \
  --data-urlencode "email=admin@localhost" \
  --data-urlencode "password=definitely-wrong-$RANDOM" \
  --data-urlencode "_csrf=$csrf" \
  "http://127.0.0.1:${integ_adm}/auth/login")
[[ "$wrong_code" == "401" ]] || fail "S11b: wrong password returned $wrong_code, want 401"
ok_code=$(curl -s -o /dev/null -w '%{http_code}' -D "$BRK_TMP/login-ok.hdr" \
  -H "Cookie: yabanin_csrf_token=$csrf" \
  --data-urlencode "email=admin@localhost" \
  --data-urlencode "password=$admin_pass" \
  --data-urlencode "_csrf=$csrf" \
  "http://127.0.0.1:${integ_adm}/auth/login")
[[ "$ok_code" == "302" ]] || fail "S11b: correct password returned $ok_code, want 302"
grep -q "yabanin_admin_session=" "$BRK_TMP/login-ok.hdr" \
  || fail "S11b: no admin session cookie on the successful login"
note "wrong password 401; seed-printed password 302 + yabanin_admin_session cookie"

# --- S12 linked deploy paths: configs render, secrets fail-closed, dispatch ---
step "S12 linked deploy paths: config renders + required-secret rejection + binary dispatch"
if [[ ! -f deploy/.env ]]; then
  integ_env_created=1
  [[ -d deploy/secrets ]] || integ_secrets_created=1
  bash scripts/deploy/init-secrets.sh >/dev/null
fi
docker compose -f deploy/docker-compose.yml config -q \
  || fail "S12: dev stack deploy/docker-compose.yml does not render"
docker compose -f deploy/docker-compose.prod.yml config -q \
  || fail "S12: prod stack deploy/docker-compose.prod.yml does not render"
docker compose -f deploy/docker-compose.prod.yml -f deploy/docker-compose.e2e.yml config -q \
  || fail "S12: prod+e2e overlay does not render"
note "dev / prod / prod+e2e compose configs render (documented prerequisite init-secrets.sh)"
set +e
neg_err=$(docker compose --env-file /dev/null -f deploy/docker-compose.prod.yml config -q 2>&1)
neg_code=$?
set -e
[[ "$neg_code" -ne 0 ]] || fail "S12: prod compose accepted a stack missing GRAFANA_ADMIN_PASSWORD"
grep -q "GRAFANA_ADMIN_PASSWORD is required" <<<"$neg_err" \
  || fail "S12: rejection does not name the missing secret: $neg_err"
note "missing required secret rejected at config time (contract §6)"
for c in gateway admin loggerd mcp migrate seed; do
  grep -q "case \"$c\":" cmd/yabanin/main.go \
    || fail "S12: subcommand $c is not dispatched by the unified binary"
done
grep -q 'subCmd == "dev"' cmd/yabanin/main.go \
  || fail "S12: dev orchestrator path missing from the unified binary"
for v in YABANIN_PG_URI YABANIN_REGION YABANIN_REDIS_ADDR YABANIN_GATEWAY_LISTEN \
         YABANIN_ADMIN_LISTEN YABANIN_LOGGERD_LISTEN YABANIN_AUTH_MODE \
         YABANIN_PROVIDER_ADDR YABANIN_SESSION_KEY YABANIN_CACHE_HMAC_SECRET \
         YABANIN_ENCRYPTION_KEY; do
  grep -rq "$v" pkg/config/ || fail "S12: env var $v unknown to pkg/config"
done
note "every compose yabanin subcommand dispatches; quickstart env vars known to pkg/config"

echo
echo "R055 REGRESSION+INTEGRATION: ALL PASS (S1–S12)"
