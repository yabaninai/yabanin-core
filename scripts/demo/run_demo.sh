#!/usr/bin/env bash
#
# run_demo.sh — one command from a clean clone to a populated dashboard.
#
# Brings up the minimal compose set, waits on real readiness endpoints, seeds a
# demo org + team + API key + admin user, replays a shaped traffic script through
# the gateway, and prints the URLs, the demo API key, and the admin login. No
# manual steps.
#
# The gateway is pointed at the in-stack mock provider (mock-openai) via
# YABANIN_PROVIDER_ADDR, and the embedder is the mock embedder (the bge-embedder
# service is built from deploy/mock-embedder) — so the demo needs no model
# download and no real provider credentials.
#
# Teardown: make demo-down

set -euo pipefail

# --- paths -------------------------------------------------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/deploy/docker-compose.yml"
SECRETS_DIR="$ROOT/deploy/secrets"
TRAFFIC="$ROOT/scripts/demo/traffic.jsonl"

# Minimal set only: no prometheus, grafana, alertmanager, classifier-ML, llama.
SERVICES=(postgres redis migrate mock-openai bge-embedder gateway loggerd admin dashboard)

# Demo credentials — printed at the end so the operator can use them immediately.
DEMO_KEY="demo-key-1234567890"
DEMO_ADMIN_EMAIL="demo@local"
DEMO_ADMIN_PASSWORD="demo-admin-123"
# bcrypt (cost 12) hash of $DEMO_ADMIN_PASSWORD, precomputed to match
# adminauth.HashPassword. Regenerate if the password changes.
DEMO_ADMIN_HASH='$2a$12$A.VN9Ew12V7DJkOibxnQauIc853N5lAvVZX4E6aBLVv4EoAVwVXv.'

# Fixed UUIDs so re-runs are idempotent (ON CONFLICT ... DO NOTHING/UPDATE).
DEMO_ORG_UUID="11111111-2222-4333-8444-555555555555"
DEMO_TEAM_UUID="99999999-8888-4777-8666-555555555555"
DEMO_KEY_UUID="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
DEMO_ADMIN_UUID="cccccccc-dddd-4eee-8fff-000000000000"

log()  { printf '\033[1;34m[demo]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[demo] FAIL: %s\033[0m\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found in PATH"

# The seed runs through the postgres container's own psql (no host psql
# dependency). The compose service is "postgres"; user/db are yabanin/yabanin.
PG_SVC="postgres"

# pg_exec runs a single SQL statement (or a heredoc via stdin) in the postgres
# container and prints the result. Exits non-zero on SQL error.
pg_exec() {
  docker compose -f "$COMPOSE_FILE" exec -T "$PG_SVC" \
    psql -U yabanin -d yabanin -v ON_ERROR_STOP=1 "$@"
}

# pg_wait polls "SELECT 1" until postgres accepts connections.
pg_wait() {
  local i
  for i in $(seq 1 60); do
    if pg_exec -tAc "SELECT 1" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# --- 1. Bring up the minimal set --------------------------------------------
# V9: optional shadow-mode demo. `make demo SHADOW=1` mirrors all non-streaming
# demo traffic to gpt-4o on the same mock provider so the /api/analytics/shadow
# comparison endpoint returns real data. Default OFF: plain `make demo` is
# unchanged. Normalize once here so bare $SHADOW reads below are set -u safe.
SHADOW="${SHADOW:-0}"
export YABANIN_SHADOW_ENABLED="${SHADOW:-false}"
# The gateway's /metrics (admin listener) requires this bearer key when set,
# and the shadow kill-switch is guarded by it. Exported so the gateway loads
# it and so the host-side curl examples in the summary match the configured
# key. The demo key file (deploy/secrets/, gitignored) is written so
# Prometheus can present it when scraping the gateway — Prometheus v2.5x
# does not expand ${VAR} inline in authorization.credentials, so a file is
# used (see credentials_file in prometheus.yml).
export YABANIN_METRICS_BEARER_KEY="demo-shadow-key"
mkdir -p "$SECRETS_DIR"
printf '%s' "demo-shadow-key" > "$SECRETS_DIR/metrics-bearer.key"
chmod 600 "$SECRETS_DIR/metrics-bearer.key"
if [[ "$SHADOW" == "1" || "$SHADOW" == "true" ]]; then
  log "shadow-mode ENABLED for this demo (mirroring to gpt-4o, sample 1.0)"
fi
log "starting compose services: ${SERVICES[*]}"
# The gateway is pointed at the in-stack mock provider by the compose file
# (YABANIN_PROVIDER_ADDR: http://mock-openai:8081), so no host-side override is
# needed.
# shellcheck disable=SC2086
docker compose -f "$COMPOSE_FILE" up -d "${SERVICES[@]}" 2>&1 | sed 's/^/    /'

# --- 2. Wait on real readiness (timeout + clear failure) --------------------
wait_http() {
  local name="$1" url="$2" timeout="${3:-60}" i=0
  while ! curl -fsS -o /dev/null "$url"; do
    i=$((i+1))
    if (( i >= timeout )); then
      fail "$name did not become ready at $url within ${timeout}s"
    fi
    sleep 1
  done
  log "ready: $name ($url)"
}

log "waiting for postgres"
pg_wait || fail "postgres did not become ready within 60s"

# The one-shot migrate service runs the full set sequentially; wait until a LATE
# migration's artifact exists (org_credits, from migration 0090) as proof the
# whole set ran. Waiting on an early table (models_registry, 0008) is not enough
# — the credit guard needs org_credits (0090) and would 503 otherwise.
log "waiting for migrations to complete (org_credits present)"
for i in $(seq 1 120); do
  if pg_exec -tAc "SELECT to_regclass('org_credits')" 2>/dev/null | grep -q org_credits; then
    break
  fi
  sleep 1
  (( i == 120 )) && fail "migrations did not create org_credits within 120s"
done
log "migrations applied (org_credits present)"

wait_http gateway   "http://localhost:8082/healthz" 90
wait_http admin     "http://localhost:9091/health"  60
wait_http dashboard "http://localhost:3000/"        60

# --- 3. Seed org + team + API key + admin user (idempotent) -----------------
log "seeding demo org, team, API key, and admin user"
KEY_HASH="$(printf '%s' "$DEMO_KEY" | shasum -a 256 | cut -d' ' -f1)"
seed_sql() {
  cat <<SQL
INSERT INTO organizations (id, name, slug)
VALUES ('$DEMO_ORG_UUID', 'Demo Org', 'demo-org')
ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name;

INSERT INTO organizations_teams (id, org_id, name, slug)
VALUES ('$DEMO_TEAM_UUID', '$DEMO_ORG_UUID', 'Demo Team', 'demo-team')
ON CONFLICT (id) DO NOTHING;

INSERT INTO api_keys (id, key_hash, org_id, name, active, team_id)
VALUES ('$DEMO_KEY_UUID', '$KEY_HASH', '$DEMO_ORG_UUID', 'demo', true, '$DEMO_TEAM_UUID')
ON CONFLICT (key_hash) DO UPDATE SET active = true, org_id = EXCLUDED.org_id, team_id = EXCLUDED.team_id;

INSERT INTO admin_users (id, email, password_hash, display_name, is_root, active)
VALUES ('$DEMO_ADMIN_UUID', '$DEMO_ADMIN_EMAIL', '$DEMO_ADMIN_HASH', 'Demo Admin', true, true)
ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, is_root = true, active = true;

-- Give the demo org a credit wallet so the gateway's credit guard lets
-- requests through (no row => 402 no_billing_setup; \$100,000 headroom).
INSERT INTO org_credits (org_id, balance_cents)
VALUES ('$DEMO_ORG_UUID', 10000000)
ON CONFLICT (org_id) DO UPDATE SET balance_cents = GREATEST(org_credits.balance_cents, EXCLUDED.balance_cents);

-- Give the demo team a monthly budget so the budget enforcer lets requests
-- through (no row => 403 budget_not_configured). Soft limit, high headroom.
INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
VALUES ('$DEMO_TEAM_UUID', 100000, false)
ON CONFLICT (team_id) DO UPDATE SET monthly_limit_usd = GREATEST(team_budgets.monthly_limit_usd, EXCLUDED.monthly_limit_usd), hard_limit = false;
SQL
}
if ! seed_sql | pg_exec -q; then
  fail "seed failed"
fi
log "demo org + team + API key + admin user + credits ready"

# --- 4. Replay the shaped traffic -------------------------------------------
log "replaying $(wc -l < "$TRAFFIC") requests through the gateway"
ok=0; err=0
  n=0
  while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  n=$((n + 1))
  issue="DEMO-$((101 + ((n - 1) % 5)))"
  pipeline="$((9001 + ((n - 1) % 3)))"
  if (( n % 2 == 0 )); then job="test"; repo="acme/web"; else job="review"; repo="acme/payments"; fi
  labels="issue=${issue},ci.system=gitlab,ci.pipeline=${pipeline},ci.job_name=${job},git.repo=${repo}"
  code="$(curl -fsS -o /dev/null -w '%{http_code}' \
    -X POST "http://localhost:8082/v1/chat/completions" \
    -H "Authorization: Bearer $DEMO_KEY" \
    -H "Content-Type: application/json" \
    -H "X-Yabanin-Labels: ${labels}" \
    -d "$line" || true)"
  if [[ "$code" == "200" ]]; then ok=$((ok+1)); else err=$((err+1)); fi
done < "$TRAFFIC"
log "replayed: $ok ok, $err non-200"

# --- 5. Let loggerd flush, then print the summary ---------------------------
log "waiting for loggerd to write the request log"
sleep 5

# --- 5b. Shadow-mode summary (only when SHADOW=1) ----------------------------
if [[ "$SHADOW" == "1" || "$SHADOW" == "true" ]]; then
  log "shadow-mode accounting:"
  shadow_rows="$(pg_exec -tAc "SELECT count(*) FROM request_logs WHERE ab_group='shadow'" 2>/dev/null || echo 0)"
  shadow_primary="$(pg_exec -tAc "SELECT count(*) FROM request_logs WHERE COALESCE(ab_group,'') <> 'shadow'" 2>/dev/null || echo 0)"
  log "  primary rows: $shadow_primary   shadow rows: $shadow_rows"
  compare_sql="SELECT 'primary=' || COALESCE(round(avg(p.cost_in_usd)::numeric, 6), 0) || ' usd/req  shadow=' || COALESCE(round(avg(sh.cost_in_usd)::numeric, 6), 0) || ' usd/req' FROM request_logs p JOIN request_logs sh ON sh.request_id = p.request_id AND sh.ab_group = 'shadow' WHERE COALESCE(p.ab_group, '') <> 'shadow'"
  pg_exec -tAc "$compare_sql" 2>/dev/null | sed 's/^/  /' || true
  log "  compare: log in at http://localhost:9091/auth/login, then"
  log "           GET http://localhost:9091/api/analytics/shadow?days=1"
  log "  kill switch (gateway admin listener, host :9092 -> container :9090):"
  log "    curl -H 'Authorization: Bearer demo-shadow-key' http://localhost:9092/admin/shadow/status"
  log "    curl -X POST -H 'Authorization: Bearer demo-shadow-key' -d '{\"enabled\": false}' http://localhost:9092/admin/shadow/toggle"
fi

log "----------------------------------------"
log "Demo is live."
log "  Dashboard : http://localhost:3000"
log "  Admin     : http://localhost:9091  (log in at /auth/login)"
log "  Gateway   : http://localhost:8082  (POST /v1/chat/completions)"
log "  API key   : $DEMO_KEY"
log "  Admin in  : $DEMO_ADMIN_EMAIL / $DEMO_ADMIN_PASSWORD"
log "----------------------------------------"
log "What was generated:"
log "  - $(wc -l < "$TRAFFIC") chat requests replayed (mix of easy/medium/hard, with repeats)"
log "  - a demo org + team + API key + admin user seeded"
log "  - spend + cache + classifier data now in the DB; log in and open"
log "    Overview / Cost / Cache / Classifier to see non-zero figures"
log "Tear down with: make demo-down"
