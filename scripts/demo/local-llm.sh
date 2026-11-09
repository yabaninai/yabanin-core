#!/usr/bin/env bash
#
# local-llm.sh — run the demo contour with a LOCAL LLM instead of the mock.
#
# Owner decision 2026-11-03: the demo contour must RUN a local LLM
# (<=1B params, permissive license). This script is the operator entry point:
#
#   scripts/demo/local-llm.sh fetch    # one-time: download + sha256-verify weights
#   scripts/demo/local-llm.sh enable   # cold/warm compose bring-up + seed + routing + smoke
#   scripts/demo/local-llm.sh smoke    # assertions only (assumes enabled)
#   scripts/demo/local-llm.sh disable  # restore the mock-primary demo contour
#
# "enable" mirrors docs/preview/DEMO.md Minutes 0-4 exactly (the verified
# path: init-secrets, three-file compose chain, migrate wait, app-role
# bootstrap, seed.sql, services) and then applies demo/local-llm.sql to make
# the local model the served model:
#   - compose: base + demo/demo-egress-override.yml + demo/local-llm-override.yml
#     (the gateway's primary upstream becomes the local model at the literal IP
#     10.207.0.10 — the same D-4 posture as the mock at 10.207.0.9),
#   - registry: demo/local-llm.sql registers local-qwen2.5-0.5b-instruct
#     (provider 'llamacpp'), makes it the SOLE tier-pool member, and pins the
#     demo org to routing_mode='always_cheap' for deterministic routing,
#   - pricing stays offline-fail-closed: provider 'llamacpp' has no price row,
#     so request_logs records cost_status='unknown_price' (N08-P04).
#
# Switch back to the stock demo: `scripts/demo/local-llm.sh disable` (or tear
# down with `down -v` and re-run the DEMO.md Minutes 0-4 sequence — a fresh
# bring-up via demo/seed.sql is always the stock contour).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CF=(-f "$ROOT/deploy/docker-compose.yml"
    -f "$ROOT/demo/demo-egress-override.yml"
    -f "$ROOT/demo/local-llm-override.yml")
docker() { command docker "$@"; }
DC() { docker compose "${CF[@]}" --project-directory "$ROOT/deploy" "$@"; }
DCB() { docker compose -f "$ROOT/deploy/docker-compose.yml" --project-directory "$ROOT/deploy" "$@"; }
MODEL="$ROOT/demo/models/qwen2.5-0.5b-instruct-q4_k_m.gguf"

DEMO_KEY="demo-key-1234567890"
DEMO_ORG_UUID="11111111-2222-4333-8444-555555555555"
GATEWAY_URL="http://localhost:8082/v1/chat/completions"

log()  { printf '\033[1;34m[local-llm]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[local-llm] FAIL: %s\033[0m\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found in PATH"
command -v curl >/dev/null 2>&1 || fail "curl not found in PATH"

pg_exec() { # psql inside the postgres container (run_demo.sh parity)
  DCB exec -T postgres psql -U yabanin -d yabanin -v ON_ERROR_STOP=1 "$@"
}

cmd_fetch() {
  "$ROOT/scripts/demo/fetch-local-model.sh"
}

cmd_enable() {
  [[ -f "$MODEL" ]] || fail "weights missing at $MODEL — run: scripts/demo/local-llm.sh fetch"
  [[ -f "$ROOT/deploy/.env" ]] || fail "deploy/.env missing — run: ./scripts/deploy/init-secrets.sh (DEMO.md Minutes 0-4)"

  log "starting compose set (base + egress pin + local-llm override)"
  DC up -d postgres migrate redis mock-openai bge-embedder local-llm | sed 's/^/    /'

  log "waiting for the baseline migration (org_credits present; a re-run may"
  log "  exit migrate with rc 3 — re-streaming an applied migration, harmless)"
  for i in $(seq 1 180); do
    pg_exec -tAc "SELECT to_regclass('org_credits')" 2>/dev/null | grep -q org_credits && break
    [[ $i == 180 ]] && fail "migrations did not produce org_credits within 180s"
    sleep 1
  done

  log "bootstrapping the app role (services SET ROLE yabanin_app; quickstart parity)"
  DCB exec -T postgres psql -U yabanin -d yabanin -v ON_ERROR_STOP=1 \
    < "$ROOT/deploy/quickstart/bootstrap-app-role.sql" >/dev/null

  log "seeding via demo/seed.sql (org/team/key/admin/credits/budgets + model pins)"
  pg_exec -q < "$ROOT/demo/seed.sql" || fail "demo/seed.sql failed"

  log "applying demo/local-llm.sql (local model row + sole pool member + always_cheap)"
  pg_exec -q -v mode=1 < "$ROOT/demo/local-llm.sql" || fail "demo/local-llm.sql (enable) failed"

  log "starting services (gateway gets the local-model provider pin from the override)"
  DC up -d gateway loggerd admin dashboard | sed 's/^/    /'
  for i in $(seq 1 90); do
    curl -fsS -o /dev/null "http://localhost:8082/healthz" 2>/dev/null && break
    [[ $i == 90 ]] && fail "gateway /healthz not ready within 90s (logs: docker compose logs gateway local-llm)"
    sleep 1
  done

  # Warm re-runs: the resolver caches model rows (TTL) and Redis may hold a
  # resolve entry from an earlier contour. Recreate the gateway so registry
  # reads start fresh; Redis resolve entries for the demo key are purged so
  # the auth path below is exercised against the CURRENT seed, never a stale
  # cache (the warm-cache short-circuit is exactly what masked review R1).
  log "recreating the gateway + flushing the demo key's Redis resolve entry"
  DC up -d --force-recreate --no-deps gateway | sed 's/^/    /'
  DCB exec -T redis sh -c "redis-cli --scan --pattern 'org:resolve:*' | xargs -r redis-cli del" \
    >/dev/null 2>&1 || true
  curl -fsS -o /dev/null "http://localhost:8082/healthz" || fail "gateway did not come back healthy"

  cmd_smoke
  log "local-LLM demo is live:"
  log "  Dashboard : http://localhost:3000"
  log "  Admin     : http://localhost:9091  (demo@local / demo-admin-123)"
  log "  Gateway   : $GATEWAY_URL  (key: $DEMO_KEY)"
  log "  Model     : local-qwen2.5-0.5b-instruct (Qwen2.5-0.5B-Instruct, Apache-2.0, on llama.cpp)"
  log "Disable with: scripts/demo/local-llm.sh disable"
}

cmd_disable() {
  log "restoring the mock-primary demo contour (demo/local-llm.sql mode=0)"
  if DCB ps -q postgres >/dev/null 2>&1 \
     && DCB exec -T postgres pg_isready -U yabanin >/dev/null 2>&1; then
    pg_exec -q -v mode=0 < "$ROOT/demo/local-llm.sql" || fail "demo/local-llm.sql (disable) failed"
    log "registry restored: cloud rows back in pools, local row disabled, org routing_mode=auto"
  else
    log "stack not running — nothing to restore in the DB"
  fi
  log "note: a gateway container started with the local-llm override still points"
  log "at 10.207.0.10. For the stock contour recreate from the base file chain"
  log "(DEMO.md Minutes 0-4) or tear the stack down (down -v) and start fresh."
}

# cmd_smoke — deterministic end-to-end assertions.
cmd_smoke() {
  log "smoke: asserting the contour end-to-end"
  log "1) base-contour auth proof (R1 round-trip): demo-key resolves via the"
  log "   CURRENT seed.sql hash, Redis resolve cache flushed, one 200 expected"
  local code body
  body="$(mktemp /tmp/opencode/local-llm-smoke-base.XXXXXX.json)"
  code="$(curl -sS -o "$body" -w '%{http_code}' -m 120 -X POST "$GATEWAY_URL" \
    -H "Authorization: Bearer $DEMO_KEY" -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"base contour auth proof"}],"max_tokens":8}' || true)"
  grep -q '"content"' "$body" || fail "base-contour proof: no completion content (HTTP ${code:-?}; body: $(head -c 200 "$body" 2>/dev/null || true))"
  rm -f "$body"
  log "   base contour: HTTP ${code:-200} completion served (seed.sql key hash works)"

  log "2) local-model assertions"
  pg_exec -tAc "SELECT model_name FROM models_registry WHERE model_name='local-qwen2.5-0.5b-instruct' AND enabled" \
    | grep -q local-qwen && log "   registry: local model row enabled" || fail "local model row not enabled"
  pg_exec -tAc "SELECT routing_mode FROM organizations WHERE slug='demo-org'" \
    | grep -q always_cheap && log "   routing: demo org pinned to always_cheap" || fail "demo org not in always_cheap mode"

  local resp
  resp="$(mktemp /tmp/opencode/local-llm-smoke-local.XXXXXX.json)"
  code="$(curl -sS -D /tmp/opencode/local-llm-smoke-headers.txt -o "$resp" -w '%{http_code}' -m 120 \
    -X POST "$GATEWAY_URL" \
    -H "Authorization: Bearer $DEMO_KEY" \
    -H "Content-Type: application/json" \
    -H 'X-Yabanin-Labels: issue=LOCAL-LLM-1,ci.system=gitlab,ci.pipeline=9001,ci.job_name=test,git.repo=acme/web' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"In one word: what color is a banana?"}],"max_tokens":16}')"
  [[ "$code" == "200" ]] || fail "local completion returned HTTP $code (body: $(head -c 300 "$resp" 2>/dev/null || true))"
  grep -q '"content"' "$resp" || fail "local completion has no content"
  log "   completion: HTTP 200, decision header: $(grep -i 'x-yabanin-decision' /tmp/opencode/local-llm-smoke-headers.txt | head -1 | cut -d' ' -f2- || echo 'ABSENT')"
  rm -f "$resp"

  log "   waiting for loggerd to flush the request log"
  sleep 6
  local row
  row="$(pg_exec -tAc "SELECT model_used, tier_used, cost_status, cost_in_usd, upstream_url FROM request_logs WHERE org_id='$DEMO_ORG_UUID' ORDER BY created_at DESC LIMIT 1" 2>/dev/null || true)"
  log "   request_logs: $row"
  grep -q 'local-qwen2.5-0.5b-instruct' <<<"$row" || fail "latest request did not serve the local model (row: $row)"
  grep -q '10.207.0.10:8080' <<<"$row" || fail "upstream_url is not the local model endpoint (row: $row)"
  grep -q 'unknown_price' <<<"$row" || fail "cost_status is not unknown_price — offline-fail-closed pricing not observable (row: $row)"
  log "   routing: model_used=local-qwen2.5-0.5b-instruct, upstream=10.207.0.10:8080"
  log "   pricing: cost_status=unknown_price (offline-fail-closed, PriceKnown=false)"
  log "smoke PASS"
}

case "${1:-}" in
  fetch)   cmd_fetch ;;
  enable)  cmd_enable ;;
  smoke)   cmd_smoke ;;
  disable) cmd_disable ;;
  *) fail "usage: local-llm.sh fetch|enable|smoke|disable" ;;
esac
