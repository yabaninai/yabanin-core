#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="deploy/docker-compose.yml"
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MAX_WAIT=60
WAIT_INTERVAL=3

ALL_PASS=true

cleanup() {
  echo ""
  echo "--- Cleanup: tearing down services ---"
  docker compose -f "${BASE_DIR}/${COMPOSE_FILE}" down 2>/dev/null || true
}
trap cleanup EXIT

PASS() { echo "[PASS] $1"; }
FAIL() { echo "[FAIL] $1"; ALL_PASS=false; }

check_health() {
  local service="$1"
  docker compose -f "${BASE_DIR}/${COMPOSE_FILE}" ps --format json "$service" 2>/dev/null \
    | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('Status',''))" 2>/dev/null \
    || echo ""
}

echo "========================================="
echo " Yabanin Smoke E2E Test"
echo "========================================="
echo ""

# --- Step 1: Start services ---
echo "[1/5] Starting docker compose in background..."
if ! docker compose -f "${BASE_DIR}/${COMPOSE_FILE}" ps --format json gateway 2>/dev/null \
    | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('Status',''))" 2>/dev/null \
    | grep -qi "running"; then
  docker compose -f "${BASE_DIR}/${COMPOSE_FILE}" up -d
  echo "  Services started."
else
  echo "  Services already running, skipping start."
fi

# --- Step 2: Wait for health ---
echo "[2/5] Waiting up to ${MAX_WAIT}s for all services to be healthy..."
ELAPSED=0
while [ "$ELAPSED" -lt "$MAX_WAIT" ]; do
  ALL_HEALTHY=true

  # Check critical services: gateway, admin, postgres, redis
  for svc in gateway admin postgres redis; do
    STATUS=$(check_health "$svc")
    if [[ "$STATUS" != *"healthy"* && "$STATUS" != *"Up"* ]]; then
      ALL_HEALTHY=false
    fi
  done

  if $ALL_HEALTHY; then
    echo "  All services healthy after ${ELAPSED}s."
    break
  fi

  sleep "$WAIT_INTERVAL"
  ELAPSED=$((ELAPSED + WAIT_INTERVAL))
done

if ! $ALL_HEALTHY; then
  FAIL "Services not healthy within ${MAX_WAIT}s. Aborting tests."
  exit 1
fi

# --- Step 3: Gateway health endpoint ---
echo "[3/5] Testing gateway /healthz..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8082/healthz 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  PASS "Gateway health returned 200"
else
  FAIL "Gateway health returned ${HTTP_CODE} (expected 200)"
fi

# --- Step 4: Admin health endpoint ---
echo "[4/5] Testing admin /health..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9091/health 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ]; then
  PASS "Admin health returned ${HTTP_CODE} (200 or 401 expected)"
else
  FAIL "Admin health returned ${HTTP_CODE} (expected 200 or 401)"
fi

# --- Step 5: Proxy API call ---
echo "[5/5] Testing gateway proxy POST /v1/chat/completions..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8082/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}' \
  2>/dev/null || echo "000")

# Should return a meaningful HTTP error (401, 500, etc.) but not connection refused/abort (000)
if [ "$HTTP_CODE" != "000" ] && [ "$HTTP_CODE" -ge 400 ] 2>/dev/null; then
  PASS "Proxy call returned ${HTTP_CODE} (non-2xx as expected, no crash)"
elif [ "$HTTP_CODE" = "200" ]; then
  PASS "Proxy call returned 200 (unexpected success but no crash)"
else
  FAIL "Proxy call failed with HTTP ${HTTP_CODE} (connection refused or abort)"
fi

# --- Summary ---
echo ""
echo "========================================="
if $ALL_PASS; then
  echo " Result: ALL CHECKS PASSED"
  echo "========================================="
  exit 0
else
  echo " Result: SOME CHECKS FAILED"
  echo "========================================="
  exit 1
fi
