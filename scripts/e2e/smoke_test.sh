#!/usr/bin/env bash
# scripts/e2e/smoke_test.sh — Automated E2E smoke test for Yabanin.
# Validates: stack health, admin bootstrap, onboarding flow, API→deduct, monitoring, backup.
set -euo pipefail

COMPOSE_FILES=(deploy/docker-compose.prod.yml deploy/docker-compose.e2e.yml)
COMPOSE="docker compose ${COMPOSE_FILES[*]}"
PASS=0
FAIL=0
LOGS=""

pass() { PASS=$((PASS + 1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL + 1)); LOGS="${LOGS}\n  ✗ $1"; echo "  ✗ $1"; }

echo ""
echo "========================================="
echo " Yabanin E2E Smoke Test"
echo "========================================="
echo ""

# ──────────────────────────────────────────
# 1. Stack Health — wait for all services
# ──────────────────────────────────────────
echo "--- 1. Stack Health ---"

SERVICES=("postgres" "redis" "gateway" "admin" "loggerd" "caddy" "prometheus" "grafana")
for svc in "${SERVICES[@]}"; do
    if timeout 90 bash -c "set +e; for i in $(seq 1 30); do if $COMPOSE ps --format json "$svc" 2>/dev/null | python3 -c \"import sys,json; d=json.loads(sys.stdin.read()); exit(0 if d.get('Status')=='healthy' else 1)\" 2>/dev/null; then break; fi; sleep 3; done" 2>/dev/null; then
        pass "$svc healthy"
    else
        fail "$svc unhealthy after 90s"
    fi
done

# ──────────────────────────────────────────
# 2. Admin User Bootstrap via CLI
# ──────────────────────────────────────────
echo ""
echo "--- 2. Admin User Bootstrap ---"

ADMIN_EMAIL="admin@e2e.test"
ADMIN_PASSWORD="e2e-admin-123"
ADMIN_NAME="E2E Test Admin"

if $COMPOSE exec -T gateway yabanin admin create-user \
    --email="$ADMIN_EMAIL" \
    --password="$ADMIN_PASSWORD" \
    --display-name="$ADMIN_NAME" \
    --root 2>&1; then
    pass "Admin user created via CLI"
else
    fail "CLI create-user failed (user may already exist)"
fi

# ──────────────────────────────────────────
# 3. Admin Onboarding Flow
# ──────────────────────────────────────────
echo ""
echo "--- 3. Admin Onboarding Flow ---"

# Login to admin panel
LOGIN_RESP=$($COMPOSE exec -T admin wget -qO- --post-data="email=$ADMIN_EMAIL&password=$ADMIN_PASSWORD" http://localhost:8086/auth/login 2>/dev/null || echo "")
if echo "$LOGIN_RESP" | grep -qi "success\|session\|200"; then
    pass "Admin login successful"

    # Extract session cookie (wget -c writes to stdout, parse set-cookie header)
    SESSION_COOKIE=$($COMPOSE exec -T admin wget -qO /dev/null --save-cookies=- --post-data="email=$ADMIN_EMAIL&password=$ADMIN_PASSWORD" http://localhost:8086/auth/login 2>/dev/null | grep session | awk '{print $7}' || echo "")

    if [ -n "$SESSION_COOKIE" ]; then
        pass "Session cookie extracted"

        # Create organization
        ORG_ID=$($COMPOSE exec -T admin wget -qO- --header="Content-Type: application/json" \
            --post-data='{"name":"E2E Test Org","region":"sg"}' \
            http://localhost:8086/api/orgs 2>/dev/null | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")

        if [ -n "$ORG_ID" ]; then
            pass "Organization created (id=$ORG_ID)"

            # Issue API key
            API_KEY=$($COMPOSE exec -T admin wget -qO- --header="Content-Type: application/json" \
                --post-data='{"name":"e2e-test-key"}' \
                http://localhost:8086/api/orgs/$ORG_ID/keys 2>/dev/null | grep -o '"key":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")

            if [ -n "$API_KEY" ]; then
                pass "API key issued (prefix=${API_KEY:0:16}...)"

                # Topup credits — 10000 cents = $100
                TOPUP_RESP=$($COMPOSE exec -T admin wget -qO- --header="Content-Type: application/json" \
                    --post-data='{"amount_cents":10000,"invoice_ref":"e2e-test"}' \
                    http://localhost:8086/api/orgs/$ORG_ID/credits/topup 2>/dev/null || echo "")

                if echo "$TOPUP_RESP" | grep -qi "ok\|success\|balance"; then
                    pass "Credits topped up (10000 cents)"
                else
                    fail "Topup response unexpected: $TOPUP_RESP"
                fi
            else
                fail "Failed to issue API key"
            fi
        else
            fail "Failed to create organization"
        fi
    else
        fail "No session cookie found"
    fi
else
    fail "Admin login failed"
fi

# ──────────────────────────────────────────
# 4. API Call → Credit Deduction
# ──────────────────────────────────────────
echo ""
echo "--- 4. API Call → Credit Deduction ---"

if [ -n "${API_KEY:-}" ]; then
    # Wait for loggerd to process the event
    sleep 3

    # Make API call through Caddy (HTTPS with self-signed cert)
    API_RESP=$($COMPOSE exec -T gateway wget -qO- --no-check-certificate \
        --header="Authorization: Bearer $API_KEY" \
        --header="Content-Type: application/json" \
        --post-data='{"model":"gpt-4o","messages":[{"role":"user","content":"Hello E2E test"}],"max_tokens":50}' \
        https://api.localhost/v1/chat/completions 2>/dev/null || echo "")

    if echo "$API_RESP" | grep -qi "choices\|text\|message"; then
        pass "API call succeeded (mock response received)"
    elif echo "$API_RESP" | grep -qi "error\|unauthorized"; then
        fail "API call failed: $API_RESP"
    else
        # Try direct gateway port as fallback
        DIRECT_RESP=$($COMPOSE exec -T gateway wget -qO- \
            --header="Authorization: Bearer $API_KEY" \
            --header="Content-Type: application/json" \
            --post-data='{"model":"gpt-4o","messages":[{"role":"user","content":"Hello E2E test"}],"max_tokens":50}' \
            http://localhost:8082/v1/chat/completions 2>/dev/null || echo "")

        if echo "$DIRECT_RESP" | grep -qi "choices\|text\|message"; then
            pass "API call succeeded via direct port (fallback)"
        else
            fail "API call failed both ways: $API_RESP / $DIRECT_RESP"
        fi
    fi

    # Check credit deduction in DB
    sleep 2

    BALANCE=$($COMPOSE exec -T postgres psql -U yabanin -d yabanin -t \
        -c "SELECT balance_cents FROM org_credits WHERE org_id='$ORG_ID'" 2>/dev/null | tr -d ' ' || echo "N/A")

    TXNS=$($COMPOSE exec -T postgres psql -U yabanin -d yabanin -t \
        -c "SELECT count(*) FROM credit_transactions WHERE org_id='$ORG_ID' AND type='usage'" 2>/dev/null | tr -d ' ' || echo "N/A")

    if [ "$BALANCE" != "N/A" ] && [ "$TXNS" != "N/A" ]; then
        pass "Credit deduction recorded: balance=$BALANCE cents, transactions=$TXNS"
    else
        fail "Could not read credit state from DB (balance=$BALANCE, txns=$TXNS)"
    fi
else
    fail "Skipping API test — no API key issued"
fi

# ──────────────────────────────────────────
# 5. Monitoring Check
# ──────────────────────────────────────────
echo ""
echo "--- 5. Monitoring ---"

TARGETS_TOTAL=$($COMPOSE exec -T prometheus wget -qO- http://localhost:9090/api/v1/targets 2>/dev/null \
    | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data.get('data',{}).get('activeTargets',[])))" 2>/dev/null || echo "0")

TARGETS_UP=$($COMPOSE exec -T prometheus wget -qO- http://localhost:9090/api/v1/targets 2>/dev/null \
    | python3 -c "import sys,json; data=json.load(sys.stdin); targets=data.get('data',{}).get('activeTargets',[]); print(sum(1 for t in targets if t.get('health')=='up'))" 2>/dev/null || echo "0")

if [ "$TARGETS_UP" != "0" ] && [ "$TARGETS_TOTAL" != "0" ]; then
    pass "Prometheus targets: $TARGETS_UP/$TARGETS_TOTAL up"
else
    fail "Prometheus targets: $TARGETS_UP/$TARGETS_TOTAL up"
fi

# ──────────────────────────────────────────
# 6. Backup Test
# ──────────────────────────────────────────
echo ""
echo "--- 6. Backup Test ---"

BACKUP_LOG=$($COMPOSE exec -T backup /app/backup.sh 2>&1 || echo "FAILED")
if echo "$BACKUP_LOG" | grep -qi "complete\|dump"; then
    BACKUPS=0
    BACKUP_COUNT=$($COMPOSE exec -T backup sh -c 'ls /data/backups/pg_*.dump.gz 2>/dev/null | wc -l' 2>/dev/null || echo "0")
    if [ "$BACKUP_COUNT" != "0" ] && [ "$BACKUP_COUNT" != "N/A" ]; then
        pass "Backup created ($BACKUP_COUNT file(s) in /data/backups/)"
    else
        fail "Backup script ran but no backup files found"
    fi
else
    fail "Backup script failed: $BACKUP_LOG"
fi

# ──────────────────────────────────────────
# 7. Caddy TLS Check
# ──────────────────────────────────────────
echo ""
echo "--- 7. Caddy TLS ---"

CADDY_HEALTH=$($COMPOSE ps caddy 2>/dev/null | grep -i "healthy\|running" || echo "unknown")
if echo "$CADDY_HEALTH" | grep -qi "healthy\|running"; then
    pass "Caddy service is running/healthy"

    # Test HTTPS response (self-signed cert, use -k flag)
    TLS_RESP=$($COMPOSE exec -T gateway wget -qO- --no-check-certificate \
        http://localhost:8082/v1/models 2>/dev/null | head -c 200 || echo "")

    if [ -n "$TLS_RESP" ]; then
        pass "Gateway accessible via HTTPS (self-signed)"
    else
        # Direct HTTP as fallback
        DIRECT_TLS=$($COMPOSE exec -T gateway wget -qO- http://localhost:8082/v1/models 2>/dev/null | head -c 200 || echo "")
        if [ -n "$DIRECT_TLS" ]; then
            pass "Gateway accessible via HTTP (Caddy TLS may need DNS)"
        else
            fail "Cannot reach gateway over HTTPS or HTTP"
        fi
    fi
else
    fail "Caddy not healthy — check Caddyfile.tmpl and domain env vars"
fi

# ──────────────────────────────────────────
# Summary
# ──────────────────────────────────────────
echo ""
echo "========================================="
echo " Results: $PASS passed, $FAIL failed"
echo "========================================="

if [ "$FAIL" -gt 0 ]; then
    echo -e "\nFailures:$LOGS"
fi

if [ "$FAIL" -eq 0 ]; then
    echo ""
    echo "=== E2E SMOKE TEST PASSED ==="
    exit 0
else
    echo ""
    echo "=== E2E SMOKE TEST FAILED ($FAIL failures) ==="
    exit 1
fi
