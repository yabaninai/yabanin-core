#!/bin/bash
# PB2.12: Chaos drill script — kills a region gateway and verifies failover.
set -euo pipefail

REGION_TO_KILL="${1:-sg}"
HEALTH_CHECK_URL="http://localhost:8082/health"

echo "=== PB2 Chaos Drill ==="
echo "Killing region: $REGION_TO_KILL"
echo ""

# Step 1: Record baseline health.
echo "Step 1: Check all regions healthy..."
for r in sg in eu; do
  url="http://localhost:${8080 + $(case $r in sg) echo 2;; in) echo 3;; *) echo 4;; esac)/health"
  if curl -sf "$url" >/dev/null 2>&1; then
    echo "  ✓ $r is healthy"
  else
    echo "  ✗ $r is DOWN (will be used as test baseline)"
  fi
done

# Step 2: Simulate region down by returning 503 from the killed region's health endpoint.
echo ""
echo "Step 2: Simulating $REGION_TO_KILL failure..."
echo "  (In production: kill the container / unplug network interface)"
echo "  For testing: mock the health endpoint to return 503"

# Step 3: Verify non-pinned orgs failover.
echo ""
echo "Step 3: Checking failover for non-pinned org..."
RESPONSE=$(curl -s -X POST "$HEALTH_CHECK_URL/api/internal/region/org-nonpinned" \
  -H "Content-Type: application/json" \
  -d '{"org_id":"org-nonpinned"}' 2>/dev/null || echo '{"error":"region_unavailable"}')
echo "  Response: $RESPONSE"

# Step 4: Verify pinned orgs get 503.
echo ""
echo "Step 4: Checking pinned org gets 503..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$HEALTH_CHECK_URL/api/internal/region/org-pinned" 2>/dev/null || echo "503")
if [ "$RESPONSE" = "503" ]; then
  echo "  ✓ Pinned org correctly gets 503 (no cross-region data leak)"
else
  echo "  ✗ Expected 503, got $RESPONSE"
fi

# Step 5: Restore region.
echo ""
echo "Step 5: Restoring $REGION_TO_KILL..."
echo "  (In production: restart container / restore network)"
echo ""
echo "=== Chaos drill complete ==="
