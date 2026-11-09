#!/usr/bin/env bash
# Run performance profiles for Yabanin services.
# Usage: ./scripts/profile_run.sh [service] [duration]
#   service: gateway|admin|loggerd (default: all)
#   duration: seconds (default: 60)

set -euo pipefail

SERVICE="${1:-all}"
DURATION="${2:-60}"
OUTPUT_DIR="profiles/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "=== Yabanin Performance Profiling ==="
echo "Service: $SERVICE  Duration: ${DURATION}s  Output: $OUTPUT_DIR"

# Collect CPU profile from gateway admin server.
collect_cpu() {
    local svc="$1"
    local addr="${2:-localhost:8086}"
    echo "[CPU] Collecting for $svc..."
    curl -s "http://${addr}/debug/pprof/profile?seconds=${DURATION}" \
        > "$OUTPUT_DIR/${svc}_cpu.prof" 2>/dev/null || echo "  (server not running, skipping)"
}

collect_heap() {
    local svc="$1"
    local addr="${2:-localhost:8086}"
    echo "[Heap] Collecting for $svc..."
    curl -s "http://${addr}/debug/pprof/heap?gc=1" \
        > "$OUTPUT_DIR/${svc}_heap.prof" 2>/dev/null || echo "  (server not running, skipping)"
}

collect_goroutine() {
    local svc="$1"
    local addr="${2:-localhost:8086}"
    echo "[Goroutines] Collecting for $svc..."
    curl -s "http://${addr}/debug/pprof/goroutine?debug=2" \
        > "$OUTPUT_DIR/${svc}_goroutine.txt" 2>/dev/null || echo "  (server not running, skipping)"
}

case "$SERVICE" in
    gateway|all)
        collect_cpu "gateway" "${YABANIN_GATEWAY_ADMIN:-localhost:8086}"
        collect_heap "gateway" "${YABANIN_GATEWAY_ADMIN:-localhost:8086}"
        collect_goroutine "gateway" "${YABANIN_GATEWAY_ADMIN:-localhost:8086}"
        ;;
    admin)
        collect_cpu "admin" "${YABANIN_ADMIN_LISTEN:-localhost:8086}"
        collect_heap "admin" "${YABANIN_ADMIN_LISTEN:-localhost:8086}"
        collect_goroutine "admin" "${YABANIN_ADMIN_LISTEN:-localhost:8086}"
        ;;
    loggerd)
        echo "loggerd has no pprof endpoint (no admin server)."
        ;;
esac

echo ""
echo "=== Profiles saved to $OUTPUT_DIR ==="
echo ""
echo "Analyze with:"
echo "  go tool pprof -http=:8081 $OUTPUT_DIR/gateway_cpu.prof"
echo "  go tool pprof -http=:8082 $OUTPUT_DIR/gateway_heap.prof"
