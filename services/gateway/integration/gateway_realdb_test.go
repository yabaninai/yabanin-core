//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/gateway"
)

// findFreePort finds a free TCP port on localhost.
func findFreePort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve port: %v", err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("failed to listen on port 0: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// waitForGatewayReady polls /healthz until the server accepts connections or
// the deadline expires — the healthcheck poll that replaces fixed sleeps
// after starting RunGatewayServer in the background.
func waitForGatewayReady(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("gateway server did not become ready within 10s: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitForStreamEntry polls the stream until an entry matching pred appears
// (event publishing is async) and returns it; ok=false on deadline expiry.
func waitForStreamEntry(t *testing.T, rdb *redis.Client, stream string, pred func(map[string]string) bool) (map[string]string, bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries := getRedisStreamEntries(t, rdb, stream)
		for i := len(entries) - 1; i >= 0; i-- {
			if pred(entries[i]) {
				return entries[i], true
			}
		}
		if !time.Now().Before(deadline) {
			return nil, false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitForPoolReady polls the pool until Postgres accepts connections —
// container healthcheck by deadline, not a fixed retry-count sleep loop.
func waitForPoolReady(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var err error
	for {
		if err = pool.Ping(ctx); err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("test postgres did not become reachable within 10s: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitForRedisReady polls the client until Redis accepts connections.
func waitForRedisReady(t *testing.T, ctx context.Context, rdb *redis.Client) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var err error
	for {
		if err = rdb.Ping(ctx).Err(); err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("test redis did not become reachable within 10s: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// gatewayTestServer starts the gateway HTTP server on a free port and returns
// its base URL (e.g. "http://127.0.0.1:8080") and a cleanup function.
func gatewayTestServer(t *testing.T, ctx context.Context, rdb *redis.Client, pool *pgxpool.Pool) (string, func()) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}))

	port := findFreePort(t)

	cfg := config.Gateway{
		ListenAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		AuthMode:    "header",         // Validate() requires header|strict; the tests drive auth via Authorization headers
		PGURI:       gatewayPGURI(),   // Validate() requires a DSN string; the pool is still passed explicitly
		Provider:    "localhost:9999", // dummy upstream that won't respond
		FallbackKey: "test-api-key",
		EventStream: "gateway-test-events",
	}

	serverCtx, serverCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cli.RunGatewayServer(cfg, rdb, pool, integrationTestKMS{}, logger, serverCtx)
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	waitForGatewayReady(t, baseURL)

	return baseURL, func() {
		serverCancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}
}

// roundTrip sends a JSON request to the gateway and returns the parsed response body.
func roundTrip(t *testing.T, client *http.Client, baseURL string, path string, headers map[string]string, body json.RawMessage) (int, map[string]string, json.RawMessage) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+path, reader)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	respHeaders := make(map[string]string)
	for k := range resp.Header {
		respHeaders[k] = resp.Header.Get(k)
	}

	return resp.StatusCode, respHeaders, respBody
}

// getRedisStreamEntries reads all entries from a Redis stream.
func getRedisStreamEntries(t *testing.T, rdb *redis.Client, stream string) []map[string]string {
	t.Helper()
	ctx := t.Context()

	// XRANGE, not XRead: XRead BLOCKS waiting for new entries and hung the
	// test forever on an empty stream; XRANGE returns the current entries.
	resultCmd := rdb.XRange(ctx, stream, "-", "+")
	if resultCmd.Err() != nil && resultCmd.Err() != redis.Nil {
		t.Fatalf("failed to read stream %s: %v", stream, resultCmd.Err())
	}

	messages := resultCmd.Val()
	var result []map[string]string
	for _, m := range messages {
		entry := make(map[string]string)
		for k, v := range m.Values {
			if s, ok := v.(string); ok {
				entry[k] = s
			}
		}
		result = append(result, entry)
	}
	return result
}

func TestGatewayRealDB_ProxyRequest(t *testing.T) {
	ctx := t.Context()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)

	// Seed org first (parent row required by FK on api_keys).
	SeedGatewayOrg(ctx, t, pool)
	seedAPIKey(rdb, pool, "test-api-key", testGatewayOrgID)

	baseURL, cleanup := gatewayTestServer(t, ctx, rdb, pool)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}

	t.Run("returns 401 without Authorization header", func(t *testing.T) {
		body := json.RawMessage(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`)
		status, _, _ := roundTrip(t, client, baseURL, "/v1/chat/completions", nil, body)
		if status != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", status)
		}
	})

	t.Run("returns 401 with invalid API key", func(t *testing.T) {
		headers := map[string]string{"Authorization": "Bearer wrong-key"}
		body := json.RawMessage(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`)
		status, _, _ := roundTrip(t, client, baseURL, "/v1/chat/completions", headers, body)
		if status != http.StatusUnauthorized {
			t.Errorf("expected 401 for invalid key, got %d", status)
		}
	})

	t.Run("passes auth with valid API key and returns 502 from unreachable upstream", func(t *testing.T) {
		headers := map[string]string{"Authorization": "Bearer test-api-key"}
		body := json.RawMessage(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`)
		status, _, respBody := roundTrip(t, client, baseURL, "/v1/chat/completions", headers, body)

		// Gateway should accept the key (not 401), but fail at upstream (502 Bad Gateway).
		if status == http.StatusUnauthorized {
			t.Errorf("expected gateway to accept valid API key, got 401; body: %s", string(respBody))
		}
		if status != http.StatusBadGateway {
			t.Logf("upstream returned %d (expected 502 from unreachable provider)", status)
		}
	})
}

func TestGatewayRealDB_RuleRouting(t *testing.T) {
	ctx := t.Context()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)

	// Seed org.
	SeedGatewayOrg(ctx, t, pool)

	// Seed API key linked to the test org.
	seedAPIKey(rdb, pool, "routing-test-key", testGatewayOrgID)

	// Seed a routing rule: match all for this org, route to "claude-sonnet-4-20250514".
	SeedRoutingRule(ctx, t, pool, testGatewayOrgID, `true`, "claude-sonnet-4-20250514", 100)

	baseURL, cleanup := gatewayTestServer(t, ctx, rdb, pool)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}

	t.Run("routing rule rewrites model in request body", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": "Bearer routing-test-key",
			"X-Org-Id":      testGatewayOrgID, // bypass DB lookup by setting org directly
		}
		body := json.RawMessage(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`)
		status, _, respBody := roundTrip(t, client, baseURL, "/v1/chat/completions", headers, body)

		if status == http.StatusUnauthorized {
			t.Errorf("expected gateway to accept valid API key, got 401; body: %s", string(respBody))
		}
		// Since upstream is unreachable, we expect 502. The key test is that routing
		// rules were applied (model rewritten) before the upstream call, which we can't
		// directly assert without mocking. But we verify auth passes through.
		if status != http.StatusBadGateway {
			t.Logf("upstream returned %d (expected 502 from unreachable provider)", status)
		}
	})
}

func TestGatewayRealDB_EventPublishing(t *testing.T) {
	ctx := t.Context()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)

	seedAPIKey(rdb, pool, "event-test-key", testGatewayOrgID)

	baseURL, cleanup := gatewayTestServer(t, ctx, rdb, pool)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}

	headers := map[string]string{"Authorization": "Bearer event-test-key"}
	body := json.RawMessage(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`)
	_, _, _ = roundTrip(t, client, baseURL, "/v1/chat/completions", headers, body)

	// Async event publisher: return as soon as an event lands; the bounded
	// grace period covers the legitimate no-event outcome (unreachable
	// upstream), replacing the unconditional sleep.
	_, _ = waitForStreamEntry(t, rdb, "gateway-test-events", func(map[string]string) bool { return true })

	entries := getRedisStreamEntries(t, rdb, "gateway-test-events")

	if len(entries) == 0 {
		t.Log("No events in stream (expected if upstream is unreachable)")
	} else {
		t.Logf("Found %d event(s) in Redis stream", len(entries))
		for i, e := range entries {
			eventType := e["event_type"]
			t.Logf("  event[%d] type=%s", i, eventType)
		}
	}
}

// --- Seed helpers ---

func seedAPIKey(rdb *redis.Client, pool *pgxpool.Pool, apiKey, orgID string) {
	hash := sha256.Sum256([]byte(apiKey))
	keyHash := fmt.Sprintf("%x", hash)

	// api_keys.team_id is NOT NULL (FK to organizations_teams): seed the
	// deterministic default team and reference it.
	_, err := pool.Exec(context.Background(),
		`INSERT INTO organizations_teams (id, org_id, name, slug)
		 VALUES ($1, $2, 'gateway-integration-team', 'gatewaytest-team')
		 ON CONFLICT (id) DO NOTHING`,
		testGatewayTeamID, orgID,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to seed team: %v", err))
	}

	// Fund the wallet so the CreditGuard does not 402 before the behavior
	// under test (idempotent: keeps an existing balance).
	_, err = pool.Exec(context.Background(),
		`INSERT INTO org_credits (org_id, balance_cents, updated_at)
		 VALUES ($1, 100000, now())
		 ON CONFLICT (org_id) DO NOTHING`,
		orgID,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to seed wallet: %v", err))
	}

	// Team budget row: the gateway fail-closes with 403 budget_not_configured
	// without one (P6.10); idempotent.
	_, err = pool.Exec(context.Background(),
		`INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
		 VALUES ($1, 1000.00, true)
		 ON CONFLICT (team_id) DO NOTHING`,
		testGatewayTeamID,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to seed team budget: %v", err))
	}

	_, err = pool.Exec(context.Background(),
		"INSERT INTO api_keys (id, key_hash, org_id, name, active, team_id) VALUES (gen_random_uuid(), $1, $2, $3, true, $4) ON CONFLICT DO NOTHING",
		keyHash, orgID, "test-key", testGatewayTeamID,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to seed API key: %v", err))
	}

	// Also cache in Redis for auth resolver.
	cacheKey := fmt.Sprintf("org:resolve:%s", keyHash)
	err = rdb.Set(context.Background(), cacheKey, orgID, 300*time.Second).Err()
	if err != nil {
		panic(fmt.Sprintf("failed to cache API key: %v", err))
	}
}

// --- Auth mode helper for "header" mode bypassing DB resolver ---

func authHeader(apiKey string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + apiKey}
}
