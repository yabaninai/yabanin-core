//go:build integration

package integration

// NEXT-15: trust-boundary matrix for the GATEWAY, over the real transport
// (real gateway server + real Postgres + real Redis + httptest upstream).
//
// Dimensions: principal (org api_key / child yag_ agent key / unknown /
// revoked) × org (A/B) × operation class (chat = billed read, MCP =
// agent-only). The identity dimension is spoof-proof by construction
// (AuthMiddleware strips X-Org-Id/X-Agent-Id at ingress); the rows below
// pin that end-to-end.
//
// Findings → separate cards (none new at time of writing; the S02 revocation
// window is characterized here deliberately: a revoked key stays valid up to
// the resolver cache TTL unless the admin-side purge runs).

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/gateway"
)

const (
	orgAID  = "11111111-2222-4333-8444-555566667777" // NEXT-15 org A (funded)
	orgBID  = "11111111-2222-4333-8444-555566668888" // NEXT-15 org B (funded)
	orgCID  = "11111111-2222-4333-8444-55556666000c" // NEXT-15 org C (overdrawn)
	teamBID = "11111111-2222-4333-8444-555566669999"
	teamCID = "11111111-2222-4333-8444-55556666010c"
)

func seedNEXT15Org(ctx context.Context, t *testing.T, db *pgxpool.Pool, orgID, teamID, slug string, balanceCents int64) {
	t.Helper()
	mustExec(ctx, t, db,
		"INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
		orgID, "next15-"+slug, "next15-"+slug)
	mustExec(ctx, t, db,
		"INSERT INTO org_credits (org_id, balance_cents, updated_at) VALUES ($1, $2, now()) ON CONFLICT (org_id) DO NOTHING",
		orgID, balanceCents)
	mustExec(ctx, t, db,
		"INSERT INTO organizations_teams (id, org_id, name, slug) VALUES ($1, $2, 'next15', 'next15') ON CONFLICT (id) DO NOTHING",
		teamID, orgID)
	mustExec(ctx, t, db,
		"INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit) VALUES ($1, 1000.00, true) ON CONFLICT (team_id) DO NOTHING",
		teamID)
}

func mustExec(ctx context.Context, t *testing.T, db *pgxpool.Pool, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(ctx, q, args...); err != nil {
		t.Fatalf("seed exec failed: %q: %v", q, err)
	}
}

// seedNEXT15AgentKey inserts a child yag_ agent key (ADL-03 shape) and returns its id.
func seedNEXT15AgentKey(ctx context.Context, t *testing.T, db *pgxpool.Pool, raw, orgID string, expiresAt *time.Time, budgetCents *int64) string {
	t.Helper()
	hash := sha256Hex(raw)
	var id string
	err := db.QueryRow(ctx, `
		INSERT INTO agent_keys (org_id, name, key_hash, active, parent_id, expires_at, daily_limit_cents)
		VALUES ($1, 'next15-child', $2, true, NULL, $3, $4)
		RETURNING id::text`,
		orgID, hash, expiresAt, budgetCents).Scan(&id)
	if err != nil {
		t.Fatalf("seed agent key: %v", err)
	}
	if budgetCents != nil {
		mustExec(ctx, t, db,
			"INSERT INTO agent_budgets (agent_id, daily_limit_cents) VALUES ($1, $2) ON CONFLICT (agent_id) DO NOTHING",
			id, *budgetCents)
	}
	return id
}

// trustBoundaryGateway starts a gateway with a reachable httptest upstream
// (chat completions succeed and echo usage) and MCP enabled.
func trustBoundaryGateway(t *testing.T, ctx context.Context, rdb *redis.Client, pool *pgxpool.Pool, stream string) (string, func()) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(upstream.Close)

	port := findFreePort(t)
	cfg := config.Gateway{
		ListenAddr:        fmt.Sprintf("127.0.0.1:%d", port),
		AuthMode:          "header",
		PGURI:             gatewayPGURI(),
		Provider:          upstream.URL,
		FallbackKey:       "next15-static-fallback",
		EventStream:       stream,
		MCPGatewayEnabled: true,
		A2AGatewayEnabled: true,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
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

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

func chatBody() json.RawMessage {
	return json.RawMessage(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`)
}

func TestNEXT15_GatewayTrustBoundary(t *testing.T) {
	ctx := t.Context()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)
	FlushGatewayRedis(ctx, t, rdb)

	// Org A: funded. Org B: funded. Isolation is proven by ZEROING A later.
	seedNEXT15Org(ctx, t, pool, orgAID, testGatewayTeamID, "a", 100000)
	seedNEXT15Org(ctx, t, pool, orgBID, teamBID, "b", 100000)
	// Org C is OVERDRAWN by seed: the credit guard caches balances in
	// process (CacheTTL), so flipping A's wallet mid-test would poison the
	// cache for later rows — a dedicated org keeps every row independent.
	seedNEXT15Org(ctx, t, pool, orgCID, teamCID, "c", -10000)

	// SeedAPIKey pins the gateway default team — orgs B and C need keys on
	// their OWN teams (api_keys.team_id has an org FK), so insert manually.
	keyA, keyB, keyC := "next15-key-a", "next15-key-b", "next15-key-c"
	SeedAPIKey(ctx, t, pool, orgAID, keyA)
	for _, k := range []struct {
		raw, org, team, name string
	}{{keyB, orgBID, teamBID, "next15-b"}, {keyC, orgCID, teamCID, "next15-c"}} {
		mustExec(ctx, t, pool,
			`INSERT INTO api_keys (id, key_hash, org_id, name, active, team_id)
			 VALUES (gen_random_uuid(), $1, $2, $3, true, $4) ON CONFLICT (key_hash) DO NOTHING`,
			sha256Hex(k.raw), k.org, k.name, k.team)
	}

	stream := fmt.Sprintf("next15-events-%d", time.Now().UnixNano())
	baseURL, cleanup := trustBoundaryGateway(t, ctx, rdb, pool, stream)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}
	post := func(t *testing.T, path, key string, extra map[string]string) (int, string) {
		t.Helper()
		headers := map[string]string{}
		if key != "" {
			headers["Authorization"] = "Bearer " + key
		}
		for k, v := range extra {
			headers[k] = v
		}
		code, _, body := roundTrip(t, client, baseURL, path, headers, chatBody())
		return code, string(body)
	}

	t.Run("unknown key is 401", func(t *testing.T) {
		if code, _ := post(t, "/v1/chat/completions", "no-such-key", nil); code != http.StatusUnauthorized {
			t.Errorf("unknown key = %d, want 401", code)
		}
	})

	t.Run("overdrawn org C is 402 — the server-derived org wins over spoofed headers", func(t *testing.T) {
		// The credit guard rejects when balance < grace (default <= 0), so an
		// overdrawn wallet is the deterministic 402; a zero balance passes.
		// Spoof attempt: claim org B with a rich wallet via client headers —
		// the resolver-derived org (C) must decide.
		code, _ := post(t, "/v1/chat/completions", keyC, map[string]string{
			"X-Org-Id": orgBID, "X-Agent-Id": "spoofed-agent", "X-Team-Id": teamBID,
		})
		if code != http.StatusPaymentRequired {
			t.Errorf("spoofed org C request = %d, want 402 (server-derived org wins)", code)
		}
	})

	t.Run("org B key with full wallet succeeds and attributes to B", func(t *testing.T) {
		code, body := post(t, "/v1/chat/completions", keyB, nil)
		if code != http.StatusOK {
			t.Errorf("org B chat = %d, want 200; body: %s", code, body)
		}
		entry := pollStreamEntry(t, rdb, stream, func(e map[string]string) bool {
			return e["org_id"] == orgBID && e["request_id"] != ""
		})
		if entry["agent_id"] != "" {
			t.Errorf("event agent_id = %q, want empty for org-key principal", entry["agent_id"])
		}
	})

	t.Run("revoked key: S02 window, then dead after resolver purge", func(t *testing.T) {
		// Warm the resolver cache with a successful call.
		if code, _ := post(t, "/v1/chat/completions", keyB, nil); code != http.StatusOK {
			t.Fatalf("pre-revoke warmup = %d, want 200", code)
		}
		// Revoke (same SQL the admin handler runs).
		mustExec(ctx, t, pool, "UPDATE api_keys SET active = false WHERE key_hash = $1", sha256Hex(keyB))
		// Within the resolver cache TTL the key is still valid (S02 bound).
		if code, _ := post(t, "/v1/chat/completions", keyB, nil); code != http.StatusOK {
			t.Errorf("revoked-but-cached = %d, want 200 (S02 window; unit: resolver_revocation_test)", code)
		}
		// Admin-side purge (router.go purgeResolverKeys) → immediate death.
		if err := rdb.Del(ctx, "org:resolve:"+sha256Hex(keyB)).Err(); err != nil {
			t.Fatalf("purge: %v", err)
		}
		if code, _ := post(t, "/v1/chat/completions", keyB, nil); code != http.StatusUnauthorized {
			t.Errorf("revoked+purged = %d, want 401", code)
		}
	})

	t.Run("child yag_ key: budget gates and attribution", func(t *testing.T) {
		// No agent_budgets row → fail-closed 403.
		noBudget := "yag_next15_nobudget0000000000000000000000"
		seedNEXT15AgentKey(ctx, t, pool, noBudget, orgAID, nil, nil)
		if code, body := post(t, "/v1/chat/completions", noBudget, nil); code != http.StatusForbidden {
			t.Errorf("agent without budget = %d, want 403; body: %s", code, body)
		}

		// Exhausted budget (limit 100, spend 100 today) → 429.
		spent := "yag_next15_spent000000000000000000000000"
		limit := int64(100)
		agentID := seedNEXT15AgentKey(ctx, t, pool, spent, orgAID, nil, &limit)
		mustExec(ctx, t, pool,
			"INSERT INTO agent_spend_daily (agent_id, day, cost_cents) VALUES ($1, current_date, 100) ON CONFLICT (agent_id, day) DO NOTHING",
			agentID)
		if code, body := post(t, "/v1/chat/completions", spent, nil); code != http.StatusTooManyRequests {
			t.Errorf("exhausted agent budget = %d, want 429; body: %s", code, body)
		}

		// Healthy child key → 200, attributed to the agent, task label survives.
		healthy := "yag_next15_healthy00000000000000000000"
		bigLimit := int64(100000)
		childID := seedNEXT15AgentKey(ctx, t, pool, healthy, orgAID, nil, &bigLimit)
		code, body := post(t, "/v1/chat/completions", healthy, map[string]string{"X-Yabanin-Task": "next15-task"})
		if code != http.StatusOK {
			t.Fatalf("healthy child = %d, want 200; body: %s", code, body)
		}
		entry := pollStreamEntry(t, rdb, stream, func(e map[string]string) bool {
			return e["agent_id"] == childID
		})
		if entry["task_id"] != "next15-task" {
			t.Errorf("event task_id = %q, want label echo", entry["task_id"])
		}
	})

	t.Run("expired child yag_ key is rejected on every call (no negative caching)", func(t *testing.T) {
		expired := "yag_next15_expired0000000000000000000"
		past := time.Now().Add(-time.Minute)
		seedNEXT15AgentKey(ctx, t, pool, expired, orgAID, &past, nil)
		for i := 0; i < 2; i++ {
			if code, _ := post(t, "/v1/chat/completions", expired, nil); code != http.StatusUnauthorized {
				t.Errorf("expired child call #%d = %d, want 401", i+1, code)
			}
		}
	})

	t.Run("MCP invoke is agent-only; org keys cannot spoof an agent identity", func(t *testing.T) {
		// Regular org key → 403 agent_only.
		code, body := post(t, "/api/mcp/invoke", keyA, nil)
		if code != http.StatusForbidden || !strings.Contains(body, "agent") {
			t.Errorf("org key on MCP = %d %q, want 403 agent_only", code, body)
		}
		// Spoofed X-Agent-Id header is stripped at ingress — still 403.
		code, body = post(t, "/api/mcp/invoke", keyA, map[string]string{"X-Agent-Id": "spoofed"})
		if code != http.StatusForbidden {
			t.Errorf("org key + spoofed X-Agent-Id on MCP = %d %q, want 403", code, body)
		}
	})

	t.Run("A2A send is agent-only; org keys cannot spoof an agent identity", func(t *testing.T) {
		// Regular org key → 403 agent_only (A2A-01 mirrors MCP-03).
		code, body := post(t, "/api/a2a/send", keyA, nil)
		if code != http.StatusForbidden || !strings.Contains(body, "agent") {
			t.Errorf("org key on A2A = %d %q, want 403 agent_only", code, body)
		}
		// Spoofed X-Agent-Id header is stripped at ingress — still 403.
		code, body = post(t, "/api/a2a/send", keyA, map[string]string{"X-Agent-Id": "spoofed"})
		if code != http.StatusForbidden {
			t.Errorf("org key + spoofed X-Agent-Id on A2A = %d %q, want 403", code, body)
		}
	})
}

// pollStreamEntry waits (event publishing is async) for an entry matching.
func pollStreamEntry(t *testing.T, rdb *redis.Client, stream string, match func(map[string]string) bool) map[string]string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entries := getRedisStreamEntries(t, rdb, stream)
		for i := len(entries) - 1; i >= 0; i-- {
			if match(entries[i]) {
				return entries[i]
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no matching stream entry in %s within 5s", stream)
	return nil
}
