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
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/gateway"
)

func seedKeyWhitelist(ctx context.Context, db *pgxpool.Pool, apiKeyID string, modelName string, allowed bool) {
	_, err := db.Exec(ctx,
		`INSERT INTO api_key_model_whitelist (api_key_id, model_name, allowed)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (api_key_id, model_name) DO UPDATE SET allowed = EXCLUDED.allowed`,
		apiKeyID, modelName, allowed,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to seed key whitelist: %v", err))
	}
}

func seedTeamWhitelist(ctx context.Context, db *pgxpool.Pool, teamID string, modelName string, allowed bool) {
	_, err := db.Exec(ctx,
		`INSERT INTO team_model_whitelist (team_id, model_name, allowed)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (team_id, model_name) DO UPDATE SET allowed = EXCLUDED.allowed`,
		teamID, modelName, allowed,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to seed team whitelist: %v", err))
	}
}

func TestGatewayRealDB_WhitelistDeny(t *testing.T) {
	ctx := context.Background()
	pool := NewGatewayTestDB(t, ctx)
	rdb := NewGatewayTestRedis(t, ctx)
	FlushGatewayRedis(ctx, t, rdb)

	SeedGatewayOrg(ctx, t, pool)
	SeedDefaultModels(ctx, t, pool)

	// Create an API key with a whitelist that DENIES "smart" model.
	hash := sha256.Sum256([]byte("test-whitelist-key"))
	keyHash := fmt.Sprintf("%x", hash)
	keyUUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890" // deterministic UUID for whitelist target
	SeedGatewayTeam(ctx, t, pool, testGatewayOrgID)
	_, err := pool.Exec(ctx,
		`INSERT INTO api_keys (id, key_hash, org_id, name, active, team_id)
		 VALUES ($1, $2, $3, 'whitelist-test-key', true, $4)
		 ON CONFLICT DO NOTHING`,
		keyUUID, keyHash, testGatewayOrgID, testGatewayTeamID,
	)
	if err != nil {
		t.Fatalf("failed to seed api_key: %v", err)
	}

	// Deny "smart" model for this key.
	seedKeyWhitelist(ctx, pool, keyUUID, "smart", false)

	port := findFreePort(t)
	cfg := config.Gateway{
		ListenAddr:     fmt.Sprintf("127.0.0.1:%d", port),
		AuthMode:       "header",         // Validate() requires header|strict
		PGURI:          gatewayPGURI(),   // Validate() requires a DSN string; the pool is still passed explicitly
		Provider:       "localhost:9999", // unreachable upstream
		FallbackKey:    "test-api-key",
		EventStream:    "gateway-test-events",
		CacheEnabled:   false,
		MetricsEnabled: true,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}))
	serverCtx, serverCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cli.RunGatewayServer(cfg, rdb, pool, integrationTestKMS{}, logger, serverCtx)
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForGatewayReady(t, baseURL)

	t.Cleanup(func() {
		serverCancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	})

	// Send request with the whitelisted key, requesting "smart" model.
	body := []byte(`{"model":"smart","messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-whitelist-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	// Expected: 403 Forbidden with permission_denied_error
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
	}

	var apiErr struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &apiErr); err != nil {
		t.Fatalf("failed to parse error body: %v\nBody: %s", err, string(bodyBytes))
	}
	if apiErr.Error.Type != "permission_denied_error" {
		t.Errorf("expected permission_denied_error type, got %q", apiErr.Error.Type)
	}
}

func TestGatewayRealDB_WhitelistNoEntry_Allows(t *testing.T) {
	ctx := context.Background()
	pool := NewGatewayTestDB(t, ctx)
	rdb := NewGatewayTestRedis(t, ctx)
	FlushGatewayRedis(ctx, t, rdb)

	SeedGatewayOrg(ctx, t, pool)
	SeedDefaultModels(ctx, t, pool)

	// Create an API key with NO whitelist entries.
	hash := sha256.Sum256([]byte("test-no-whitelist-key"))
	keyHash := fmt.Sprintf("%x", hash)
	SeedGatewayTeam(ctx, t, pool, testGatewayOrgID)
	_, err := pool.Exec(ctx,
		`INSERT INTO api_keys (id, key_hash, org_id, name, active, team_id)
		 VALUES (gen_random_uuid(), $1, $2, 'no-whitelist-key', true, $3)
		 ON CONFLICT DO NOTHING`,
		keyHash, testGatewayOrgID, testGatewayTeamID,
	)
	if err != nil {
		t.Fatalf("failed to seed api_key: %v", err)
	}

	port := findFreePort(t)
	cfg := config.Gateway{
		ListenAddr:     fmt.Sprintf("127.0.0.1:%d", port),
		AuthMode:       "header",         // Validate() requires header|strict
		PGURI:          gatewayPGURI(),   // Validate() requires a DSN string; the pool is still passed explicitly
		Provider:       "localhost:9999", // unreachable upstream
		FallbackKey:    "test-api-key",
		EventStream:    "gateway-test-events",
		CacheEnabled:   false,
		MetricsEnabled: true,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}))
	serverCtx, serverCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cli.RunGatewayServer(cfg, rdb, pool, integrationTestKMS{}, logger, serverCtx)
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForGatewayReady(t, baseURL)

	t.Cleanup(func() {
		serverCancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	})

	// Send request with a key that has NO whitelist — should be allowed through (fail-open).
	body := []byte(`{"model":"smart","messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-no-whitelist-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Without whitelist entries, request proceeds to upstream which is unreachable → 502.
	// Key point: it did NOT get a 403 from whitelist check.
	if resp.StatusCode == http.StatusForbidden {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Errorf("expected non-403 (upstream error), got 403. Body: %s", string(bodyBytes))
	}
}
