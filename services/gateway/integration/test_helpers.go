//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/testdb"
)

const (
	testGatewayOrgID  = "b1f0c3d4-e5a6-4b7c-8d9e-0f1a2b3c4d5e"
	testGatewayTeamID = "b1f0c3d4-e5a6-4b7c-8d9e-0f1a2b3c4d5f" // default team of the gateway test org
	testGatewaySlug   = "gatewaytest"

	gatewayPGURIDefault     = "postgres://yabanin:yabanin@localhost/yabanin?sslmode=disable"
	gatewayRedisAddrDefault = "localhost:6379"
)

func gatewayPGURI() string {
	if v := os.Getenv("YABANIN_PG_URI"); v != "" {
		return v
	}
	return gatewayPGURIDefault
}

func gatewayRedisAddr() string {
	if v := os.Getenv("YABANIN_REDIS_ADDR"); v != "" {
		return v
	}
	return gatewayRedisAddrDefault
}

// NewGatewayTestDB returns the gateway database for realdb tests.
//
// QG2-B3 (owner decision 2026-09-13: Docker required for tests): without an
// explicit YABANIN_PG_URI override the tests use the package-wide
// disposable, fully migrated Postgres stand from pkg/testdb — no shared
// dev stand, no skip. The pool is package-wide and never closed per test.
func NewGatewayTestDB(t testing.TB, _ context.Context) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("YABANIN_PG_URI") != "" {
		pool, err := pgxpool.New(context.Background(), gatewayPGURI())
		if err != nil {
			t.Fatalf("failed to create pgx pool from YABANIN_PG_URI: %v", err)
		}
		if err := pool.Ping(context.Background()); err != nil {
			t.Fatalf("failed to ping postgres from YABANIN_PG_URI: %v", err)
		}
		return pool
	}
	return testdb.Postgres(t)
}

// NewGatewayTestRedis returns the gateway Redis. Same contract as
// NewGatewayTestDB: explicit env override wins, otherwise the package-wide
// disposable stand; never closed per test (use FlushGatewayRedis instead).
func NewGatewayTestRedis(t testing.TB, _ context.Context) *redis.Client {
	t.Helper()
	if os.Getenv("YABANIN_REDIS_ADDR") != "" {
		rdb := redis.NewClient(&redis.Options{Addr: gatewayRedisAddr()})
		if err := rdb.Ping(context.Background()).Err(); err != nil {
			t.Fatalf("failed to ping redis from YABANIN_REDIS_ADDR: %v", err)
		}
		return rdb
	}
	return testdb.Redis(t)
}

// SeedGatewayOrg seeds the deterministic gateway test org in FK order
// (org → wallet → team → budget), so a fresh container needs no residue from
// other tests. team_budgets.team_id carries an FK to organizations_teams, so
// the team row must exist before the budget insert — the original helper
// omitted the team and silently SKIPped filtered runs on fresh containers
// (N07-P01-T06 defect, 2026-11-03 acceptance record).
func SeedGatewayOrg(ctx context.Context, t testing.TB, db *pgxpool.Pool) {
	t.Helper()
	_, err := db.Exec(ctx, `
		INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO NOTHING
	`, testGatewayOrgID, "gateway-integration-org", testGatewaySlug)
	if err != nil {
		t.Skipf("failed to seed organization: %v", err)
	}
	// Fund the org wallet: api_keys without an org_credits row hit the
	// CreditGuard 402 (no_billing_setup) before any routing/whitelist logic.
	_, err = db.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, updated_at)
		VALUES ($1, 100000, now())
		ON CONFLICT (org_id) DO NOTHING
	`, testGatewayOrgID)
	if err != nil {
		t.Skipf("failed to seed org wallet: %v", err)
	}
	// Team row first: team_budgets.team_id references organizations_teams.
	// SeedGatewayTeam is idempotent and creates the same deterministic team
	// every seeded api_keys row references.
	SeedGatewayTeam(ctx, t, db, testGatewayOrgID)
	// Team budget: without a team_budgets row the gateway fail-closes with
	// 403 budget_not_configured before reaching upstream (P6.10).
	_, err = db.Exec(ctx, `
		INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
		VALUES ($1, 1000.00, true)
		ON CONFLICT (team_id) DO NOTHING
	`, testGatewayTeamID)
	if err != nil {
		t.Skipf("failed to seed team budget: %v", err)
	}
}

// SeedGatewayTeam creates the deterministic default team of the gateway test
// org. api_keys.team_id is NOT NULL with an FK to organizations_teams, so
// every seeded key references this team.
func SeedGatewayTeam(ctx context.Context, t testing.TB, db *pgxpool.Pool, orgID string) {
	t.Helper()
	_, err := db.Exec(ctx, `
		INSERT INTO organizations_teams (id, org_id, name, slug)
		VALUES ($1, $2, 'gateway-integration-team', 'gatewaytest-team')
		ON CONFLICT (id) DO NOTHING
	`, testGatewayTeamID, orgID)
	if err != nil {
		t.Skipf("failed to seed team: %v", err)
	}
}

func SeedAPIKey(ctx context.Context, t testing.TB, db *pgxpool.Pool, orgID string, rawKey string) string {
	t.Helper()
	SeedGatewayTeam(ctx, t, db, orgID)
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := fmt.Sprintf("%x", hash)
	_, err := db.Exec(ctx, `
		INSERT INTO api_keys (id, key_hash, org_id, name, active, team_id)
		VALUES (gen_random_uuid(), $1, $2, $3, true, $4)
		ON CONFLICT (key_hash) DO NOTHING
	`, keyHash, orgID, "test-key", testGatewayTeamID)
	if err != nil {
		t.Skipf("failed to seed api_key: %v", err)
	}
	return keyHash
}

func SeedRoutingRule(ctx context.Context, t testing.TB, db *pgxpool.Pool, orgID string, matchExpr string, targetModel string, priority int) {
	t.Helper()
	_, err := db.Exec(ctx, `
		INSERT INTO routing_rules (id, org_id, match_expr, target_model, priority, enabled) 
		VALUES (gen_random_uuid(), $1, $2, $3, $4, true)
		ON CONFLICT DO NOTHING
	`, orgID, matchExpr, targetModel, priority)
	if err != nil {
		t.Skipf("failed to seed routing_rule: %v", err)
	}
}

func SeedDefaultModels(ctx context.Context, t testing.TB, db *pgxpool.Pool) {
	t.Helper()
	_, err := db.Exec(ctx, `
		INSERT INTO models_registry (model_name, display_name, tier) VALUES
			('smart', 'Smart model (default)', 'smart'),
			('cheap', 'Cheap model', 'cheap'),
			('turbo', 'Turbo model', 'turbo')
		ON CONFLICT (model_name) DO NOTHING
	`)
	if err != nil {
		t.Skipf("failed to seed models_registry: %v", err)
	}
}

func FlushGatewayRedis(ctx context.Context, t testing.TB, rdb *redis.Client) {
	t.Helper()
	if err := rdb.FlushDB(ctx).Err(); err != nil && err != redis.Nil {
		t.Skipf("failed to flush redis: %v", err)
	}
}
