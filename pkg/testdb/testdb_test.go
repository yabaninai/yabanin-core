package testdb

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/regionrouter"
)

func TestPostgresStand(t *testing.T) {
	pool := Postgres(t)
	var tables int
	if err := pool.QueryRow(context.Background(),
		"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").Scan(&tables); err != nil {
		t.Fatalf("query disposable postgres: %v", err)
	}
	if tables < 50 {
		t.Fatalf("expected the migrated schema, got %d tables", tables)
	}
}

// TestPostgresApp_RunsAsAppRole proves the app-role helper matches the
// production pool posture: every connection assumes the non-owner yabanin_app
// role (SET ROLE; bootstrapped by applyMigrations) and carries the app.region
// GUC, so the region RLS policies bind — a foreign-region INSERT must be
// rejected by WITH CHECK.
func TestPostgresApp_RunsAsAppRole(t *testing.T) {
	pool := PostgresApp(t, "eu")

	var role, region string
	if err := pool.QueryRow(context.Background(),
		"SELECT current_user, current_setting('app.region')").Scan(&role, &region); err != nil {
		t.Fatalf("query app-role pool identity: %v", err)
	}
	if role != regionrouter.AppRole {
		t.Fatalf("expected pool connections as %q, got %q", regionrouter.AppRole, role)
	}
	if region != "eu" {
		t.Fatalf("expected app.region=eu, got %q", region)
	}

	// Own-region row: accepted (home_region defaults to the GUC).
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO request_logs (model_requested, model_used, status_code, duration_ms, tokens_in, tokens_out, method)
		 VALUES ('m', 'm', 200, 0, 0, 0, 'POST')`); err != nil {
		t.Fatalf("own-region insert must succeed: %v", err)
	}
	// Foreign-region row: rejected by the WITH CHECK clause.
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO request_logs (model_requested, model_used, status_code, duration_ms, tokens_in, tokens_out, method, home_region)
		 VALUES ('m', 'm', 200, 0, 0, 0, 'POST', 'us')`); err == nil {
		t.Fatal("foreign-region insert must be rejected by region RLS")
	}
}

func TestRedisStand(t *testing.T) {
	c := Redis(t)
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("ping disposable redis: %v", err)
	}
}
