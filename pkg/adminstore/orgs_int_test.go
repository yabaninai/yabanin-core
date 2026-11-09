package adminstore

// ENT-07/QA-01: DB-gated organization CRUD round-trip against the shared dev
// Postgres. Skips when the database is unavailable so offline unit runs stay
// green (repo convention: services/loggerd/consumer credits_int_test.go).

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openAdminTestPool returns the package-wide disposable, fully migrated
// Postgres stand (QG2-B3: Docker required for the tests gate; skipped only
// in -short mode). Tests serialize on the package mutex because they share
// the stand and recreate schema pieces.
func openAdminTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := testdb.Postgres(t)
	adminStoreMu.Lock()
	t.Cleanup(adminStoreMu.Unlock)
	return pool
}

type mutex = sync.Mutex

var adminStoreMu mutex

func TestStore_OrganizationCRUD_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	// Self-sufficient schema: other packages' teardowns may have dropped the
	// shared wallet table (repo-wide shared-DB caveat, see QG2-B3).
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS org_credits (
			org_id text PRIMARY KEY,
			balance_cents bigint DEFAULT 0 NOT NULL,
			updated_at timestamptz DEFAULT now() NOT NULL
		)`)
	require.NoError(t, err)

	slug := fmt.Sprintf("qa-crud-%d", time.Now().UnixNano())
	org, err := store.CreateOrganization(ctx, "QA CRUD Org", slug)
	require.NoError(t, err)
	require.NotEmpty(t, org.ID)

	got, err := store.GetOrganizationByID(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, "QA CRUD Org", got.Name)
	assert.Equal(t, slug, got.Slug)
	assert.True(t, got.CacheEnabled, "new orgs default to semantic cache enabled")

	bySlug, err := store.GetOrganizationBySlug(ctx, slug)
	require.NoError(t, err)
	assert.Equal(t, org.ID, bySlug.ID)

	// The creation transaction must have initialized an empty wallet.
	var balance int64
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT balance_cents FROM org_credits WHERE org_id = $1", org.ID).Scan(&balance))
	assert.Equal(t, int64(0), balance)

	// Cleanup: remove the seeded org (wallet cascades via FK policy).
	_, err = pool.Exec(ctx, "DELETE FROM organizations WHERE id = $1", org.ID)
	require.NoError(t, err)
	_, err = store.GetOrganizationByID(ctx, org.ID)
	require.Error(t, err, "deleted org must not resolve")
}
