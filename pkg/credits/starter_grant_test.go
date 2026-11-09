package credits

// W-CRED: beta starter grant tests. The unit tests pin the env resolution;
// the integration tests pin the exactly-once contract on the disposable
// migrated stand (testdb.Postgres, skipped in -short): a repeated call is a
// no-op, concurrent callers double-grant nothing, and the ledger row carries
// the marker + exact micro amount.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestStarterGrantCents_Env(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		t.Setenv(StarterGrantEnvVar, "")
		assert.Equal(t, DefaultStarterGrantCents, StarterGrantCents())
	})
	t.Run("env override", func(t *testing.T) {
		t.Setenv(StarterGrantEnvVar, "12345")
		assert.Equal(t, int64(12345), StarterGrantCents())
	})
	t.Run("unparseable falls back to default", func(t *testing.T) {
		t.Setenv(StarterGrantEnvVar, "not-a-number")
		assert.Equal(t, DefaultStarterGrantCents, StarterGrantCents())
	})
	t.Run("zero disables", func(t *testing.T) {
		t.Setenv(StarterGrantEnvVar, "0")
		assert.Equal(t, int64(0), StarterGrantCents())
	})
}

// starterGrantFixture isolates one org on the shared stand: unique org id,
// pre-created tables (order-independence with the legacy-shape tests) and
// exact row cleanup.
type starterGrantFixture struct {
	org string
}

func newStarterGrantFixture(t *testing.T, pool *pgxpool.Pool) *starterGrantFixture {
	t.Helper()
	ctx := context.Background()
	// The shared stand may be reshaped by this package's legacy-shape tests
	// under -shuffle: make sure the production-shape tables exist first.
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS org_credits (
			org_id TEXT PRIMARY KEY,
			balance_cents BIGINT NOT NULL DEFAULT 0,
			remainder_micro_usd BIGINT NOT NULL DEFAULT 0 CHECK (remainder_micro_usd >= 0 AND remainder_micro_usd < 10000),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS credit_transactions (
			id BIGSERIAL PRIMARY KEY,
			org_id TEXT NOT NULL,
			amount_cents BIGINT NOT NULL,
			balance_after BIGINT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('topup', 'usage')),
			request_id TEXT,
			invoice_ref TEXT,
			metadata JSONB DEFAULT '{}',
			amount_micro_usd BIGINT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	require.NoError(t, err)

	fx := &starterGrantFixture{org: fmt.Sprintf("wcred-%x", time.Now().UnixNano())}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, fx.org)
		_, _ = pool.Exec(ctx, `DELETE FROM org_credits WHERE org_id = $1`, fx.org)
	})
	return fx
}

// starterGrantRows counts the starter-grant marker rows and returns the
// wallet balance.
func starterGrantRows(t *testing.T, pool *pgxpool.Pool, org string) (int64, int64) {
	t.Helper()
	ctx := context.Background()
	var rows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND type = 'topup' AND invoice_ref = $2`,
		org, StarterGrantReason).Scan(&rows))
	var balance int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, org).Scan(&balance))
	return rows, balance
}

func TestEnsureStarterGrant_ExactlyOnce(t *testing.T) {
	pool := testdb.Postgres(t)
	fx := newStarterGrantFixture(t, pool)
	ctx := context.Background()

	granted, err := EnsureStarterGrant(ctx, pool, fx.org, 5000)
	require.NoError(t, err)
	require.True(t, granted, "the first call must grant")

	rows, balance := starterGrantRows(t, pool, fx.org)
	require.Equal(t, int64(1), rows, "exactly one starter-grant ledger row")
	require.Equal(t, int64(5000), balance)

	// Repeated call (re-seed / re-create replay): idempotent no-op.
	granted, err = EnsureStarterGrant(ctx, pool, fx.org, 5000)
	require.NoError(t, err)
	require.False(t, granted, "the repeat call must be a no-op")

	rows, balance = starterGrantRows(t, pool, fx.org)
	assert.Equal(t, int64(1), rows, "the grant stays exactly one per org")
	assert.Equal(t, int64(5000), balance, "the wallet must not move again")

	// A different org still gets its own grant (per-org idempotency).
	other := fx.org + "-b"
	granted, err = EnsureStarterGrant(ctx, pool, other, 2500)
	require.NoError(t, err)
	require.True(t, granted)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, other)
		_, _ = pool.Exec(ctx, `DELETE FROM org_credits WHERE org_id = $1`, other)
	})
	rows, balance = starterGrantRows(t, pool, other)
	assert.Equal(t, int64(1), rows)
	assert.Equal(t, int64(2500), balance)
}

func TestEnsureStarterGrant_ConcurrentCallsGrantOnce(t *testing.T) {
	pool := testdb.Postgres(t)
	fx := newStarterGrantFixture(t, pool)
	ctx := context.Background()

	// Two org-creation paths racing on the same org (seed + admin API):
	// the advisory lock serializes them and the marker makes the loser a
	// no-op — exactly one grant lands.
	const racers = 8
	results := make([]bool, racers)
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = EnsureStarterGrant(ctx, pool, fx.org, 5000)
		}(i)
	}
	wg.Wait()

	for i := range errs {
		require.NoError(t, errs[i], "racer %d", i)
	}
	var grantedCount int
	for _, g := range results {
		if g {
			grantedCount++
		}
	}
	assert.Equal(t, 1, grantedCount, "exactly one racer may grant")

	rows, balance := starterGrantRows(t, pool, fx.org)
	assert.Equal(t, int64(1), rows)
	assert.Equal(t, int64(5000), balance)
}

func TestEnsureStarterGrant_DisabledAndValidation(t *testing.T) {
	pool := testdb.Postgres(t)
	fx := newStarterGrantFixture(t, pool)
	ctx := context.Background()

	// Amount <= 0: disabled, no database writes at all.
	granted, err := EnsureStarterGrant(ctx, pool, fx.org, 0)
	require.NoError(t, err)
	require.False(t, granted)
	_, err = EnsureStarterGrant(ctx, pool, fx.org, -5)
	require.NoError(t, err)

	// Empty org / nil db: parameter rejection.
	_, err = EnsureStarterGrant(ctx, pool, "", 5000)
	require.Error(t, err)
	_, err = EnsureStarterGrant(ctx, nil, fx.org, 5000)
	require.Error(t, err)

	// Store method without a database: rejected, not silently granted.
	st := NewStore(nil, nil)
	_, err = st.EnsureStarterGrant(ctx, fx.org, 5000)
	require.Error(t, err)
}

func TestEnsureStarterGrant_StoreMethodInvalidatesCache(t *testing.T) {
	pool := testdb.Postgres(t)
	fx := newStarterGrantFixture(t, pool)
	ctx := context.Background()

	// Seed a wallet first so GetBalance has a row to cache.
	_, err := pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents) VALUES ($1, 100)`, fx.org)
	require.NoError(t, err)

	st := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -100, CacheTTL: time.Minute})
	before, err := st.GetBalance(ctx, fx.org)
	require.NoError(t, err)
	require.Equal(t, int64(100), before.BalanceCents)

	granted, err := st.EnsureStarterGrant(ctx, fx.org, 5000)
	require.NoError(t, err)
	require.True(t, granted)

	// The cached (stale) value must not survive the grant.
	after, err := st.GetBalance(ctx, fx.org)
	require.NoError(t, err)
	assert.Equal(t, int64(5100), after.BalanceCents, "the store must serve the post-grant balance")

	rows, _ := starterGrantRows(t, pool, fx.org)
	assert.Equal(t, int64(1), rows)
}
