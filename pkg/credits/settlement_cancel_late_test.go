package credits

// N06-P04-T09 wallet-level settlement contract (ratified D1–D3, see
// artifacts/internal-delivery-program/N06-P04/contract.md): a cancel and a late usage
// complete ONE operation. The wallet primitive settles a request identity
// exactly once; a later event for the same identity claims nothing no matter
// which billing configuration it came from (legacy whole cents or exact
// µUSD); a repeated event never charges twice — not even under concurrent
// replays; and an unknown outcome is rejected instead of being masked as a
// zero charge, leaving the identity free for the real priced event.

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSettlementStand prepares the disposable stand for this corpus.
// setupTestTables only guarantees the base tables: sibling tests in this
// package drop and recreate credit_transactions in the legacy pre-0023
// shape (store_test.go teardown/setup) and -shuffle decides who runs
// first, so the additive guard below restores the production partial
// unique index that shape loses — the durable request-identity backstop
// this corpus pins (uniq_credit_transactions_usage_request_id, migration
// 0001). Re-adding it is additive and matches the migrated schema exactly.
func setupSettlementStand(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	setupTestTables(ctx, t, pool)
	_, err := pool.Exec(ctx, `
		CREATE UNIQUE INDEX IF NOT EXISTS uniq_credit_transactions_usage_request_id
		ON credit_transactions (request_id)
		WHERE request_id IS NOT NULL AND type = 'usage'`)
	require.NoError(t, err, "restore the production usage-identity unique index")
}

// usageRowsFor returns the number of usage ledger rows and their exact µUSD
// sum for one request identity. The identity contract is observable here:
// one settled operation means exactly one row whose amount never changes.
func usageRowsFor(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID, requestID string) (count int64, microSum int64) {
	t.Helper()
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(SUM(amount_micro_usd), 0)
		FROM credit_transactions
		WHERE org_id = $1 AND request_id = $2 AND type = 'usage'`,
		orgID, requestID,
	).Scan(&count, &microSum)
	require.NoError(t, err)
	return count, microSum
}

// D1: a priced cancel settles the consumed prefix exactly once. The late
// usage event for the same request — carrying the full final amount, which
// differs from the settled prefix — claims nothing, and a repeated cancel
// delivery replays the same operation. The settled amount never moves.
func TestSettlementCancelBillsOnce_LateUsageClaimsNothing(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupSettlementStand(ctx, t, pool)

	orgID := "t09-cancel-late"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})
	reqID := "req-t09-cancel-late"

	// The priced cancel: $0.015 prefix = one whole cent plus a 5000µ residue.
	cancelPrefix := money.MicroUSD(15000)
	require.NoError(t, store.DeductMicro(ctx, orgID, cancelPrefix, reqID, nil))

	count, microSum := usageRowsFor(ctx, t, pool, orgID, reqID)
	assert.Equal(t, int64(1), count, "the cancel settles exactly one usage row")
	assert.Equal(t, -int64(cancelPrefix), microSum)
	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(-1), balanceCents)
	assert.Equal(t, int64(5000), remainder)

	// Late usage for the same identity arrives with the full final amount:
	// the one-operation contract claims nothing — not even the difference.
	lateUsage := money.MicroUSD(40000)
	require.NoError(t, store.DeductMicro(ctx, orgID, lateUsage, reqID, nil),
		"late usage of an already settled identity is an idempotent no-op")

	// A repeated cancel delivery replays the same settled operation too.
	require.NoError(t, store.DeductMicro(ctx, orgID, cancelPrefix, reqID, nil))

	count, microSum = usageRowsFor(ctx, t, pool, orgID, reqID)
	assert.Equal(t, int64(1), count, "still exactly one usage row")
	assert.Equal(t, -int64(cancelPrefix), microSum, "the settled amount never changes")
	balanceCents, remainder = walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(-1), balanceCents)
	assert.Equal(t, int64(5000), remainder, "residue from the single charge only")
	requireReconciled(ctx, t, pool, orgID)
}

// Old and new billing configuration converge on one operation: the legacy
// whole-cents path and the exact µUSD path share the request identity, so
// whichever settles first, the other configuration's late arrival completes
// nothing and the settled amount stands.
func TestSettlementLegacyAndExactPathsOneOperation(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupSettlementStand(ctx, t, pool)

	cases := []struct {
		name         string
		org          string
		firstCharge  func(s *Store, org, req string) error
		lateArrival  func(s *Store, org, req string) error
		wantRowMicro int64
	}{
		{
			name: "legacy settles first, exact late usage claims nothing",
			org:  "t09-paths-legacy-first",
			firstCharge: func(s *Store, org, req string) error {
				return s.Deduct(context.Background(), org, 2, req, nil) // 2¢ = 20000µ
			},
			lateArrival: func(s *Store, org, req string) error {
				return s.DeductMicro(context.Background(), org, money.MicroUSD(9000), req, nil)
			},
			wantRowMicro: -20000,
		},
		{
			name: "exact settles first, legacy late usage claims nothing",
			org:  "t09-paths-exact-first",
			firstCharge: func(s *Store, org, req string) error {
				return s.DeductMicro(context.Background(), org, money.MicroUSD(9000), req, nil)
			},
			lateArrival: func(s *Store, org, req string) error {
				return s.Deduct(context.Background(), org, 2, req, nil)
			},
			wantRowMicro: -9000,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seedWallet(ctx, t, pool, tc.org, 0)
			store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})
			reqID := "req-" + tc.org

			require.NoError(t, tc.firstCharge(store, tc.org, reqID))
			require.NoError(t, tc.lateArrival(store, tc.org, reqID),
				"a late arrival from the other configuration is an idempotent no-op")

			count, microSum := usageRowsFor(ctx, t, pool, tc.org, reqID)
			assert.Equal(t, int64(1), count, "one operation across both configurations")
			assert.Equal(t, tc.wantRowMicro, microSum)
			requireReconciled(ctx, t, pool, tc.org)
		})
	}
}

// A repeated settle event never charges twice even when the replays race:
// the per-org advisory lock serializes the writers, so exactly one replica
// applies and the rest observe the settled identity and no-op.
func TestSettlementReplayRaceChargesOnce(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupSettlementStand(ctx, t, pool)

	orgID := "t09-replay-race"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})
	reqID := "req-t09-replay-race"
	prefix := money.MicroUSD(15000) // one whole cent plus a 5000µ residue

	const replicas = 8
	var wg sync.WaitGroup
	errs := make(chan error, replicas)
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := store.DeductMicro(ctx, orgID, prefix, reqID, nil); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("replayed settle failed: %v", err)
	}

	count, microSum := usageRowsFor(ctx, t, pool, orgID, reqID)
	assert.Equal(t, int64(1), count, "a repeated event never charges twice")
	assert.Equal(t, -int64(prefix), microSum)
	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(-1), balanceCents)
	assert.Equal(t, int64(5000), remainder)
	requireReconciled(ctx, t, pool, orgID)
}

// D2: an unknown outcome can never settle as a zero (or negative) charge —
// the wallet-level gate is the positive-amount rule, applied before any
// transaction or identity use — and the rejection consumes nothing, so the
// real priced event for the same identity still settles. A zero row would
// have poisoned the identity against that late priced event.
func TestSettlementUnknownOutcomeRejected_IdentityStaysChargeable(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupSettlementStand(ctx, t, pool)

	orgID := "t09-unknown"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})
	reqID := "req-t09-unknown"

	require.Error(t, store.DeductMicro(ctx, orgID, 0, reqID, nil))
	require.Error(t, store.DeductMicro(ctx, orgID, money.MicroUSD(-7000), reqID, nil))
	require.Error(t, store.Deduct(ctx, orgID, 0, reqID, nil),
		"the legacy configuration enforces the same gate")

	ledgerCents, ledgerMicro, nullMicro := ledgerTotals(ctx, t, pool, orgID)
	assert.Equal(t, int64(0), ledgerCents, "rejected unknown outcomes never write ledger rows")
	assert.Equal(t, int64(0), ledgerMicro)
	assert.Equal(t, int64(0), nullMicro)
	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(0), balanceCents)
	assert.Equal(t, int64(0), remainder)

	priced := money.MicroUSD(7000)
	require.NoError(t, store.DeductMicro(ctx, orgID, priced, reqID, nil),
		"the real priced event settles after the unknown rejections")
	count, microSum := usageRowsFor(ctx, t, pool, orgID, reqID)
	assert.Equal(t, int64(1), count)
	assert.Equal(t, -int64(priced), microSum)
	requireReconciled(ctx, t, pool, orgID)
}

// A settled request identity surfacing under a different org is the
// request-identity conflict: the wallet primitive fails hard with the
// PostgreSQL unique violation the consumer classifies, and the conflicting
// wallet keeps every cent.
func TestSettlementIdentityConflictOtherOrgRejected(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupSettlementStand(ctx, t, pool)

	orgA, orgB := "t09-conflict-a", "t09-conflict-b"
	seedWallet(ctx, t, pool, orgA, 500)
	seedWallet(ctx, t, pool, orgB, 500)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})
	reqID := "req-t09-conflict"

	require.NoError(t, store.DeductMicro(ctx, orgA, money.MicroUSD(7000), reqID, nil))

	err := store.DeductMicro(ctx, orgB, money.MicroUSD(7000), reqID, nil)
	require.Error(t, err, "the same identity under another org must not charge")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "identity conflicts surface as the unique violation")
	assert.Equal(t, "23505", pgErr.Code)

	count, microSum := usageRowsFor(ctx, t, pool, orgB, reqID)
	assert.Equal(t, int64(0), count, "the conflict charged nothing")
	assert.Equal(t, int64(0), microSum)
	balanceCents, remainder := walletRow(ctx, t, pool, orgB)
	assert.Equal(t, int64(500), balanceCents)
	assert.Equal(t, int64(0), remainder)

	count, microSum = usageRowsFor(ctx, t, pool, orgA, reqID)
	assert.Equal(t, int64(1), count, "the legitimate settlement stands")
	assert.Equal(t, int64(-7000), microSum)
}
