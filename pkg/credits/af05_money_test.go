package credits

import (
	"context"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AF-05 acceptance (live disposable PG): exact micro-USD billing with a
// durable sub-cent remainder next to the cents ledger.

// seedWallet inserts (or resets) an org wallet and returns a cleanup that
// removes its ledger rows so tests stay independent on the shared stand.
func seedWallet(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID string, balanceCents int64) {
	t.Helper()
	_, err := pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, orgID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd, updated_at)
		VALUES ($1, $2, 0, now())
		ON CONFLICT (org_id) DO UPDATE SET balance_cents = $2, remainder_micro_usd = 0, updated_at = now()`,
		orgID, balanceCents)
	require.NoError(t, err)
}

func walletRow(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID string) (balanceCents int64, remainder int64) {
	t.Helper()
	err := pool.QueryRow(ctx,
		`SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id = $1`, orgID,
	).Scan(&balanceCents, &remainder)
	require.NoError(t, err)
	return balanceCents, remainder
}

// ledgerTotals returns (sum amount_cents, sum amount_micro_usd with NULL as 0,
// count of rows whose amount_micro_usd IS NULL — the historical cents-only rows).
func ledgerTotals(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID string) (cents int64, micro int64, nullMicro int64) {
	t.Helper()
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(amount_cents), 0),
		       COALESCE(SUM(amount_micro_usd), 0),
		       COUNT(*) FILTER (WHERE amount_micro_usd IS NULL)
		FROM credit_transactions WHERE org_id = $1`, orgID,
	).Scan(&cents, &micro, &nullMicro)
	require.NoError(t, err)
	return cents, micro, nullMicro
}

// requireReconciled pins the AF-05 invariant for a wallet seeded from a
// micro-clean state (balance 0, empty ledger): owed micro total derived from
// the wallet plus its residue equals the exact micro the ledger recorded —
// owed = (−balance_cents)*10000 + remainder == −SUM(amount_micro_usd).
func requireReconciled(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID string) {
	t.Helper()
	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	ledgerCents, ledgerMicro, _ := ledgerTotals(ctx, t, pool, orgID)
	assert.Equal(t, ledgerCents, balanceCents, "wallet cents must equal the cents ledger sum")
	assert.Equal(t, -balanceCents*int64(money.MicroPerCent)+remainder, -ledgerMicro,
		"owed µUSD (wallet + residue) must equal the exact µUSD the ledger billed")
}

// Acceptance: 1000 individual requests at $0.004 bill exactly $4.00, across
// store restarts (a fresh Store every 100 charges = a new process). The
// pre-AF-05 code billed $0.00 for the same workload. Deep grace keeps the
// scenario a pure accumulation (no admission stop at the default −$1 floor).
func TestDeductMicro_ThousandSubCentRequestsAcrossRestarts(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(context.Background(), t, pool)

	orgID := "af05-thousand"
	seedWallet(ctx, t, pool, orgID, 0)

	price := money.MicroUSD(4000) // $0.004
	const total = 1000

	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})
	for i := 0; i < total; i++ {
		// Restart: a fresh Store instance (fresh cache, fresh process view)
		// every 100 charges.
		if i%100 == 0 {
			store = NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})
		}
		require.NoError(t, store.DeductMicro(ctx, orgID, price, fmt.Sprintf("req-af05-%04d", i), nil), "charge %d", i)
	}

	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(-400), balanceCents, "1000 × $0.004 = exactly −$4.00 in whole cents")
	assert.Equal(t, int64(0), remainder, "exact multiple leaves no residue")

	ledgerCents, ledgerMicro, nullMicro := ledgerTotals(ctx, t, pool, orgID)
	assert.Equal(t, int64(-400), ledgerCents)
	assert.Equal(t, int64(-4_000_000), ledgerMicro, "ledger carries the exact µUSD total")
	assert.Equal(t, int64(0), nullMicro, "every new row carries exact micro")
	requireReconciled(ctx, t, pool, orgID)
}

// Replay of the same request never double-charges — at exact µUSD either.
func TestDeductMicro_ReplayDoesNotDoubleCharge(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(context.Background(), t, pool)

	orgID := "af05-replay"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStore(pool, nil)

	price := money.MicroUSD(4000)
	require.NoError(t, store.DeductMicro(ctx, orgID, price, "req-af05-replay", nil))
	for i := 0; i < 5; i++ {
		require.NoError(t, store.DeductMicro(ctx, orgID, price, "req-af05-replay", nil), "replay must be an idempotent no-op")
	}

	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(0), balanceCents, "single sub-cent charge leaves whole cents untouched")
	assert.Equal(t, int64(4000), remainder, "charged exactly once")

	ledgerCents, ledgerMicro, _ := ledgerTotals(ctx, t, pool, orgID)
	assert.Equal(t, int64(0), ledgerCents)
	assert.Equal(t, int64(-4000), ledgerMicro)
}

// The remainder carries until it reaches a whole cent, which is charged
// atomically in the same transaction.
func TestDeductMicro_RemainderCarryChargesWholeCent(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(context.Background(), t, pool)

	orgID := "af05-carry"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStore(pool, nil)

	price := money.MicroUSD(4000) // $0.004
	for i := 0; i < 3; i++ {
		require.NoError(t, store.DeductMicro(ctx, orgID, price, fmt.Sprintf("req-af05-carry-%d", i), nil))
	}

	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	// 3 × 4000µ = 12000µ = 1 cent + 2000µ residue.
	assert.Equal(t, int64(-1), balanceCents, "third sub-cent charge carries a whole cent")
	assert.Equal(t, int64(2000), remainder, "residue after carry")
	requireReconciled(ctx, t, pool, orgID)

	// Balance view is remainder-aware: the true position is −1.2 cents
	// (billed −1 cent, 2000µ residue pending), floored for display.
	bal, err := store.GetBalance(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, int64(-2), bal.BalanceCents, "floored effective cents (never overstates spendable money)")
	assert.Equal(t, int64(-12000), bal.BalanceMicroUSD, "exact effective = −10000µ billed − 2000µ residue")
	assert.Equal(t, int64(2000), bal.RemainderMicroUSD)
}

// Floor boundaries with a fractional remainder (AF-01 contract, extended):
// the floor is on the effective balance — a charge landing exactly on the
// floor is allowed only when it carries no residue.
func TestDeductMicro_FloorBoundariesWithRemainder(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(context.Background(), t, pool)

	cases := []struct {
		name        string
		floor       int64
		balance     int64
		remMicro    int64
		chargeMicro int64
		wantErr     error
		wantBalance int64
		wantRem     int64
	}{
		{
			name: "at floor with residue pending rejects", floor: 0, balance: 0, remMicro: 4000,
			chargeMicro: 1000, wantErr: ErrInsufficientCredits, wantBalance: 0, wantRem: 4000,
		},
		{
			// Wallet 2c with 9999µ pending residue = 10001µ effective; a 5000µ
			// charge carries the residue's cent and lands 1 cent above floor.
			name: "headroom above floor admits despite residue carry", floor: 0, balance: 2, remMicro: 9999,
			chargeMicro: 5000, wantErr: nil, wantBalance: 1, wantRem: 4999,
		},
		{
			name: "exact floor landing allowed with zero residue", floor: 0, balance: 1, remMicro: 0,
			chargeMicro: 10000, wantErr: nil, wantBalance: 0, wantRem: 0,
		},
		{
			// 1c − 1.5c lands exactly on the floor carrying 5000µ residue:
			// the effective balance would dip below the floor — rejected.
			name: "exact floor landing with residue rejects", floor: 0, balance: 1, remMicro: 0,
			chargeMicro: 15000, wantErr: ErrInsufficientCredits, wantBalance: 1, wantRem: 0,
		},
		{
			name: "negative floor overdraft exact landing", floor: -100, balance: -99, remMicro: 0,
			chargeMicro: 10000, wantErr: nil, wantBalance: -100, wantRem: 0,
		},
		{
			name: "negative floor with sub-cent overshot rejects", floor: -100, balance: -99, remMicro: 0,
			chargeMicro: 10001, wantErr: ErrInsufficientCredits, wantBalance: -99, wantRem: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orgID := "af05-floor-" + tc.name
			seedWallet(ctx, t, pool, orgID, tc.balance)
			_, err := pool.Exec(ctx, `UPDATE org_credits SET remainder_micro_usd = $2 WHERE org_id = $1`, orgID, tc.remMicro)
			require.NoError(t, err)

			store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: tc.floor, CacheTTL: time.Minute})
			err = store.DeductMicro(ctx, orgID, money.MicroUSD(tc.chargeMicro), "req-"+orgID, nil)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			balanceCents, remainder := walletRow(ctx, t, pool, orgID)
			assert.Equal(t, tc.wantBalance, balanceCents)
			assert.Equal(t, tc.wantRem, remainder)
		})
	}
}

// Admission (CheckBalance) keeps the AF-01 boundary with fractional state:
// wallet == floor rejects even with pending residue; one cent of headroom
// admits regardless of residue.
func TestCheckBalance_FractionalAdmission(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(context.Background(), t, pool)

	cases := []struct {
		name    string
		balance int64
		rem     int64
		wantErr error
	}{
		{"wallet at floor rejects", 0, 4000, ErrInsufficientCredits},
		{"wallet below floor rejects", -1, 0, ErrInsufficientCredits},
		{"one cent above floor admits with residue", 1, 9999, nil},
		{"one cent above floor admits without residue", 1, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orgID := "af05-adm-" + tc.name
			seedWallet(ctx, t, pool, orgID, tc.balance)
			_, err := pool.Exec(ctx, `UPDATE org_credits SET remainder_micro_usd = $2 WHERE org_id = $1`, orgID, tc.rem)
			require.NoError(t, err)

			store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: 0, CacheTTL: time.Minute})
			bal, err := store.CheckBalance(ctx, orgID)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.NotNil(t, bal)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.balance, bal.BalanceCents+(bal.RemainderMicroUSD+int64(money.MicroPerCent)-1)/int64(money.MicroPerCent),
				"effective view must reconstruct the raw wallet")
		})
	}
}

// Concurrent exact charges never lose a residue update: the final wallet is
// the exact arithmetic total (serializable + FOR UPDATE under -race). Deep
// grace keeps admission out of the picture — this tests exactness.
func TestDeductMicro_ConcurrentExactTotals(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(context.Background(), t, pool)

	orgID := "af05-concurrent"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})

	// 8 concurrent replicas × 50 charges: 400 × $0.004 = $1.60 exactly. The
	// serializable retry budget (4 attempts) is sized for replica-class
	// contention; heavier fan-out belongs to the AF-06 durable executor.
	const workers = 8
	const perWorker = 50
	price := money.MicroUSD(4000)

	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if err := store.DeductMicro(ctx, orgID, price, fmt.Sprintf("req-af05-c-%d-%d", w, i), nil); err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent charge failed: %v", err)
	}

	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(-160), balanceCents, "400 × $0.004 = exactly −$1.60")
	assert.Equal(t, int64(0), remainder)
	requireReconciled(ctx, t, pool, orgID)
}

// Historical (pre-AF-05) cents-only ledger rows are never recalculated and
// stay consistent with fractional activity on top of them.
func TestDeductMicro_HistoricalLedgerUntouched(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(context.Background(), t, pool)

	orgID := "af05-historical"
	seedWallet(ctx, t, pool, orgID, 500)

	// A pre-migration settlement: cents only, no exact micro recorded. The
	// wallet already reflects it (balance 500 after a −500 charge).
	_, err := pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, metadata, amount_micro_usd)
		VALUES ($1, -500, 500, 'usage', 'req-legacy-1', '{}', NULL)`, orgID)
	require.NoError(t, err)

	store := NewStore(pool, nil)
	require.NoError(t, store.DeductMicro(ctx, orgID, money.MicroUSD(4000), "req-af05-hist", nil))

	var legacyAmount *int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT amount_micro_usd FROM credit_transactions WHERE org_id=$1 AND request_id='req-legacy-1'`, orgID,
	).Scan(&legacyAmount))
	assert.Nil(t, legacyAmount, "historical row must not be rewritten")

	txns, err := store.GetTransactions(ctx, orgID, 50)
	require.NoError(t, err)
	var sawLegacy, sawNew bool
	for _, tx := range txns {
		if tx.RequestID != nil && *tx.RequestID == "req-legacy-1" {
			sawLegacy = true
			assert.Nil(t, tx.AmountMicro)
			assert.Equal(t, int64(-500), tx.AmountCents)
		}
		if tx.RequestID != nil && *tx.RequestID == "req-af05-hist" {
			sawNew = true
			require.NotNil(t, tx.AmountMicro)
			assert.Equal(t, int64(-4000), *tx.AmountMicro)
			assert.Equal(t, int64(0), tx.AmountCents, "purely fractional charge: zero whole cents")
		}
	}
	assert.True(t, sawLegacy && sawNew, "both ledger generations visible")

	// Wallet: 500 cents (legacy charge already applied), then a 4000µ
	// fractional charge: whole cents stand, residue 4000µ.
	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(500), balanceCents)
	assert.Equal(t, int64(4000), remainder)
}

// TopUp is whole-cents and exact on the micro ledger; it never disturbs the
// accrued sub-cent residue, and effective balance moves by exactly the cents.
func TestTopUp_InteractsWithRemainderExactly(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(context.Background(), t, pool)

	orgID := "af05-topup"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStore(pool, nil)

	require.NoError(t, store.DeductMicro(ctx, orgID, money.MicroUSD(4000), "req-af05-topup-1", nil))
	require.NoError(t, store.TopUp(ctx, orgID, 100, "inv-af05"))

	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(100), balanceCents, "top-up adds whole cents only")
	assert.Equal(t, int64(4000), remainder, "residue untouched by top-up")

	bal, err := store.GetBalance(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, int64(99), bal.BalanceCents, "effective floored cents: 100 − 1 (residue)")
	assert.Equal(t, int64(1000000-4000), bal.BalanceMicroUSD, "exact effective micro")

	_, micro, nullMicro := ledgerTotals(ctx, t, pool, orgID)
	assert.Equal(t, int64(1000000-4000), micro, "top-up row is exact in micro too")
	assert.Equal(t, int64(0), nullMicro)
}

// Zero-amount and invalid deductions are rejected at the boundary — unknown
// price must never become a zero (or negative) charge.
func TestDeductMicro_BoundaryRejections(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(ctx, t, pool)

	orgID := "af05-boundary"
	seedWallet(ctx, t, pool, orgID, 100)
	store := NewStore(pool, nil)

	require.Error(t, store.DeductMicro(ctx, orgID, 0, "req-zero", nil))
	require.Error(t, store.DeductMicro(ctx, orgID, money.MicroUSD(-4000), "req-negative", nil))
	require.Error(t, store.Deduct(ctx, orgID, 0, "req-zero-cents", nil))

	_, _, nullMicro := ledgerTotals(ctx, t, pool, orgID)
	assert.Equal(t, int64(0), nullMicro, "rejected charges never write ledger rows")
	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(100), balanceCents)
	assert.Equal(t, int64(0), remainder)

	// Unknown price/usage stays decodable at the caller: money.QuoteFromUSD
	// classifies missing/invalid quotes as unknown, not zero.
	if _, state := money.QuoteFromUSD(0, false); state != money.QuoteUnknown {
		t.Fatalf("absent quote classified %v, want unknown", state)
	}
}

// A store without a database rejects charges instead of pretending success.
func TestDeductMicro_NilDBIsError(t *testing.T) {
	store := NewStore(nil, nil)
	require.Error(t, store.DeductMicro(context.Background(), "org-x", money.MicroUSD(1), "req-x", nil))
	require.Error(t, store.DeductMicro(context.Background(), "", money.MicroUSD(1), "req-x", nil))
}

// Wallets beyond the representable µUSD range fail closed with an explicit
// error instead of wrapping (a wrapped balance could flip sign and silently
// block admission for every org).
func TestEffectiveBalance_OverflowFailsClosed(t *testing.T) {
	huge := int64(math.MaxInt64)
	if _, err := effectiveBalance("org-x", huge, 0, time.Time{}); err == nil {
		t.Fatal("overflowing wallet must error, not wrap")
	}
	if _, err := effectiveBalance("org-x", -huge, 0, time.Time{}); err == nil {
		t.Fatal("overflowing overdraft must error, not wrap")
	}
	// The representable extremes stay exact.
	b, err := effectiveBalance("org-x", math.MaxInt64/int64(money.MicroPerCent), 9999, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, math.MaxInt64/int64(money.MicroPerCent)-1, b.BalanceCents)
}

// LowBalanceOrgs reports orgs below the threshold, lowest first. The stand
// is shared, so assertions are scoped to this test's orgs.
func TestLowBalanceOrgs(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(ctx, t, pool)

	seedWallet(ctx, t, pool, "af05-low-a", -5)
	seedWallet(ctx, t, pool, "af05-low-b", -1)
	seedWallet(ctx, t, pool, "af05-high", 50)

	store := NewStore(pool, nil)
	orgs, err := store.LowBalanceOrgs(ctx, 0, 1000)
	require.NoError(t, err)

	var mine []string
	for _, org := range orgs {
		if org == "af05-low-a" || org == "af05-low-b" {
			mine = append(mine, org)
		}
		require.NotEqual(t, "af05-high", org, "positive wallet must not be reported")
	}
	require.Len(t, mine, 2, "both negative wallets reported")
	assert.Equal(t, "af05-low-a", mine[0], "lowest balance first")
	assert.Equal(t, "af05-low-b", mine[1])
}

// Transaction listing clamps out-of-range limits to the default page.
func TestGetTransactions_LimitClamped(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(ctx, t, pool)

	orgID := "af05-tx-clamp"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStore(pool, nil)
	for i := 0; i < 3; i++ {
		require.NoError(t, store.TopUp(ctx, orgID, 100, fmt.Sprintf("inv-%d", i)))
	}

	txns, err := store.GetTransactions(ctx, orgID, 0)
	require.NoError(t, err)
	assert.Len(t, txns, 3, "limit<=0 falls back to the default page size")
}
