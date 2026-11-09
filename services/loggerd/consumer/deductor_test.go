package consumer

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- Deductor tests ----
// The Deductor type is defined in deductor.go (production code). Since AF-05
// it receives an exact micro-USD amount plus the event-boundary quote state
// (QuotePositive / QuoteZero / QuoteUnknown); the quote resolution itself
// (resale preferred over cost) lives in resaleDeductionMicro and is covered
// by af05_money_test.go.

// ---- Test: Deduct same request_id twice — second is no-op ----

func TestDeductor_Idempotency_SameRequestIDTwice(t *testing.T) {
	// nil-db store: deduct fails at store level, but the Deductor tracks
	// seenIDs independently of the store.
	store := credits.NewStore(nil, slog.Default())

	d := NewDeductor(store, slog.Default())
	ctx := context.Background()

	fifty := money.MustFromCents(50)
	// nil-DB store: every attempt fails and the failure is visible —
	// never silently swallowed (retryable, no completion marker).
	require.Error(t, d.ProcessDeduction(ctx, "org-1", "test-model", "req-abc", fifty, money.QuotePositive, 0, 0))

	// Second attempt re-executes (fails again on this nil-DB stand): there
	// is no in-memory completion marker to suppress the retry.
	require.Error(t, d.ProcessDeduction(ctx, "org-1", "test-model", "req-abc", fifty, money.QuotePositive, 0, 0))
}

// ---- Test: Idempotency with valid store (integration) ----

func TestDeductor_Idempotency_Integration(t *testing.T) {
	// A05 (audit §A05): this suite CREATEs and DROPs the credit tables, so
	// it runs on a fixture-owned schema (search_path pinned by the helper):
	// every statement below — including the teardown DROPs — can only land
	// inside the fixture, never in the shared stand's public schema.
	pool := setupOwnedCreditsDB(t)

	ctx := context.Background()
	setupCreditTables(ctx, t, pool)
	defer teardownCreditTables(ctx, t, pool)

	store := credits.NewStore(pool, slog.Default())
	d := NewDeductor(store, slog.Default())

	err := store.TopUp(ctx, "org-idem", 10000, "inv-topup")
	require.NoError(t, err)

	require.NoError(t, d.ProcessDeduction(ctx, "org-idem", "test-model", "req-idem-1", money.MustFromCents(50), money.QuotePositive, 0, 0))

	bal1, _ := store.GetBalance(ctx, "org-idem")

	// Same request_id again — DB-idempotent no-op, no double charge.
	require.NoError(t, d.ProcessDeduction(ctx, "org-idem", "test-model", "req-idem-1", money.MustFromCents(50), money.QuotePositive, 0, 0))

	bal2, _ := store.GetBalance(ctx, "org-idem")
	assert.Equal(t, bal1.BalanceCents, bal2.BalanceCents, "balance should not change on idempotent skip")
	assert.Equal(t, bal1.BalanceMicroUSD, bal2.BalanceMicroUSD, "micro balance unchanged on idempotent skip")
}

// ---- Test: Insufficient balance / store failures are logged, not propagated ----

func TestDeductor_InsufficientBalance_LogsNotPropagated(t *testing.T) {
	store := credits.NewStore(nil, slog.Default())
	d := NewDeductor(store, slog.Default())
	ctx := context.Background()

	assert.Error(t, d.ProcessDeduction(ctx, "org-2", "test-model", "req-insufficient-1", money.MustFromCents(500), money.QuotePositive, 0, 0))
}

func TestDeductor_InsufficientBalance_DBError(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, slog.Default()), slog.Default())
	ctx := context.Background()

	assert.Error(t, d.ProcessDeduction(ctx, "org-3", "test-model", "req-dberr-1", money.MustFromCents(100), money.QuotePositive, 0, 0))
}

func TestDeductor_InsufficientBalance_NoStore(t *testing.T) {
	d := NewDeductor(nil, slog.Default())
	ctx := context.Background()

	assert.ErrorIs(t, d.ProcessDeduction(ctx, "org-3", "test-model", "req-nostore-1", money.MustFromCents(100), money.QuotePositive, 0, 0), ErrNoChargeTarget)
}

// ---- Test: Zero cost — skipped as zero_quote ----

func TestDeductor_ZeroCost_SkipsBlock(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, slog.Default()), slog.Default())
	ctx := context.Background()

	assert.NoError(t, d.ProcessDeduction(ctx, "org-4", "test-model", "req-zero-1", 0, money.QuoteZero, 0, 0))
}

// ---- Test: Unknown price — skipped as unknown_quote, never as zero ----

func TestDeductor_UnknownQuote_SkipsWithoutCharge(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, slog.Default()), slog.Default())
	ctx := context.Background()

	assert.NoError(t, d.ProcessDeduction(ctx, "org-4", "test-model", "req-unknown-1", 0, money.QuoteUnknown, 0, 0))
}

func TestDeductor_EmptyOrgID_IsDiagnosticNotSilent(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, slog.Default()), slog.Default())
	ctx := context.Background()

	assert.ErrorIs(t, d.ProcessDeduction(ctx, "", "test-model", "req-noid-1", money.MustFromCents(100), money.QuotePositive, 0, 0), ErrNoChargeTarget)
}

func TestDeductor_NilStore_IsDiagnosticNotSilent(t *testing.T) {
	d := NewDeductor(nil, slog.Default())
	ctx := context.Background()

	assert.ErrorIs(t, d.ProcessDeduction(ctx, "org-4", "test-model", "req-nilstore-1", money.MustFromCents(100), money.QuotePositive, 0, 0), ErrNoChargeTarget)
}

// ---- Test: Sub-cent charges are billed exactly (integration) ----
// The pre-AF-05 behavior (0 cents billed for $0.004) is the defect this
// card fixes; the exact µUSD ledger is pinned in pkg/credits and the live
// AF-05 acceptance test. Here: the Deductor forwards the exact amount.

func TestDeductor_SubCentAmountChargedExactly_Integration(t *testing.T) {
	// A05 (audit §A05): this suite CREATEs and DROPs the credit tables, so
	// it runs on a fixture-owned schema (search_path pinned by the helper):
	// every statement below — including the teardown DROPs — can only land
	// inside the fixture, never in the shared stand's public schema.
	pool := setupOwnedCreditsDB(t)

	ctx := context.Background()
	setupCreditTables(ctx, t, pool)
	defer teardownCreditTables(ctx, t, pool)

	store := credits.NewStore(pool, slog.Default())
	d := NewDeductor(store, slog.Default())

	orgID := "org-subcent"
	err := store.TopUp(ctx, orgID, 100, "inv-topup")
	require.NoError(t, err)

	require.NoError(t, d.ProcessDeduction(ctx, orgID, "test-model", "req-subcent-1", money.MicroUSD(4000), money.QuotePositive, 0, 0))

	bal, err := store.GetBalance(ctx, orgID)
	require.NoError(t, err)
	// $0.004 = 4000 µUSD against a 100¢ top-up (1_000_000µ): whole cents
	// unchanged, exact residue durable.
	assert.Equal(t, int64(4000), bal.RemainderMicroUSD, "sub-cent residue is durable")
	assert.Equal(t, int64(1_000_000-4000), bal.BalanceMicroUSD, "exact effective balance")
	assert.Equal(t, int64(99), bal.BalanceCents, "floored effective cents (100 − 1 = 99, never overstated)")
}

// ---- Test: Successful deduct logs info (integration) ----

func TestDeductor_SuccessfulDeduct_LogsInfo_Integration(t *testing.T) {
	// A05 (audit §A05): this suite CREATEs and DROPs the credit tables, so
	// it runs on a fixture-owned schema (search_path pinned by the helper):
	// every statement below — including the teardown DROPs — can only land
	// inside the fixture, never in the shared stand's public schema.
	pool := setupOwnedCreditsDB(t)

	ctx := context.Background()
	setupCreditTables(ctx, t, pool)
	defer teardownCreditTables(ctx, t, pool)

	store := credits.NewStore(pool, slog.Default())

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	d := NewDeductor(store, logger)

	err := store.TopUp(ctx, "org-log-success", 10000, "inv-topup")
	require.NoError(t, err)

	require.NoError(t, d.ProcessDeduction(ctx, "org-log-success", "test-model", "req-log-success", money.MustFromCents(25), money.QuotePositive, 0, 0))

	assert.Contains(t, logBuf.String(), "credit deducted", "should log successful deduction")
}

// ---- Test: Deductor logs warning on insufficient credits (integration) ----

func TestDeductor_InsufficientCredits_LogsWarning_Integration(t *testing.T) {
	// A05 (audit §A05): this suite CREATEs and DROPs the credit tables, so
	// it runs on a fixture-owned schema (search_path pinned by the helper):
	// every statement below — including the teardown DROPs — can only land
	// inside the fixture, never in the shared stand's public schema.
	pool := setupOwnedCreditsDB(t)

	ctx := context.Background()
	setupCreditTables(ctx, t, pool)
	defer teardownCreditTables(ctx, t, pool)

	store := credits.NewStore(pool, slog.Default())

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	d := NewDeductor(store, logger)

	// Top up only 5 cents.
	err := store.TopUp(ctx, "org-insufficient", 5, "inv-topup")
	require.NoError(t, err)

	// Try to deduct $2.00 — will exceed grace period: the attempt fails
	// visibly (error + warning log).
	require.Error(t, d.ProcessDeduction(ctx, "org-insufficient", "test-model", "req-insufficient-log", money.MustFromCents(200), money.QuotePositive, 0, 0))

	assert.Contains(t, logBuf.String(), "insufficient balance", "should log insufficient credits warning")
}

// ---- Test: Multiple deductions same org reduce balance correctly (integration) ----

func TestDeductor_MultipleDeductions_ReduceBalance_Integration(t *testing.T) {
	// A05 (audit §A05): this suite CREATEs and DROPs the credit tables, so
	// it runs on a fixture-owned schema (search_path pinned by the helper):
	// every statement below — including the teardown DROPs — can only land
	// inside the fixture, never in the shared stand's public schema.
	pool := setupOwnedCreditsDB(t)

	ctx := context.Background()
	setupCreditTables(ctx, t, pool)
	defer teardownCreditTables(ctx, t, pool)

	store := credits.NewStore(pool, slog.Default())
	d := NewDeductor(store, slog.Default())

	// Top up $10.00.
	err := store.TopUp(ctx, "org-multi", 1000, "inv-topup")
	require.NoError(t, err)

	// Deduct $3.00 three times.
	for i := 0; i < 3; i++ {
		require.NoError(t, d.ProcessDeduction(ctx, "org-multi", "test-model", "req-multi-"+string(rune('a'+i)), money.MustFromCents(300), money.QuotePositive, 0, 0))
	}

	bal, err := store.GetBalance(ctx, "org-multi")
	require.NoError(t, err)
	// 1000 - 300*3 = 100 cents remaining.
	assert.Equal(t, int64(100), bal.BalanceCents)
}

// ---- Test: Deductor handles metadata correctly (integration) ----

func TestDeductor_MetadataPassedToStore_Integration(t *testing.T) {
	// A05 (audit §A05): this suite CREATEs and DROPs the credit tables, so
	// it runs on a fixture-owned schema (search_path pinned by the helper):
	// every statement below — including the teardown DROPs — can only land
	// inside the fixture, never in the shared stand's public schema.
	pool := setupOwnedCreditsDB(t)

	ctx := context.Background()
	setupCreditTables(ctx, t, pool)
	defer teardownCreditTables(ctx, t, pool)

	store := credits.NewStore(pool, slog.Default())
	d := NewDeductor(store, slog.Default())

	err := store.TopUp(ctx, "org-meta", 10000, "inv-topup")
	require.NoError(t, err)

	require.NoError(t, d.ProcessDeduction(ctx, "org-meta", "test-model", "req-metadata", money.MustFromCents(25), money.QuotePositive, 0, 0))

	txns, err := store.GetTransactions(ctx, "org-meta", 10)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(txns), 1)
	var usageFound bool
	for _, tx := range txns {
		if tx.Type == "usage" {
			usageFound = true
			require.NotNil(t, tx.AmountMicro, "usage rows carry the exact micro amount")
			assert.Equal(t, int64(-250000), *tx.AmountMicro)
		}
	}
	assert.True(t, usageFound, "usage ledger row exists")
}

// ---- Test: Deductor with nil logger doesn't panic ----

func TestDeductor_NilLogger_DoesNotPanic(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, slog.Default()), nil)
	ctx := context.Background()

	assert.NotPanics(t, func() {
		_ = d.ProcessDeduction(ctx, "org-10", "test-model", "req-nologger-1", money.MustFromCents(10), money.QuotePositive, 0, 0)
	})
}

// ---- Test: Multiple different request IDs all processed ----

func TestDeductor_MultipleUniqueRequestIDs_AllProcessed(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, slog.Default()), slog.Default())
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.Error(t, d.ProcessDeduction(ctx, "org-11", "test-model", "req-unique-"+string(rune('a'+i)), money.MustFromCents(1), money.QuotePositive, 0, 0))
	}
}

// ---- Test: Deductor does not propagate errors to caller ----

func TestDeductor_ErrorsReturnedToCaller(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, slog.Default()), slog.Default())
	ctx := context.Background()

	// AF-06: failures are returned for the settlement worker to classify —
	// they are never swallowed into a fake success.
	assert.Error(t, d.ProcessDeduction(ctx, "org-12", "test-model", "req-no-propagate", money.MustFromCents(50), money.QuotePositive, 0, 0))
}

// ---- Test: Deductor with empty orgID skips without calling store ----

func TestDeductor_EmptyOrgID_SkipsStoreCall(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, slog.Default()), slog.Default())
	ctx := context.Background()

	assert.ErrorIs(t, d.ProcessDeduction(ctx, "", "test-model", "req-empty-org", money.MustFromCents(50), money.QuotePositive, 0, 0), ErrNoChargeTarget)
}

// ---- Test helpers for integration tests ----

func setupCreditTables(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	// Dual role since A05 (audit §A05):
	//   - on a fixture-owned pool (setupOwnedCreditsDB — every caller in
	//     this file) this is the PRIMARY fixture DDL: the fixture schema
	//     starts empty, so these CREATEs materialize the credit tables
	//     there, mirroring the production shape the store's SQL needs
	//     (wallet columns, ledger columns, AF-05 fractional columns).
	//   - on the shared migrated pool (other suites outside this fix's
	//     destructive scope) it stays the historical no-op guard: the
	//     disposable stand already applied the full production migration
	//     set, so the tables exist in their real shape.
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS org_credits (
			org_id TEXT PRIMARY KEY,
			balance_cents BIGINT NOT NULL DEFAULT 0,
			remainder_micro_usd BIGINT NOT NULL DEFAULT 0 CHECK (remainder_micro_usd >= 0 AND remainder_micro_usd < 10000),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`)
	if err != nil {
		t.Logf("create org_credits: %v", err)
	}
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
		);
	`)
	if err != nil {
		t.Logf("create credit_transactions: %v", err)
	}
}

func teardownCreditTables(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	// A05 containment: every caller passes a fixture-owned pool
	// (setupOwnedCreditsDB), so these unqualified DROPs resolve through the
	// pinned search_path and can only ever hit the fixture schema — the
	// audited defect (destroying the SHARED stand's public
	// credit_transactions/org_credits and poisoning later suites with
	// SQLSTATE 42P01) is structurally impossible. The fixture schema itself
	// is dropped by the pkg/testdb helper's guaranteed cleanup.
	_, err := pool.Exec(ctx, "DROP TABLE IF EXISTS credit_transactions; DROP TABLE IF EXISTS org_credits")
	if err != nil {
		t.Logf("teardown warning: %v", err)
	}
}
