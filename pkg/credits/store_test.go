package credits

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// setupTestDB returns the package-wide disposable, fully migrated Postgres
// stand (QG2-B3: Docker required for the tests gate; skipped only in
// -short mode). No CI service fixture or shared stand is involved.
func setupTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testdb.Postgres(t)
}

// setupFixtureDB returns a fixture-owned, isolated-schema pool on the shared
// stand — the ownership boundary for every raw-DDL fixture in this package
// (testdb.PostgresOwnedSchema, the A05 primitive). setupTestTables builds
// the illustrative interim posture (0028 shape including the global usage
// index that 0029 contracts away) and teardownTestTables DROPs the tables;
// inside the fixture schema that DDL can never reshape the public migrated
// schema that overshoot, sqlcontract, the crash/starter corpora and the
// migrated_posture invariant measure directly. Unqualified fixture DDL
// keeps resolving through current_schema(); teardown is guaranteed restore.
func setupFixtureDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testdb.PostgresOwnedSchema(t, t.Name())
}

func setupTestTables(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	// Mirrors the migrated shape (0001 + 0018 fractional money); on the
	// disposable stand the production migrations already created these, so
	// this is a no-op guard that also restores tables after a teardown.
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS org_credits (
			org_id TEXT PRIMARY KEY,
			balance_cents BIGINT NOT NULL DEFAULT 0,
			remainder_micro_usd BIGINT NOT NULL DEFAULT 0 CHECK (remainder_micro_usd >= 0 AND remainder_micro_usd < 10000),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`)
	if err != nil {
		t.Fatalf("create org_credits: %v", err)
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
		t.Fatalf("create credit_transactions: %v", err)
	}
	// 0001 usage-identity backstop, restored alongside the 0028 expansion:
	// sibling tests drop and recreate credit_transactions in older shapes
	// and -shuffle decides who runs first, so every setup guarantees the
	// full interim posture (original global index live next to the
	// domain-split arbiters) instead of inheriting whatever shape the
	// previous test left behind.
	_, err = pool.Exec(ctx, `
		CREATE UNIQUE INDEX IF NOT EXISTS uniq_credit_transactions_usage_request_id
		ON credit_transactions (request_id)
		WHERE request_id IS NOT NULL AND type = 'usage'::text;
	`)
	if err != nil {
		t.Fatalf("restore the production usage-identity unique index: %v", err)
	}
	// 0028 invocation identity (expand), byte-mirrored: the invocation
	// column plus the domain-split usage arbiters. The original global
	// index above intentionally stays live alongside them — the interim
	// posture pinned by the migration: same-correlation usage rows still
	// collide loudly until 0029 contracts it away.
	_, err = pool.Exec(ctx, `
		ALTER TABLE credit_transactions ADD COLUMN IF NOT EXISTS invocation_id uuid;
		CREATE UNIQUE INDEX IF NOT EXISTS uniq_credit_transactions_usage_legacy
			ON credit_transactions (request_id)
			WHERE ((request_id IS NOT NULL) AND (invocation_id IS NULL) AND (type = 'usage'::text));
		CREATE UNIQUE INDEX IF NOT EXISTS uniq_credit_transactions_invocation
			ON credit_transactions (invocation_id)
			WHERE ((invocation_id IS NOT NULL) AND (type = 'usage'::text));
	`)
	if err != nil {
		t.Fatalf("apply 0028 invocation scaffolding: %v", err)
	}
}

func teardownTestTables(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `DROP TABLE IF EXISTS credit_transactions; DROP TABLE IF EXISTS org_credits;`)
	if err != nil {
		t.Logf("teardown warning: %v", err)
	}
}

func TestGetBalance_ZeroWhenNoWallet(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	store := NewStore(pool, nil)

	bal, err := store.GetBalance(ctx, "org-new-123")
	if !IsNoWallet(err) {
		t.Fatalf("GetBalance: expected ErrNoWallet, got %v", err)
	}
	if bal != nil {
		t.Errorf("expected nil balance for no-wallet case, got %+v", bal)
	}
}

func TestTopUp_IncreasesBalance(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	store := NewStore(pool, nil)

	// Top up $10.00 (1000 cents).
	err := store.TopUp(ctx, "org-topup", 1000, "inv-001")
	if err != nil {
		t.Fatalf("TopUp: %v", err)
	}

	bal, err := store.GetBalance(ctx, "org-topup")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.BalanceCents != 1000 {
		t.Errorf("expected balance_cents=1000, got %d", bal.BalanceCents)
	}

	// Top up another $5.00 (500 cents).
	err = store.TopUp(ctx, "org-topup", 500, "inv-002")
	if err != nil {
		t.Fatalf("TopUp: %v", err)
	}

	bal, err = store.GetBalance(ctx, "org-topup")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.BalanceCents != 1500 {
		t.Errorf("expected balance_cents=1500, got %d", bal.BalanceCents)
	}
}

func TestGetBalance_CachedWalletTimestamp(t *testing.T) {
	ctx := t.Context()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	const org = "org-cached-stamp"
	stamp := time.Date(2024, time.March, 3, 11, 27, 43, 0, time.UTC)
	if _, err := pool.Exec(ctx, "INSERT INTO org_credits (org_id, balance_cents, updated_at) VALUES ($1, 432, $2)", org, stamp); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool, nil)
	for _, source := range []string{"database", "cache"} {
		bal, err := store.GetBalance(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		if !bal.UpdatedAt.Equal(stamp) || bal.BalanceCents != 432 {
			t.Fatalf("%s read returned %d cents at %s, want 432 cents at %s", source, bal.BalanceCents, bal.UpdatedAt, stamp)
		}
	}
}

func TestDeduct_ReducesBalance(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	store := NewStore(pool, nil)

	// Top up $10.00 first.
	err := store.TopUp(ctx, "org-deduct", 1000, "inv-010")
	if err != nil {
		t.Fatalf("TopUp: %v", err)
	}

	// Deduct $3.50 (350 cents).
	reqID := "req-chat-42"
	err = store.Deduct(ctx, "org-deduct", 350, reqID, map[string]interface{}{"model": "gpt-4o"})
	if err != nil {
		t.Fatalf("Deduct: %v", err)
	}

	bal, err := store.GetBalance(ctx, "org-deduct")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.BalanceCents != 650 {
		t.Errorf("expected balance_cents=650, got %d", bal.BalanceCents)
	}
}

func TestDeduct_FailsWhenBelowGracePeriod(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	store := NewStore(pool, nil)

	// Top up $0.50 (50 cents).
	err := store.TopUp(ctx, "org-grace", 50, "inv-020")
	if err != nil {
		t.Fatalf("TopUp: %v", err)
	}

	// Try to deduct $1.00 (100 cents) — would bring balance to -50, which is OK.
	// But deduct $2.00 (200 cents) — would bring to -150, below grace period (-100).
	reqID := "req-too-much"
	err = store.Deduct(ctx, "org-grace", 200, reqID, nil)
	if err == nil {
		t.Fatal("expected Deduct to fail when balance would go below grace period")
	}
	if !errors.Is(err, ErrInsufficientCredits) {
		t.Fatalf("expected ErrInsufficientCredits, got %v", err)
	}

	bal, _ := store.GetBalance(ctx, "org-grace")
	if bal.BalanceCents != 50 {
		t.Errorf("balance should be unchanged at 50, got %d", bal.BalanceCents)
	}
}

func TestCheckBalance_AllowsGracePeriod(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	store := NewStore(pool, nil)

	// Top up $0.50 (50 cents).
	err := store.TopUp(ctx, "org-check", 50, "inv-030")
	if err != nil {
		t.Fatalf("TopUp: %v", err)
	}

	// Deduct $1.00 to go to -50 (within grace period of -100).
	err = store.Deduct(ctx, "org-check", 100, "req-grace-ok", nil)
	if err != nil {
		t.Fatalf("Deduct within grace: %v", err)
	}

	// CheckBalance should still pass (balance is -50, grace is -100).
	bal, err := store.CheckBalance(ctx, "org-check")
	if err != nil {
		t.Fatalf("CheckBalance should pass at -50: %v", err)
	}
	if bal.BalanceCents != -50 {
		t.Errorf("expected balance_cents=-50, got %d", bal.BalanceCents)
	}

	// Top up to 100 cents so we can deduct enough to go below grace.
	err = store.TopUp(ctx, "org-check", 150, "inv-grace-topup")
	if err != nil {
		t.Fatalf("TopUp for grace test: %v", err)
	}

	// Now balance is 100. Deduct 250 to go to -150 (below grace of -100).
	err = store.Deduct(ctx, "org-check", 250, "req-grace-exceed", nil)
	if !errors.Is(err, ErrInsufficientCredits) {
		t.Fatalf("expected ErrInsufficientCredits when balance exceeds grace period, got %v", err)
	}

	// Rejection must be a clean rollback observed on the fixture DB — not a
	// cached wallet read (the store could serve balance 100 from memory
	// while the wallet row or the ledger drifted) and not a swallowed write.
	var walletCents int64
	if err := pool.QueryRow(ctx,
		`SELECT balance_cents FROM org_credits WHERE org_id = 'org-check'`).Scan(&walletCents); err != nil {
		t.Fatalf("wallet row after blocked deduct: %v", err)
	}
	if walletCents != 100 {
		t.Errorf("expected wallet_cents=100 (unchanged), got %d", walletCents)
	}
	var strayRows int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM credit_transactions
		 WHERE org_id = 'org-check' AND request_id = 'req-grace-exceed' AND type = 'usage'`).Scan(&strayRows); err != nil {
		t.Fatalf("ledger rows for rejected request: %v", err)
	}
	if strayRows != 0 {
		t.Errorf("rejected request must leave zero usage rows, got %d", strayRows)
	}

	// Manually set balance below grace period to test CheckBalance rejection.
	_, err = store.db.Exec(ctx, `UPDATE org_credits SET balance_cents = -200 WHERE org_id = 'org-check'`)
	if err != nil {
		t.Fatalf("manual balance update: %v", err)
	}

	// Invalidate the in-memory cache so CheckBalance reads from DB.
	store.mu.Lock()
	delete(store.cache, "org-check")
	store.mu.Unlock()

	// Now CheckBalance should fail.
	_, err = store.CheckBalance(ctx, "org-check")
	if !errors.Is(err, ErrInsufficientCredits) {
		t.Fatalf("expected CheckBalance to return ErrInsufficientCredits, got %v", err)
	}
}

func TestTransactions_Recorded(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	store := NewStore(pool, nil)

	// Top up $10.00, deduct $3.50.
	err := store.TopUp(ctx, "org-txn", 1000, "inv-040")
	if err != nil {
		t.Fatalf("TopUp: %v", err)
	}

	err = store.Deduct(ctx, "org-txn", 350, "req-chat-99", map[string]interface{}{"model": "claude-sonnet"})
	if err != nil {
		t.Fatalf("Deduct: %v", err)
	}

	txns, err := store.GetTransactions(ctx, "org-txn", 10)
	if err != nil {
		t.Fatalf("GetTransactions: %v", err)
	}
	if len(txns) != 2 {
		t.Fatalf("expected 2 transactions, got %d", len(txns))
	}

	// Most recent should be the deduction.
	if txns[0].Type != "usage" {
		t.Errorf("most recent txn should be 'usage', got '%s'", txns[0].Type)
	}
	if txns[0].AmountCents != -350 {
		t.Errorf("expected amount_cents=-350, got %d", txns[0].AmountCents)
	}

	// Second should be the top-up.
	if txns[1].Type != "topup" {
		t.Errorf("second txn should be 'topup', got '%s'", txns[1].Type)
	}
	if txns[1].AmountCents != 1000 {
		t.Errorf("expected amount_cents=1000, got %d", txns[1].AmountCents)
	}
}

func TestInvalidTopUp_AmountMustBePositive(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	store := NewStore(pool, nil)

	err := store.TopUp(ctx, "org-invalid", 0, "inv-050")
	if err == nil {
		t.Fatal("expected error for zero amount top-up")
	}

	err = store.TopUp(ctx, "org-invalid", -100, "inv-050")
	if err == nil {
		t.Fatal("expected error for negative amount top-up")
	}
}

// isContentionErr reports whether the error is a PostgreSQL serialization
// failure (SQLSTATE 40001) or deadlock (40P01) — exactly the failure classes
// the store's own retry loop treats as retryable contention (mirrors the
// unexported isSerializationFailure). Deadlocks can surface here because the
// deduction serializes per-org via a transaction-scoped advisory lock, not
// via serializable isolation.
func isContentionErr(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "40001" || pgErr.Code == "40P01"
}

func TestConcurrentDeductions(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	store := NewStore(pool, nil)

	// Top up $10.00 (1000 cents).
	err := store.TopUp(ctx, "org-concurrent", 1000, "inv-060")
	if err != nil {
		t.Fatalf("TopUp: %v", err)
	}

	// 25 concurrent deductions of $0.50 (50 cents each); total $12.50
	// exceeds the wallet by $2.50. Deterministic ledger truth under the
	// production floor rule (post > floor, or post == floor with a zero new
	// remainder — whole-cent charges satisfy the second branch): exactly 22
	// charges land, ending the wallet at 1000 − 22×50 = −100, exactly ON the
	// grace floor (default −100), and the remaining 3 are rejected with
	// ErrInsufficientCredits. Contention (serialization failure/deadlock) is
	// retried post-phase, so these totals must hold regardless of scheduling;
	// any other error is a bug and fails the test.
	const (
		workers     = 25
		amountCents = int64(50)
		wantDebits  = 22
		wantFloor   = 3
	)

	// Request IDs are the idempotency key — preserve each worker's identity
	// end-to-end so results can be compared against the ledger per ID.
	ids := make([]string, workers)
	for i := range ids {
		ids[i] = fmt.Sprintf("req-concurrent-%d", i)
	}

	// Coordinated, bounded phase: every worker starts on the same gate and
	// every result must arrive before the deadline.
	phaseCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	results := runDeductionPhase(phaseCtx, t, store, "org-concurrent", amountCents, ids)
	unresolved := unresolvedContentions(t, results, ids)
	settleContentions(phaseCtx, t, store, "org-concurrent", amountCents, ids, results, unresolved)
	assertDeterministicOutcome(t, results, ids, wantDebits, wantFloor)
	verifyWalletFloor(ctx, t, pool, store, "org-concurrent", 1000, amountCents, wantDebits)
	verifyPerIDLedger(ctx, t, pool, "org-concurrent", results, ids, wantDebits)
}

// runDeductionPhase fires one Deduct per request ID behind a common gate and
// waits for all results under the phase deadline, so a hung worker fails the
// test instead of hanging the run.
func runDeductionPhase(ctx context.Context, t *testing.T, store *Store, org string, amountCents int64, ids []string) []error {
	t.Helper()
	results := make([]error, len(ids))
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate
			results[i] = store.Deduct(ctx, org, amountCents, ids[i], nil)
		}(i)
	}
	close(gate)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("deduction phase exceeded deadline: %v", ctx.Err())
	}
	return results
}

// unresolvedContentions classifies the phase results. Only recognized
// contention may remain unresolved here: a floor rejection is already final
// (the wallet only moves down during the test), and ErrNoWallet for a
// just-funded wallet or any connection/schema error is a bug, not a balance
// decision.
func unresolvedContentions(t *testing.T, results []error, ids []string) []int {
	t.Helper()
	var unresolved []int
	for i, err := range results {
		switch {
		case err == nil:
		case errors.Is(err, ErrInsufficientCredits):
		case isContentionErr(err):
			unresolved = append(unresolved, i)
		default:
			t.Fatalf("deduction %d (%s): unexpected error: %v", i, ids[i], err)
		}
	}
	return unresolved
}

// settleContentions retries unresolved contention sequentially: no concurrent
// writers remain post-phase, so a bounded number of attempts must end in
// success or a floor rejection.
func settleContentions(ctx context.Context, t *testing.T, store *Store, org string, amountCents int64, ids []string, results []error, unresolved []int) {
	t.Helper()
	for _, i := range unresolved {
		for attempt := 1; attempt <= 5; attempt++ {
			err := store.Deduct(ctx, org, amountCents, ids[i], nil)
			if err == nil || errors.Is(err, ErrInsufficientCredits) {
				results[i] = err
				break
			}
			if attempt == 5 || !isContentionErr(err) {
				t.Fatalf("retry %d (%s): unexpected error after %d attempts: %v", i, ids[i], attempt, err)
			}
		}
	}
}

// assertDeterministicOutcome pins the scheduling-independent ledger truth:
// exactly wantDebits charges land and wantFloor floor rejections occur —
// the floor is a hard ledger bound.
func assertDeterministicOutcome(t *testing.T, results []error, ids []string, wantDebits, wantFloor int) {
	t.Helper()
	successes, floor := 0, 0
	for i, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrInsufficientCredits):
			floor++
		default:
			t.Fatalf("unclassified result for %s: %v", ids[i], err)
		}
	}
	if successes != wantDebits || floor != wantFloor {
		t.Fatalf("deterministic outcome violated: %d debits + %d floor rejections, want %d + %d",
			successes, floor, wantDebits, wantFloor)
	}
}

// verifyWalletFloor asserts exact accounting and the grace floor on the
// fixture DB — independent of the store's in-memory cache.
func verifyWalletFloor(ctx context.Context, t *testing.T, pool *pgxpool.Pool, store *Store, org string, startCents, amountCents int64, debits int) {
	t.Helper()
	var walletCents int64
	if err := pool.QueryRow(ctx,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, org).Scan(&walletCents); err != nil {
		t.Fatalf("wallet row: %v", err)
	}
	if want := startCents - amountCents*int64(debits); walletCents != want {
		t.Errorf("exact accounting violated: wallet %d, want %d", walletCents, want)
	}
	if walletCents < store.cfg.GracePeriodCents {
		t.Errorf("grace period violated: %d < %d", walletCents, store.cfg.GracePeriodCents)
	}
}

// verifyPerIDLedger checks usage rows per request ID — exactly one row per
// successful deduction and zero for rejected ones, not just counts.
func verifyPerIDLedger(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string, results []error, ids []string, wantDebits int) {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT request_id FROM credit_transactions WHERE org_id = $1 AND type = 'usage'`, org)
	if err != nil {
		t.Fatalf("ledger query: %v", err)
	}
	defer rows.Close()
	ledger := make(map[string]int, wantDebits)
	for rows.Next() {
		var id *string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan ledger row: %v", err)
		}
		if id == nil {
			t.Fatal("usage row without request_id")
		}
		ledger[*id]++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("ledger rows: %v", err)
	}
	if len(ledger) != wantDebits {
		t.Fatalf("expected %d distinct usage rows, got %d", wantDebits, len(ledger))
	}
	for i := range ids {
		want := 0
		if results[i] == nil {
			want = 1
		}
		if ledger[ids[i]] != want {
			t.Errorf("request %s: %d ledger rows, want %d", ids[i], ledger[ids[i]], want)
		}
	}
}

func TestDeduct_IdempotentDuplicate(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	store := NewStore(pool, nil)

	orgID := "org-idempotent"
	requestID := "req-unique-123"

	// Top up first.
	err := store.TopUp(ctx, orgID, 10000, "inv-idem")
	if err != nil {
		t.Fatalf("TopUp: %v", err)
	}

	// First deduct — should succeed.
	err = store.Deduct(ctx, orgID, 500, requestID, map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		t.Fatalf("Deduct (first): %v", err)
	}

	// Second deduct with same request_id — should be idempotent (no-op).
	err = store.Deduct(ctx, orgID, 500, requestID, map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		t.Fatalf("Deduct (second): %v", err)
	}

	// Verify balance is still 9500 (not double-charged).
	balance, err := store.GetBalance(ctx, orgID)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if balance.BalanceCents != 9500 {
		t.Errorf("expected balance 9500 after idempotent deduct, got %d", balance.BalanceCents)
	}

	// Verify only 1 usage transaction exists.
	txns, err := store.GetTransactions(ctx, orgID, 100)
	if err != nil {
		t.Fatalf("GetTransactions: %v", err)
	}
	usageTxns := 0
	for _, tx := range txns {
		if tx.Type == "usage" && tx.RequestID != nil && *tx.RequestID == requestID {
			usageTxns++
		}
	}
	if usageTxns != 1 {
		t.Errorf("expected 1 usage transaction for this request_id, got %d", usageTxns)
	}
}

func TestNewStoreWithConfig_NilLogger(t *testing.T) {
	// NewStoreWithConfig should handle nil logger gracefully.
	store := NewStoreWithConfig(nil, nil, DefaultConfig())
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.log == nil {
		t.Fatal("expected non-nil log after nil logger fallback")
	}

	// GetBalance with nil DB and nil logger should not panic.
	balance, err := store.GetBalance(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("GetBalance with nil db: %v", err)
	}
	if balance.OrgID != "test-org" {
		t.Errorf("expected org_id 'test-org', got %q", balance.OrgID)
	}
	if balance.BalanceCents != 0 {
		t.Errorf("expected zero balance, got %d", balance.BalanceCents)
	}
}
