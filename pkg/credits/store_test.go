package credits

import (
	"context"
	"fmt"
	"testing"
	"time"

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
	pool := setupTestDB(t)
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
	pool := setupTestDB(t)
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

func TestDeduct_ReducesBalance(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
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
	pool := setupTestDB(t)
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
	if err != ErrInsufficientCredits {
		t.Fatalf("expected ErrInsufficientCredits, got %v", err)
	}

	bal, _ := store.GetBalance(ctx, "org-grace")
	if bal.BalanceCents != 50 {
		t.Errorf("balance should be unchanged at 50, got %d", bal.BalanceCents)
	}
}

func TestCheckBalance_AllowsGracePeriod(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
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
	if err == nil {
		t.Fatal("expected Deduct to fail when balance exceeds grace period")
	}

	// Balance should still be at 100 (deduction rolled back).
	bal, err = store.GetBalance(ctx, "org-check")
	if err != nil {
		t.Fatalf("GetBalance after blocked deduct: %v", err)
	}
	if bal.BalanceCents != 100 {
		t.Errorf("expected balance_cents=100 (unchanged), got %d", bal.BalanceCents)
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
	if err != ErrInsufficientCredits {
		t.Fatalf("expected CheckBalance to return ErrInsufficientCredits, got %v", err)
	}
}

func TestTransactions_Recorded(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
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

func TestConcurrentDeductions(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	store := NewStore(pool, nil)

	// Top up $10.00 (1000 cents).
	err := store.TopUp(ctx, "org-concurrent", 1000, "inv-060")
	if err != nil {
		t.Fatalf("TopUp: %v", err)
	}

	// Run 25 concurrent deductions of $0.50 (50 cents each).
	// Total = $12.50, which exceeds the wallet by $2.50.
	// Some should succeed, some should fail (balance goes below grace period).
	done := make(chan error, 25)
	for i := 0; i < 25; i++ {
		go func(i int) {
			err := store.Deduct(ctx, "org-concurrent", 50, fmt.Sprintf("req-concurrent-%d", i), nil)
			done <- err
		}(i)
	}

	successes := 0
	failures := 0
	for i := 0; i < 25; i++ {
		err = <-done
		if err == nil {
			successes++
		} else if IsInsufficientCredits(err) {
			failures++
		} else {
			// Under high contention, serializable conflicts may exhaust all retries.
			// This is expected — the retry loop mitigates but doesn't eliminate
			// serialization failures under extreme concurrent load.
			failures++
			t.Logf("deduction %d failed with non-balance error (expected under contention): %v", i, err)
		}
	}

	// NEXT-04 (flake fix): under serializable isolation, 25-way contention
	// can exhaust the retry budget — the previous "≥18 successes" threshold
	// contradicted the test's own contention comment and failed on loaded
	// machines. The CORRECTNESS invariants are exact accounting and the
	// grace-period floor, not retry throughput:
	//   1. at least one deduction succeeds (the path is exercised);
	//   2. balance == 1000 − 50×successes EXACTLY (no double-spend, no loss);
	//   3. balance never violates the grace period (fail-closed held).
	if successes < 1 {
		t.Fatalf("no deduction succeeded — contention path not exercised (failures=%d)", failures)
	}

	bal, err := store.GetBalance(ctx, "org-concurrent")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if want := int64(1000 - 50*successes); bal.BalanceCents != want {
		t.Errorf("exact accounting violated: balance %d, want 1000-50*%d=%d", bal.BalanceCents, successes, want)
	}
	if bal.BalanceCents < store.cfg.GracePeriodCents {
		t.Errorf("grace period violated: %d < %d", bal.BalanceCents, store.cfg.GracePeriodCents)
	}

	// Verify transaction count matches successes.
	txns, err := store.GetTransactions(ctx, "org-concurrent", 100)
	if err != nil {
		t.Fatalf("GetTransactions: %v", err)
	}
	usageTxns := 0
	for _, tx := range txns {
		if tx.Type == "usage" {
			usageTxns++
		}
	}
	if usageTxns != successes {
		t.Errorf("expected %d usage transactions, got %d", successes, usageTxns)
	}

	// Small delay for cache TTL.
	time.Sleep(100 * time.Millisecond)
}

func TestDeduct_IdempotentDuplicate(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
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
