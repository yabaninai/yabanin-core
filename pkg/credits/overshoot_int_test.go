//go:build integration

// NEXT-17: budget-overshoot measurement. These tests MEASURE the current
// admission architecture (gateway check-then-serve, async deduction in
// loggerd) and pin the invariants that any reservation scheme (NEXT-18)
// must preserve. Numbers land in the work record and ADR-0001.
package credits

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// TestOvershoot_ConcurrentAdmissionRace: with the check-then-serve pattern,
// every concurrent request that passes the PRODUCTION admission check
// (CheckBalance: reject iff wallet ≤ grace floor, default −100) before the
// first deduction lands is admitted — the overshoot depth equals
// (admitted × cost) − balance. This is the architectural window ADR-0001
// closes with durable reservations. Measured figures at concurrency=100
// with a 100¢ wallet and 10¢ charges:
//
//	served notional = 100 × 10¢                 = 1000¢
//	beyond funds    = 1000¢ − 100¢ wallet       =  900¢
//	collectible     = wallet 100¢ → floor −100¢ =  200¢
//	uncollected     = 900¢ − 200¢               =  800¢
//
// Exact ledger truth per case (admitted, debits, final wallet):
// (1,1,90) (10,10,0) (100,20,−100). Whole-cent charges may land exactly ON
// the floor — the production rule admits post == floor when the new
// remainder is 0 — so the 20th debit from 100¢ ends at −100, never past it,
// and the remaining 80 admissions are rejected with ErrInsufficientCredits.
func TestOvershoot_ConcurrentAdmissionRace(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	const org = "org-overshoot-race"
	const costCents = int64(10) // $0.10 per request

	cases := []struct {
		concurrency int
		admitted    int64
		debits      int64
		finalCents  int64
	}{
		{1, 1, 1, 90},
		{10, 10, 10, 0},
		{100, 100, 20, -100},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("concurrency=%d", tc.concurrency), func(t *testing.T) {
			// Fresh store per case: GetBalance caches positive reads for
			// CacheTTL (30s default), so a store shared across cases would
			// serve the previous case's final balance (e.g. −100) against
			// the reset wallet and make the next admission phase flaky.
			store := NewStore(pool, nil)
			resetOvershootCase(ctx, t, pool, org, 100)

			// Bounded wait: the whole case must finish inside the deadline.
			caseCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()

			// Deterministic admits: the deduction phase starts only after
			// every admission read has completed, so each goroutine saw the
			// untouched 100¢ wallet (100 > floor −100).
			admitted, rejected := runAdmissionPhase(caseCtx, t, store, org, tc.concurrency)
			if admitted != tc.admitted || rejected != 0 {
				t.Fatalf("admission race: admitted=%d rejected=%d, want exactly %d admitted and 0 rejected",
					admitted, rejected, tc.admitted)
			}

			debits := settleAdmissions(caseCtx, t, store, org, tc.concurrency, admitted, costCents)
			walletCents, usageRows := queryOvershootTruth(caseCtx, t, pool, org)
			if debits != tc.debits || walletCents != tc.finalCents || usageRows != tc.debits {
				t.Errorf("overshoot accounting: debits=%d (want %d), wallet=%d (want %d), usage rows=%d (want %d)",
					debits, tc.debits, walletCents, tc.finalCents, usageRows, tc.debits)
			}

			// Derived diagnostics: uncollected notional is the
			// served-but-never-collected remainder — rejections × cost, NOT
			// a wallet-arithmetic difference (which double-counts what
			// settlement did collect); overshoot exists only while the
			// wallet is negative.
			uncollected := (tc.admitted - debits) * costCents
			overshoot := max(int64(0), -walletCents)
			t.Logf("concurrency=%3d: admitted=%3d debits=%3d final_wallet=%d cents (overshoot beyond $0 = %d cents, uncollected = %d cents)",
				tc.concurrency, tc.admitted, debits, walletCents, overshoot, uncollected)
		})
	}
}

func resetOvershootCase(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string, walletCents int64) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents) VALUES ($1, $2)
		 ON CONFLICT (org_id) DO UPDATE SET balance_cents = $2`, org, walletCents); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM credit_transactions WHERE org_id = $1`, org); err != nil {
		t.Fatal(err)
	}
}

// runAdmissionPhase races `concurrency` goroutines through the production
// floor-aware CheckBalance behind one start gate; only a floor rejection may
// land in the rejected count, and the phase deadline fails the case instead
// of hanging the run.
func runAdmissionPhase(ctx context.Context, t *testing.T, store *Store, org string, concurrency int) (admitted, rejected int64) {
	t.Helper()
	var admittedCount, rejectedCount atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := store.CheckBalance(ctx, org); err != nil {
				if errors.Is(err, ErrInsufficientCredits) {
					rejectedCount.Add(1)
					return
				}
				t.Errorf("admission: unexpected error: %v", err)
				return
			}
			admittedCount.Add(1)
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("admission phase exceeded deadline: %v", ctx.Err())
	}
	return admittedCount.Load(), rejectedCount.Load()
}

// settleAdmissions charges every admitted request once, mirroring what
// loggerd does after completion; anything other than a floor rejection is a
// bug and fails the case.
func settleAdmissions(ctx context.Context, t *testing.T, store *Store, org string, concurrency int, admitted, costCents int64) (debits int64) {
	t.Helper()
	for i := int64(0); i < admitted; i++ {
		err := store.Deduct(ctx, org, costCents,
			fmt.Sprintf("race-%d-%d", concurrency, i), nil)
		if err == nil {
			debits++
			continue
		}
		if errors.Is(err, ErrInsufficientCredits) {
			continue
		}
		t.Fatalf("settlement %d: unexpected error: %v", i, err)
	}
	return debits
}

// queryOvershootTruth reads wallet and usage-row counts from the fixture DB —
// independent of the store's in-memory cache and of the in-process counters.
func queryOvershootTruth(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) (walletCents, usageRows int64) {
	t.Helper()
	if err := pool.QueryRow(ctx,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, org).Scan(&walletCents); err != nil {
		t.Fatalf("wallet row: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND type = 'usage'`, org).Scan(&usageRows); err != nil {
		t.Fatalf("ledger count: %v", err)
	}
	return walletCents, usageRows
}

// TestOvershoot_ReplayIsIdempotent: loggerd replay/restart redelivers the
// same request_id; the deduction MUST be a no-op the second time. This is
// the invariant NEXT-18 reservations must keep.
func TestOvershoot_ReplayIsIdempotent(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	store := NewStore(pool, nil)
	const org = "org-overshoot-replay"
	if _, err := pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents) VALUES ($1, $2)
		 ON CONFLICT (org_id) DO UPDATE SET balance_cents = $2`, org, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err := store.Deduct(ctx, org, 10, "replay-req-1", nil); err != nil {
			t.Fatalf("deduct #%d: %v", i, err)
		}
	}
	bal, _ := store.GetBalance(ctx, org)
	if bal.BalanceCents != 990 {
		t.Fatalf("replayed deduction is not idempotent: balance=%d, want 990", bal.BalanceCents)
	}
}

// TestOvershoot_GraceFloor: deductions stop at the configured grace floor;
// the floor is the CURRENT overshoot bound per org.
func TestOvershoot_GraceFloor(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -50})
	const org = "org-overshoot-grace"
	if _, err := pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents) VALUES ($1, $2)
		 ON CONFLICT (org_id) DO UPDATE SET balance_cents = $2`, org, 30); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	// 30 - 60 = -30 ≥ -50: allowed (inside the grace band).
	if err := store.Deduct(ctx, org, 60, "grace-1", nil); err != nil {
		t.Fatalf("deduct inside the grace band: %v", err)
	}
	bal, _ := store.GetBalance(ctx, org)
	if bal.BalanceCents != -30 {
		t.Fatalf("balance after grace-band deduct: %d, want -30", bal.BalanceCents)
	}
	// -30 - 60 = -90 < -50: rejected — the floor is a hard ledger bound.
	if err := store.Deduct(ctx, org, 60, "grace-2", nil); err == nil {
		t.Fatal("deduction beyond the grace floor must fail")
	}
	// There is NO partial deduction to the floor: the whole amount is
	// rejected (measured behavior NEXT-18 must keep or explicitly change).
	_ = time.Second
}
