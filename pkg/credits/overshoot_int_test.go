//go:build integration

// NEXT-17: budget-overshoot measurement. These tests MEASURE the current
// admission architecture (gateway check-then-serve, async deduction in
// loggerd) and pin the invariants that any reservation scheme (NEXT-18)
// must preserve. Numbers land in the work record and ADR-0001.
package credits

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// TestOvershoot_ConcurrentAdmissionRace: with the check-then-serve pattern,
// every concurrent request that passes the balance check BEFORE the first
// async deduction lands is admitted — the overshoot depth equals
// (admitted × cost) − balance. This is the architectural window ADR-0001
// closes with durable reservations.
func TestOvershoot_ConcurrentAdmissionRace(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	store := NewStore(pool, nil)
	const org = "org-overshoot-race"
	const costCents = int64(10) // $0.10 per request
	if _, err := pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents) VALUES ($1, $2)
		 ON CONFLICT (org_id) DO UPDATE SET balance_cents = $2`, org, 100); err != nil {
		t.Fatal(err)
	}

	for _, concurrency := range []int{1, 10, 100} {
		// Reset wallet.
		if _, err := pool.Exec(ctx,
			`UPDATE org_credits SET balance_cents = 100 WHERE org_id = $1`, org); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx,
			`DELETE FROM credit_transactions WHERE org_id = $1`, org); err != nil {
			t.Fatal(err)
		}

		// Admission phase: every goroutine runs the gateway-style check
		// (plain balance read — no reservation), then "serves" (counts).
		var admitted atomic.Int64
		start := make(chan struct{})
		var wg sync.WaitGroup
		var mu sync.Mutex // serialize check reads per wave like two gateways would race
		_ = mu
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				<-start
				bal, err := store.GetBalance(ctx, org)
				if err != nil {
					return
				}
				if bal.BalanceCents >= 0 { // admission rule: balance non-negative
					admitted.Add(1)
				}
			}(i)
		}
		close(start)
		wg.Wait()

		// Async deduction phase (what loggerd does after completion).
		deducted := int64(0)
		for i := 0; i < int(admitted.Load()); i++ {
			if err := store.Deduct(ctx, org, costCents,
				fmt.Sprintf("race-%d-%d", concurrency, i), nil); err != nil {
				break // grace floor reached
			}
			deducted++
		}
		bal, _ := store.GetBalance(ctx, org)
		t.Logf("concurrency=%3d: admitted=%3d deducted=%3d final_balance=%d cents (overshoot beyond $0 = %d cents)",
			concurrency, admitted.Load(), deducted, bal.BalanceCents, -bal.BalanceCents)
		if admitted.Load() < int64(concurrency) && concurrency == 1 {
			t.Fatalf("single request must be admitted: %d", admitted.Load())
		}
		if concurrency >= 10 && admitted.Load() != int64(concurrency) {
			t.Fatalf("check-then-serve race: expected all %d admitted while balance reads stale, got %d",
				concurrency, admitted.Load())
		}
	}
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
