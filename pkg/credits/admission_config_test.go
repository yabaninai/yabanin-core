package credits

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AF-01 regressions (audit fixtures TestReview_* from code-review-2026-10-02).

// TestConfig_ExplicitZeroGracePeriodIsPreserved: GracePeriodCents=0 is a
// valid explicit configuration ("no overdraft allowed"), not "not set".
// NewStoreWithConfig must keep it verbatim instead of silently substituting
// the DefaultConfig grace, and must not touch the explicitly given TTL.
func TestConfig_ExplicitZeroGracePeriodIsPreserved(t *testing.T) {
	s := NewStoreWithConfig(nil, nil, Config{GracePeriodCents: 0, CacheTTL: time.Second})
	if s.cfg.GracePeriodCents != 0 {
		t.Fatalf("explicit zero grace replaced: grace=%d, want 0", s.cfg.GracePeriodCents)
	}
	if s.cfg.CacheTTL != time.Second {
		t.Fatalf("explicit cache TTL replaced: ttl=%v, want 1s", s.cfg.CacheTTL)
	}
}

// TestConfig_DefaultConstructorUnchanged: the compatible explicit default
// constructor still yields the historical defaults (-$1.00 grace, 30s TTL).
func TestConfig_DefaultConstructorUnchanged(t *testing.T) {
	def := DefaultConfig()
	if def.GracePeriodCents != -100 {
		t.Fatalf("DefaultConfig grace changed: %d, want -100", def.GracePeriodCents)
	}
	if def.CacheTTL != 30*time.Second {
		t.Fatalf("DefaultConfig TTL changed: %v, want 30s", def.CacheTTL)
	}

	s := NewStore(nil, nil)
	if s.cfg.GracePeriodCents != def.GracePeriodCents || s.cfg.CacheTTL != def.CacheTTL {
		t.Fatalf("NewStore config drifted from DefaultConfig: grace=%d, ttl=%v",
			s.cfg.GracePeriodCents, s.cfg.CacheTTL)
	}
}

// TestConfig_NegativeGracePeriodPreserved: negative grace (intentional
// overdraft) keeps working; an unset TTL falls back to the default per field.
func TestConfig_NegativeGracePeriodPreserved(t *testing.T) {
	s := NewStoreWithConfig(nil, nil, Config{GracePeriodCents: -500})
	if s.cfg.GracePeriodCents != -500 {
		t.Fatalf("negative grace replaced: grace=%d, want -500", s.cfg.GracePeriodCents)
	}
	if s.cfg.CacheTTL != 30*time.Second {
		t.Fatalf("unset TTL should default per field: ttl=%v, want 30s", s.cfg.CacheTTL)
	}
}

// TestCheckBalance_ExhaustedGraceFloorRejectsAdmission: admission must not
// allow positive consumption when the effective balance is exhausted. At
// balance == floor every positive deduction breaches the floor, so the floor
// itself must be rejected (inclusive); floor+1 cent is the last admissible
// balance; floor−1 cent is rejected outright.
func TestCheckBalance_ExhaustedGraceFloorRejectsAdmission(t *testing.T) {
	const floor = int64(-100)
	cases := []struct {
		name      string
		balance   int64
		wantAdmit bool
	}{
		{"floor_minus_1", floor - 1, false},
		{"floor", floor, false},
		{"floor_plus_1", floor + 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Non-nil pool so the balance cache path is reachable; the seeded
			// cache entry means the DB is never touched (audit-fixture style).
			s := NewStoreWithConfig(&pgxpool.Pool{}, nil, Config{GracePeriodCents: floor, CacheTTL: time.Minute})
			s.mu.Lock()
			s.cache["org-a"] = &cachedBalance{walletCents: tc.balance, updated: time.Now()}
			s.mu.Unlock()

			bal, err := s.CheckBalance(context.Background(), "org-a")
			if tc.wantAdmit {
				if err != nil {
					t.Fatalf("balance %d must be admissible, got err=%v", tc.balance, err)
				}
				if bal == nil || bal.BalanceCents != tc.balance {
					t.Fatalf("admitted balance mismatch: %+v, want %d", bal, tc.balance)
				}
				return
			}
			if !errors.Is(err, ErrInsufficientCredits) {
				t.Fatalf("balance %d must stop admission with ErrInsufficientCredits, got err=%v", tc.balance, err)
			}
		})
	}
}

// TestCheckBalance_DBErrorIsNotAdmittedBalance: a real database failure must
// surface as an error (503 upstream), never as an admissible zero balance and
// never as insufficient credits.
func TestCheckBalance_DBErrorIsNotAdmittedBalance(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)

	// Force a genuine DB error: the wallet table does not exist past this drop.
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS org_credits`); err != nil {
		t.Fatalf("drop org_credits: %v", err)
	}
	defer teardownTestTables(ctx, t, pool)

	s := NewStore(pool, nil)
	bal, err := s.CheckBalance(ctx, "org-db-error")
	if err == nil {
		t.Fatal("DB error must not look like an admissible balance")
	}
	if IsInsufficientCredits(err) {
		t.Fatalf("DB error must not be reported as insufficient credits: %v", err)
	}
	if bal != nil {
		t.Fatalf("DB error must not return a balance object: %+v", bal)
	}
}

// TestCheckBalance_CancelledContextIsNotAdmittedBalance: a cancelled context
// must fail closed — no balance, no admission.
func TestCheckBalance_CancelledContextIsNotAdmittedBalance(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	if _, err := pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents) VALUES ('org-cancelled', 1000)`); err != nil {
		t.Fatalf("seed wallet: %v", err)
	}

	s := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -100, CacheTTL: time.Minute})

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	bal, err := s.CheckBalance(cancelled, "org-cancelled")
	if err == nil {
		t.Fatal("cancelled context must not look like an admissible balance")
	}
	if IsInsufficientCredits(err) {
		t.Fatalf("cancelled context must not be reported as insufficient credits: %v", err)
	}
	if bal != nil {
		t.Fatalf("cancelled context must not return a balance object: %+v", bal)
	}
}
