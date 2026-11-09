package budget

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// TestDefaultReservationConfig_MatchesADR14 pins the §14 parameter defaults.
func TestDefaultReservationConfig_MatchesADR14(t *testing.T) {
	cfg := DefaultReservationConfig()
	require.Equal(t, 10*time.Minute, cfg.TTL, "ReservationTTL / lease (D13)")
	require.Equal(t, 5*time.Second, cfg.EscrowHorizon, "EscrowHorizon (D10)")
	require.InDelta(t, 0.1, cfg.EscrowMaxFraction, 1e-9, "EscrowMaxFraction (D10)")
	require.Equal(t, int64(20), cfg.EscrowLowWaterBounds, "EscrowLowWater (D10)")
	require.Equal(t, int64(-100), cfg.DefaultGraceFloorCents, "global grace default -$1.00")
}

// TestReservationConfigWithDefaults covers the fallbacks for unset/invalid
// config fields. DefaultGraceFloorCents has no implicit substitution:
// explicit 0 is a valid "no overdraft" floor (AF-01) — callers wanting the
// standard grace start from DefaultReservationConfig().
func TestReservationConfigWithDefaults(t *testing.T) {
	cfg := ReservationConfig{}.withDefaults()
	require.Equal(t, DefaultReservationConfig().TTL, cfg.TTL)
	require.Equal(t, DefaultReservationConfig().EscrowHorizon, cfg.EscrowHorizon)
	require.InDelta(t, DefaultReservationConfig().EscrowMaxFraction, cfg.EscrowMaxFraction, 1e-9)
	require.Equal(t, DefaultReservationConfig().EscrowLowWaterBounds, cfg.EscrowLowWaterBounds)
	require.Equal(t, int64(0), cfg.DefaultGraceFloorCents, "explicit 0 floor stays 0 (no overdraft)")

	custom := ReservationConfig{
		TTL:                    time.Second,
		EscrowHorizon:          2 * time.Second,
		EscrowMaxFraction:      0.5,
		EscrowLowWaterBounds:   3,
		DefaultGraceFloorCents: -5,
	}.withDefaults()
	require.Equal(t, time.Second, custom.TTL)
	require.Equal(t, int64(3), custom.EscrowLowWaterBounds)

	outOfRange := ReservationConfig{EscrowMaxFraction: 1.5}.withDefaults()
	require.InDelta(t, 0.1, outOfRange.EscrowMaxFraction, 1e-9, ">1 fraction is invalid, falls back")
}

// TestGrantDelta_ClampRule exercises the pure §5.3 sizing rule:
// Δ = clamp(rate × EscrowHorizon, min = bound, max = EscrowMaxFraction × free),
// with the near-exhaustion case issuing exactly one bound.
func TestGrantDelta_ClampRule(t *testing.T) {
	cfg := DefaultReservationConfig()

	tests := []struct {
		name      string
		free      int64
		bound     int64
		rate      int64
		avgBound  int64
		unlimited bool
		want      int64
		refuse    bool
	}{
		{
			// rate×5s = 2M, but 0.1×free = 100k caps it.
			name: "fraction cap beats rate sizing",
			free: 1_000_000, bound: 1_000, rate: 400_000, // µUSD/s ($0.40/s)
			want: 100_000,
		},
		{
			// rate×5s = 2M, 0.1×free = 1M caps it.
			name: "fraction cap at larger free",
			free: 10_000_000, bound: 1_000, rate: 400_000, // µUSD/s ($0.40/s)
			want: 1_000_000,
		},
		{
			name: "bound is the floor of the clamp",
			free: 10_000_000, bound: 500_000, rate: 1,
			want: 500_000,
		},
		{
			name: "low water: exactly one bound",
			free: 150_000, bound: 100_000, rate: 4_000_000, // µUSD/s
			want: 100_000, // free 150k < 20×100k low water
		},
		{
			name: "low water uses avg bound when supplied",
			free: 150_000, bound: 50_000, avgBound: 100_000, rate: 4_000_000, // µUSD/s
			want: 50_000, // 150k < 20×100k → exactly the request bound
		},
		{
			name: "rate zero degenerates to per-request reserve",
			free: 10_000_000, bound: 7_000, rate: 0,
			want: 7_000,
		},
		{
			name: "zero bound (price 0): no reservation, exhaustion check only",
			free: 10_000_000, bound: 0, rate: 0,
			want: 0,
		},
		{
			name: "bound exactly equals free: admitted",
			free: 100, bound: 100, rate: 0,
			want: 100,
		},
		{
			name: "bound above free: refused",
			free: 99, bound: 100, rate: 0,
			refuse: true,
		},
		{
			name: "negative free: refused",
			free: -1, bound: 0, rate: 0,
			refuse: true,
		},
		{
			name: "unlimited (advisory scope): no fraction or free cap",
			free: math.MaxInt64, bound: 1_000, rate: 400_000, // µUSD/s ($0.40/s) unlimited: true,
			want: 2_000_000,
		},
		{
			name: "rate overflow clamps to the fraction cap",
			free: 10_000_000, bound: 1, rate: math.MaxInt64,
			want: 1_000_000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := grantDelta(tc.free, tc.bound, tc.rate, tc.avgBound, tc.unlimited, cfg)
			if tc.refuse {
				require.Error(t, err)
				if tc.free < 0 {
					require.Contains(t, err.Error(), "negative")
				} else {
					require.Contains(t, err.Error(), "exceeds free capacity")
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			// The admission invariant: reserved + Δ ≤ L always holds.
			require.LessOrEqual(t, got, tc.free)
		})
	}
}

// TestGrantDelta_InvariantUnderFractionPinch: when the fraction cap dips
// below the bound (spiky request vs small free), the bound still wins while
// it fits — the clamp conflict resolves toward the request, never below it.
func TestGrantDelta_InvariantUnderFractionPinch(t *testing.T) {
	cfg := DefaultReservationConfig()
	free := int64(250_000)
	bound := int64(40_000) // 0.1×free = 25k < bound; low water 20×bound > free
	got, err := grantDelta(free, bound, 1_000_000, 0, false, cfg)
	require.NoError(t, err)
	require.Equal(t, bound, got, "near-exhaustion grants exactly bound")
	require.LessOrEqual(t, got, free)
}

// TestSortGrantRequests pins the canonical lock order wallet → team_month →
// agent_day → session (ADR §5.3) and the duplicate/unknown rejection.
func TestSortGrantRequests(t *testing.T) {
	in := []GrantRequest{
		{Scope: ScopeSession, Key: "s"},
		{Scope: ScopeWallet, Key: "w"},
		{Scope: ScopeAgentDay, Key: "a"},
		{Scope: ScopeTeamMonth, Key: "t"},
	}
	ordered, err := sortGrantRequests(in)
	require.NoError(t, err)
	require.Equal(t, []ScopeKind{ScopeWallet, ScopeTeamMonth, ScopeAgentDay, ScopeSession},
		[]ScopeKind{ordered[0].Scope, ordered[1].Scope, ordered[2].Scope, ordered[3].Scope})

	// Input slice must not be mutated.
	require.Equal(t, ScopeSession, in[0].Scope)

	_, err = sortGrantRequests([]GrantRequest{{Scope: ScopeWallet, Key: "w"}, {Scope: ScopeWallet, Key: "w"}})
	require.ErrorIs(t, err, ErrInvalidRequest)

	_, err = sortGrantRequests([]GrantRequest{{Scope: ScopeKind("bogus"), Key: "x"}})
	require.ErrorIs(t, err, ErrInvalidRequest)

	_, err = sortGrantRequests([]GrantRequest{{Scope: ScopeWallet, Key: ""}})
	require.ErrorIs(t, err, ErrInvalidRequest)
}

// TestCentsToMicro covers the signed overflow-checked conversion used for
// wallet capacities and grace floors.
func TestCentsToMicro(t *testing.T) {
	got, err := centsToMicro(-100)
	require.NoError(t, err)
	require.Equal(t, int64(-1_000_000), got)

	got, err = centsToMicro(10_000)
	require.NoError(t, err)
	require.Equal(t, int64(100_000_000), got)

	_, err = centsToMicro(math.MaxInt64/10_000 + 1)
	require.Error(t, err)
	_, err = centsToMicro(-math.MaxInt64/10_000 - 1)
	require.Error(t, err)
}

// canned FOR SHARE allowance answer plus recorded execs whose row counts
// can be forced to zero (the §7.1.3 underflow predicate).
type settleTxStub struct {
	pgx.Tx // nil-embedded: only Exec/QueryRow are exercised

	execs     []string
	allowance func(query string) ([]any, error)
	zeroRows  bool // the next reserve decrement matches zero rows
}

func (s *settleTxStub) Exec(_ context.Context, query string, _ ...any) (pgconn.CommandTag, error) {
	s.execs = append(s.execs, query)
	if s.zeroRows && strings.Contains(query, "reserved_micro_usd = reserved_micro_usd -") {
		s.zeroRows = false
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (s *settleTxStub) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	if s.allowance != nil {
		vals, err := s.allowance(query)
		return &recRow{data: vals, err: err}
	}
	return &recRow{err: errors.New("settleTxStub: unexpected QueryRow")}
}

func (s *settleTxStub) tookAdvisoryLock() bool {
	for _, q := range s.execs {
		if strings.Contains(q, "pg_advisory_xact_lock") {
			return true
		}
	}
	return false
}

func (s *settleTxStub) decremented(scope string) bool {
	for _, q := range s.execs {
		if strings.Contains(q, "reserved_micro_usd = reserved_micro_usd -") && strings.Contains(q, scope) {
			return true
		}
	}
	return false
}

// TestSettleDecrementTx applies the §5.3 Settle step 2 in the caller's
// transaction: a live allowance's scope reserve drops by min(actual, bound)
// under the per-org advisory lock; released/gone allowances and zero
// amounts are ledger-only; underflow is the explicit ErrReservedUnderflow.
func TestSettleDecrementTx(t *testing.T) {
	liveWallet := func(query string) ([]any, error) {
		if strings.Contains(query, "FROM budget_allowances") {
			return []any{string(ScopeWallet), "org-1", "", string(AllowanceActive)}, nil
		}
		return nil, errors.New("unexpected QueryRow")
	}

	t.Run("live allowance releases min(actual, bound)", func(t *testing.T) {
		tx := &settleTxStub{allowance: liveWallet}
		applied, err := SettleDecrementTx(context.Background(), tx, "org-1", 7, 15_000, 12_000)
		require.NoError(t, err)
		require.Equal(t, int64(12_000), applied, "bound wins over a higher actual")
		require.True(t, tx.tookAdvisoryLock(), "serialized with the other money writers")
		require.True(t, tx.decremented("org_credits"))

		tx = &settleTxStub{allowance: liveWallet}
		applied, err = SettleDecrementTx(context.Background(), tx, "org-1", 7, 5_000, 12_000)
		require.NoError(t, err)
		require.Equal(t, int64(5_000), applied, "a smaller actual wins over the bound")
	})

	t.Run("negative inputs clamp to a zero, ledger-only settle", func(t *testing.T) {
		tx := &settleTxStub{allowance: liveWallet}
		applied, err := SettleDecrementTx(context.Background(), tx, "org-1", 7, -5, -3)
		require.NoError(t, err)
		require.Zero(t, applied)
		require.False(t, tx.decremented("org_credits"), "nothing leaves the scope row")
	})

	t.Run("released allowance is ledger-only", func(t *testing.T) {
		tx := &settleTxStub{allowance: func(query string) ([]any, error) {
			return []any{string(ScopeWallet), "org-1", "", string(AllowanceReleased)}, nil
		}}
		applied, err := SettleDecrementTx(context.Background(), tx, "org-1", 7, 12_000, 12_000)
		require.NoError(t, err)
		require.Zero(t, applied, "§5.3: the reserve is never decremented twice")
		require.False(t, tx.decremented("org_credits"))
	})

	t.Run("vanished allowance is ledger-only", func(t *testing.T) {
		tx := &settleTxStub{allowance: func(query string) ([]any, error) {
			return nil, pgx.ErrNoRows
		}}
		applied, err := SettleDecrementTx(context.Background(), tx, "org-1", 7, 12_000, 12_000)
		require.NoError(t, err)
		require.Zero(t, applied)
		require.False(t, tx.decremented("org_credits"))
	})

	t.Run("reserve underflow is the explicit invariant error", func(t *testing.T) {
		tx := &settleTxStub{allowance: liveWallet, zeroRows: true}
		_, err := SettleDecrementTx(context.Background(), tx, "org-1", 7, 12_000, 12_000)
		require.ErrorIs(t, err, ErrReservedUnderflow, "§7.1.3 drift must surface, never clamp")
	})

	t.Run("no linkage is a no-op", func(t *testing.T) {
		tx := &settleTxStub{}
		applied, err := SettleDecrementTx(context.Background(), tx, "org-1", 0, 12_000, 12_000)
		require.NoError(t, err)
		require.Zero(t, applied)
		require.Empty(t, tx.execs)
	})

	t.Run("empty org is rejected", func(t *testing.T) {
		tx := &settleTxStub{allowance: liveWallet}
		_, err := SettleDecrementTx(context.Background(), tx, "", 7, 12_000, 12_000)
		require.ErrorIs(t, err, ErrInvalidRequest)
	})
}

// TestCloseAbandonedReplicaValidation: the permanently-lost-replica
// verdict (N06-P05) refuses an empty replica id before touching any
// database resource — a nil store config is enough to prove the guard
// runs first.
func TestCloseAbandonedReplicaValidation(t *testing.T) {
	store := NewReservationStoreWithConfig(nil, nil, DefaultReservationConfig())
	_, err := store.CloseAbandonedReplica(context.Background(), "", ReservationSafetyWindow)
	require.ErrorIs(t, err, ErrInvalidRequest)
}
