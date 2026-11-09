package adminstore

// The budgets caps status under the
// mockDB. Teeth:
//
//	a cap whose state cannot be compared is unknown (missing carbon limit,
//	unmeasurable carbon usage, missing wallet) — never ok, never 0;
//	the credits floor comparison is inverted (balance ≤ floor → over,
//	overdraft above floor → near);
//	fixed cap order [usd_monthly_budget, carbon_monthly_grams, credits_floor];
//	80% near threshold; org errors propagate.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capsFixtures carries the raw aggregates the caps queries return.
type capsFixtures struct {
	budgetCents int64 // org_caps.monthly_budget_cents override (nil = default)
	budgetSet   bool
	monthSpend  float64 // OrgMonthSpendCents source sum (USD)
	carbonGrams float64
	carbonUnv   float64
	unmodeled   int64
	unverified  int64
	usageRows   int64
	carbonLimit *float64 // injected carbon limit
	floorCents  *int64   // org override floor (nil = platform default)
	hasWallet   bool
	balance     int64
}

func f64ptr(v float64) *float64 { return &v }
func i64ptr(v int64) *int64     { return &v }

// capsOrgID is a valid organization UUID (GetOrgBudgetSettings UUID-parses
// the id before querying).
const capsOrgID = "11111111-1111-1111-1111-111111111111"

func newCapsStore(t *testing.T, fx capsFixtures) *Store {
	t.Helper()
	rowFor := func(sql string) pgx.Row {
		switch {
		case strings.Contains(sql, "reservations_mode"):
			// GetOrgBudgetSettings: org_id, grace_floor_cents, mode, cap.
			// **int64 destinations scan raw int64 values (or nil).
			var floorOverride interface{}
			if fx.floorCents != nil {
				floorOverride = *fx.floorCents
			}
			return &mockPGXRow{data: [][]interface{}{{capsOrgID, floorOverride, "off, ignored", nil}}}
		case strings.Contains(sql, "org_credits"):
			if !fx.hasWallet {
				return &mockPGXRow{err: pgx.ErrNoRows}
			}
			return &mockPGXRow{data: [][]interface{}{{fx.balance, time.Now().UTC()}}}
		case strings.Contains(sql, "carbon_factors"):
			return &mockPGXRow{data: [][]interface{}{{fx.carbonGrams, fx.carbonUnv, fx.unmodeled, fx.unverified, fx.usageRows}}}
		case strings.Contains(sql, "SUM(cost_in_usd), 0) FROM request_logs"):
			return &mockPGXRow{data: [][]interface{}{{fx.monthSpend}}}
		case strings.Contains(sql, "IS NOT NULL"):
			// EffectiveOrgCaps: exists, rpm, tpm, budget, itpm, otpm, ktpm.
			// **int64 destinations scan raw int64 values (or nil).
			var budgetOverride interface{}
			if fx.budgetSet {
				budgetOverride = fx.budgetCents
			}
			return &mockPGXRow{data: [][]interface{}{{true, nil, nil, budgetOverride, nil, nil, nil}}}
		default:
			return &mockPGXRow{err: errors.New("caps test: unexpected QueryRow: " + sql)}
		}
	}
	return newForTest(&mockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			return rowFor(sql)
		},
	}, newTestLogger(), nil)
}

func runCapsStatus(t *testing.T, fx capsFixtures) *BudgetCapsStatus {
	t.Helper()
	store := newCapsStore(t, fx)
	status, err := store.GetBudgetCapsStatus(context.Background(), capsOrgID, fx.carbonLimit)
	require.NoError(t, err)
	require.Len(t, status.Caps, 3, "fixed caps: usd budget, carbon, credits floor")
	require.Equal(t, CapIDUSDMonthlyBudget, status.Caps[0].ID)
	require.Equal(t, CapIDCarbonMonthly, status.Caps[1].ID)
	require.Equal(t, CapIDCreditsFloor, status.Caps[2].ID)
	for i, cap := range status.Caps {
		require.NoErrorf(t, cap.Used.Validate(), "cap %d used-side must satisfy the measure vocabulary", i)
	}
	require.Equal(t, WalletUnitScale, status.CreditsScale)
	return status
}

// TestBudgetCaps_USDMonthlyStatuses — over / near / ok at the 100% and 80%
// thresholds of the effective (default) budget.
func TestBudgetCaps_USDMonthlyStatuses(t *testing.T) {
	defaultLimit := int64(10000) // $100
	t.Run("over at limit", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{budgetSet: true, budgetCents: defaultLimit, monthSpend: 100.0, usageRows: 1})
		cap := status.Caps[0]
		requireAmount(t, cap.Used, 100)
		require.NotNil(t, cap.Limit)
		assert.InDelta(t, 100, *cap.Limit, 1e-9)
		assert.Equal(t, CapStatusOver, cap.Status)
		assert.Equal(t, FidelityExact, cap.Used.Fidelity, "enforcement accounting is exact")
		assert.Equal(t, ProvenanceOrgCaps, cap.Used.Provenance)
	})
	t.Run("near at 80%", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{budgetSet: true, budgetCents: defaultLimit, monthSpend: 80.0, usageRows: 1})
		assert.Equal(t, CapStatusNear, status.Caps[0].Status)
	})
	t.Run("just below near", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{budgetSet: true, budgetCents: defaultLimit, monthSpend: 79.99, usageRows: 1})
		assert.Equal(t, CapStatusOK, status.Caps[0].Status)
	})
	t.Run("default budget applies without override", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{monthSpend: 0, usageRows: 1})
		require.NotNil(t, status.Caps[0].Limit)
		assert.InDelta(t, float64(DefaultOrgCapsMonthlyBudgetCents)/100, *status.Caps[0].Limit, 1e-9)
		assert.Equal(t, CapStatusOK, status.Caps[0].Status)
	})
}

// TestBudgetCaps_CarbonMatrix — the carbon cap is unknown unless BOTH the
// injected limit and a measurable usage exist.
func TestBudgetCaps_CarbonMatrix(t *testing.T) {
	t.Run("no limit configured is unknown", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{carbonGrams: 500, usageRows: 10})
		cap := status.Caps[1]
		assert.Nil(t, cap.Limit)
		assert.Equal(t, CapStatusUnknown, cap.Status)
		assert.Contains(t, cap.Note, "no carbon budget configured")
		requireAmount(t, cap.Used, 500, "usage still measured with the limit absent")
	})
	t.Run("limit present and measurable compares", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{carbonGrams: 900, usageRows: 10, carbonLimit: f64ptr(1000)})
		cap := status.Caps[1]
		require.NotNil(t, cap.Limit)
		assert.InDelta(t, 1000, *cap.Limit, 1e-9)
		assert.Equal(t, CapStatusNear, cap.Status, "90% of limit is near")
		assert.Equal(t, FidelityExact, cap.Used.Fidelity)
	})
	t.Run("limit present but usage unmeasurable is unknown", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{usageRows: 10, unmodeled: 10, carbonLimit: f64ptr(1000)})
		cap := status.Caps[1]
		assert.Nil(t, cap.Used.Amount, "unmodeled fleet must not read as zero grams")
		assert.Equal(t, CapStatusUnknown, cap.Status, "cannot compare unknown usage to a limit")
		assert.NotEmpty(t, cap.Note)
	})
	t.Run("unverified factors degrade the used mark", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{carbonGrams: 100, carbonUnv: 40, unverified: 3, usageRows: 10, carbonLimit: f64ptr(1000)})
		assert.Equal(t, FidelityEstimated, status.Caps[1].Used.Fidelity)
		assert.Equal(t, CapStatusOK, status.Caps[1].Status)
	})
}

// TestBudgetCaps_CreditsFloorMatrix — inverted comparison semantics.
func TestBudgetCaps_CreditsFloorMatrix(t *testing.T) {
	t.Run("balance at floor is over", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{usageRows: 1, hasWallet: true, balance: -100, floorCents: i64ptr(-100)})
		cap := status.Caps[2]
		requireAmount(t, cap.Used, -100)
		assert.Equal(t, CapStatusOver, cap.Status, "balance == floor is over")
	})
	t.Run("overdraft above floor is near", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{usageRows: 1, hasWallet: true, balance: -50, floorCents: i64ptr(-100)})
		assert.Equal(t, CapStatusNear, status.Caps[2].Status)
	})
	t.Run("positive balance is ok", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{usageRows: 1, hasWallet: true, balance: 2500})
		assert.Equal(t, CapStatusOK, status.Caps[2].Status)
		requireAmount(t, status.Caps[2].Used, 2500)
		assert.Equal(t, FidelityExact, status.Caps[2].Used.Fidelity)
	})
	t.Run("platform default floor when no override", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{usageRows: 1, hasWallet: true, balance: 0})
		cap := status.Caps[2]
		require.NotNil(t, cap.Limit)
		assert.InDelta(t, -1.0, *cap.Limit, 1e-9, "platform default floor is -$1.00")
		assert.Equal(t, CapStatusOK, cap.Status, "zero balance is above the default floor")
	})
	t.Run("no wallet is unknown, not ok", func(t *testing.T) {
		status := runCapsStatus(t, capsFixtures{usageRows: 1, hasWallet: false})
		cap := status.Caps[2]
		assert.Nil(t, cap.Used.Amount, "no wallet is unknown, never a zero balance")
		assert.Equal(t, FidelityUnknown, cap.Used.Fidelity)
		assert.Equal(t, CapStatusUnknown, cap.Status)
		assert.Contains(t, cap.Note, "no wallet")
	})
}

// TestBudgetCaps_Guards — nil DB and empty org refuse.
func TestBudgetCaps_Guards(t *testing.T) {
	nilStore := newForTest(nil, newTestLogger(), nil)
	_, err := nilStore.GetBudgetCapsStatus(context.Background(), "org-1", nil)
	require.Error(t, err)
	_, err = newCapsStore(t, capsFixtures{}).GetBudgetCapsStatus(context.Background(), "", nil)
	require.Error(t, err)
}
