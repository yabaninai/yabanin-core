package budget

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The batched wallet settlement must be the per-job DeductMicro semantics
// as a pure function (ADR-0001 §5.5: batch ≡ sequential). The reference
// below mirrors the deductOnceMicro SQL expression by expression.
func deductMicroReference(balanceCents, remainderMicro, amountMicro, floorCents int64) (newBalance, newRemainder, chargeCents int64, applied bool) {
	dedCents := amountMicro / int64(money.MicroPerCent)
	dedRem := amountMicro % int64(money.MicroPerCent)
	chargeCents = dedCents + (remainderMicro+dedRem)/int64(money.MicroPerCent)
	newRemainder = (remainderMicro + dedRem) % int64(money.MicroPerCent)
	newBalance = balanceCents - chargeCents
	applied = newBalance > floorCents || (newBalance == floorCents && newRemainder == 0)
	return newBalance, newRemainder, chargeCents, applied
}

// Property: for random wallets, remainders, charges and floors, the batch's
// sequential carry step agrees with the per-job reference everywhere the
// subtraction is representable.
func TestCarryWalletCharge_MatchesDeductMicroSemantics(t *testing.T) {
	rng := rand.New(rand.NewSource(20261002)) //nolint:gosec // property fixture, not crypto
	for i := 0; i < 1000; i++ {
		balance := rng.Int63n(500_00) - 50_00 // −$50 … $450
		remainder := rng.Int63n(int64(money.MicroPerCent))
		amount := rng.Int63n(300_0000) + 1 // 1 µUSD … $3
		floor := -rng.Int63n(100_000)      // 0 … −$10

		gotBalance, gotRemainder, gotCharge, gotApplied := carryWalletCharge(balance, remainder, amount, floor)
		wantBalance, wantRemainder, wantCharge, wantApplied := deductMicroReference(balance, remainder, amount, floor)

		assert.Equal(t, wantApplied, gotApplied, "applied: balance=%d rem=%d amount=%d floor=%d", balance, remainder, amount, floor)
		if !gotApplied {
			// A blocked job leaves the wallet untouched.
			assert.Equal(t, balance, gotBalance)
			assert.Equal(t, remainder, gotRemainder)
			continue
		}
		assert.Equal(t, wantBalance, gotBalance, "balance: balance=%d rem=%d amount=%d floor=%d", balance, remainder, amount, floor)
		assert.Equal(t, wantRemainder, gotRemainder, "remainder: balance=%d rem=%d amount=%d floor=%d", balance, remainder, amount, floor)
		assert.Equal(t, wantCharge, gotCharge)
	}
}

// The exact floor landing is the documented AF-01 boundary: a charge that
// lands exactly on the floor with a zero remainder applies; one micro more
// does not.
func TestCarryWalletCharge_FloorLandingBoundary(t *testing.T) {
	// Balance 100¢, floor −100¢: a 200¢ charge lands exactly on the floor
	// with remainder 0 — allowed.
	newBalance, newRemainder, _, applied := carryWalletCharge(100, 0, 2_000_000, -100)
	assert.True(t, applied)
	assert.Equal(t, int64(-100), newBalance)
	assert.Equal(t, int64(0), newRemainder)

	// A sub-cent residue on the exact-floor landing makes it overdraw —
	// rejected, wallet untouched.
	_, _, _, applied = carryWalletCharge(100, 5_000, 2_000_000, -100)
	assert.False(t, applied)

	// One micro beyond the exact landing crosses the floor — rejected.
	_, _, _, applied = carryWalletCharge(100, 0, 2_000_001, -100)
	assert.False(t, applied)
}

// A blocked charge must leave the running state untouched so later batch
// jobs apply against the wallet exactly as sequential executions would.
func TestCarryWalletCharge_BlockedLeavesStateUntouched(t *testing.T) {
	balance, remainder := int64(-100), int64(9_999)
	gotBalance, gotRemainder, _, applied := carryWalletCharge(balance, remainder, 50_000, -100)
	assert.False(t, applied)
	assert.Equal(t, balance, gotBalance)
	assert.Equal(t, remainder, gotRemainder)
}

// min(actual, bound) with negative clamps — the §5.3 settle amount.
func TestSettleDecrementMicro(t *testing.T) {
	assert.Equal(t, int64(300), settleDecrementMicro(300, 500), "actual below bound → actual")
	assert.Equal(t, int64(500), settleDecrementMicro(700, 500), "overshoot clamps to bound")
	assert.Equal(t, int64(0), settleDecrementMicro(0, 500))
	assert.Equal(t, int64(0), settleDecrementMicro(-5, 500), "negative actual clamps to zero")
	assert.Equal(t, int64(0), settleDecrementMicro(300, -1), "negative bound clamps to zero")
}

// The batch charge kinds map onto the reserve scopes (§4.1) implicitly
// through the allowance rows; the constants must stay the wire values the
// consumer writes.
func TestSettleKindWireValues(t *testing.T) {
	require.Equal(t, "resale_deduction", SettleKindResale)
	require.Equal(t, "team_spend", SettleKindTeam)
	require.Equal(t, "agent_spend", SettleKindAgent)
	require.Equal(t, "session_spend", SettleKindSession)
	require.Equal(t, "settle_decrement_micro_usd", ReconcileSettleKey)
}

// A batch that lists the same job id twice is a caller-contract violation:
// dispositions are keyed by job id, so the duplicate would collapse two
// settle attempts into one disposition (an applied entry overwritten by its
// replay's Applied=false would hide the decrement). The batch must refuse
// the input before opening any transaction — the caller's per-job fallback
// then executes each job exactly once, so a repeated event can never charge
// twice (N06-P04 D1).
type beginProbeDB struct{ beginErr error }

func (b beginProbeDB) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, b.beginErr
}

func TestSettleOrgBatch_RejectsDuplicateJobIDsBeforeTx(t *testing.T) {
	entries := []SettleEntry{
		{JobID: 7, Kind: SettleKindResale, RequestID: "r-1", Amount: 100_000},
		{JobID: 8, Kind: SettleKindResale, RequestID: "r-2", Amount: 100_000},
		{JobID: 7, Kind: SettleKindResale, RequestID: "r-1", Amount: 100_000},
	}
	_, err := SettleOrgBatch(context.Background(), beginProbeDB{beginErr: fmt.Errorf("begin must never be reached")}, "org-1", 0, entries, BatchSpenders{})
	require.ErrorContains(t, err, "duplicate job id 7")
}
