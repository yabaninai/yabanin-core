package credits

// N06-P04-T10 independent invariant verification of the settlement surface
// (contract: artifacts/internal-delivery-program/N06-P04/contract.md). The one-operation
// guarantee is probed adversarially where the plain compatibility corpus does
// not look: rights (a request identity binds to exactly one org even when
// two orgs race it), resource limits (a charge at the top of the
// representable range fails closed without wrapping, and a cancelled caller
// leaves no partial state), data (wallet and ledger stay reconciled through
// every refusal) and negative scenarios (a funds refusal never burns the
// identity, so the priced event still settles exactly once).

import (
	"context"
	"math"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Rights: the usage-identity unique index is global by contract — a request
// identity belongs to exactly one org. The per-org advisory locks cannot
// order two orgs racing the same identity (different lock keys), so the
// index itself decides: exactly one org settles, the loser's insert fails
// with the 23505 the consumer classifies, and the losing wallet keeps every
// cent — no shared charge, no partial wallet write, no silent no-op.
func TestSettlementIdentityConflictCrossOrgRace(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupSettlementStand(ctx, t, pool)

	orgA, orgB := "t10-race-a", "t10-race-b"
	seedWallet(ctx, t, pool, orgA, 0)
	seedWallet(ctx, t, pool, orgB, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})
	reqID := "req-t10-race"
	charge := money.MicroUSD(7000)

	start := make(chan struct{})
	var mu sync.Mutex
	errs := map[string]error{}
	var wg sync.WaitGroup
	for _, org := range []string{orgA, orgB} {
		wg.Add(1)
		go func(org string) {
			defer wg.Done()
			<-start
			err := store.DeductMicro(ctx, org, charge, reqID, nil)
			mu.Lock()
			errs[org] = err
			mu.Unlock()
		}(org)
	}
	close(start)
	wg.Wait()

	var winners, losers []string
	for _, org := range []string{orgA, orgB} {
		if errs[org] == nil {
			winners = append(winners, org)
			continue
		}
		var pgErr *pgconn.PgError
		require.ErrorAs(t, errs[org], &pgErr,
			"%s: the losing org is refused by the identity index, not by a crash: %v", org, errs[org])
		require.Equal(t, "23505", pgErr.Code, "%s: refusal is the unique violation", org)
		losers = append(losers, org)
	}
	require.Len(t, winners, 1, "exactly one org settles the shared identity")
	require.Len(t, losers, 1, "the other org is explicitly refused")

	winnerOrg, loserOrg := winners[0], losers[0]
	count, microSum := usageRowsFor(ctx, t, pool, winnerOrg, reqID)
	assert.Equal(t, int64(1), count, "the winner settled exactly one operation")
	assert.Equal(t, -int64(charge), microSum)
	balanceCents, remainder := walletRow(ctx, t, pool, winnerOrg)
	assert.Equal(t, int64(0), balanceCents)
	assert.Equal(t, int64(7000), remainder)
	requireReconciled(ctx, t, pool, winnerOrg)

	count, microSum = usageRowsFor(ctx, t, pool, loserOrg, reqID)
	assert.Equal(t, int64(0), count, "the loser charged nothing")
	assert.Equal(t, int64(0), microSum)
	balanceCents, remainder = walletRow(ctx, t, pool, loserOrg)
	assert.Equal(t, int64(0), balanceCents, "the losing wallet keeps every cent")
	assert.Equal(t, int64(0), remainder)
	requireReconciled(ctx, t, pool, loserOrg)
}

// Resource limits: a charge at the top of the representable range fails
// closed at both configuration boundaries on a funded wallet — the legacy
// whole-cents entry refuses out-of-range cents at the money gate, the exact
// µUSD entry refuses an unpayable amount at the wallet floor — and neither
// refusal wraps a value, writes a ledger row or burns the identity: the
// priced settlement that follows lands exactly once, and a replay of the
// settled identity stays a no-op whatever amount it carries.
func TestSettlementHugeChargeFailsClosed_IdentityStaysFree(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupSettlementStand(ctx, t, pool)

	orgID := "t10-huge"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: 0})
	reqID := "req-t10-huge"
	require.NoError(t, store.TopUp(ctx, orgID, 500, "inv-t10-huge"))

	require.ErrorIs(t, store.Deduct(ctx, orgID, math.MaxInt64, reqID, nil), money.ErrRange,
		"the legacy configuration refuses out-of-range cents at the money gate")
	require.ErrorIs(t, store.DeductMicro(ctx, orgID, money.MicroUSD(math.MaxInt64), reqID, nil),
		ErrInsufficientCredits,
		"the exact configuration refuses an unpayable amount at the wallet floor")

	ledgerCents, ledgerMicro, nullMicro := ledgerTotals(ctx, t, pool, orgID)
	assert.Equal(t, int64(500), ledgerCents, "refusals never write ledger rows (only the top-up stands)")
	assert.Equal(t, int64(500_0000), ledgerMicro)
	assert.Equal(t, int64(0), nullMicro)
	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(500), balanceCents, "no wrap, no partial write")
	assert.Equal(t, int64(0), remainder)

	priced := money.MicroUSD(7000)
	require.NoError(t, store.DeductMicro(ctx, orgID, priced, reqID, nil),
		"the real priced event settles after the refused huge charges")
	count, microSum := usageRowsFor(ctx, t, pool, orgID, reqID)
	assert.Equal(t, int64(1), count)
	assert.Equal(t, -int64(priced), microSum)
	requireReconciled(ctx, t, pool, orgID)

	// A huge replay of the settled identity is the ordinary no-op: the
	// one-operation contract answers the identity, not the amount.
	require.NoError(t, store.DeductMicro(ctx, orgID, money.MicroUSD(math.MaxInt64), reqID, nil))
	count, microSum = usageRowsFor(ctx, t, pool, orgID, reqID)
	assert.Equal(t, int64(1), count, "a huge replay never charges twice")
	assert.Equal(t, -int64(priced), microSum)
	balanceCents, remainder = walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(500), balanceCents)
	assert.Equal(t, int64(7000), remainder)
	requireReconciled(ctx, t, pool, orgID)
}

// Resource limits: a caller that gives up mid-settlement cannot produce a
// half-applied charge. A cancelled context fails the deduction with the
// cancellation itself — never reported as success, never misclassified as a
// balance answer — the wallet and ledger stay untouched, and the identity
// stays free for the real priced event, which then settles exactly once.
func TestSettlementCancelledContextLeavesNoPartialState(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupSettlementStand(ctx, t, pool)

	orgID := "t10-cancelled"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})
	reqID := "req-t10-cancelled"

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	err := store.DeductMicro(cancelled, orgID, money.MicroUSD(7000), reqID, nil)
	require.ErrorIs(t, err, context.Canceled, "the cancellation surfaces, never a fake success")
	require.NotErrorIs(t, err, ErrInsufficientCredits, "a cancelled settlement is not a balance answer")

	ledgerCents, ledgerMicro, nullMicro := ledgerTotals(ctx, t, pool, orgID)
	assert.Equal(t, int64(0), ledgerCents, "no partial ledger row")
	assert.Equal(t, int64(0), ledgerMicro)
	assert.Equal(t, int64(0), nullMicro)
	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(0), balanceCents)
	assert.Equal(t, int64(0), remainder)

	priced := money.MicroUSD(7000)
	require.NoError(t, store.DeductMicro(ctx, orgID, priced, reqID, nil),
		"the identity was never consumed by the cancelled attempt")
	count, microSum := usageRowsFor(ctx, t, pool, orgID, reqID)
	assert.Equal(t, int64(1), count)
	assert.Equal(t, -int64(priced), microSum)
	requireReconciled(ctx, t, pool, orgID)
}

// Negative scenario: a cancel refused for funds (no overdraft configured)
// writes nothing and consumes nothing. After the wallet is funded, the same
// request identity settles exactly once on the first priced delivery, and
// further deliveries of that identity — from either billing configuration —
// complete nothing: the refusal never became a silent zero and never turned
// into a second charge.
func TestSettlementFundsRefusalKeepsIdentityChargeable(t *testing.T) {
	ctx := context.Background()
	pool := setupTestDB(t)
	setupSettlementStand(ctx, t, pool)

	orgID := "t10-funds"
	seedWallet(ctx, t, pool, orgID, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: 0})
	reqID := "req-t10-funds"
	prefix := money.MicroUSD(12000)

	require.ErrorIs(t, store.DeductMicro(ctx, orgID, prefix, reqID, nil), ErrInsufficientCredits)

	ledgerCents, ledgerMicro, nullMicro := ledgerTotals(ctx, t, pool, orgID)
	assert.Equal(t, int64(0), ledgerCents, "the refused cancel wrote nothing")
	assert.Equal(t, int64(0), ledgerMicro)
	assert.Equal(t, int64(0), nullMicro)
	balanceCents, remainder := walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(0), balanceCents)
	assert.Equal(t, int64(0), remainder)

	require.NoError(t, store.TopUp(ctx, orgID, 100, "inv-t10-funds"))
	require.NoError(t, store.DeductMicro(ctx, orgID, prefix, reqID, nil),
		"the same identity settles on the first funded delivery")

	count, microSum := usageRowsFor(ctx, t, pool, orgID, reqID)
	assert.Equal(t, int64(1), count)
	assert.Equal(t, -int64(prefix), microSum)

	// Late arrivals from both configurations claim nothing.
	require.NoError(t, store.DeductMicro(ctx, orgID, money.MicroUSD(45000), reqID, nil))
	require.NoError(t, store.Deduct(ctx, orgID, 3, reqID, nil))
	count, microSum = usageRowsFor(ctx, t, pool, orgID, reqID)
	assert.Equal(t, int64(1), count, "a repeated event never charges twice")
	assert.Equal(t, -int64(prefix), microSum)
	balanceCents, remainder = walletRow(ctx, t, pool, orgID)
	assert.Equal(t, int64(99), balanceCents)
	assert.Equal(t, int64(2000), remainder)
	requireReconciled(ctx, t, pool, orgID)
}
