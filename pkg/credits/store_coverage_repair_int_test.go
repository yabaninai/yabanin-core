package credits

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/require"
)

// These tests pin the block coverage critical-go requires in pkg/credits:
// the no-DB wallet read path, the caller-mapped zero-balance view, the
// retry sleep honoring context cancellation, and the pre-0028 insert
// error wrapping.

func TestCheckBalanceWithoutDBKeepsZeroBalanceView(t *testing.T) {
	store := NewStore(nil, slog.Default())
	bal, err := store.CheckBalance(context.Background(), "credits-nil-db-org")
	require.NoError(t, err)
	require.NotNil(t, bal)
	require.Equal(t, "credits-nil-db-org", bal.OrgID)
}

func TestDeductMicroRetrySleepHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	const org, request = "credits-retry-cancel", "credits-retry-cancel-request"
	seedWallet(ctx, t, pool, org, 100)
	installCreditInsertSerializationFailure(t, ctx, pool, 1)

	// Cancel from the retry log handler: the Warn fires after the backoff
	// delay is drawn and immediately before the select, so the cancellation
	// deterministically lands inside the sleep window instead of racing a
	// randomized jitter duration.
	handler := &cancelOnRetryLog{Handler: slog.Default().Handler(), cancelFn: cancel}
	store := NewStore(pool, slog.New(handler))
	err := store.DeductMicro(ctx, org, money.MicroUSD(250000), request, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, handler.fired(), "retry warning must have fired")
}

// cancelOnRetryLog cancels the deduction context the first time the store
// logs the serialization-retry warning, pinning the cancellation inside the
// backoff select window. With must return the same handler: the store wraps
// its logger via log.With(...), and the embedded default handler would
// otherwise take over and Handle would never fire.
type cancelOnRetryLog struct {
	slog.Handler
	cancelFn func()
	firedA   atomic.Bool
}

func (h *cancelOnRetryLog) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *cancelOnRetryLog) WithGroup(string) slog.Handler { return h }

func (h *cancelOnRetryLog) fired() bool { return h.firedA.Load() }

func (h *cancelOnRetryLog) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "deduct serialization conflict, retrying" && h.firedA.CompareAndSwap(false, true) {
		h.cancelFn()
	}
	return h.Handler.Handle(ctx, r)
}

func TestInsertUsageTransactionRollbackWrapsExecFailure(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx))

	store := NewStore(pool, slog.Default())
	err = store.insertUsageTransaction(ctx, tx, "credits-tx-rollback-org", "credits-tx-rollback-req", "", 5, -5, money.MicroUSD(50000), []byte("{}"), false)
	require.Error(t, err)
	require.ErrorContains(t, err, "deduct insert transaction")
}
