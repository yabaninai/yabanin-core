package adminstore

// The credits ledger view under the
// mockDB. Teeth:
//
//	no wallet → wallet null + ledger_consistent null (nothing to reconcile
//	against), but the ledger still renders;
//	ledger drift is surfaced honestly (ledger_consistent false), never
//	laundered into a corrected balance;
//	the starter grant is claimed iff a topup row carries the
//	StarterGrantReason invoice_ref, with the claimed amount from the ledger;
//	page limits clamp 1..100 with a 50 default; newest first.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ledgerFixtures carries the ledger aggregates the queries return.
type ledgerFixtures struct {
	hasWallet   bool
	balance     int64
	updated     time.Time
	grantCents  int64
	grantCount  int64
	ledgerSum   int64
	ledgerCount int64
	txRows      [][]interface{}
}

func newLedgerStore(t *testing.T, fx ledgerFixtures) *Store {
	t.Helper()
	rowFor := func(sql string) pgx.Row {
		switch {
		case strings.Contains(sql, "org_credits"):
			if !fx.hasWallet {
				return &mockPGXRow{err: pgx.ErrNoRows}
			}
			return &mockPGXRow{data: [][]interface{}{{fx.balance, fx.updated}}}
		case strings.Contains(sql, "invoice_ref"):
			return &mockPGXRow{data: [][]interface{}{{fx.grantCents, fx.grantCount}}}
		case strings.Contains(sql, "credit_transactions"):
			return &mockPGXRow{data: [][]interface{}{{fx.ledgerSum, fx.ledgerCount}}}
		default:
			return &mockPGXRow{err: errors.New("ledger test: unexpected QueryRow: " + sql)}
		}
	}
	return newForTest(&mockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			return rowFor(sql)
		},
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			if strings.Contains(sql, "ORDER BY created_at DESC") {
				return &mockPGXRows{data: fx.txRows}, nil
			}
			return nil, errors.New("ledger test: unexpected Query: " + sql)
		},
	}, newTestLogger(), nil)
}

func txRow(id int64, typ string, amount, balanceAfter int64, reqID, invoice interface{}, at time.Time, micro interface{}) []interface{} {
	// Nullable columns pass raw values (string/int64) or nil — the mock
	// Scan cases for **string/**int64 read raw values.
	return []interface{}{id, typ, amount, balanceAfter, reqID, invoice, at, micro}
}

// TestCreditsLedger_WalletAndConsistency — consistent and drifted ledgers.
func TestCreditsLedger_WalletAndConsistency(t *testing.T) {
	t.Run("consistent ledger", func(t *testing.T) {
		store := newLedgerStore(t, ledgerFixtures{
			hasWallet: true, balance: 4000, updated: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC),
			grantCents: 5000, grantCount: 1,
			ledgerSum: 4000, ledgerCount: 3,
		})
		view, err := store.GetCreditsLedgerView(context.Background(), capsOrgID, 0)
		require.NoError(t, err)
		require.NotNil(t, view.Wallet)
		assert.Equal(t, int64(4000), view.Wallet.BalanceCents)
		require.NotNil(t, view.LedgerConsistent)
		assert.True(t, *view.LedgerConsistent)
		assert.Equal(t, int64(4000), view.LedgerSumCents)
		assert.Equal(t, int64(3), view.TransactionCount)
		require.NotNil(t, view.StarterGrant)
		assert.True(t, view.StarterGrant.Claimed)
		assert.Equal(t, int64(5000), view.StarterGrant.ClaimedCents)
		assert.Equal(t, credits.StarterGrantCents(), view.StarterGrant.ConfiguredCents)
		assert.Equal(t, WalletUnitScale, view.CreditsScale)
		assert.Empty(t, view.Transactions, "empty page renders as [] not null")
	})
	t.Run("drift is surfaced, not hidden", func(t *testing.T) {
		store := newLedgerStore(t, ledgerFixtures{
			hasWallet: true, balance: 4000, updated: time.Now(),
			grantCents: 5000, grantCount: 1,
			ledgerSum: 3900, ledgerCount: 3, // $1.00 unaccounted drift
		})
		view, err := store.GetCreditsLedgerView(context.Background(), capsOrgID, 50)
		require.NoError(t, err)
		require.NotNil(t, view.LedgerConsistent)
		assert.False(t, *view.LedgerConsistent, "ledger sum != balance must read as inconsistent")
		assert.Equal(t, int64(4000), view.Wallet.BalanceCents, "the balance is never rewritten to the ledger sum")
	})
	t.Run("no wallet still renders the ledger", func(t *testing.T) {
		store := newLedgerStore(t, ledgerFixtures{
			hasWallet:  false,
			grantCents: 0, grantCount: 0,
			ledgerSum: 0, ledgerCount: 0,
		})
		view, err := store.GetCreditsLedgerView(context.Background(), capsOrgID, 50)
		require.NoError(t, err)
		assert.Nil(t, view.Wallet)
		assert.Nil(t, view.LedgerConsistent, "nothing to reconcile against")
		assert.False(t, view.StarterGrant.Claimed)
		assert.Equal(t, int64(0), view.StarterGrant.ClaimedCents)
	})
}

// TestCreditsLedger_TransactionsPage — newest-first rows with nullable
// request_id/invoice_ref/micro attribution.
func TestCreditsLedger_TransactionsPage(t *testing.T) {
	reqID := "req-777"
	micro := int64(-1234)
	invoice := "beta-starter-grant"
	rows := [][]interface{}{
		txRow(3, "usage", -1234, 3766, reqID, nil, time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC), micro),
		txRow(2, "topup", 5000, 5000, nil, invoice, time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC), nil),
	}
	store := newLedgerStore(t, ledgerFixtures{
		hasWallet: true, balance: 3766, updated: time.Now(),
		grantCents: 5000, grantCount: 1,
		ledgerSum: 3766, ledgerCount: 2,
		txRows: rows,
	})
	view, err := store.GetCreditsLedgerView(context.Background(), capsOrgID, 50)
	require.NoError(t, err)
	require.Len(t, view.Transactions, 2)

	first := view.Transactions[0]
	assert.Equal(t, int64(3), first.ID)
	assert.Equal(t, "usage", first.Type)
	assert.Equal(t, int64(-1234), first.AmountCents, "usage rows are negative")
	assert.Equal(t, int64(3766), first.BalanceAfter)
	require.NotNil(t, first.RequestID)
	assert.Equal(t, "req-777", *first.RequestID)
	assert.Nil(t, first.InvoiceRef)
	require.NotNil(t, first.AmountMicroUSD)
	assert.Equal(t, int64(-1234), *first.AmountMicroUSD)
	assert.Equal(t, "2026-11-02T09:00:00Z", first.CreatedAt)

	second := view.Transactions[1]
	assert.Equal(t, "topup", second.Type)
	assert.Nil(t, second.RequestID)
	require.NotNil(t, second.InvoiceRef)
	assert.Equal(t, credits.StarterGrantReason, *second.InvoiceRef)
	assert.Nil(t, second.AmountMicroUSD)
}

// TestCreditsLedger_ClampLimits — 0/negative → 50, >100 → 100, in-range kept.
func TestCreditsLedger_ClampLimits(t *testing.T) {
	assert.Equal(t, 50, ClampLedgerLimit(0))
	assert.Equal(t, 50, ClampLedgerLimit(-5))
	assert.Equal(t, 1, ClampLedgerLimit(1))
	assert.Equal(t, 77, ClampLedgerLimit(77))
	assert.Equal(t, 100, ClampLedgerLimit(120))
}

// TestCreditsLedger_Guards — nil DB and empty org refuse.
func TestCreditsLedger_Guards(t *testing.T) {
	nilStore := newForTest(nil, newTestLogger(), nil)
	_, err := nilStore.GetCreditsLedgerView(context.Background(), capsOrgID, 50)
	require.Error(t, err)
	_, err = newLedgerStore(t, ledgerFixtures{}).GetCreditsLedgerView(context.Background(), "", 50)
	require.Error(t, err)
}
