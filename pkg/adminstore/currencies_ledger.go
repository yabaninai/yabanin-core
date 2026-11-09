package adminstore

// GET /api/credits/ledger: the wallet
// ledger view. Raw ledger listing (topups, usage settlements, the beta
// starter grant) plus a best-effort consistency signal: the sum of all
// ledger deltas compared against the wallet balance. Drift is a
// reconciliation signal for operators, not a silent rewrite.
//
// The starter grant is surfaced by its invoice_ref marker
// (credits.StarterGrantReason) so the UI can render "beta grant: $50
// claimed" without string-matching in the frontend.

import (
	"context"
	"fmt"
	"time"

	"github.com/reireirei/yabanin/pkg/credits"
)

// Ledger limits.
const (
	LedgerDefaultLimit = 50
	LedgerMaxLimit     = 100
)

// LedgerWallet is the wallet block; nil wallet = org has no wallet row yet.
type LedgerWallet struct {
	BalanceCents int64  `json:"balance_cents"`
	UpdatedAt    string `json:"updated_at"`
}

// LedgerStarterGrant reports the configured beta grant and whether this org
// has claimed it (invoice_ref = credits.StarterGrantReason on a topup row).
type LedgerStarterGrant struct {
	// ConfiguredCents is the currently configured grant amount
	// (credits.StarterGrantCents — the env knob, not the org's history).
	ConfiguredCents int64 `json:"configured_cents"`
	// ClaimedCents is what the org actually received (0 when unclaimed).
	ClaimedCents int64 `json:"claimed_cents"`
	// Claimed reports whether the grant row exists.
	Claimed bool `json:"claimed"`
}

// LedgerTransaction is one credit_transactions row.
type LedgerTransaction struct {
	ID           int64   `json:"id"`
	Type         string  `json:"type"` // topup | usage
	AmountCents  int64   `json:"amount_cents"`
	BalanceAfter int64   `json:"balance_after"`
	RequestID    *string `json:"request_id"`
	InvoiceRef   *string `json:"invoice_ref"`
	CreatedAt    string  `json:"created_at"`
	// AmountMicroUSD is the exact µUSD attribution on usage rows (nil on
	// topups).
	AmountMicroUSD *int64 `json:"amount_micro_usd"`
}

// CreditsLedgerView is the GET /api/credits/ledger payload.
type CreditsLedgerView struct {
	OrgID          string              `json:"org_id"`
	Wallet         *LedgerWallet       `json:"wallet"`
	StarterGrant   *LedgerStarterGrant `json:"starter_grant"`
	Transactions   []LedgerTransaction `json:"transactions"`
	LedgerSumCents int64               `json:"ledger_sum_cents"`
	// TransactionCount is the org's total ledger row count (not the page).
	TransactionCount int64 `json:"transaction_count"`
	// LedgerConsistent: ledger sum == wallet balance. nil when no wallet
	// exists (nothing to reconcile against).
	LedgerConsistent *bool  `json:"ledger_consistent"`
	CreditsScale     string `json:"credits_scale"`
}

// ClampLedgerLimit applies the 1..100 page bounds (0/negative → default).
func ClampLedgerLimit(limit int) int {
	if limit <= 0 {
		return LedgerDefaultLimit
	}
	if limit > LedgerMaxLimit {
		return LedgerMaxLimit
	}
	return limit
}

// GetCreditsLedgerView builds the ledger view for one org.
func (s *Store) GetCreditsLedgerView(ctx context.Context, orgID string, limit int) (*CreditsLedgerView, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if orgID == "" {
		return nil, fmt.Errorf("org id is required")
	}
	limit = ClampLedgerLimit(limit)

	out := &CreditsLedgerView{
		OrgID:        orgID,
		StarterGrant: &LedgerStarterGrant{ConfiguredCents: credits.StarterGrantCents()},
		CreditsScale: WalletUnitScale,
	}

	// Wallet.
	balanceCents, updatedAt, hasWallet, err := s.walletBalance(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("credits ledger: %w", err)
	}
	if hasWallet {
		out.Wallet = &LedgerWallet{
			BalanceCents: balanceCents,
			UpdatedAt:    updatedAt.UTC().Format(time.RFC3339),
		}
	}

	// Starter grant claim state.
	var claimedCents, claimCount int64
	err = s.db.QueryRow(ctx, `
		SELECT COALESCE(SUM(amount_cents), 0), COUNT(*)
		FROM credit_transactions
		WHERE org_id = $1 AND type = 'topup' AND invoice_ref = $2`,
		orgID, credits.StarterGrantReason).Scan(&claimedCents, &claimCount)
	if err != nil {
		return nil, fmt.Errorf("credits ledger: starter grant: %w", err)
	}
	out.StarterGrant.Claimed = claimCount > 0
	out.StarterGrant.ClaimedCents = claimedCents

	// Ledger page (newest first; id breaks created_at ties deterministically).
	rows, err := s.db.Query(ctx, `
		SELECT id, type, amount_cents, balance_after, request_id, invoice_ref, created_at, amount_micro_usd
		FROM credit_transactions
		WHERE org_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2`,
		orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("credits ledger: transactions: %w", err)
	}
	defer rows.Close()
	out.Transactions = []LedgerTransaction{}
	for rows.Next() {
		var tx LedgerTransaction
		var createdAt time.Time
		if err := rows.Scan(&tx.ID, &tx.Type, &tx.AmountCents, &tx.BalanceAfter,
			&tx.RequestID, &tx.InvoiceRef, &createdAt, &tx.AmountMicroUSD); err != nil {
			return nil, fmt.Errorf("credits ledger: transaction scan: %w", err)
		}
		tx.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		out.Transactions = append(out.Transactions, tx)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("credits ledger: transactions rows: %w", err)
	}

	// Full-ledger sum + count for the consistency signal.
	var ledgerSum int64
	var ledgerCount int64
	err = s.db.QueryRow(ctx, `
		SELECT COALESCE(SUM(amount_cents), 0), COUNT(*)
		FROM credit_transactions WHERE org_id = $1`,
		orgID).Scan(&ledgerSum, &ledgerCount)
	if err != nil {
		return nil, fmt.Errorf("credits ledger: sum: %w", err)
	}
	out.LedgerSumCents = ledgerSum
	out.TransactionCount = ledgerCount
	if hasWallet {
		consistent := ledgerSum == balanceCents
		out.LedgerConsistent = &consistent
	}
	return out, nil
}
