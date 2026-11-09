package consumer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
)

// ErrNoChargeTarget means a settlement intent exists but the mandatory
// charge cannot even be attempted (billing not configured / org missing).
// This is a diagnostic condition for the settlement worker — never a
// silent skip.
var ErrNoChargeTarget = errors.New("settlement charge target is not configured")

// Deductor executes the resale credit deduction for the settlement worker.
// Since AF-06 it has NO best-effort semantics and NO in-memory dedup:
//
//   - ProcessDeduction returns an error on any failed charge attempt; the
//     caller (settlement worker) classifies it as retryable or terminal.
//     There is deliberately no seenIDs map: a failed attempt is retryable
//     by definition, and an unbounded in-memory marker must never decide
//     money (the audited defect — a transient DB error permanently ate the
//     charge while the marker said "done").
//   - Idempotency is the DB contract in credits.Store: the usage ledger row
//     is unique per (org, request_id), so a retry after a committed charge
//     is a no-op — exactly one charge per settlement identity, across
//     restarts and replicas.
//
// Since AF-05 the amount is exact integer micro-USD, validated at the event
// boundary, applied via credits.Store.DeductMicro: whole cents land on the
// cents ledger, the sub-cent residue accumulates durably on the wallet.
type Deductor struct {
	store  *credits.Store
	logger *slog.Logger
}

// NewDeductor creates a Deductor with the given credit store and logger.
func NewDeductor(store *credits.Store, logger *slog.Logger) *Deductor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Deductor{
		store:  store,
		logger: logger.With("component", "deductor"),
	}
}

// ProcessDeduction performs one credit-deduction attempt for a completed
// request and returns an error on failure (retryable or not — the caller
// decides). amount is the exact validated charge (event-boundary quote
// resolution: positive resale_cost_usd preferred over positive
// estimated_cost_usd); state distinguishes a genuine zero quote from an
// unknown price — both are legitimately nothing-to-charge and settle as a
// no-op with a distinct skip metric, while any store failure is returned,
// never swallowed.
func (d *Deductor) ProcessDeduction(ctx context.Context, orgID, modelUsed, requestID string, amount money.MicroUSD, state money.QuoteState, tokensIn, tokensOut int64) error {
	if d == nil || d.store == nil || orgID == "" {
		return fmt.Errorf("%w: store=%v org=%q", ErrNoChargeTarget, d != nil && d.store != nil, orgID)
	}

	switch state {
	case money.QuotePositive:
		// chargeable — fall through to the deduction below.
	case money.QuoteZero:
		metrics.CreditDeductionSkippedTotal.WithLabelValues("zero_quote").Inc()
		d.logger.Warn("credit deduction skipped — zero-cost event",
			slog.String("org_id", orgID),
			slog.String("request_id", requestID),
			slog.String("model", modelUsed),
		)
		return nil
	default: // money.QuoteUnknown
		metrics.CreditDeductionSkippedTotal.WithLabelValues("unknown_quote").Inc()
		d.logger.Warn("credit deduction skipped — unknown price/usage (distinct from zero)",
			slog.String("org_id", orgID),
			slog.String("request_id", requestID),
			slog.String("model", modelUsed),
			slog.String("quote_state", state.String()),
		)
		return nil
	}

	if requestID == "" || amount <= 0 {
		// An intent that claims a positive quote but carries no request id or
		// no positive amount violates the contract — a poison job for the
		// settlement worker, never a transient condition.
		return fmt.Errorf("%w: invalid resale deduction charge: request_id=%q amount=%d", ErrPoisonJob, requestID, int64(amount))
	}

	err := d.store.DeductMicro(ctx, orgID, amount, requestID, map[string]interface{}{
		"model":            modelUsed,
		"tokens":           tokensIn + tokensOut,
		"amount_micro_usd": int64(amount),
	})
	if err != nil {
		// Observability at the deduction layer: the disposition (retry vs
		// terminal debt) belongs to the settlement worker, but the failed
		// charge attempt must be visible here too.
		if credits.IsInsufficientCredits(err) {
			d.logger.Warn("credit deduction blocked — insufficient balance",
				slog.String("org_id", orgID),
				slog.String("request_id", requestID),
				slog.Int64("amount_micro_usd", int64(amount)),
			)
		} else if credits.IsNoWallet(err) {
			d.logger.Warn("credit deduction skipped — no wallet",
				slog.String("org_id", orgID),
				slog.String("request_id", requestID),
				slog.Int64("amount_micro_usd", int64(amount)),
			)
		} else {
			d.logger.Warn("credit deduction failed (settlement worker will retry)",
				slog.String("org_id", orgID),
				slog.String("request_id", requestID),
				slog.String("error", err.Error()),
			)
		}
		return fmt.Errorf("credit deduction failed: %w", err)
	}

	d.logger.Info("credit deducted",
		slog.String("org_id", orgID),
		slog.String("request_id", requestID),
		slog.Int64("amount_micro_usd", int64(amount)),
		slog.Int64("compat_cents", amount.Cents()),
	)
	return nil
}
