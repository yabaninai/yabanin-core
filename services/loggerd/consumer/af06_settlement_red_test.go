package consumer

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/require"
)

// Ported from the audit packet consumer_review_test.go
// (TestReview_FailedDeductionMustNotBeMarkedComplete, reproductions.log F01),
// rewritten to the AF-06 contract after the fix. The pre-AF-06 Deductor set
// its in-memory seenIDs marker BEFORE the store call, so a transient DB
// outage permanently ate the charge (void semantics, unbounded map — RED:
// "failed deduction is marked complete, preventing retry").
//
// AF-06 contract pinned here:
//   - a failed store call surfaces as an error (retryable, never swallowed);
//   - there is no completion marker: EVERY call re-attempts the charge and
//     DB-level idempotency (credits.Store unique (org, request, 'usage'))
//     decides — a committed charge stays one charge, a failed one retries.
func TestProcessDeduction_StoreErrorIsRetryableNotCompleted(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, silentLogger()), silentLogger())
	ctx := context.Background()

	charge := money.MustFromCents(1)

	// First attempt: the nil-DB store fails; the error must be visible.
	err := d.ProcessDeduction(ctx, "org-a", "model", "req-a", charge, money.QuotePositive, 1, 1)
	require.Error(t, err, "a failed charge must not be reported as success")
	require.NotErrorIs(t, err, ErrNoChargeTarget, "a store failure is a real attempt failure, not a missing target")

	// Retry after the outage: the attempt is re-executed (it fails again on
	// this nil-DB stand, proving no completion marker suppressed it).
	err = d.ProcessDeduction(ctx, "org-a", "model", "req-a", charge, money.QuotePositive, 1, 1)
	require.Error(t, err, "retry must re-attempt the charge, not silently skip")
}

// A missing charge target (no store / no org) is a diagnostic condition,
// surfaced as ErrNoChargeTarget — never a silent success.
func TestProcessDeduction_NoChargeTargetIsDiagnostic(t *testing.T) {
	d := NewDeductor(nil, silentLogger())
	err := d.ProcessDeduction(context.Background(), "org-a", "model", "req-a", money.MustFromCents(1), money.QuotePositive, 1, 1)
	require.ErrorIs(t, err, ErrNoChargeTarget)

	err = d.ProcessDeduction(context.Background(), "", "model", "req-a", money.MustFromCents(1), money.QuotePositive, 1, 1)
	require.ErrorIs(t, err, ErrNoChargeTarget)
}

// Zero and unknown quotes are legitimately nothing-to-charge: they settle as
// no-ops (nil) with distinct skip metrics — this is the AF-05 contract kept.
func TestProcessDeduction_ZeroAndUnknownQuotesAreNoOps(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, silentLogger()), silentLogger())
	ctx := context.Background()

	require.NoError(t, d.ProcessDeduction(ctx, "org-z", "model", "req-zero", 0, money.QuoteZero, 1, 1))
	require.NoError(t, d.ProcessDeduction(ctx, "org-z", "model", "req-unknown", 0, money.QuoteUnknown, 1, 1))
}

// An invalid charge (no request id / non-positive amount with a positive
// quote) must not silently pass: it is an intent-contract violation.
func TestProcessDeduction_InvalidPositiveChargeRejected(t *testing.T) {
	d := NewDeductor(credits.NewStore(nil, silentLogger()), silentLogger())
	ctx := context.Background()

	require.Error(t, d.ProcessDeduction(ctx, "org-a", "model", "", money.MustFromCents(1), money.QuotePositive, 1, 1))
	require.Error(t, d.ProcessDeduction(ctx, "org-a", "model", "req-a", 0, money.QuotePositive, 1, 1))
}
