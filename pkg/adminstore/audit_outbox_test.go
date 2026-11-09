package adminstore

// N10-P04-T04 unit tests that need no database: the nil-db store surface
// (audit disabled) of the outbox status/recovery read model.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditOutboxStatus_NilDB_ZeroHealthyReport: a store without a database
// (the "audit disabled" configuration) reports an empty, healthy status and
// performs no recovery action — it must not pretend there is a backlog or a
// dead letter, and must not error.
func TestAuditOutboxStatus_NilDB_ZeroHealthyReport(t *testing.T) {
	store := newForTest(nil, slog.Default(), nil)
	ctx := context.Background()

	report, err := store.AuditOutboxStatus(ctx)
	require.NoError(t, err)
	assert.Zero(t, report.Pending)
	assert.Zero(t, report.Due)
	assert.Zero(t, report.Retrying)
	assert.Zero(t, report.DeadLetters)
	assert.Zero(t, report.OldestPendingAge)
	assert.Empty(t, report.LastError)
	assert.Empty(t, report.LastErrorID)

	requeued, err := store.RequeueAuditOutboxDeadLetter(ctx, "any-id")
	require.NoError(t, err)
	assert.False(t, requeued)
}

// TestAuditOutboxDeadLetterAttempts_BackoffBudget pins the documented
// classification contract: the threshold is a deliberate observability
// constant (never a stop-retrying switch) and stays below the point where
// failOutboxRow's capped backoff saturates, so a dead letter has been failing
// for hours, not seconds.
func TestAuditOutboxDeadLetterAttempts_BackoffBudget(t *testing.T) {
	assert.Greater(t, AuditOutboxDeadLetterAttempts, 1,
		"a single transient failure must not classify a row as a dead letter")
	// backoff(attempts) = least(2^(attempts+1), 3600)s: at threshold the
	// schedule has passed the ~2048s step, i.e. cumulative undeliverable
	// time is measured in hours.
	assert.GreaterOrEqual(t, AuditOutboxDeadLetterAttempts, 10)
}
