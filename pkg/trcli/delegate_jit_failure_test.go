package trcli

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/auditlog"
	"github.com/reireirei/yabanin/pkg/jitaccess"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The decision (pgxpool) and the audit append (database/sql) ride separate
// connections, so an audit failure after the terminal transition is a real
// window. The pinned posture is fail-loud: the CLI reports the gap, never a
// success, and never fakes or silently reconciles the missing row.

// deadAuditWriter returns an audit writer bound to a connection that can
// never establish (loopback port 1 refuses): a deterministic audit-write
// failure with the real writer logic, no mock.
func deadAuditWriter(t *testing.T) *auditlog.Writer {
	t.Helper()
	db, err := sql.Open("pgx", "postgres://127.0.0.1:1/none?connect_timeout=2")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return auditlog.NewWriter(db)
}

// TestIntJITCLI_Failure_AuditGapAfterApprovalIsLoud: the terminal transition
// commits, then the audit append fails — the operator gets a loud error, the
// approval stays applied and visible, and no APPROVE row exists (the gap is
// surfaced, not papered over).
func TestIntJITCLI_Failure_AuditGapAfterApprovalIsLoud(t *testing.T) {
	pool := testdb.Postgres(t)
	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	ctx := context.Background()

	admins := seedJITCLIAdmins(t, pool, true, true, 2)
	requester, approver := admins[0], admins[1]

	rec, err := st.mgr.Request(ctx, requester.ID, "root", "audit gap probe")
	require.NoError(t, err)

	st.audit = deadAuditWriter(t)
	err = runJITDecision(ctx, &strings.Builder{}, st, jitDecisionOpts{
		decision: "approve", requestID: rec.ID, approver: approver.ID,
		digest: rec.Binds.ParamsDigest, ip: "127.0.0.1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit write failed")

	after, err := st.mgr.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, jitaccess.StatusApproved, after.Status,
		"the terminal transition is already committed — the gap must be visible, not hidden")
	assert.True(t, st.mgr.IsActive(ctx, requester.ID, "root"))

	_, ok := jitAuditDetails(t, st, auditlog.ActionApprove, approver.ID, rec.ID)
	assert.False(t, ok, "no APPROVE row may exist — the CLI reported the gap instead of faking one")
}

// TestIntJITCLI_Failure_RefusalJournalFailureJoins: when both the decision is
// refused and the refusal journaling fails, the operator sees both facts and
// the request stays pending (partial/unknown never counts as success).
func TestIntJITCLI_Failure_RefusalJournalFailureJoins(t *testing.T) {
	pool := testdb.Postgres(t)
	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	ctx := context.Background()

	admins := seedJITCLIAdmins(t, pool, true, true, 2)
	requester, approver := admins[0], admins[1]

	rec, err := st.mgr.Request(ctx, requester.ID, "root", "joined failure probe")
	require.NoError(t, err)

	st.audit = deadAuditWriter(t)
	err = runJITDecision(ctx, &strings.Builder{}, st, jitDecisionOpts{
		decision: "approve", requestID: rec.ID, approver: approver.ID,
		digest: strings.Repeat("0", 64), ip: "127.0.0.1",
	})
	require.ErrorIs(t, err, jitaccess.ErrDigestMismatch)
	assert.Contains(t, err.Error(), "audit", "the journaling failure must ride along, not vanish")

	cur, err := st.mgr.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, jitaccess.StatusPending, cur.Status)
}
