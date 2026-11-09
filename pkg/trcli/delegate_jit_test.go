package trcli

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/auditlog"
	"github.com/reireirei/yabanin/pkg/jitaccess"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Postgres-backed acceptance flows below use the disposable stand.

func TestDelegateCLIJitSurfaceWiring(t *testing.T) {
	out, err := executeDelegate(t, t.TempDir(), "jit", "--help")
	require.NoError(t, err)
	for _, want := range []string{"request", "show", "approve", "deny", "list", "expire"} {
		assert.Contains(t, out, want, "jit subcommand %s must be registered", want)
	}
}

func TestDelegateCLIJitDecisionFlagsRequired(t *testing.T) {
	// Missing --digest must fail at the flag layer, before any connection.
	_, err := executeDelegate(t, t.TempDir(), "jit", "approve", "some-id", "--pg-uri", "postgres://x", "--approver", "a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "digest")
}

// jitCLIAdmin is one seeded admin_users row for the CLI scenarios.
type jitCLIAdmin struct {
	ID    string
	Email string
}

var jitSeedMu sync.Mutex

func seedJITCLIAdmins(t *testing.T, pool *pgxpool.Pool, root, active bool, n int) []jitCLIAdmin {
	t.Helper()
	jitSeedMu.Lock()
	defer jitSeedMu.Unlock()
	admins := make([]jitCLIAdmin, 0, n)
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		a := jitCLIAdmin{ID: uuid.NewString(), Email: "jit-cli-" + uuid.NewString() + "@test"}
		_, err := pool.Exec(context.Background(),
			`INSERT INTO admin_users (id, email, password_hash, is_root, active) VALUES ($1, $2, 'x', $3, $4)`,
			a.ID, a.Email, root, active)
		require.NoError(t, err)
		admins = append(admins, a)
		ids = append(ids, a.ID)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM admin_audit_logs WHERE admin_id = ANY($1) AND resource = $2`, ids, auditlog.ResourceJITAccess)
		_, _ = pool.Exec(ctx, `DELETE FROM jit_access WHERE admin_id = ANY($1) OR approver_id = ANY($1)`, ids)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_users WHERE id = ANY($1)`, ids)
	})
	return admins
}

// openJITCLIStores builds the operator surface over the disposable stand.
func openJITCLIStores(t *testing.T, pool *pgxpool.Pool) (*jitStores, func()) {
	t.Helper()
	st, closeStores, err := openJITStores(context.Background(), pool.Config().ConnString())
	require.NoError(t, err)
	return st, closeStores
}

// jitAuditDetails fetches the newest audit row for one decision.
func jitAuditDetails(t *testing.T, st *jitStores, action, adminID, requestID string) (string, bool) {
	t.Helper()
	var details string
	err := st.pool.QueryRow(context.Background(), `
		SELECT details FROM admin_audit_logs
		WHERE action=$1 AND resource=$2 AND admin_id=$3 AND details LIKE $4
		ORDER BY seq DESC LIMIT 1`,
		action, auditlog.ResourceJITAccess, adminID, "request="+requestID+"%").Scan(&details)
	if err != nil {
		return "", false
	}
	return details, true
}

// TestIntJITCLI_Acceptance1_WorkingFlowWithAudit: request -> approval by a
// different root operator through the operator surface -> audit APPROVE row
// carrying actor, IP and the request digest -> chain still verifies.
func TestIntJITCLI_Acceptance1_WorkingFlowWithAudit(t *testing.T) {
	pool := testdb.Postgres(t)
	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	ctx := context.Background()

	admins := seedJITCLIAdmins(t, pool, true, true, 2)
	requester, approver := admins[0], admins[1]

	var out strings.Builder
	require.NoError(t, runJITRequest(ctx, &out, st, requester.ID, "root", "break-glass fix"))

	rec, err := st.mgr.Get(ctx, func() string {
		// The printed block starts with "request <id>".
		line := strings.TrimSpace(strings.SplitN(out.String(), "\n", 2)[0])
		_, id, found := strings.Cut(line, "request ")
		require.True(t, found, "request output must name the id: %q", line)
		return strings.TrimSpace(id)
	}())
	require.NoError(t, err)
	require.Equal(t, jitaccess.StatusPending, rec.Status)

	out.Reset()
	require.NoError(t, runJITDecision(ctx, &out, st, jitDecisionOpts{
		decision: "approve", requestID: rec.ID, approver: approver.ID,
		digest: rec.Binds.ParamsDigest, adminName: "Root B", ip: "127.0.0.1",
	}))
	assert.Contains(t, out.String(), "approved: "+rec.ID)
	assert.True(t, st.mgr.IsActive(ctx, requester.ID, "root"), "elevation must be active for the TTL")

	details, ok := jitAuditDetails(t, st, auditlog.ActionApprove, approver.ID, rec.ID)
	require.True(t, ok, "audit APPROVE row must exist")
	assert.Contains(t, details, "digest="+rec.Binds.ParamsDigest)

	// D6 sweep leg: age the approval, run the surface's expire command.
	_, err = pool.Exec(ctx, `UPDATE jit_access SET expires_at = now() - interval '1 second' WHERE id = $1`, rec.ID)
	require.NoError(t, err)
	out.Reset()
	require.NoError(t, runJITExpire(ctx, &out, st))
	assert.Contains(t, out.String(), "1 request(s) flipped to expired")
	assert.False(t, st.mgr.IsActive(ctx, requester.ID, "root"))
	after, err := st.mgr.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, jitaccess.StatusExpired, after.Status)
}

// TestIntJITCLI_Acceptance2_DigestMismatch: a decision quoting a stale or
// altered digest is refused, journaled as DENY and leaves the request
// pending for the honest decision.
func TestIntJITCLI_Acceptance2_DigestMismatch(t *testing.T) {
	pool := testdb.Postgres(t)
	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	ctx := context.Background()

	admins := seedJITCLIAdmins(t, pool, true, true, 2)
	requester, approver := admins[0], admins[1]

	rec, err := st.mgr.Request(ctx, requester.ID, "root", "changed args check")
	require.NoError(t, err)

	err = runJITDecision(ctx, &strings.Builder{}, st, jitDecisionOpts{
		decision: "approve", requestID: rec.ID, approver: approver.ID,
		digest: strings.Repeat("0", 64), ip: "127.0.0.1",
	})
	require.ErrorIs(t, err, jitaccess.ErrDigestMismatch)

	details, ok := jitAuditDetails(t, st, auditlog.ActionDeny, approver.ID, rec.ID)
	require.True(t, ok, "the refused attempt must be journaled as DENY")
	assert.Contains(t, details, "reason=digest mismatch")
	assert.Contains(t, details, "digest="+rec.Binds.ParamsDigest, "the stored digest is journaled, not the quoted one")

	cur, err := st.mgr.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, jitaccess.StatusPending, cur.Status)

	// The honest decision still lands.
	require.NoError(t, runJITDecision(ctx, &strings.Builder{}, st, jitDecisionOpts{
		decision: "approve", requestID: rec.ID, approver: approver.ID,
		digest: rec.Binds.ParamsDigest, ip: "127.0.0.1",
	}))

	// Replaying the SAME approval afterwards is refused and journaled.
	err = runJITDecision(ctx, &strings.Builder{}, st, jitDecisionOpts{
		decision: "approve", requestID: rec.ID, approver: approver.ID,
		digest: rec.Binds.ParamsDigest, ip: "127.0.0.1",
	})
	require.ErrorIs(t, err, jitaccess.ErrNotPending)
	_, ok = jitAuditDetails(t, st, auditlog.ActionDeny, approver.ID, rec.ID)
	assert.True(t, ok)
}

// TestIntJITCLI_Acceptance3_SelfApproval: the requester (even a root one)
// cannot approve their own request; the refusal is journaled.
func TestIntJITCLI_Acceptance3_SelfApproval(t *testing.T) {
	pool := testdb.Postgres(t)
	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	ctx := context.Background()

	requester := seedJITCLIAdmins(t, pool, true, true, 1)[0]

	rec, err := st.mgr.Request(ctx, requester.ID, "root", "self attempt")
	require.NoError(t, err)

	err = runJITDecision(ctx, &strings.Builder{}, st, jitDecisionOpts{
		decision: "approve", requestID: rec.ID, approver: requester.ID,
		digest: rec.Binds.ParamsDigest, ip: "127.0.0.1",
	})
	require.ErrorIs(t, err, jitaccess.ErrSelfApproval)

	details, ok := jitAuditDetails(t, st, auditlog.ActionDeny, requester.ID, rec.ID)
	require.True(t, ok)
	assert.Contains(t, details, "reason=self-approval blocked")

	cur, err := st.mgr.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, jitaccess.StatusPending, cur.Status)
}

// TestIntJITCLI_DenyFlow: an explicit deny by another root operator is
// terminal and journaled with the operator's reason.
func TestIntJITCLI_DenyFlow(t *testing.T) {
	pool := testdb.Postgres(t)
	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	ctx := context.Background()

	admins := seedJITCLIAdmins(t, pool, true, true, 2)
	requester, approver := admins[0], admins[1]

	rec, err := st.mgr.Request(ctx, requester.ID, "root", "deny me")
	require.NoError(t, err)

	var out strings.Builder
	require.NoError(t, runJITDecision(ctx, &out, st, jitDecisionOpts{
		decision: "deny", requestID: rec.ID, approver: approver.ID,
		digest: rec.Binds.ParamsDigest, reason: "not justified", ip: "127.0.0.1",
	}))
	assert.Contains(t, out.String(), "denied: "+rec.ID)

	details, ok := jitAuditDetails(t, st, auditlog.ActionDeny, approver.ID, rec.ID)
	require.True(t, ok)
	assert.Contains(t, details, "reason=not justified")

	after, err := st.mgr.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, jitaccess.StatusDenied, after.Status)
	assert.False(t, st.mgr.IsActive(ctx, requester.ID, "root"))
}

// TestIntJITCLI_PendingQueueAndAuditChain: the queue lists the undecided
// request and the audit chain (including the decision rows) verifies.
func TestIntJITCLI_PendingQueueAndAuditChain(t *testing.T) {
	pool := testdb.Postgres(t)
	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	ctx := context.Background()

	admins := seedJITCLIAdmins(t, pool, true, true, 2)
	requester, approver := admins[0], admins[1]

	rec, err := st.mgr.Request(ctx, requester.ID, "root", "queue check")
	require.NoError(t, err)

	var out strings.Builder
	require.NoError(t, runJITList(ctx, &out, st))
	assert.Contains(t, out.String(), rec.ID)
	assert.Contains(t, out.String(), rec.Binds.ParamsDigest)

	require.NoError(t, runJITDecision(ctx, &strings.Builder{}, st, jitDecisionOpts{
		decision: "approve", requestID: rec.ID, approver: approver.ID,
		digest: rec.Binds.ParamsDigest, ip: "127.0.0.1",
	}))

	// D5 evidence: the whole chain — ordinary rows plus the decision rows —
	// stays tamper-evident. (The pgx stdlib driver is registered by the
	// delegate command's audit connection.)
	sqlDB, err := sql.Open("pgx", pool.Config().ConnString())
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()
	broken, err := auditlog.NewVerifier(sqlDB).Verify(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), broken, "audit chain must verify after decision writes")
}
