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

// driven through the ACTUAL operator entry point — the cobra `delegate jit`
// commands against a real Postgres stand — not the run* helpers and not
// direct helper calls. Every jitCLI invocation is a fresh CLI process
// equivalent: fresh cobra parse, fresh connection pair, full flag boundary.

// jitCLI runs one real `yb delegate jit ...` invocation against the stand.
func jitCLI(t *testing.T, pgURI string, args ...string) (string, error) {
	t.Helper()
	require.NotEmpty(t, args, "jit subcommand required")
	full := append([]string{"jit", args[0], "--pg-uri", pgURI}, args[1:]...)
	return executeDelegate(t, t.TempDir(), full...)
}

// jitParseRequest extracts the request id and digest a decision must quote
// from the `jit request` output — exactly what an operator copies.
func jitParseRequest(t *testing.T, out string) (id, digest string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if after, found := strings.CutPrefix(line, "request "); found && id == "" {
			id = strings.TrimSpace(after)
		}
		if after, found := strings.CutPrefix(line, "digest: "); found {
			digest = strings.TrimSpace(after)
		}
	}
	require.NotEmpty(t, id, "output must name the request id: %q", out)
	require.Len(t, digest, 64, "output must carry the request digest: %q", out)
	return id, digest
}

// TestIntJITCLI_E2E_Acceptance1_WorkingFlow (contract example 1): request →
// approval by a DIFFERENT root operator → elevation active (1h TTL) → audit
// APPROVE carrying the digest → sweep makes the aged approval terminally
// expired. All decision legs through the CLI surface.
func TestIntJITCLI_E2E_Acceptance1_WorkingFlow(t *testing.T) {
	pool := testdb.Postgres(t)
	uri := pool.Config().ConnString()
	ctx := context.Background()

	admins := seedJITCLIAdmins(t, pool, true, true, 2)
	requester, approver := admins[0], admins[1]

	out, err := jitCLI(t, uri, "request", "--admin", requester.ID, "--role", "root", "--reason", "break-glass fix")
	require.NoError(t, err, out)
	id, digest := jitParseRequest(t, out)

	out, err = jitCLI(t, uri, "approve", id,
		"--approver", approver.ID, "--digest", digest, "--admin-name", "Root B", "--ip", "127.0.0.1")
	require.NoError(t, err, out)
	assert.Contains(t, out, "approved: "+id)

	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	assert.True(t, st.mgr.IsActive(ctx, requester.ID, "root"), "approved elevation must be active")

	details, ok := jitAuditDetails(t, st, auditlog.ActionApprove, approver.ID, id)
	require.True(t, ok, "audit APPROVE row must exist")
	assert.Contains(t, details, "digest="+digest)

	_, err = pool.Exec(ctx, `UPDATE jit_access SET expires_at = now() - interval '1 second' WHERE id = $1`, id)
	require.NoError(t, err)
	out, err = jitCLI(t, uri, "expire")
	require.NoError(t, err, out)
	assert.Contains(t, out, "flipped to expired")
	assert.False(t, st.mgr.IsActive(ctx, requester.ID, "root"), "expired elevation must not be active")

	out, err = jitCLI(t, uri, "show", id)
	require.NoError(t, err, out)
	assert.Contains(t, out, "status: expired")
}

// TestIntJITCLI_E2E_Acceptance2_ReplayAndChangedArgs (contract example 2):
// through the same CLI boundary — an approval quoting anything but the exact
// digest is refused and journaled as DENY with the STORED digest; the honest
// decision still lands; replaying the same approval afterwards is refused
// and journaled too.
func TestIntJITCLI_E2E_Acceptance2_ReplayAndChangedArgs(t *testing.T) {
	pool := testdb.Postgres(t)
	uri := pool.Config().ConnString()

	admins := seedJITCLIAdmins(t, pool, true, true, 2)
	requester, approver := admins[0], admins[1]

	out, err := jitCLI(t, uri, "request", "--admin", requester.ID, "--role", "root", "--reason", "changed args")
	require.NoError(t, err, out)
	id, digest := jitParseRequest(t, out)

	// Changed argument: wrong digest through the real command boundary.
	_, err = jitCLI(t, uri, "approve", id, "--approver", approver.ID, "--digest", strings.Repeat("0", 64), "--ip", "127.0.0.1")
	require.ErrorIs(t, err, jitaccess.ErrDigestMismatch)

	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	denyDetails, ok := jitAuditDetails(t, st, auditlog.ActionDeny, approver.ID, id)
	require.True(t, ok, "the refused attempt must be journaled as DENY")
	assert.Contains(t, denyDetails, "reason=digest mismatch")
	assert.Contains(t, denyDetails, "digest="+digest, "the stored digest is journaled, not the quoted one")

	out, err = jitCLI(t, uri, "show", id)
	require.NoError(t, err, out)
	assert.Contains(t, out, "status: pending")

	out, err = jitCLI(t, uri, "approve", id, "--approver", approver.ID, "--digest", digest)
	require.NoError(t, err, out)

	// Replay of the SAME approval through the same boundary.
	_, err = jitCLI(t, uri, "approve", id, "--approver", approver.ID, "--digest", digest)
	require.ErrorIs(t, err, jitaccess.ErrNotPending)
	_, ok = jitAuditDetails(t, st, auditlog.ActionDeny, approver.ID, id)
	assert.True(t, ok, "the replayed approval must be journaled as DENY")

	out, err = jitCLI(t, uri, "show", id)
	require.NoError(t, err, out)
	assert.Contains(t, out, "status: approved")
}

// TestIntJITCLI_E2E_Acceptance3_SelfApprovalAndSweep (contract example 3):
// self-approval is refused through the CLI boundary; the aged pending
// request ends terminally expired under the sweep; no late decision applies.
func TestIntJITCLI_E2E_Acceptance3_SelfApprovalAndSweep(t *testing.T) {
	pool := testdb.Postgres(t)
	uri := pool.Config().ConnString()
	ctx := context.Background()

	requester := seedJITCLIAdmins(t, pool, true, true, 1)[0]

	out, err := jitCLI(t, uri, "request", "--admin", requester.ID, "--role", "root", "--reason", "self attempt")
	require.NoError(t, err, out)
	id, digest := jitParseRequest(t, out)

	_, err = jitCLI(t, uri, "approve", id, "--approver", requester.ID, "--digest", digest, "--ip", "127.0.0.1")
	require.ErrorIs(t, err, jitaccess.ErrSelfApproval)

	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	denyDetails, ok := jitAuditDetails(t, st, auditlog.ActionDeny, requester.ID, id)
	require.True(t, ok)
	assert.Contains(t, denyDetails, "reason=self-approval blocked")

	out, err = jitCLI(t, uri, "show", id)
	require.NoError(t, err, out)
	assert.Contains(t, out, "status: pending")

	_, err = pool.Exec(ctx, `UPDATE jit_access SET expires_at = now() - interval '1 second' WHERE id = $1`, id)
	require.NoError(t, err)
	out, err = jitCLI(t, uri, "expire")
	require.NoError(t, err, out)
	assert.Contains(t, out, "flipped to expired")

	// Terminal: no late decision through the boundary, not even with the
	// exact digest.
	_, err = jitCLI(t, uri, "approve", id, "--approver", requester.ID, "--digest", digest)
	require.ErrorIs(t, err, jitaccess.ErrNotPending)
	out, err = jitCLI(t, uri, "show", id)
	require.NoError(t, err, out)
	assert.Contains(t, out, "status: expired")
}

// TestIntJITCLI_E2E_AuditChainIntactAfterFullFlow: after a mixed CLI-driven
// flow (approval + explicit deny + sweep), the whole audit chain — ordinary
// rows plus the decision rows — still verifies. Public-core surface only: no
// proprietary imports, no entitlement checks in the path.
func TestIntJITCLI_E2E_AuditChainIntactAfterFullFlow(t *testing.T) {
	pool := testdb.Postgres(t)
	uri := pool.Config().ConnString()
	ctx := context.Background()

	admins := seedJITCLIAdmins(t, pool, true, true, 2)
	requester, approver := admins[0], admins[1]

	out, err := jitCLI(t, uri, "request", "--admin", requester.ID, "--role", "root", "--reason", "approve me")
	require.NoError(t, err, out)
	id, digest := jitParseRequest(t, out)
	_, err = jitCLI(t, uri, "approve", id, "--approver", approver.ID, "--digest", digest)
	require.NoError(t, err, out)

	out, err = jitCLI(t, uri, "request", "--admin", requester.ID, "--role", "root", "--reason", "deny me")
	require.NoError(t, err, out)
	id2, digest2 := jitParseRequest(t, out)
	_, err = jitCLI(t, uri, "deny", id2, "--approver", approver.ID, "--digest", digest2, "--reason", "not justified")
	require.NoError(t, err, out)

	_, err = jitCLI(t, uri, "expire")
	require.NoError(t, err)

	sqlDB, err := sql.Open("pgx", uri)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()
	broken, verr := auditlog.NewVerifier(sqlDB).Verify(ctx)
	require.NoError(t, verr)
	assert.Equal(t, int64(0), broken, "audit chain must verify after the CLI-driven flow")
}
