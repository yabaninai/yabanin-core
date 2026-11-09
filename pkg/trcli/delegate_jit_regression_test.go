package trcli

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/auditlog"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// work proved the chain verifies after decision writes; this anchor pins the
// stronger property — the decision rows are full citizens of the
// tamper-evident chain: their stored hash satisfies the published formula
// recomputed from the stored columns, and a direct DB edit of the journaled
// payload is detected by the verifier. The mutation proof (recomputing with a
// drifted formula would be self-consistent) is documented in

func TestIntJIT_Regression_AuditRowHashBindsToPayload(t *testing.T) {
	pool := testdb.Postgres(t)
	st, closeStores := openJITCLIStores(t, pool)
	defer closeStores()
	ctx := context.Background()

	admins := seedJITCLIAdmins(t, pool, true, true, 2)
	requester, approver := admins[0], admins[1]

	rec, err := st.mgr.Request(ctx, requester.ID, "root", "chain anchor")
	require.NoError(t, err)
	require.NoError(t, runJITDecision(ctx, &strings.Builder{}, st, jitDecisionOpts{
		decision: "approve", requestID: rec.ID, approver: approver.ID,
		digest: rec.Binds.ParamsDigest, adminName: "Root B", ip: "127.0.0.1",
	}))

	// The stored APPROVE row satisfies the v1 formula recomputed from its
	// own stored columns.
	var (
		seq      int64
		action   string
		resource string
		details  string
		adminID  string
		ip       string
		prevHash string
		rowHash  string
		version  int
	)
	err = st.pool.QueryRow(ctx, `
		SELECT seq, action, resource, details, admin_id, ip_address, prev_hash, row_hash, hash_version
		FROM admin_audit_logs
		WHERE action=$1 AND resource=$2 AND admin_id=$3 AND details LIKE $4
		ORDER BY seq DESC LIMIT 1`,
		auditlog.ActionApprove, auditlog.ResourceJITAccess, approver.ID,
		"request="+rec.ID+"%").Scan(&seq, &action, &resource, &details,
		&adminID, &ip, &prevHash, &rowHash, &version)
	require.NoError(t, err)
	assert.Equal(t, auditlog.HashVersionV1, version)
	want := auditlog.RowHash(prevHash, auditlog.PayloadV1(action, resource, details, adminID, ip))
	assert.Equal(t, want, rowHash, "stored hash must satisfy the published chain formula")

	// Tamper-EVIDENCE: a direct DB edit of the journaled payload is detected
	// by the verifier (the row cleanup removes the tampered row afterwards).
	_, err = pool.Exec(ctx, `UPDATE admin_audit_logs SET details = details || ' tampered' WHERE seq=$1`, seq)
	require.NoError(t, err)
	sqlDB, err := sql.Open("pgx", pool.Config().ConnString())
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()
	broken, err := auditlog.NewVerifier(sqlDB).Verify(ctx)
	// The verifier reports the first break either as a nonzero seq or as the
	// tampering error naming the row; a DB-level failure carries neither.
	detected := broken != 0 || (err != nil && strings.Contains(err.Error(), "row_hash mismatch"))
	require.True(t, detected, "a tampered decision row must be detected (broken=%d, err=%v)", broken, err)
}
