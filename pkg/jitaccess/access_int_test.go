package jitaccess

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// (D1-D4, D6, D7). The D5 audit-row assertions live with the operator
// surface in pkg/trcli (the audit write belongs to the decision handler).
// The D5 vocabulary constructors are covered by pkg/auditlog action tests.

type jitAdmin struct {
	ID    string
	Email string
}

// jitAdminSpec seeds one admin_users row (the root check reads them).
type jitAdminSpec struct {
	Root   bool
	Active bool
}

func seedJITAdmins(t *testing.T, pool *pgxpool.Pool, specs ...jitAdminSpec) []jitAdmin {
	t.Helper()
	admins := make([]jitAdmin, 0, len(specs))
	ids := make([]string, 0, len(specs))
	for i, s := range specs {
		a := jitAdmin{ID: uuid.NewString(), Email: "jit-int-" + uuid.NewString() + "-" + string(rune('a'+i)) + "@test"}
		require.NoError(t, func() error {
			_, err := pool.Exec(context.Background(),
				`INSERT INTO admin_users (id, email, password_hash, is_root, active) VALUES ($1, $2, 'x', $3, $4)`,
				a.ID, a.Email, s.Root, s.Active)
			return err
		}(), "seed admin %d", i)
		admins = append(admins, a)
		ids = append(ids, a.ID)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM jit_access WHERE admin_id = ANY($1) OR approver_id = ANY($1)`, ids)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_users WHERE id = ANY($1)`, ids)
	})
	return admins
}

// ageRequest forces the request's pending window into the past (the only
// lever the sweep needs; time travel is otherwise not a product feature).
func ageRequest(t *testing.T, pool *pgxpool.Pool, requestID string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE jit_access SET expires_at = now() - interval '1 second' WHERE id = $1`, requestID)
	require.NoError(t, err)
}

// jitAcceptance1_WorkingFlow: request -> approval by a DIFFERENT root
// operator -> elevation active for the 1h TTL -> sweep makes the aged
// approval terminally expired. (The audit APPROVE-with-digest leg of this
// acceptance example is asserted end-to-end by the trcli operator test.)
func TestIntJIT_Acceptance1_WorkingFlow(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	admins := seedJITAdmins(t, pool,
		jitAdminSpec{Root: true, Active: true}, // requester (root; only a different human may approve)
		jitAdminSpec{Root: true, Active: true}, // approver (other root operator)
	)
	requester, approver := admins[0], admins[1]

	rec, err := m.Request(ctx, requester.ID, "root", "break-glass fix")
	require.NoError(t, err)
	require.Equal(t, StatusPending, rec.Status)
	require.NotEmpty(t, rec.Binds.ParamsDigest)

	decided, err := m.Approve(ctx, rec.ID, approver.ID, rec.Binds)
	require.NoError(t, err)
	assert.Equal(t, StatusApproved, decided.Status)
	require.NotNil(t, decided.ApproverID)
	assert.Equal(t, approver.ID, *decided.ApproverID)
	// D6: the elevation is active for the approved TTL (1h), not the
	// pending window.
	assert.WithinDuration(t, time.Now().Add(ApprovedTTL), decided.ExpiresAt, 2*time.Minute)
	assert.True(t, m.IsActive(ctx, requester.ID, "root"), "approved elevation must be active")

	// D6: the sweep flips the aged approval to terminal expired.
	ageRequest(t, pool, rec.ID)
	flipped, err := m.ExpirePast(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, flipped, int64(1))
	assert.False(t, m.IsActive(ctx, requester.ID, "root"), "expired elevation must not be active")

	after, err := m.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusExpired, after.Status)
	// Expired is terminal: no late decision applies.
	_, err = m.Approve(ctx, rec.ID, approver.ID, after.Binds)
	assert.ErrorIs(t, err, ErrNotPending)
}

// jitAcceptance2_ReplayAndChangedArgs: an approval quoting anything but the
// exact reviewed digest is refused and leaves the request pending; the
// correct decision still lands afterwards; replaying the SAME approval a
// second time is refused (the request is no longer pending).
func TestIntJIT_Acceptance2_ReplayAndChangedArgs(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	requester := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: true})[0]
	approver := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: true})[0]

	rec, err := m.Request(ctx, requester.ID, "finance-ops", "quarter close")
	require.NoError(t, err)

	// Changed argument: the digest no longer matches the stored request.
	tampered := rec.Binds
	tampered.ParamsDigest = "0000000000000000000000000000000000000000000000000000000000000000"
	_, err = m.Approve(ctx, rec.ID, approver.ID, tampered)
	require.ErrorIs(t, err, ErrDigestMismatch)

	// Stale view: the requester changed between review and decision.
	stale := rec.Binds
	stale.Org = "someone-else"
	_, err = m.Approve(ctx, rec.ID, approver.ID, stale)
	require.ErrorIs(t, err, ErrDigestMismatch)

	pending, err := m.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusPending, pending.Status, "failed decisions must not mutate state")

	// The honest decision (exact binds) goes through.
	_, err = m.Approve(ctx, rec.ID, approver.ID, rec.Binds)
	require.NoError(t, err)

	// Replay of the same approval: rejected, nothing changes.
	_, err = m.Approve(ctx, rec.ID, approver.ID, rec.Binds)
	require.ErrorIs(t, err, ErrNotPending)
	after, err := m.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusApproved, after.Status)
}

// jitAcceptance3_SelfApprovalAndPendingSweep: a root requester still cannot
// approve their own request, and a pending request older than 24h ends
// terminally expired under the sweep.
func TestIntJIT_Acceptance3_SelfApprovalAndPendingSweep(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	requester := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: true})[0]

	rec, err := m.Request(ctx, requester.ID, "root", "self-service attempt")
	require.NoError(t, err)
	_, err = m.Approve(ctx, rec.ID, requester.ID, rec.Binds)
	require.ErrorIs(t, err, ErrSelfApproval)

	cur, err := m.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusPending, cur.Status)

	ageRequest(t, pool, rec.ID)
	flipped, err := m.ExpirePast(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, flipped, int64(1))

	after, err := m.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusExpired, after.Status)
}

func TestIntJIT_RootOnlyApprover(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	requester := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: true})[0]
	plain := seedJITAdmins(t, pool, jitAdminSpec{Root: false, Active: true})[0]
	inactiveRoot := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: false})[0]
	outside := jitAdmin{ID: uuid.NewString()} // unknown id

	rec, err := m.Request(ctx, requester.ID, "root", "authorization matrix")
	require.NoError(t, err)

	for name, approver := range map[string]string{
		"non-root":   plain.ID,
		"inactive":   inactiveRoot.ID,
		"unknown":    outside.ID,
		"not-a-uuid": "definitely-not-a-uuid",
	} {
		_, err := m.Approve(ctx, rec.ID, approver, rec.Binds)
		require.ErrorIs(t, err, ErrApproverNotRoot, name)
	}

	cur, err := m.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusPending, cur.Status, "unauthorized attempts must not decide")
}

func TestIntJIT_DenyIsTerminal(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	requester := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: true})[0]
	approver := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: true})[0]

	rec, err := m.Request(ctx, requester.ID, "root", "deny me")
	require.NoError(t, err)

	denied, err := m.Deny(ctx, rec.ID, approver.ID, rec.Binds)
	require.NoError(t, err)
	assert.Equal(t, StatusDenied, denied.Status)
	assert.False(t, m.IsActive(ctx, requester.ID, "root"))

	// denied is terminal: no approve after deny, no second deny.
	_, err = m.Approve(ctx, rec.ID, approver.ID, rec.Binds)
	require.ErrorIs(t, err, ErrNotPending)
	_, err = m.Deny(ctx, rec.ID, approver.ID, rec.Binds)
	require.ErrorIs(t, err, ErrNotPending)
}

func TestIntJIT_PendingQueueListsUndecided(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	requester := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: true})[0]

	rec, err := m.Request(ctx, requester.ID, "root", "queue me")
	require.NoError(t, err)

	queue, err := m.PendingRequests(ctx)
	require.NoError(t, err)
	found := false
	for _, r := range queue {
		if r.ID == rec.ID {
			found = true
			assert.Equal(t, rec.Binds, r.Binds)
		}
	}
	assert.True(t, found, "fresh request must appear in the pending queue")
}

func TestIntJIT_UnknownRequest(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	_, err := m.Get(ctx, uuid.NewString())
	require.ErrorIs(t, err, ErrNotFound)
	_, err = m.Approve(ctx, uuid.NewString(), uuid.NewString(), ApprovalBinds{})
	require.ErrorIs(t, err, ErrNotFound)
}

func TestIntJIT_InputValidation(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	requester := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: true})[0]

	_, err := m.Request(ctx, "", "root", "no admin")
	require.Error(t, err)
	_, err = m.Request(ctx, requester.ID, "  ", "blank role")
	require.Error(t, err)
	rec, err := m.Request(ctx, requester.ID, "root", "valid")
	require.NoError(t, err)
	_, err = m.Approve(ctx, rec.ID, "  ", rec.Binds)
	require.Error(t, err)
	cur, err := m.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusPending, cur.Status, "invalid input must not decide")
}

func TestIntJIT_ActiveRequestsListsLiveElevations(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	admins := seedJITAdmins(t, pool,
		jitAdminSpec{Root: true, Active: true},
		jitAdminSpec{Root: true, Active: true},
	)
	requester, approver := admins[0], admins[1]

	rec, err := m.Request(ctx, requester.ID, "root", "list me")
	require.NoError(t, err)
	_, err = m.Approve(ctx, rec.ID, approver.ID, rec.Binds)
	require.NoError(t, err)

	active, err := m.ActiveRequests(ctx)
	require.NoError(t, err)
	found := false
	for _, r := range active {
		if r.ID == rec.ID {
			found = true
			assert.Equal(t, StatusApproved, r.Status)
			assert.Equal(t, rec.Binds, r.Binds)
		}
	}
	assert.True(t, found, "approved elevation must be listed as active")
}

func TestIntJIT_DeniedStampIsImmediate(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	requester := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: true})[0]
	approver := seedJITAdmins(t, pool, jitAdminSpec{Root: true, Active: true})[0]

	rec, err := m.Request(ctx, requester.ID, "root", "terminal stamp check")
	require.NoError(t, err)
	denied, err := m.Deny(ctx, rec.ID, approver.ID, rec.Binds)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), denied.ExpiresAt, time.Minute,
		"a denial must never carry an active window")
}
