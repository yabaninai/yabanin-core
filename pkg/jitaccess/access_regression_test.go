package jitaccess

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// observable security posture, so they get their own anchors. The mutation
// proofs against these anchors (reordered checks, weakened binding, widened
// sweep) are documented with commands and exit codes in

// TestJIT_Regression_AuthorizationOrdering pins the decide ordering: the
// self rule is reported before the root verdict, and the root verdict before
// the digest verdict — a non-root (or self) approver never learns whether the
// digest would have matched.
func TestJIT_Regression_AuthorizationOrdering(t *testing.T) {
	base := jitBasePending()
	tampered := base.Binds
	tampered.ParamsDigest = strings.Repeat("0", 64)
	notRoot := func(context.Context, string) (bool, error) { return false, nil }

	t.Run("self-approval precedes the root verdict", func(t *testing.T) {
		m := NewManager(jitLazyPool(t))
		m.WithRootCheck(notRoot)
		m.queryRow = func(context.Context, string, ...any) pgx.Row { return jitStubRow(t, base) }
		// The requester themselves, even when the checker answers not-root
		// and the quoted digest is wrong: the self rule is what is reported.
		_, err := m.Approve(context.Background(), base.ID, base.AdminID, tampered)
		require.ErrorIs(t, err, ErrSelfApproval)
		assert.NotErrorIs(t, err, ErrApproverNotRoot)
	})

	t.Run("authorization precedes the digest verdict", func(t *testing.T) {
		m := NewManager(jitLazyPool(t))
		m.WithRootCheck(notRoot)
		m.queryRow = func(context.Context, string, ...any) pgx.Row { return jitStubRow(t, base) }
		// A non-root approver quoting a WRONG digest learns only that they
		// are not root — never whether the digest would have matched.
		_, err := m.Approve(context.Background(), base.ID, "approver-2", tampered)
		require.ErrorIs(t, err, ErrApproverNotRoot)
		assert.NotErrorIs(t, err, ErrDigestMismatch)
	})
}
