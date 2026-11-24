package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/config"
)

func TestGatewayBindsInvocationStoreToApplicationPool(t *testing.T) {
	w, _, _ := wireTestDeps(t, t.Context(), config.Gateway{})
	gw := newGatewaySkeleton(t.Context(), w)
	t.Cleanup(gw.auth.lastUsed.Close)
	store, ok := gw.invocations.(pgInvocationStore)
	require.True(t, ok, "production gateway needs the PostgreSQL admission store")
	require.Same(t, w.pool, store.pool)

	w.pool = nil
	offline := newGatewaySkeleton(t.Context(), w)
	ctx := withInvocationIdentity(t.Context(), newTestIdentity())
	require.ErrorIs(t, offline.confirmPaidInvocation(ctx, invocationKindChat), ErrInvocationStoreUnavailable)
}
