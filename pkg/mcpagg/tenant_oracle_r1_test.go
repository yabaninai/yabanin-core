package mcpagg

// TENANT-ORACLE-01 (auth/SSE correction packet, case 9): two real orgs
// use the SAME server name and the SAME tool name; only one caller is
// granted. The authorized org's sink is hit exactly once, the other
// org's sink is hit zero times, and BOTH policy consultations are
// asserted to carry their own org/subject with the shared server/tool
// identity — recorded at the ToolGuard seam, delegating to the real
// RLS-store-backed engine.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// tenantOracleRecorder wraps the real engine at the exact seam the proxy
// consults, recording (org, subject, server, tool) per guard call.
type tenantOracleRecorder struct {
	inner ToolGuard
	mu    sync.Mutex
	seen  [][4]string
}

func (r *tenantOracleRecorder) record(orgID, subject, server, tool string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, [4]string{orgID, subject, server, tool})
}

func (r *tenantOracleRecorder) args() [][4]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][4]string, len(r.seen))
	copy(out, r.seen)
	return out
}

func (r *tenantOracleRecorder) GuardArgs(ctx context.Context, orgID, subject, server, tool string, argsJSON json.RawMessage) toolpolicy.ArgsReport {
	r.record(orgID, subject, server, tool)
	return r.inner.GuardArgs(ctx, orgID, subject, server, tool, argsJSON)
}

func (r *tenantOracleRecorder) GuardResult(ctx context.Context, orgID, subject, server, tool string, result json.RawMessage) toolpolicy.ResultReport {
	r.record(orgID, subject, server, tool)
	return r.inner.GuardResult(ctx, orgID, subject, server, tool, result)
}

// TestTenantOracle_01_SameNameOneGrant: org A (no policy rows — implicit
// allow at the guard) and org B (deny row for the same server+tool) each
// own a SEPARATE counting upstream registered under the SAME server name
// "knowledge", with the SAME tool "search".
func TestTenantOracle_01_SameNameOneGrant(t *testing.T) {
	fxA := newToolGrantIntFixture(t, "tenant-a")
	fxB := newToolGrantIntFixture(t, "tenant-b")
	require.NotEqual(t, fxA.org, fxB.org, "two distinct real orgs")
	require.NotEqual(t, fxA.up.URL, fxB.up.URL, "two distinct physical sinks")

	// Org B revokes the shared name through the real admin store.
	_, err := fxB.policies.Create(context.Background(), toolpolicy.CreateParams{OrgID: fxB.org,
		Name: "deny-search", Subject: "*", Server: "knowledge", Tool: "search",
		Action: toolpolicy.ActionDeny, Priority: 10, Enabled: true})
	require.NoError(t, err, "org B's deny row must land through the real store")
	fxB.engine.Invalidate(fxB.org)

	// Production topology: ONE engine shared by both proxies (the
	// gateway wires NewProxy(...).WithToolGuard(sharedEngine)) — the
	// org-scoped loader rows are what keeps the shared cache honest.
	// Each fixture's store points at the same physical tool_policies
	// table under the app-role RLS posture, so either serves both orgs.
	shared := toolpolicy.NewEngine(fxA.policies, time.Minute)
	recA := &tenantOracleRecorder{inner: shared}
	recB := &tenantOracleRecorder{inner: shared}
	fxA.proxy = fxA.proxy.WithToolGuard(recA)
	fxB.proxy = fxB.proxy.WithToolGuard(recB)

	// The granted caller: success and exactly one hit on ITS sink.
	require.NoError(t, toolGrantIntInvoke(fxA, "search", json.RawMessage(`{"q":"a"}`)),
		"org A holds no deny row: the same-name tool must succeed for the granted caller")
	assert.Equal(t, int32(1), fxA.up.calls.Load(), "the authorized sink is hit exactly once")
	assert.Zero(t, fxB.up.calls.Load(), "org A's call must never touch org B's sink")

	// The other caller: documented refusal, zero hits on its own sink.
	var iErr *InvokeError
	require.ErrorAs(t, toolGrantIntInvoke(fxB, "search", json.RawMessage(`{"q":"b"}`)), &iErr,
		"org B's caller must be refused")
	assert.Equal(t, ErrCodeToolBlocked, iErr.Code, "the refusal is the documented policy code")
	assert.Equal(t, int32(1), fxA.up.calls.Load(), "org B's refusal adds nothing to org A's sink")
	assert.Zero(t, fxB.up.calls.Load(), "zero hits for the non-granted org's own sink")

	// Both policy consultations carried their OWN identity with the SAME
	// shared server/tool names: no cross-org consult, no corrupted
	// subject/server/tool parameters.
	seenA := recA.args()
	require.NotEmpty(t, seenA, "org A's invocation must consult the guard")
	for _, c := range seenA {
		assert.Equal(t, [4]string{fxA.org, fxA.agent, "knowledge", "search"}, c,
			"org A's consultations must carry org A's own identity over the shared name")
	}
	seenB := recB.args()
	require.NotEmpty(t, seenB, "org B's invocation must consult the guard")
	for _, c := range seenB {
		assert.Equal(t, [4]string{fxB.org, fxB.agent, "knowledge", "search"}, c,
			"org B's consultations must carry org B's own identity over the shared name")
	}
	for _, c := range seenB {
		assert.NotEqual(t, fxA.org, c[0], "org B's guard must never consult with org A's id")
	}
}
