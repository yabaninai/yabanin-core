package loopexec

// E01-P04-W02-C03: the read/respond/admin grant matrix as executable
// fixtures, plus confused-deputy negatives asserting ORG ATTRIBUTION ON
// EVERY HOP — a deputy executor acts with the CALLER's org, never its own.
//
// FAKE-VS-REAL (boundary-fixture precedent, E01-P02 W05):
//   - REAL: the BuiltinExecutor, the toolexec.Executor, the Registry
//     dispatch, the Config/Call/Scope validation and the guard WIRING
//     (WithToolGuard — the same interface seam the production
//     *toolpolicy.Engine rides).
//   - RECORDING (fake): guard-attribution recorder implements the
//     toolexec.ToolGuard INTERFACE so the tests can observe which
//     (org, subject, server, tool) each guarded hop was attributed to.
//     It records and by default allows; it is a harness, not enforcement —
//     the denial it can emit proves only that a deny decision BLOCKS the
//     call at the real seam (tool_blocked, no execution), not that policy
//     evaluation itself is correct (that lives in pkg/toolpolicy tests).
//
// Grant model mapping (design doc W02-grant-model-design.md §1): respond =
// ActionInvoke, read = ActionList (refused by v1 builtin), admin = outside
// the Action vocabulary — unexpressible, fail-closed at the executor AND at
// any Policy (unrecognized action = denial, enterprise/loop config.go).
//
// Mandatory variants (W01-C02 matrix): allowed / empty-unavailable upstream
// (unknown server = ErrNoExecutor at this seam) / rights-denial + cross-org
// (matrix denial cells + deputy org-confusion) / replay (identical calls
// re-evaluated per call against the CURRENT config; route allow-list
// narrowing is the revocation analogue). Rollback: N/A — the seam holds no
// durable state (Config is a per-call value, Registry entries are
// immutable after Register); nothing to roll back.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/agentloop"
	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// guardHop is one recorded guarded-call attribution.
type guardHop struct {
	org     string
	subject string
	server  string
	tool    string
}

// attributionRecorder is a ToolGuard that records every hop's attribution
// and by default allows. denyArgs flips the next (and every) GuardArgs into
// a deny to prove the deny decision blocks execution at the real seam.
type attributionRecorder struct {
	mu       sync.Mutex
	hops     []guardHop
	results  int
	denyArgs bool
	denyMsg  string
}

func (r *attributionRecorder) GuardArgs(_ context.Context, orgID, subject, server, tool string, _ json.RawMessage) toolpolicy.ArgsReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hops = append(r.hops, guardHop{org: orgID, subject: subject, server: server, tool: tool})
	if r.denyArgs {
		return toolpolicy.ArgsReport{Denied: true, Reason: r.denyMsg}
	}
	return toolpolicy.ArgsReport{}
}

func (r *attributionRecorder) GuardResult(_ context.Context, _, _, _, _ string, _ json.RawMessage) toolpolicy.ResultReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results++
	return toolpolicy.ResultReport{}
}

func (r *attributionRecorder) snapshot() (hops []guardHop, results int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]guardHop(nil), r.hops...), r.results
}

// newRecordingBuiltin wires the REAL executor chain with the recording
// guard: toolexec.Executor + WithToolGuard + BuiltinExecutor + Registry —
// exactly the production wiring shape, with the recorder substituted for
// the policy engine.
func newRecordingBuiltin(t *testing.T) (*BuiltinExecutor, *attributionRecorder) {
	t.Helper()
	rec := &attributionRecorder{}
	x := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil).WithToolGuard(rec)
	b, err := NewBuiltinExecutor(x)
	require.NoError(t, err)
	return b, rec
}

// deputyConfig is the route configuration a deputy loop runs ON BEHALF OF
// the caller: the scope is the CALLER's (org-caller). The deputy's own org
// (org-deputy) must never appear in any attribution.
func deputyConfig(tools ...string) Config {
	cfg := validConfig()
	cfg.Scope = Scope{OrgID: "org-caller", ProjectID: "proj-1", Route: "deputy-loop"}
	cfg.AllowedTools = tools
	return cfg
}

func deputyCall(tool string) Call {
	return Call{
		Scope:   Scope{OrgID: "org-caller", ProjectID: "proj-1", Route: "deputy-loop"},
		Server:  Server,
		Tool:    tool,
		Action:  ActionInvoke,
		Subject: "sub-caller",
	}
}

// TestGrantMatrix_ReadRespondAdmin is the grant-model matrix as one fixture
// table: every cell names its grant class and expected refusal sentinel.
// Refusal cells additionally assert ZERO guarded hops (a refusal never
// reaches the executor's guard path); the allowed cell asserts exactly one
// hop attributed to the caller org.
func TestGrantMatrix_ReadRespondAdmin(t *testing.T) {
	ctx := context.Background()
	offRoute := deputyCall("time_now")
	offRoute.Tool = "http_request" // real builtin name, kept off the route list

	crossOrg := deputyCall("time_now")
	crossOrg.Scope.OrgID = "org-deputy"

	delegated := deputyCall("time_now")
	delegated.Credential = agentloop.CredentialRef{Mode: agentloop.CredentialDelegatedUser}

	noSubject := deputyCall("time_now")
	noSubject.Subject = ""

	cases := []struct {
		name    string
		call    Call
		cfg     Config
		wantErr error
	}{
		{"respond allowed on-route", deputyCall("time_now"), deputyConfig("yabanin:time_now"), nil},
		{"read refused in v1", func() Call { c := deputyCall("time_now"); c.Action = ActionList; return c }(), deputyConfig("yabanin:time_now"), ErrNotPermitted},
		{"admin is unexpressible", func() Call { c := deputyCall("time_now"); c.Action = "admin"; return c }(), deputyConfig("yabanin:time_now"), ErrNotPermitted},
		{"respond off-route tool refused", offRoute, deputyConfig("yabanin:time_now"), ErrNotPermitted},
		{"respond empty route allow-list refuses", deputyCall("time_now"), deputyConfig(), ErrNotPermitted},
		{"respond delegated-user credential refused", delegated, deputyConfig("yabanin:time_now"), ErrNotPermitted},
		{"respond empty subject refused", noSubject, deputyConfig("yabanin:time_now"), ErrSubjectRequired},
		{"respond cross-org scope refused", crossOrg, deputyConfig("yabanin:time_now"), ErrNotPermitted},
	}

	b, rec := newRecordingBuiltin(t)
	reg := NewRegistry()
	require.NoError(t, reg.Register(Server, b))

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hopsBefore, _ := rec.snapshot()
			res, err := reg.Execute(ctx, tc.cfg, tc.call)
			if tc.wantErr == nil {
				require.NoError(t, err)
				assert.Equal(t, Server, res.Server)
				hops, _ := rec.snapshot()
				require.Len(t, hops, len(hopsBefore)+1, "the allowed cell executes exactly one guarded hop")
				assert.Equal(t, "org-caller", hops[len(hops)-1].org, "the hop is attributed to the caller org")
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			hops, _ := rec.snapshot()
			assert.Len(t, hops, len(hopsBefore), "a refusal must never reach the guarded hop")
		})
	}

	t.Run("unknown server is the unavailable-upstream refusal", func(t *testing.T) {
		// Mandatory variant 2 at this seam: no executor registered for the
		// named server — fail-closed dispatch, not a silent no-op.
		call := deputyCall("time_now")
		call.Server = "nowhere"
		_, err := reg.Execute(ctx, deputyConfig("nowhere:time_now"), call)
		require.ErrorIs(t, err, ErrNoExecutor)
	})
}

// TestConfusedDeputy_CallerOrgAttributionOnEveryHop: the deputy law. A
// deputy executor running a caller's route attributes EVERY guarded hop to
// the CALLER's org and subject; presenting the deputy's own org is refused
// before any hop; a guard deny cannot be smuggled past; and calls are
// re-evaluated against the CURRENT route config (replay variant).
func TestConfusedDeputy_CallerOrgAttributionOnEveryHop(t *testing.T) {
	ctx := context.Background()
	b, rec := newRecordingBuiltin(t)
	reg := NewRegistry()
	require.NoError(t, reg.Register(Server, b))

	t.Run("allowed hop is attributed to the caller org and subject", func(t *testing.T) {
		_, err := reg.Execute(ctx, deputyConfig("yabanin:time_now"), deputyCall("time_now"))
		require.NoError(t, err)
		hops, _ := rec.snapshot()
		require.Len(t, hops, 1)
		assert.Equal(t, "org-caller", hops[0].org, "attribution is the CALLER's org")
		assert.Equal(t, "sub-caller", hops[0].subject, "the subject rides the hop verbatim")
		assert.Equal(t, Server, hops[0].server)
		assert.Equal(t, "time_now", hops[0].tool)
		for _, h := range hops {
			assert.NotEqual(t, "org-deputy", h.org, "the deputy's own org must never appear in attribution")
		}
	})

	t.Run("deputy substituting its own org is refused before any hop", func(t *testing.T) {
		hopsBefore, _ := rec.snapshot()
		call := deputyCall("time_now")
		call.Scope.OrgID = "org-deputy" // the confused-deputy attempt
		_, err := reg.Execute(ctx, deputyConfig("yabanin:time_now"), call)
		require.ErrorIs(t, err, ErrNotPermitted)
		hops, _ := rec.snapshot()
		assert.Len(t, hops, len(hopsBefore), "org confusion must be refused before the guarded hop")
	})

	t.Run("guard deny blocks execution at the seam", func(t *testing.T) {
		denying, denyRec := newRecordingBuiltin(t)
		denyRec.denyArgs, denyRec.denyMsg = true, "matrix-deny-rule"
		denyReg := NewRegistry()
		require.NoError(t, denyReg.Register(Server, denying))
		_, err := denyReg.Execute(ctx, deputyConfig("yabanin:time_now"), deputyCall("time_now"))
		require.Error(t, err, "a deny decision must surface, never pass silently")
		_, results := denyRec.snapshot()
		assert.Zero(t, results, "an args-deny must stop before execution (no result hop)")
		assert.Contains(t, err.Error(), "matrix-deny-rule")
	})

	t.Run("identical calls re-evaluate against the current route config", func(t *testing.T) {
		// Replay variant: no memoized verdicts — each call is checked
		// against the config passed NOW.
		onRoute := deputyConfig("yabanin:time_now")
		for i := 0; i < 2; i++ {
			_, err := reg.Execute(ctx, onRoute, deputyCall("time_now"))
			require.NoError(t, err, "identical allowed call %d", i+1)
		}
		hops, _ := rec.snapshot()
		require.Len(t, hops, 3, "two more caller-org hops (1 from the first subtest)")
		assert.Equal(t, "org-caller", hops[2].org)

		// The revocation analogue at this seam: the route allow-list is
		// narrowed (a fresh Config value — no durable state to roll back),
		// and the byte-identical call is now refused.
		hopsBefore, _ := rec.snapshot()
		_, err := reg.Execute(ctx, deputyConfig("yabanin:other"), deputyCall("time_now"))
		require.ErrorIs(t, err, ErrNotPermitted, "the identical replay after narrowing must refuse")
		hops, _ = rec.snapshot()
		assert.Len(t, hops, len(hopsBefore))
	})
}

// TestGrantMatrix_AdminActionRejectedByVocabulary pins the admin class
// fail-closed at BOTH vocabulary gates named by the design doc: the loopexec
// Action constants (only invoke/list exist) and the grant-action vocabulary
// the loop mirrors (mcpagg GrantActionInvoke/GrantActionList, pinned
// byte-for-byte by TestActionVocabularyMirrorsGrantActions). "admin" is not
// a member of either, so no executor or policy can ever be handed it as a
// known action.
func TestGrantMatrix_AdminActionRejectedByVocabulary(t *testing.T) {
	assert.NotEqual(t, ActionInvoke, Action("admin"))
	assert.NotEqual(t, ActionList, Action("admin"))
	// The Action constants are the complete v1 vocabulary surface: a value
	// outside {invoke, list} has no executor path (builtin refuses every
	// action except invoke) and no grant row can carry it (migration 0020
	// CHECK + grantAllowsAction unknown-action refusal, pinned in
	// pkg/mcpagg/grant_enforcement_negative_test.go).
	cases := []Action{"admin", "invoke ", "INVOKE", ""}
	for _, a := range cases {
		ctx := context.Background()
		b, _ := newRecordingBuiltin(t)
		call := deputyCall("time_now")
		call.Action = a
		_, err := b.Execute(ctx, deputyConfig("yabanin:time_now"), call)
		require.ErrorIs(t, err, ErrNotPermitted, "action %q", a)
	}
}
