package budget

// NEXT-18c unit tests: the pure pieces of the admission layer (mode
// resolution and clamping, the Finalize termination set, the event tuple
// wire contract, denial wrapping, nil safety). The store-backed cycles run
// in admission_int_test.go against a disposable Postgres.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResolveMode(t *testing.T) {
	require.Equal(t, ModeOff, ResolveMode(""))
	require.Equal(t, ModeOff, ResolveMode("off"))
	require.Equal(t, ModeShadow, ResolveMode("shadow"))
	require.Equal(t, ModeEnforce, ResolveMode("enforce"))
	// Anything else fails safe to off — a mistyped env value must never
	// activate reservations.
	require.Equal(t, ModeOff, ResolveMode("ENFORCE"))
	require.Equal(t, ModeOff, ResolveMode("sto"))
}

func TestEffectiveModeClampsToDeploymentGate(t *testing.T) {
	off, shadow, enforce := ModeOff, ModeShadow, ModeEnforce
	require.Equal(t, off, EffectiveMode(off, enforce), "gate off keeps every org off")
	require.Equal(t, shadow, EffectiveMode(shadow, enforce), "shadow gate degrades enforce orgs")
	require.Equal(t, enforce, EffectiveMode(enforce, enforce))
	require.Equal(t, shadow, EffectiveMode(enforce, shadow))
	require.Equal(t, off, EffectiveMode(enforce, off))
	require.Equal(t, off, EffectiveMode(off, shadow))
}

// TestAdmissionGateClampRuntime pins the N06-P03 negative cases at the
// runtime boundary (Plan), not just on the pure function: the deployment
// gate clamps the stored org mode exactly as EffectiveMode does, an unknown
// stored value fails closed to off, and a clamped-to-shadow org is served
// with would-deny observability instead of denials.
func TestAdmissionGateClampRuntime(t *testing.T) {
	ctx := context.Background()

	t.Run("off gate ignores stored enforce — nothing activates, nothing denied", func(t *testing.T) {
		loader := func(context.Context, string) (OrgSettings, error) {
			return OrgSettings{Mode: ModeEnforce}, nil
		}
		adm := NewAdmission(nil, ScopedRateSource{}, nil, "rep-clamp-off", ModeOff, loader, AdmissionConfig{})
		plan, err := adm.Plan(ctx, Request{OrgID: "org-1"})
		require.NoError(t, err)
		require.Equal(t, ModeOff, plan.Mode)
		require.Empty(t, plan.WouldDeny)
		rsv, err := adm.Reserve(ctx, plan)
		require.ErrorIs(t, err, ErrNotReserved)
		require.Nil(t, rsv)
	})

	t.Run("unknown stored mode fails closed to off", func(t *testing.T) {
		// A legacy/corrupt column value must never activate reservations:
		// ResolveMode degrades it to off before the gate sees it.
		loader := func(context.Context, string) (OrgSettings, error) {
			return OrgSettings{Mode: Mode("enforce_mistyped")}, nil
		}
		adm := NewAdmission(nil, ScopedRateSource{}, nil, "rep-clamp-unknown", ModeEnforce, loader, AdmissionConfig{})
		plan, err := adm.Plan(ctx, Request{OrgID: "org-1"})
		require.NoError(t, err)
		require.Equal(t, ModeOff, plan.Mode)
		require.Empty(t, plan.WouldDeny)
	})

	t.Run("shadow gate degrades a stored enforce org at runtime", func(t *testing.T) {
		loader := func(context.Context, string) (OrgSettings, error) {
			return OrgSettings{Mode: ModeEnforce}, nil
		}
		adm := NewAdmission(nil, ScopedRateSource{}, nil, "rep-clamp-shadow", ModeShadow, loader, AdmissionConfig{})
		// The empty planned chain makes estimation fail; shadow answers with
		// a would-deny plan in the CLAMPED mode, enforce would return an
		// error — the shape of the outcome proves the stored enforce was
		// degraded to shadow before admission.
		plan, err := adm.Plan(ctx, Request{OrgID: "org-1"})
		require.NoError(t, err)
		require.Equal(t, ModeShadow, plan.Mode, "stored enforce served under the shadow gate")
		require.NotEmpty(t, plan.WouldDeny)
	})

	t.Run("unclamped enforce org still denies at runtime", func(t *testing.T) {
		loader := func(context.Context, string) (OrgSettings, error) {
			return OrgSettings{Mode: ModeEnforce}, nil
		}
		adm := NewAdmission(nil, ScopedRateSource{}, nil, "rep-clamp-enforce", ModeEnforce, loader, AdmissionConfig{})
		_, err := adm.Plan(ctx, Request{OrgID: "org-1"})
		require.Error(t, err, "no clamp — the stored enforce mode stays authoritative")
	})
}

func TestValidTermination(t *testing.T) {
	for _, term := range []Termination{
		TerminationCompleted, TerminationClientCancel, TerminationIdleTimeout,
		TerminationUpstreamErr, TerminationPolicyDenied,
	} {
		require.True(t, ValidTermination(term), term)
	}
	require.False(t, ValidTermination(""))
	require.False(t, ValidTermination("cancelled"))
}

// TestReservationTuplesJSON_wireContract pins the event field shape the
// consumer parses (NEXT-18d parseReservationTuples): snake_case keys and
// exact µUSD integers.
func TestReservationTuplesJSON_wireContract(t *testing.T) {
	rsv := &Reservation{Scopes: []ScopeReserve{
		{Scope: ScopeWallet, Key: "org-1", Period: "", AllowanceID: 42, Bound: 1500000},
		{Scope: ScopeTeamMonth, Key: "team-9", Period: "2026-10", AllowanceID: 43, Bound: 900000},
	}}
	var decoded []map[string]any
	require.NoError(t, json.Unmarshal([]byte(rsv.TuplesJSON()), &decoded))
	require.Len(t, decoded, 2)
	require.Equal(t, "wallet", decoded[0]["scope_kind"])
	require.Equal(t, "org-1", decoded[0]["scope_key"])
	require.Empty(t, decoded[0]["period"])
	require.InDelta(t, float64(42), decoded[0]["allowance_id"], 0)
	require.InDelta(t, float64(1500000), decoded[0]["bound_micro_usd"], 0)
	require.Equal(t, "team_month", decoded[1]["scope_kind"])
	require.Equal(t, "2026-10", decoded[1]["period"])

	// Nothing reserved → empty field, which the consumer treats as legacy.
	require.Empty(t, (*Reservation)(nil).TuplesJSON())
	require.Empty(t, (&Reservation{}).TuplesJSON())
}

func TestDenialWrapsScopeError(t *testing.T) {
	inner := errors.New("boom")
	d := &Denial{Scope: ScopeTeamMonth, Err: inner}
	require.Equal(t, ScopeTeamMonth, d.Scope)
	require.ErrorIs(t, d.Err, inner)
	require.ErrorIs(t, error(d), inner)
	require.Contains(t, d.Error(), "team_month")
	var nilD *Denial
	require.NotPanics(t, func() { _ = nilD.Error(); _ = nilD.Unwrap() })
}

// TestAdmissionNilAndOffSafety: a nil controller and a controller gated to
// off must keep every pipeline touchpoint a no-op.
func TestAdmissionNilAndOffSafety(t *testing.T) {
	var nilAdm *Admission
	ctx := context.Background()
	require.NotPanics(t, func() {
		plan, err := nilAdm.Plan(ctx, Request{OrgID: "org"})
		require.NoError(t, err)
		require.Equal(t, ModeOff, plan.Mode)
		rsv, err := nilAdm.Reserve(ctx, plan)
		require.ErrorIs(t, err, ErrNotReserved)
		require.Nil(t, rsv)
		nilAdm.Finalize(rsv, 5, 5)
		nilAdm.Start(ctx)
		nilAdm.Stop()
		nilAdm.Shutdown(ctx)
		require.Equal(t, int64(0), int64(nilAdm.LocalEscrow()))
	})

	off := NewAdmission(nil, ScopedRateSource{}, nil, "rep-off", ModeOff, nil, AdmissionConfig{})
	require.NotPanics(t, func() {
		plan, err := off.Plan(ctx, Request{OrgID: "org"})
		require.NoError(t, err)
		require.Equal(t, ModeOff, plan.Mode)
		rsv, err := off.Reserve(ctx, plan)
		require.ErrorIs(t, err, ErrNotReserved)
		require.Nil(t, rsv)
		off.Start(ctx) // must not launch the housekeeping loop
		off.Stop()
		off.Shutdown(ctx)
	})
}

// TestReservationConfigDefaults pins the §14/§5.1 cycle parameters.
func TestReservationConfigDefaults(t *testing.T) {
	def := DefaultAdmissionConfig()
	require.Equal(t, 5*time.Second, def.PreCheckTTL)
	require.Equal(t, 60*time.Second, def.RenewalInterval)
	require.Equal(t, 10*time.Second, def.IdleReturn)
	require.Equal(t, 5*time.Second, def.OrgTTL)

	filled := AdmissionConfig{}.withDefaults()
	require.Equal(t, def, filled)
}

func TestRefusalScopePrefersWallet(t *testing.T) {
	reqs := []GrantRequest{
		{Scope: ScopeTeamMonth, Key: "t"},
		{Scope: ScopeWallet, Key: "o"},
	}
	require.Equal(t, ScopeWallet, refusalScope(reqs))
	require.Equal(t, ScopeTeamMonth, refusalScope(reqs[:1]))
	require.Equal(t, ScopeWallet, refusalScope(nil))
}
