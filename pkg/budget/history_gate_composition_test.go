package budget

// Composition tests: the history-profile layer and the durable-history
// admission gate (HistoryAdmission) must form ONE gate, not two. Pins, in
// order of owner risk:
//
//   - when a HistoryAdmission is armed, CheckHistory/AdmitWithHistory
//     delegate to it — the probe is evaluated EXACTLY once per attempt, and
//     the money leg (planAfterHistory) never re-consults the gate (no
//     double gating, no double probe cost);
//   - the delegated verdict keeps BOTH error identities: this package's
//     503-class ErrHistoryCapacity AND the gate's
//     ErrHistoryUnavailable/typed outage, so callers of either layer map
//     the refusal correctly;
//   - the loss profile survives delegation: allow_loss + outage admits
//     with the visible HistoryDecision.Loss marker (the buffer's refusal
//     stays visible as the decision Reason);
//   - the mode has ONE owner: an armed gate owns the active mode, and
//     SetHistoryMode re-pins the armed gate instead of forking a second
//     mode;
//   - arming BOTH wirings (probe + capacity seam) cannot stack: the armed
//     gate takes precedence, the seam stays inert, one evaluation.

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// countingProbe is a HistoryProbe fake that counts evaluations — the
// single-enforcement-point witness.
type countingProbe struct {
	mu    sync.Mutex
	calls int
	state HistoryState
	err   error
}

func newCountingProbe(state HistoryState, err error) *countingProbe {
	return &countingProbe{state: state, err: err}
}

func (p *countingProbe) ProbeHistory(context.Context) (HistoryState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.state, p.err
}

func (p *countingProbe) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// TestAdmitWithHistoryDelegatesToArmedGate: with the N10-P04-T03 gate armed
// (and no capacity seam), AdmitWithHistory evaluates the probe exactly once
// per attempt — the money leg must not re-consult it — and the typed
// decision/refusal carry the composed identities.
func TestAdmitWithHistoryDelegatesToArmedGate(t *testing.T) {
	ctx := context.Background()

	t.Run("reject profile: outage refuses with both error identities, probed once", func(t *testing.T) {
		adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
		probe := newCountingProbe(HistoryStateBufferFull, nil)
		adm.SetHistoryAdmission(NewHistoryAdmission(probe, HistoryModeReject, nil))

		rsv, dec, err := adm.AdmitWithHistory(ctx, historyRequest("org-compose"), "k-reject")
		require.ErrorIs(t, err, ErrHistoryCapacity,
			"this package's 503-class identity must survive delegation")
		require.ErrorIs(t, err, ErrHistoryUnavailable,
			"the N10-P04-T03 identity must survive delegation")
		var outage *HistoryOutageError
		require.ErrorAs(t, err, &outage, "the typed outage rides the refusal")
		require.Equal(t, HistoryStateBufferFull, outage.State)
		require.Nil(t, rsv)
		require.Equal(t, HistoryModeReject, dec.Mode)
		require.Equal(t, HistoryRejectedFull, dec.State)
		require.False(t, dec.Admitted())
		require.Error(t, dec.Reason, "the refusal carries the gate's verdict")
		require.Equal(t, 1, probe.callCount(),
			"the history leg must be evaluated exactly once per attempt (no Plan re-consult)")
	})

	t.Run("allow_loss profile: outage admits with the loss marker, probed once", func(t *testing.T) {
		adm, db := newHistoryStoreAdmission(t, ModeEnforce)
		probe := newCountingProbe(HistoryStateBufferFull, nil)
		adm.SetHistoryAdmission(NewHistoryAdmission(probe, HistoryModeAllowLoss, nil))
		grantsBefore := db.grantCount()

		rsv, dec, err := adm.AdmitWithHistory(ctx, historyRequest("org-compose"), "k-loss")
		require.NoError(t, err)
		require.NotNil(t, rsv, "the loss profile keeps serving (money leg unchanged)")
		require.Equal(t, 1, db.grantCount()-grantsBefore, "the escrow grant is unchanged by the history loss")
		require.Equal(t, HistoryModeAllowLoss, dec.Mode)
		require.Equal(t, HistoryLossAccepted, dec.State)
		require.True(t, dec.Loss, "the visible loss marker must survive delegation")
		require.Error(t, dec.Reason, "the loss marker keeps the buffer's refusal visible")
		require.Equal(t, 1, probe.callCount(),
			"the history leg must be evaluated exactly once per attempt (no Plan re-consult)")
	})

	t.Run("healthy gate: persisted, probed once", func(t *testing.T) {
		adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
		probe := newCountingProbe(HistoryStateOK, nil)
		adm.SetHistoryAdmission(NewHistoryAdmission(probe, HistoryModeReject, nil))

		rsv, dec, err := adm.AdmitWithHistory(ctx, historyRequest("org-compose"), "k-ok")
		require.NoError(t, err)
		require.NotNil(t, rsv)
		require.Equal(t, HistoryPersisted, dec.State)
		require.False(t, dec.Loss)
		require.Equal(t, 1, probe.callCount(),
			"a healthy attempt still probes exactly once (no Plan re-consult)")
	})
}

// TestHistoryModeSingleOwnerWhenGateArmed: the armed HistoryAdmission owns
// the ACTIVE mode; SetHistoryMode re-pins it (fail-safe resolution) instead
// of forking a second mode between the layers.
func TestHistoryModeSingleOwnerWhenGateArmed(t *testing.T) {
	adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
	probe := newCountingProbe(HistoryStateOK, nil)

	adm.SetHistoryMode(HistoryModeAllowLoss) // seam-layer pin before arming
	gate := NewHistoryAdmission(probe, HistoryModeReject, nil)
	adm.SetHistoryAdmission(gate)

	require.Equal(t, HistoryModeReject, adm.historyProfile(),
		"the armed gate owns the active mode — the seam pin does not fork it")

	adm.SetHistoryMode(HistoryModeAllowLoss) // re-pin after arming
	require.Equal(t, HistoryModeAllowLoss, gate.Mode(),
		"SetHistoryMode must reach the armed gate: one mode vocabulary, one owner")
	require.Equal(t, HistoryModeAllowLoss, adm.historyProfile())

	adm.SetHistoryMode("garbage")
	require.Equal(t, HistoryModeReject, gate.Mode(),
		"an unknown value fail-safes the armed gate back to reject")
}

// TestHistoryGateBothWiringsSingleEvaluation: arming the N10-P04-T03 gate
// AND the capacity seam must not stack into two evaluations — the armed
// gate takes precedence (documented in SetHistoryCapacity), the seam stays
// inert, and the attempt still probes exactly once.
func TestHistoryGateBothWiringsSingleEvaluation(t *testing.T) {
	ctx := context.Background()
	adm, _ := newHistoryStoreAdmission(t, ModeEnforce)

	seam := newHistoryCheck(errBufferFull) // would refuse if consulted
	adm.SetHistoryCapacity(seam.evaluate)
	probe := newCountingProbe(HistoryStateOK, nil)
	adm.SetHistoryAdmission(NewHistoryAdmission(probe, HistoryModeReject, nil))

	rsv, dec, err := adm.AdmitWithHistory(ctx, historyRequest("org-compose"), "k-both")
	require.NoError(t, err, "the armed gate (healthy) decides — not the seam (full)")
	require.NotNil(t, rsv)
	require.Equal(t, HistoryPersisted, dec.State)
	require.Equal(t, 1, probe.callCount(), "exactly one probe evaluation")
	require.Zero(t, seam.callCount(), "the seam stays inert while the gate is armed")
}
