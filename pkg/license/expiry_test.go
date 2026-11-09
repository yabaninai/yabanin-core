// Expiry machine battery (E01-P05 card W04-C01, batch B): the packet law
// «истечение не открывает запрещённых действий и не блокирует экспорт
// данных/core» pinned over the total phase partition, the boundary
// instants, the served-State derivation and the entitlement delegates.
// Adversarial inputs (clock rollback monotonicity, recomputation
// idempotence) are W04-C03's expiry_adversarial_test.go.
package license

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exAnchor is a fixed anchor for the machine's absolute-date probes (the
// machine is injectable-clock, so absolute dates are deterministic here —
// unlike StateFromClaims, which is probed via relative offsets).
var exAnchor = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)

func TestExpiryPhase_TotalPartitionAndBoundaries(t *testing.T) {
	expiresAt := time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		at    time.Time
		want  ExpiryPhase
		label string
	}{
		{expiresAt.Add(-365 * 24 * time.Hour), PhaseActive, "a year before"},
		{expiresAt.Add(-time.Nanosecond), PhaseActive, "the last nanosecond of the term"},
		{expiresAt, PhaseActive, "the exact ExpiresAt instant is still active (inclusive)"},
		{expiresAt.Add(time.Nanosecond), PhaseGrace, "one nanosecond past expiry enters grace"},
		{expiresAt.Add(3 * 24 * time.Hour), PhaseGrace, "mid-grace"},
		{GraceEnd(expiresAt).Add(-time.Nanosecond), PhaseGrace, "the last grace nanosecond"},
		{GraceEnd(expiresAt), PhaseHardExpired, "the exact grace-end instant (State dead zone) fails closed as hard-expired"},
		{GraceEnd(expiresAt).Add(time.Nanosecond), PhaseHardExpired, "one nanosecond past grace hard-expires"},
		{GraceEnd(expiresAt).Add(365 * 24 * time.Hour), PhaseHardExpired, "far future"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ExpiryPhaseAt(expiresAt, tc.at), "%s", tc.label)
	}
	assert.Equal(t, expiresAt.Add(GracePeriod), GraceEnd(expiresAt), "GraceEnd is ExpiresAt+GracePeriod")

	// The zero ExpiresAt (no activation document — feature-dark contour)
	// is hard-expired: fail closed, never an accidental active posture.
	assert.Equal(t, PhaseHardExpired, ExpiryPhaseAt(time.Time{}, exAnchor))
}

func TestExpiryPosture_PacketLawHoldsAtEveryInstant(t *testing.T) {
	expiresAt := time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC)
	instants := []time.Time{
		expiresAt.Add(-24 * time.Hour),
		expiresAt,
		expiresAt.Add(time.Nanosecond),
		expiresAt.Add(6 * 24 * time.Hour),
		GraceEnd(expiresAt),                       // the dead-zone instant
		GraceEnd(expiresAt).Add(-time.Nanosecond), // last grace nanosecond
		GraceEnd(expiresAt).Add(time.Nanosecond),  // first hard-expired nanosecond
		GraceEnd(expiresAt).Add(90 * 24 * time.Hour),
	}
	for _, at := range instants {
		p := ExpiryPostureAt(expiresAt, at)
		assert.True(t, p.CoreAllowed, "expiry never blocks core (at %s)", at)
		assert.True(t, p.DataExportAllowed, "expiry never blocks data export (at %s)", at)
		assert.Equal(t, p.Phase != PhaseHardExpired, p.EnterpriseAllowed,
			"enterprise is open exactly before hard expiry (at %s)", at)
	}

	// Fail-closed boundary: at the exact grace-end instant enterprise is
	// already closed (strict Before — same verdict as State.Active).
	p := ExpiryPostureAt(expiresAt, GraceEnd(expiresAt))
	assert.False(t, p.EnterpriseAllowed, "the grace-end instant closes enterprise")
	assert.True(t, p.CoreAllowed && p.DataExportAllowed)

	// The feature-dark contour (no activation document).
	dark := ExpiryPostureAt(time.Time{}, exAnchor)
	assert.False(t, dark.EnterpriseAllowed)
	assert.True(t, dark.CoreAllowed, "even the dark contour keeps core")
	assert.True(t, dark.DataExportAllowed, "even the dark contour keeps data export")
}

func TestExpiryPosture_FromStateDerivation(t *testing.T) {
	base := func(mod func(*State)) State {
		st := State{Active: true, OrgID: "ex-org"}
		if mod != nil {
			mod(&st)
		}
		return st
	}
	cases := []struct {
		label string
		st    State
		phase ExpiryPhase
		ent   bool
	}{
		{"active", base(nil), PhaseActive, true},
		{"grace", base(func(s *State) { s.Active, s.Expired = true, true }), PhaseGrace, true},
		{"hard", base(func(s *State) { s.Active, s.HardExpired = false, true }), PhaseHardExpired, false},
		{"dead zone / zero state", State{}, PhaseHardExpired, false},
	}
	for _, tc := range cases {
		p := ExpiryPostureFromState(tc.st)
		assert.Equal(t, tc.phase, p.Phase, "%s", tc.label)
		assert.Equal(t, tc.ent, p.EnterpriseAllowed, "%s", tc.label)
		assert.True(t, p.CoreAllowed, "%s: core stays allowed", tc.label)
		assert.True(t, p.DataExportAllowed, "%s: export stays allowed", tc.label)
	}

	// The unreachable Active∧Expired∧HardExpired shape still fails closed.
	p := ExpiryPostureFromState(State{Active: true, Expired: true, HardExpired: true})
	assert.False(t, p.EnterpriseAllowed)
}

// TestExpiryPosture_AgreesWithStateFromClaims pins the machine against the
// served-state derivation: for offsets far from any boundary (hours, so the
// real clock cannot flake), ExpiryPostureAt and StateFromClaims must agree
// on enterprise openness and phase.
func TestExpiryPosture_AgreesWithStateFromClaims(t *testing.T) {
	cases := []struct {
		offset time.Duration // ExpiresAt = now.Add(offset): positive = term still running
		phase  ExpiryPhase
		ent    bool
	}{
		{+48 * time.Hour, PhaseActive, true},
		{-48 * time.Hour, PhaseGrace, true},
		{-8 * 24 * time.Hour, PhaseHardExpired, false},
	}
	for _, tc := range cases {
		c := Claims{
			OrgID:     "ex-org",
			Features:  []string{"protection-pack"},
			ExpiresAt: time.Now().Add(tc.offset),
			IssuedAt:  time.Now().Add(-720 * time.Hour),
			Nonce:     "ex-agree",
		}
		st := StateFromClaims(c)
		p := ExpiryPostureAt(c.ExpiresAt, time.Now())
		assert.Equal(t, st.Active, p.EnterpriseAllowed,
			"offset %s: machine enterprise == served State.Active", tc.offset)
		assert.Equal(t, tc.phase, p.Phase, "offset %s", tc.offset)
		assert.Equal(t, st.Expired || st.HardExpired, p.Phase != PhaseActive,
			"offset %s: degradation flags agree", tc.offset)
	}
}

// TestExpiryEntitlementDelegates pins the machine's entitlement plane: the
// delegates answer exactly as the maintenance gates do (no re-derivation,
// no divergence), and the run right reads no clock (I24).
func TestExpiryEntitlementDelegates(t *testing.T) {
	ended := loadCorpusEntitlement(t, "maintenance_ended.json")
	critical := loadCorpusEntitlement(t, "critical_only.json")

	// Delegation equality across fixed instants (incl. exact boundaries).
	instants := []time.Time{
		exAnchor,
		ended.MaintenanceEnd,
		ended.MaintenanceEnd.Add(24 * time.Hour),
		exAnchor.Add(365 * 24 * time.Hour),
	}
	for _, at := range instants {
		assert.Equal(t, ended.UpdatesEntitledAt(at), UpdateRightAt(ended, at), "UpdateRightAt delegates verbatim (at %s)", at)
		assert.Equal(t, critical.CriticalFixEntitledAt("2026.1", at), CriticalFixRightAt(critical, "2026.1", at),
			"CriticalFixRightAt delegates verbatim (at %s)", at)
	}

	// I24 law: the run right is identical at every instant and after
	// maintenance end — no clock input can move it.
	for _, at := range instants {
		require.True(t, RunRight(ended, "internal-loop"), "run right at %s", at)
		require.False(t, RunRight(ended, "media-persistence"))
	}

	// The packet law on the entitlement plane: maintenance end closes
	// updates (never re-opens anything) and the I25 exception is exactly
	// the critical-fix window — no right outside the signed documents.
	assert.False(t, UpdateRightAt(ended, exAnchor), "updates closed after the term")
	assert.True(t, CriticalFixRightAt(critical, "2026.1", exAnchor), "I25 exception while supported")
	assert.False(t, CriticalFixRightAt(critical, "2027.0", exAnchor), "flag-off line fails closed")
	assert.False(t, CriticalFixRightAt(ended, "2026.1", exAnchor), "line absent from the document fails closed")
}
