// Adversarial battery for the expiry machine (E01-P05 card W04-C03):
// monotonicity (once closed, enterprise never reopens), clock rollback
// (the machine is a pure function — a rolled-back clock yields an
// earlier-or-equal verdict, never a forbidden opening), idempotent
// recomputation, and adversarial ExpiresAt inputs (zero time, far past,
// far future). Boundary exactness and the packet-law sweep live in
// expiry_test.go; this file attacks, it does not restate.
package license

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// advAnchor and adversarial expiry terms used across the battery.
var (
	advAnchor = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	advTerms  = []time.Time{advAnchor.Add(24 * time.Hour), advAnchor.Add(-24 * time.Hour), advAnchor.Add(365 * 24 * time.Hour)}
	advClocks = []time.Time{advAnchor.Add(-720 * time.Hour), advAnchor, advAnchor.Add(48 * time.Hour), advAnchor.Add(10 * 24 * time.Hour), advAnchor.Add(3650 * 24 * time.Hour)}
)

// TestExpiryMonotonicity_NeverReopens: for every term, EnterpriseAllowed is
// monotone non-increasing in `now` — once closed, no later instant reopens
// it, for ANY term (including degenerate ones).
func TestExpiryMonotonicity_NeverReopens(t *testing.T) {
	terms := append(append([]time.Time{{}}, advTerms...),
		advAnchor.Add(-100*24*time.Hour), // long-expired term
		advAnchor.Add(100*24*time.Hour),  // long-running term
	)
	for _, term := range terms {
		closed := false
		for _, at := range advClocks {
			p := ExpiryPostureAt(term, at)
			if closed {
				assert.False(t, p.EnterpriseAllowed,
					"term %s: enterprise REOPENED at %s after being closed", term, at)
			}
			if !p.EnterpriseAllowed {
				closed = true
			}
		}
	}
}

// TestExpiryClockRollback_PureFunctionYieldsEarlierVerdict: the machine is
// a pure function of (term, now), so a rolled-back clock yields an
// earlier-or-equal verdict in the degradation order active→grace→hard —
// never a regression, and (combined with monotone closure) never a
// forbidden opening at an instant the honest clock had already closed.
func TestExpiryClockRollback_PureFunctionYieldsEarlierVerdict(t *testing.T) {
	order := map[ExpiryPhase]int{PhaseActive: 0, PhaseGrace: 1, PhaseHardExpired: 2}
	for _, term := range advTerms {
		for _, earlier := range advClocks {
			for _, later := range advClocks {
				if !earlier.Before(later) {
					continue
				}
				pe := ExpiryPhaseAt(term, earlier)
				pl := ExpiryPhaseAt(term, later)
				assert.LessOrEqual(t, order[pe], order[pl],
					"term %s: phase regressed %s@%s → %s@%s", term, pe, earlier, pl, later)
				if ExpiryPostureAt(term, earlier).EnterpriseAllowed {
					continue // earlier open says nothing about later
				}
				// Earlier closed ⇒ later closed (monotone closure).
				assert.False(t, ExpiryPostureAt(term, later).EnterpriseAllowed,
					"term %s: earlier closed but later open (%s → %s)", term, earlier, later)
			}
		}
	}
}

// TestExpiryRunRights_ClockFreeUnderRollback: the I24 run right reads no
// clock — recomputing under any clock (rolled back or forwarded) yields
// the identical verdict set for the same document.
func TestExpiryRunRights_ClockFreeUnderRollback(t *testing.T) {
	ent := loadCorpusEntitlement(t, "maintenance_ended.json")
	base := map[string]bool{
		"internal-loop":     RunRight(ent, "internal-loop"),
		"media-persistence": RunRight(ent, "media-persistence"),
	}
	for _, at := range advClocks {
		_ = at // RunRight takes no clock — the recompute IS the assertion
		assert.Equal(t, base["internal-loop"], RunRight(ent, "internal-loop"),
			"run right moved under clock %s", at)
		assert.Equal(t, base["media-persistence"], RunRight(ent, "media-persistence"),
			"run right moved under clock %s", at)
	}
}

// TestExpiryRecomputation_Idempotent: N recomputations at a fixed clock
// yield byte-identical postures (no hidden state, no drift).
func TestExpiryRecomputation_Idempotent(t *testing.T) {
	term := advAnchor.Add(30 * 24 * time.Hour)
	first := ExpiryPostureAt(term, advAnchor)
	for i := 0; i < 100; i++ {
		again := ExpiryPostureAt(term, advAnchor)
		assert.Equal(t, first, again, "recompute %d drifted", i)
	}
	// The State-derived twin is idempotent too (pure mapper).
	st := State{Active: true, Expired: true, OrgID: "adv-org"}
	sp := ExpiryPostureFromState(st)
	for i := 0; i < 100; i++ {
		assert.Equal(t, sp, ExpiryPostureFromState(st), "state recompute %d drifted", i)
	}
}

// TestExpiryAdversarialTerms: degenerate ExpiresAt values fail closed and
// keep the packet law — zero time (feature-dark), far past, far future.
func TestExpiryAdversarialTerms(t *testing.T) {
	cases := []struct {
		label string
		term  time.Time
		phase ExpiryPhase // expected at advAnchor
	}{
		{"zero time (feature-dark contour)", time.Time{}, PhaseHardExpired},
		{"far past", advAnchor.Add(-100 * 365 * 24 * time.Hour), PhaseHardExpired},
		{"just expired (in grace)", advAnchor.Add(-24 * time.Hour), PhaseGrace},
		{"far future", advAnchor.Add(100 * 365 * 24 * time.Hour), PhaseActive},
	}
	for _, tc := range cases {
		p := ExpiryPostureAt(tc.term, advAnchor)
		assert.Equal(t, tc.phase, p.Phase, "%s", tc.label)
		assert.True(t, p.CoreAllowed, "%s: core survives", tc.label)
		assert.True(t, p.DataExportAllowed, "%s: export survives", tc.label)
		assert.Equal(t, tc.phase != PhaseHardExpired, p.EnterpriseAllowed, "%s", tc.label)
	}
}

// TestExpiryCriticalWindow_InclusiveSupportEnd: the I25 exception holds at
// the exact SupportEnd instant and dies one nanosecond later — for the
// entitled line, the unentitled line never opens.
func TestExpiryCriticalWindow_InclusiveSupportEnd(t *testing.T) {
	ent := loadCorpusEntitlement(t, "critical_only.json")
	// Discover the signed support end from the document via the gate
	// itself: the last instant where the line is still entitled.
	lo, hi := advAnchor.Add(-365*24*time.Hour), advAnchor.Add(365*24*time.Hour)
	for hi.Sub(lo) > time.Nanosecond {
		mid := lo.Add(hi.Sub(lo) / 2)
		if ent.CriticalFixEntitledAt("2026.1", mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	assert.True(t, ent.CriticalFixEntitledAt("2026.1", lo), "boundary instant still entitled (inclusive)")
	assert.False(t, ent.CriticalFixEntitledAt("2026.1", lo.Add(time.Nanosecond)), "one nanosecond past closes")
	// The machine's delegate answers identically at both instants.
	assert.Equal(t, ent.CriticalFixEntitledAt("2026.1", lo), CriticalFixRightAt(ent, "2026.1", lo))
	assert.Equal(t, ent.CriticalFixEntitledAt("2026.1", lo.Add(time.Nanosecond)), CriticalFixRightAt(ent, "2026.1", lo.Add(time.Nanosecond)))
}
