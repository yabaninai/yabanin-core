package guardhooks

// The manifest not_covered block. A pack may explicitly declare which
// OWASP-2026 scenarios (the closed registry EV-A01…EV-A08) it does NOT
// cover, and why: a signed, honest denial. Silence about a scenario is
// not a denial — it means coverage unknown, exactly like a missing
// coverage block; only an explicit row states partial or not_covered.
//
// Honesty contract: the covered/partial/not_covered/unknown view model
// (CoverageStateFor) reads this block together with the coverage block.
// A scenario id may never be both claimed (coverage) and denied
// (not_covered) by the same manifest — that contradiction is rejected
// at decode, so a pack cannot say "I cover EV-A07" and "I do not cover
// EV-A07" at once.

import "fmt"

const (
	// MaxNotCoveredEntries bounds the not_covered block (parity with
	// MaxCoverageEntries) so decoding and validation stay cheap even for
	// a hostile manifest.
	MaxNotCoveredEntries = 64
	// MaxNotCoveredReasonLen bounds one denial reason: a sentence of
	// explanation, not prose dump.
	MaxNotCoveredReasonLen = 256
)

// The four states of the coverage view model. They are the complete and
// disjoint vocabulary of "what does this pack say about scenario X":
// covered — a signed coverage claim exists; partial / not_covered — a
// signed denial row exists (partial = the text-signal part is coverable,
// the reason names the part that is not); unknown — no statement at all.
// Absence of a statement is NEVER upgraded to covered.
const (
	CoverageStateCovered    = "covered"
	CoverageStatePartial    = "partial"
	CoverageStateNotCovered = "not_covered"
	CoverageStateUnknown    = "unknown"
)

// NotCoveredEntry is one declared denial row: the scenario id from the
// closed EV-A01…EV-A08 registry, the denial state and the mandatory
// reason (why the scenario is not — or only partly — covered by this
// pack). A row without a reason is invalid: an unexplained denial is
// indistinguishable from no denial.
type NotCoveredEntry struct {
	EvID   string `json:"ev_id"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}

// validateNotCoveredShape is the decode-time half of not_covered
// validation: ids from the closed registry, an explicit denial state, a
// mandatory bounded reason, unique rows and a bounded block size.
func validateNotCoveredShape(entries []NotCoveredEntry) error {
	if len(entries) == 0 {
		return nil
	}
	if len(entries) > MaxNotCoveredEntries {
		return fmt.Errorf("guard pack manifest: %d not_covered entries exceeds the %d-entry limit", len(entries), MaxNotCoveredEntries)
	}
	seenEv := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, known := KnownEvIDs[entry.EvID]; !known {
			return fmt.Errorf("guard pack manifest: not_covered ev_id %q is not in the scenario registry (EV-A01…EV-A08)", entry.EvID)
		}
		if entry.State != CoverageStatePartial && entry.State != CoverageStateNotCovered {
			return fmt.Errorf("guard pack manifest: not_covered ev_id %q has invalid state %q (only %q or %q)", entry.EvID, entry.State, CoverageStatePartial, CoverageStateNotCovered)
		}
		if entry.Reason == "" || len(entry.Reason) > MaxNotCoveredReasonLen {
			return fmt.Errorf("guard pack manifest: not_covered ev_id %q requires a reason (1..%d characters)", entry.EvID, MaxNotCoveredReasonLen)
		}
		if _, dup := seenEv[entry.EvID]; dup {
			return fmt.Errorf("guard pack manifest: duplicate not_covered ev_id %q", entry.EvID)
		}
		seenEv[entry.EvID] = struct{}{}
	}
	return nil
}

// validateCoverageNotCoveredConsistency enforces the contradiction rule
// coverage ∩ not_covered = ∅: a scenario may not be claimed by a
// coverage row and denied by a not_covered row of the same manifest.
// Violation makes the manifest invalid at decode.
func validateCoverageNotCoveredConsistency(coverage []CoverageEntry, notCovered []NotCoveredEntry) error {
	if len(coverage) == 0 || len(notCovered) == 0 {
		return nil
	}
	denied := make(map[string]struct{}, len(notCovered))
	for _, entry := range notCovered {
		denied[entry.EvID] = struct{}{}
	}
	for _, entry := range coverage {
		for _, id := range entry.EvIDs {
			if _, clash := denied[id]; clash {
				return fmt.Errorf("guard pack manifest: scenario %q is both claimed (coverage rule %q) and denied (not_covered) — contradiction", id, entry.RuleID)
			}
		}
	}
	return nil
}

// DeclaresNotCovered reports whether the manifest carries a not_covered
// declaration. Absence means unknown, never "covers everything".
func (m PackManifest) DeclaresNotCovered() bool { return len(m.NotCovered) > 0 }

// CoverageStateFor answers the view model for one scenario id: covered
// (a signed claim), partial / not_covered (a signed denial row, whose
// state is the answer) or unknown (no statement at all). Unknown is
// never upgraded to covered: absence of a statement is not coverage. On
// an inconsistent struct (both a claim and a denial for one id —
// impossible in a decoded manifest, rejected at decode) the denial
// wins, so the view never over-reports coverage.
func (m PackManifest) CoverageStateFor(evID string) string {
	for _, row := range m.NotCovered {
		if row.EvID == evID {
			return row.State
		}
	}
	for _, entry := range m.Coverage {
		for _, id := range entry.EvIDs {
			if id == evID {
				return CoverageStateCovered
			}
		}
	}
	return CoverageStateUnknown
}

// CoverageStates renders the full view over the closed scenario
// registry — the audit surface of the state model: every EV-A01…EV-A08
// id with its covered/partial/not_covered/unknown verdict for this
// manifest.
func (m PackManifest) CoverageStates() map[string]string {
	states := make(map[string]string, len(KnownEvIDs))
	for id := range KnownEvIDs {
		states[id] = m.CoverageStateFor(id)
	}
	return states
}
