package guardhooks

// The manifest coverage block. A pack may
// declare, per detector rule, which OWASP-2026 scenarios (the closed registry
// EV-A01…EV-A08) its evidence tests cover. The declaration is a CLAIM by the pack author,
// signed like the rest of the manifest (W03-C02), never a synthesized or
// assumed coverage.
//
// Honesty contract: ABSENCE of a coverage declaration means "coverage
// unknown" — it is NEVER interpreted as full coverage (W03-C01 AC). The
// covered/partial/not_covered/unknown view model on top of this declaration
// is W04; this file only fixes the declaration itself and its validation.

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// MaxCoverageEntries bounds the coverage block so manifest decoding and
	// validation stay cheap even for a hostile manifest (MaxPackManifestFiles
	// parity).
	MaxCoverageEntries = 64
	// MaxCoverageRuleIDLen bounds one rule_id string (detector rule ids are
	// short identifiers, not prose).
	MaxCoverageRuleIDLen = 128
	// MaxCoverageEvidenceLen bounds one evidence_test reference (a test name
	// or file:line citation, not a log dump).
	MaxCoverageEvidenceLen = 256
)

// KnownEvIDs is the closed scenario-id registry the coverage block may
// reference (W01 map §9: EV-A01…EV-A08). An id outside this set is a decode
// error, not a silently ignored row: scenario vocabulary must not drift
// between manifest editions.
var KnownEvIDs = map[string]struct{}{
	"EV-A01": {}, // ASI01+LLM01 payload injection
	"EV-A02": {}, // ASI02 tool-argument abuse
	"EV-A03": {}, // ASI06+LLM04 poisoned content
	"EV-A04": {}, // LLM02 sensitive-data leakage (the one existing claim)
	"EV-A05": {}, // ASI09+LLM07 system-prompt leak patterns (partial)
	"EV-A06": {}, // ASI03 credential-misuse patterns
	"EV-A07": {}, // ASI05/07/08/10 behavioral — packs must not claim (gap)
	"EV-A08": {}, // LLM09/LLM10 misinformation/consumption (gap)
}

// CoverageEntry is one declared coverage row: the pack's own detector rule
// (rule_id), the scenarios its evidence covers (ev_ids) and the live test
// that carries the evidence (evidence_test, a Go test name or file:line).
type CoverageEntry struct {
	RuleID       string   `json:"rule_id"`
	EvIDs        []string `json:"ev_ids"`
	EvidenceTest string   `json:"evidence_test"`
}

// validateCoverageShape is the decode-time (manifest-level) half of coverage
// validation: everything checkable without the pack's detector rules —
// non-empty bounded rule_id without cross-pack/path syntax, ev_ids drawn
// from the closed registry without duplicates, a non-empty evidence
// reference, unique rows, bounded block size. The rule_id-must-exist-in-
// detector.json half lives at pack LOAD (ValidateCoverageAgainstRules),
// the only point where the manifest and the detector rules coexist.
func validateCoverageShape(entries []CoverageEntry) error {
	if len(entries) == 0 {
		return nil
	}
	if len(entries) > MaxCoverageEntries {
		return fmt.Errorf("guard pack manifest: %d coverage entries exceeds the %d-entry limit", len(entries), MaxCoverageEntries)
	}
	seenRule := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.RuleID == "" || len(entry.RuleID) > MaxCoverageRuleIDLen {
			return fmt.Errorf("guard pack manifest: coverage rule_id must be 1..%d characters", MaxCoverageRuleIDLen)
		}
		// Findings address pack detectors as "packID:ruleID" and file paths
		// travel through the loader: a coverage rule_id that itself carries
		// that syntax can only be an attempt to point elsewhere.
		if strings.ContainsAny(entry.RuleID, ":/\\") {
			return fmt.Errorf("guard pack manifest: coverage rule_id %q must not contain ':', '/' or '\\'", entry.RuleID)
		}
		if _, dup := seenRule[entry.RuleID]; dup {
			return fmt.Errorf("guard pack manifest: duplicate coverage rule_id %q", entry.RuleID)
		}
		seenRule[entry.RuleID] = struct{}{}
		if len(entry.EvIDs) == 0 {
			return fmt.Errorf("guard pack manifest: coverage rule_id %q must declare at least one ev_id", entry.RuleID)
		}
		seenEv := make(map[string]struct{}, len(entry.EvIDs))
		for _, id := range entry.EvIDs {
			if _, known := KnownEvIDs[id]; !known {
				return fmt.Errorf("guard pack manifest: coverage rule_id %q references unknown scenario id %q (registry: EV-A01…EV-A08)", entry.RuleID, id)
			}
			if _, dup := seenEv[id]; dup {
				return fmt.Errorf("guard pack manifest: coverage rule_id %q repeats scenario id %q", entry.RuleID, id)
			}
			seenEv[id] = struct{}{}
		}
		if entry.EvidenceTest == "" || len(entry.EvidenceTest) > MaxCoverageEvidenceLen {
			return fmt.Errorf("guard pack manifest: coverage rule_id %q requires an evidence_test reference (1..%d characters)", entry.RuleID, MaxCoverageEvidenceLen)
		}
	}
	return nil
}

// ValidateCoverageAgainstRules is the load-time half of coverage validation:
// every declared rule_id must exist in the pack's own detector.json. An
// unknown rule_id makes the pack INVALID (W03-C02 AC), so a coverage claim
// can never point at another pack's rules or at nothing.
func ValidateCoverageAgainstRules(entries []CoverageEntry, ruleIDs map[string]struct{}) error {
	if len(entries) == 0 {
		return nil
	}
	if len(ruleIDs) == 0 {
		return errors.New("guard pack coverage: pack declares coverage but has no detector rules")
	}
	for _, entry := range entries {
		if _, ok := ruleIDs[entry.RuleID]; !ok {
			return fmt.Errorf("guard pack coverage: rule_id %q is not declared by this pack's detector.json", entry.RuleID)
		}
	}
	return nil
}

// DeclaresCoverage reports whether the manifest carries a coverage
// declaration. Absence is UNKNOWN, never "full coverage": no code path may
// treat a missing declaration as a coverage statement (W03-C01 AC; the
// 4-state view model on top is W04).
func (m PackManifest) DeclaresCoverage() bool { return len(m.Coverage) > 0 }
