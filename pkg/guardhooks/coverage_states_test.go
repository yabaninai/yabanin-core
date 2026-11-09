package guardhooks

// The 4-state coverage view model: covered / partial / not_covered /
// unknown, derived from the decoded manifest's coverage claims and
// not_covered denials. The load-bearing rule: absence of a statement is
// UNKNOWN, never covered — a pack that stays silent about a scenario
// does not cover it by implication.

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// statesFixtureManifest decodes a real, shape-valid pack that uses all
// four states at once: coverage claims for EV-A01…A04, denials for
// EV-A05 (partial), EV-A07 and EV-A08 (not_covered), silence on EV-A06.
func statesFixtureManifest(t *testing.T) PackManifest {
	t.Helper()
	root, data := writeNotCoveredPack(t, []CoverageEntry{
		{RuleID: "cov-rule", EvIDs: []string{"EV-A01", "EV-A02", "EV-A03", "EV-A04"}, EvidenceTest: "TestCoverageStatesFourStates"},
	}, gapNotCoveredRows())
	verified, _, err := LoadDetectorPackWithVerifier(root, data, nil)
	require.NoError(t, err)
	return verified.Manifest
}

func TestCoverageStatesFourStatesDistinguishable(t *testing.T) {
	// Allowed variant: one real decoded pack exercising all four states;
	// each verdict is distinct and lands on the expected EV.
	manifest := statesFixtureManifest(t)
	states := manifest.CoverageStates()
	require.Len(t, states, len(KnownEvIDs), "the view answers for the whole closed registry")

	expect := map[string]string{
		"EV-A01": CoverageStateCovered,
		"EV-A02": CoverageStateCovered,
		"EV-A03": CoverageStateCovered,
		"EV-A04": CoverageStateCovered,
		"EV-A05": CoverageStatePartial,
		"EV-A06": CoverageStateUnknown,
		"EV-A07": CoverageStateNotCovered,
		"EV-A08": CoverageStateNotCovered,
	}
	require.Equal(t, expect, states)
	for id, want := range expect {
		require.Equal(t, want, manifest.CoverageStateFor(id), "EV %s", id)
	}
}

func TestCoverageStatesVocabularyDisjoint(t *testing.T) {
	// The four states are pairwise distinct vocabulary — no state can
	// collapse into another silently.
	all := []string{CoverageStateCovered, CoverageStatePartial, CoverageStateNotCovered, CoverageStateUnknown}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			require.NotEqual(t, all[i], all[j])
		}
	}
}

func TestCoverageStatesAbsenceIsUnknown(t *testing.T) {
	// Empty variant: a pack with NEITHER coverage NOR not_covered
	// answers unknown for every registry id — not covered, not denied,
	// exactly "coverage unknown".
	root, data := writeNotCoveredPack(t, nil, nil)
	verified, _, err := LoadDetectorPackWithVerifier(root, data, nil)
	require.NoError(t, err)
	require.False(t, verified.Manifest.DeclaresCoverage())
	require.False(t, verified.Manifest.DeclaresNotCovered())
	for id := range KnownEvIDs {
		require.Equal(t, CoverageStateUnknown, verified.Manifest.CoverageStateFor(id), "EV %s", id)
	}
	require.Equal(t, map[string]string{
		"EV-A01": CoverageStateUnknown, "EV-A02": CoverageStateUnknown, "EV-A03": CoverageStateUnknown, "EV-A04": CoverageStateUnknown,
		"EV-A05": CoverageStateUnknown, "EV-A06": CoverageStateUnknown, "EV-A07": CoverageStateUnknown, "EV-A08": CoverageStateUnknown,
	}, verified.Manifest.CoverageStates())
}

func TestCoverageStatesUnknownNeverCovered(t *testing.T) {
	// The honesty rule encoded: claiming EV-A04 does not cover EV-A07 —
	// silence about a scenario never upgrades to covered, and the view
	// answers unknown even for ids outside the registry (total
	// function, no invented states).
	manifest := statesFixtureManifest(t)
	require.Equal(t, CoverageStateCovered, manifest.CoverageStateFor("EV-A04"))
	require.Equal(t, CoverageStateUnknown, manifest.CoverageStateFor("EV-A06"), "silence is unknown, not covered")
	require.NotEqual(t, CoverageStateCovered, manifest.CoverageStateFor("EV-A06"))
	require.Equal(t, CoverageStateUnknown, manifest.CoverageStateFor("EV-A99"), "ids outside the registry are unknown, never covered")
}

func TestCoverageStatesSilentAboutGapIsUnknownNotDenied(t *testing.T) {
	// A pack that claims EV-A04 and stays silent about the gap rows is
	// VALID: silence about a gap scenario is allowed and means unknown —
	// only an explicit not_covered row states partial/not_covered.
	root, data := writeNotCoveredPack(t, []CoverageEntry{
		{RuleID: "cov-rule", EvIDs: []string{"EV-A04"}, EvidenceTest: "TestCoverageStatesSilentAboutGap"},
	}, nil)
	verified, _, err := LoadDetectorPackWithVerifier(root, data, nil)
	require.NoError(t, err)
	require.Equal(t, CoverageStateUnknown, verified.Manifest.CoverageStateFor("EV-A07"))
	require.Equal(t, CoverageStateUnknown, verified.Manifest.CoverageStateFor("EV-A08"))
	require.False(t, verified.Manifest.DeclaresNotCovered())
}

func TestCoverageStatesDenialWinsOnInconsistentStruct(t *testing.T) {
	// A decoded manifest can never carry a claim and a denial for the
	// same id (rejected at decode); if an inconsistent struct reaches
	// the view anyway, the DENIAL wins so the view never over-reports
	// coverage.
	inconsistent := PackManifest{
		Coverage:   []CoverageEntry{{RuleID: "cov-rule", EvIDs: []string{"EV-A07"}, EvidenceTest: "TestX"}},
		NotCovered: []NotCoveredEntry{{EvID: "EV-A07", State: CoverageStateNotCovered, Reason: "behavioral plane"}},
	}
	require.Equal(t, CoverageStateNotCovered, inconsistent.CoverageStateFor("EV-A07"))
}

func TestCoverageStatesSurviveJSONRoundtrip(t *testing.T) {
	// The states computed before and after a marshal/decode roundtrip of
	// the manifest are identical — the view is a function of the
	// decoded section contents only.
	manifest := statesFixtureManifest(t)
	before := manifest.CoverageStates()
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	redecoded, err := DecodePackManifest(data)
	require.NoError(t, err)
	require.Equal(t, before, redecoded.CoverageStates())
}
