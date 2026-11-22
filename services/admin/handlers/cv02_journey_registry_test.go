//go:build integration

package handlers

// Negative verifier tests for the CV-02 journey case registries.
//
// These are FAST, pure unit tests of the verifier itself (no Postgres, no
// browser, no Playwright run): a full green desktop manifest passes, a
// missing or skipped desktop case fails while naming the case, and the
// archived 390px mobile cases neither satisfy nor break the desktop gate —
// absent or skipped they are only noted, an executed archived case fails
// even when a skipped occurrence or attempt would mask it. All fixtures are
// simulated Playwright reports; nothing here executes the browser suite.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// cv02VerifierFlat builds one flattened spec whose title starts with the
// given AC-* case ID and whose single result records the given status.
func cv02VerifierFlat(id, status string) cv02FlatSpec {
	return cv02VerifierFlatTests(id, status)
}

// cv02VerifierFlatTests builds one flattened spec with an explicit list of
// attempt statuses (simulating multi-attempt or multi-test observations).
func cv02VerifierFlatTests(id string, statuses ...string) cv02FlatSpec {
	tests := make([]cv02PWTest, 0, len(statuses))
	for _, status := range statuses {
		tests = append(tests, cv02PWTest{Results: []cv02PWResult{{Status: status}}})
	}
	return cv02FlatSpec{
		Suite: "cv02 verifier fixture",
		Spec: cv02PWSpec{
			Title: id + " verifier fixture case",
			Tests: tests,
		},
	}
}

// cv02VerifierDesktopManifest builds the full green desktop manifest: every
// required case passed, no archived case collected.
func cv02VerifierDesktopManifest() []cv02FlatSpec {
	specs := make([]cv02FlatSpec, 0, len(cv02RequiredJourneyCases))
	for _, id := range cv02RequiredJourneyCases {
		specs = append(specs, cv02VerifierFlat(id, "passed"))
	}
	return specs
}

func cv02VerifierContains(problems []string, substr string) bool {
	for _, p := range problems {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}

// Full desktop set: every case passed, archived cases absent — the gate is
// green and the archived outcome is reported, not silent.
func TestCV02JourneyVerifierFullDesktopSetPasses(t *testing.T) {
	specs := cv02VerifierDesktopManifest()
	cases, problems := cv02CaseVerdicts(specs)
	require.Empty(t, problems, "a full passing desktop manifest must not produce problems")
	require.Len(t, cases, len(cv02RequiredJourneyCases))
	for _, c := range cases {
		require.Equal(t, "passed", c.Status, "case %s", c.ID)
	}

	archivedCases, archivedProblems := cv02ArchivedCaseVerdicts(specs)
	require.Empty(t, archivedProblems, "absent archived cases must not affect the desktop gate")
	require.Len(t, archivedCases, len(cv02ArchivedJourneyCases))
	for _, c := range archivedCases {
		require.Equal(t, "archived-not-collected", c.Status, "archived case %s", c.ID)
	}
}

// A missing desktop case fails and names it.
func TestCV02JourneyVerifierMissingDesktopCaseFails(t *testing.T) {
	dropped := cv02RequiredJourneyCases[0]
	var specs []cv02FlatSpec
	for _, id := range cv02RequiredJourneyCases[1:] {
		specs = append(specs, cv02VerifierFlat(id, "passed"))
	}
	cases, problems := cv02CaseVerdicts(specs)
	require.NotEmpty(t, problems, "a manifest missing a desktop case must fail")
	require.True(t, cv02VerifierContains(problems, dropped),
		"the failure must name the missing case %s, got: %v", dropped, problems)
	require.True(t, cv02VerifierContains(problems, "MISSING"), "got: %v", problems)
	for _, c := range cases {
		if c.ID == dropped {
			require.Equal(t, "missing", c.Status)
		}
	}
}

// A skipped desktop case fails and names it.
func TestCV02JourneyVerifierSkippedDesktopCaseFails(t *testing.T) {
	skipped := cv02RequiredJourneyCases[len(cv02RequiredJourneyCases)-1]
	specs := cv02VerifierDesktopManifest()
	for i := range specs {
		if strings.HasPrefix(specs[i].Spec.Title, skipped) {
			specs[i].Spec.Tests[0].Results[0].Status = "skipped"
		}
	}
	_, problems := cv02CaseVerdicts(specs)
	require.NotEmpty(t, problems, "a skipped desktop case must fail the gate")
	require.True(t, cv02VerifierContains(problems, skipped),
		"the failure must name the skipped case %s, got: %v", skipped, problems)
}

// Archived 390px cases collected but entirely skipped/not-run: noted, and
// the desktop gate stays green — including duplicate occurrences.
func TestCV02JourneyVerifierArchivedSkippedKeepsGateGreen(t *testing.T) {
	for _, archivedStatus := range []string{"skipped", "not-run"} {
		specs := cv02VerifierDesktopManifest()
		for _, id := range cv02ArchivedJourneyCases {
			specs = append(specs, cv02VerifierFlat(id, archivedStatus))
		}
		_, problems := cv02CaseVerdicts(specs)
		require.Empty(t, problems, "archived %s cases must not affect the desktop gate", archivedStatus)

		archivedCases, archivedProblems := cv02ArchivedCaseVerdicts(specs)
		require.Empty(t, archivedProblems, "archived %s cases must not fail the gate", archivedStatus)
		for _, c := range archivedCases {
			require.Equal(t, "archived-skipped", c.Status, "archived case %s", c.ID)
		}
	}

	// Duplicate archived occurrences, every one skipped: still only noted.
	specs := cv02VerifierDesktopManifest()
	specs = append(specs,
		cv02VerifierFlat(cv02ArchivedJourneyCases[0], "skipped"),
		cv02VerifierFlat(cv02ArchivedJourneyCases[0], "not-run"),
	)
	_, problems := cv02CaseVerdicts(specs)
	require.Empty(t, problems, "duplicate skipped archived occurrences must not affect the desktop gate")
	_, archivedProblems := cv02ArchivedCaseVerdicts(specs)
	require.Empty(t, archivedProblems, "duplicate skipped archived occurrences must not fail the gate")
}

// An archived 390px case that EXECUTED fails the gate and names it.
func TestCV02JourneyVerifierArchivedRunFailsGate(t *testing.T) {
	for _, executed := range []string{"passed", "failed", "timedOut", "interrupted"} {
		specs := cv02VerifierDesktopManifest()
		specs = append(specs, cv02VerifierFlat(cv02ArchivedJourneyCases[0], executed))

		// The desktop registry stays green: the archived ID is known to the
		// registry, so it must not surface as an unknown case either.
		_, problems := cv02CaseVerdicts(specs)
		require.Empty(t, problems, "an executed archived case must not break desktop enforcement (status %s)", executed)

		_, archivedProblems := cv02ArchivedCaseVerdicts(specs)
		require.NotEmpty(t, archivedProblems, "an executed archived case (status %s) must fail the gate", executed)
		require.True(t, cv02VerifierContains(archivedProblems, cv02ArchivedJourneyCases[0]),
			"the failure must name the archived case, got: %v", archivedProblems)
	}
}

// A skipped observation must not mask an executed one: mixed duplicates and
// mixed attempts both fail and name the archived case.
func TestCV02JourneyVerifierArchivedMixedObservationsFailGate(t *testing.T) {
	archived := cv02ArchivedJourneyCases[1]

	// Two occurrences: a skipped first one, then an executed second one.
	specs := cv02VerifierDesktopManifest()
	specs = append(specs,
		cv02VerifierFlat(archived, "skipped"),
		cv02VerifierFlat(archived, "passed"),
	)
	_, problems := cv02CaseVerdicts(specs)
	require.Empty(t, problems, "archived duplicates must not break desktop enforcement")
	_, archivedProblems := cv02ArchivedCaseVerdicts(specs)
	require.NotEmpty(t, archivedProblems, "a skipped occurrence must not mask an executed duplicate")
	require.True(t, cv02VerifierContains(archivedProblems, archived), "got: %v", archivedProblems)

	// One occurrence, two recorded attempts: skipped first, executed second.
	specs = cv02VerifierDesktopManifest()
	specs = append(specs, cv02VerifierFlatTests(archived, "skipped", "passed"))
	_, problems = cv02CaseVerdicts(specs)
	require.Empty(t, problems, "archived attempt mixing must not break desktop enforcement")
	_, archivedProblems = cv02ArchivedCaseVerdicts(specs)
	require.NotEmpty(t, archivedProblems, "a skipped attempt must not mask an executed one")
	require.True(t, cv02VerifierContains(archivedProblems, archived), "got: %v", archivedProblems)

	// Same occurrence order, executed attempt first.
	specs = cv02VerifierDesktopManifest()
	specs = append(specs, cv02VerifierFlatTests(archived, "passed", "skipped"))
	_, archivedProblems = cv02ArchivedCaseVerdicts(specs)
	require.NotEmpty(t, archivedProblems, "an executed attempt must fail regardless of order")
	require.True(t, cv02VerifierContains(archivedProblems, archived), "got: %v", archivedProblems)
}

// Unknown and duplicate case IDs still fail (existing registry semantics).
func TestCV02JourneyVerifierUnknownAndDuplicateFail(t *testing.T) {
	specs := cv02VerifierDesktopManifest()
	specs = append(specs, cv02VerifierFlat("AC-NOPE", "passed"))
	_, problems := cv02CaseVerdicts(specs)
	require.NotEmpty(t, problems, "an unknown case ID must fail")
	require.True(t, cv02VerifierContains(problems, "AC-NOPE"), "got: %v", problems)

	dup := append(cv02VerifierDesktopManifest(), cv02VerifierFlat("AC-RT", "passed"))
	_, problems = cv02CaseVerdicts(dup)
	require.NotEmpty(t, problems, "a duplicate case ID must fail")
	require.True(t, cv02VerifierContains(problems, "appears 2 times"), "got: %v", problems)
}
