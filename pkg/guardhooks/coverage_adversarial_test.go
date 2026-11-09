package guardhooks

// Adversarial battery for the coverage/not_covered sections. The
// contradiction rule: a scenario claimed by coverage AND denied by
// not_covered in the same manifest is invalid — even with a valid
// signature over the contradictory bytes. A full-coverage-style claim
// built without evidence rows is rejected (evidence is mandatory per
// row). Silence about a scenario is allowed and stays unknown. Repeated
// decode of the same bytes is stable.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCoverageAdversarialClaimOnDeniedEvInvalid(t *testing.T) {
	// A coverage row claiming a scenario that the pack's own not_covered
	// section denies is a contradiction ⇒ the manifest is invalid, in
	// both construction orders and for both denial states.
	build := func(evID string, denialState string) []byte {
		_, data := writeNotCoveredPack(t,
			[]CoverageEntry{{RuleID: "cov-rule", EvIDs: []string{"EV-A01", evID}, EvidenceTest: "TestCoverageAdversarial"}},
			[]NotCoveredEntry{{EvID: evID, State: denialState, Reason: "denied here"}})
		return data
	}
	for _, tc := range []struct {
		evID  string
		state string
	}{
		{"EV-A05", CoverageStatePartial},
		{"EV-A05", CoverageStateNotCovered},
		{"EV-A07", CoverageStateNotCovered},
		{"EV-A08", CoverageStateNotCovered},
	} {
		_, err := DecodePackManifest(build(tc.evID, tc.state))
		require.Error(t, err, "claim+deny on %s (%s) must be invalid", tc.evID, tc.state)
		require.Contains(t, err.Error(), "contradiction")
		require.Contains(t, err.Error(), tc.evID)
	}
}

func TestCoverageAdversarialSignedContradictionStillInvalid(t *testing.T) {
	// A valid signature over contradictory bytes does not legitimize
	// them: verification passes, the decode-time contradiction check
	// still rejects the manifest.
	f := newSigningFixture(t)
	detector := []byte(`{"detectors":[{"rule_id":"cov-rule","rule_version":"1","category":"secret","pattern":"MARKER_[0-9]+"}]}`)
	manifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "advpack", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files:      []PackFile{{Path: "detector.json", SHA256: sha256Sum(detector)}},
		Coverage:   []CoverageEntry{{RuleID: "cov-rule", EvIDs: []string{"EV-A07"}, EvidenceTest: "TestX"}},
		NotCovered: []NotCoveredEntry{{EvID: "EV-A07", State: CoverageStateNotCovered, Reason: "behavioral plane"}},
	}
	signed := f.signManifest(t, manifest, testSignKeyID)
	_, err := DecodePackManifestWithVerifier(signed, testVerifier(t, f))
	require.Error(t, err)
	require.Contains(t, err.Error(), "contradiction", "signature validity must not rescue a claim+deny pair")
}

func TestCoverageAdversarialFullClaimWithoutEvidenceRejected(t *testing.T) {
	// A pack claiming EVERY registry scenario ("full coverage") without
	// evidence rows is rejected: evidence_test is mandatory per row, so
	// a bare full claim cannot even decode.
	allEVs := make([]string, 0, len(KnownEvIDs))
	for id := range KnownEvIDs {
		allEVs = append(allEVs, id)
	}
	manifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "advpack", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files:    []PackFile{{Path: "detector.json", SHA256: strings.Repeat("ab", 32)}},
		Coverage: []CoverageEntry{{RuleID: "cov-rule", EvIDs: allEVs}},
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	_, err = DecodePackManifest(data)
	require.Error(t, err, "full-coverage claim without evidence must be rejected")
	require.Contains(t, err.Error(), "evidence_test")

	// The same full claim with a witness per row decodes: schema-level
	// validity is not claim acceptance — the claims review reads the
	// rows; here we only pin that the rejection above is about the
	// missing evidence, not about claiming the registry.
	_, okData := writeNotCoveredPack(t,
		[]CoverageEntry{{RuleID: "cov-rule", EvIDs: allEVs, EvidenceTest: "TestCoverageAdversarial"}},
		nil)
	decoded, err := DecodePackManifest(okData)
	require.NoError(t, err)
	states := decoded.CoverageStates()
	for id := range KnownEvIDs {
		require.Equal(t, CoverageStateCovered, states[id], "EV %s", id)
	}
}

func TestCoverageAdversarialSilenceAboutGapAllowed(t *testing.T) {
	// Silence about a gap scenario is not forbidden: a pack claiming
	// EV-A04 while saying nothing about EV-A07/EV-A08 is valid, and the
	// silent scenarios read as unknown — never covered, never denied.
	_, data := writeNotCoveredPack(t,
		[]CoverageEntry{{RuleID: "cov-rule", EvIDs: []string{"EV-A04"}, EvidenceTest: "TestCoverageAdversarialSilence"}},
		nil)
	decoded, err := DecodePackManifest(data)
	require.NoError(t, err)
	require.Equal(t, CoverageStateCovered, decoded.CoverageStateFor("EV-A04"))
	require.Equal(t, CoverageStateUnknown, decoded.CoverageStateFor("EV-A07"))
	require.Equal(t, CoverageStateUnknown, decoded.CoverageStateFor("EV-A08"))
	require.False(t, decoded.DeclaresNotCovered())
}

func TestCoverageAdversarialRepeatDecodeStable(t *testing.T) {
	// Repeat variant: decoding the same pack bytes twice yields the
	// same verdict — valid stays valid and equal, invalid fails with a
	// stable error.
	_, validData := writeNotCoveredPack(t,
		[]CoverageEntry{{RuleID: "cov-rule", EvIDs: []string{"EV-A01"}, EvidenceTest: "TestCoverageAdversarialRepeat"}},
		gapNotCoveredRows())
	first, firstErr := DecodePackManifest(validData)
	second, secondErr := DecodePackManifest(validData)
	require.NoError(t, firstErr)
	require.NoError(t, secondErr)
	require.Equal(t, first, second)
	require.Equal(t, first.CoverageStates(), second.CoverageStates())

	_, badData := writeNotCoveredPack(t,
		[]CoverageEntry{{RuleID: "cov-rule", EvIDs: []string{"EV-A06", "EV-A05"}, EvidenceTest: "TestCoverageAdversarialRepeat"}},
		gapNotCoveredRows())
	_, errOne := DecodePackManifest(badData)
	_, errTwo := DecodePackManifest(badData)
	require.Error(t, errOne, "EV-A05 is claimed and denied — contradiction")
	require.Equal(t, errOne.Error(), errTwo.Error())
}

func TestCoverageAdversarialDenialOnlyPackValid(t *testing.T) {
	// A pack that denies the gap rows and claims nothing is the honest
	// minimal shape: valid, nothing covered, gaps stated with reasons.
	_, data := writeNotCoveredPack(t, nil, gapNotCoveredRows())
	decoded, err := DecodePackManifest(data)
	require.NoError(t, err)
	require.True(t, decoded.DeclaresNotCovered())
	require.False(t, decoded.DeclaresCoverage())
	states := decoded.CoverageStates()
	require.Equal(t, CoverageStatePartial, states["EV-A05"])
	require.Equal(t, CoverageStateNotCovered, states["EV-A07"])
	require.Equal(t, CoverageStateNotCovered, states["EV-A08"])
	for _, id := range []string{"EV-A01", "EV-A02", "EV-A03", "EV-A04", "EV-A06"} {
		require.Equal(t, CoverageStateUnknown, states[id], "EV %s", id)
	}
}
