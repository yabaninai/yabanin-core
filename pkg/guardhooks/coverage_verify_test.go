package guardhooks

// Coverage validation + signing. The coverage block is validated at
// DECODE (shape — coverage_test.go) and at LOAD (rule_id must exist in the
// pack's own detector.json — the anchor in LoadDetectorPackWithVerifier),
// and it is SIGNED: tampering any coverage row of a signed pack after
// signing breaks verification, while coverage-less signed packs keep
// verifying byte-identically.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeCoveragePack writes an UNSIGNED one-detector pack (rule "cov-rule")
// whose manifest declares the given coverage, and returns the pack root plus
// manifest bytes.
func writeCoveragePack(t *testing.T, coverage []CoverageEntry) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	detector := []byte(`{"detectors":[{"rule_id":"cov-rule","rule_version":"1","category":"secret","pattern":"MARKER_[0-9]+"}]}`)
	require.NoError(t, os.WriteFile(filepath.Join(root, "detector.json"), detector, 0o600))
	manifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "covpack", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files:    []PackFile{{Path: "detector.json", SHA256: sha256Sum(detector)}},
		Coverage: coverage,
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	return root, data
}

// signedCoverageManifest returns a SIGNED manifest (v1 ed25519 over the
// canonical payload, which includes the coverage block) plus its verifier.
func signedCoverageManifest(t *testing.T, coverage []CoverageEntry) ([]byte, SignatureVerifier) {
	t.Helper()
	f := newSigningFixture(t)
	detector := []byte(`{"detectors":[{"rule_id":"cov-rule","rule_version":"1","category":"secret","pattern":"MARKER_[0-9]+"}]}`)
	manifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "covpack", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files:    []PackFile{{Path: "detector.json", SHA256: sha256Sum(detector)}},
		Coverage: coverage,
	}
	return f.signManifest(t, manifest, testSignKeyID), testVerifier(t, f)
}

func TestPackCoverageVerifyTamperedCoverageFails(t *testing.T) {
	signed, verifier := signedCoverageManifest(t, []CoverageEntry{
		{RuleID: "cov-rule", EvIDs: []string{"EV-A04"}, EvidenceTest: "TestCovEvidence"},
	})
	_, err := DecodePackManifestWithVerifier(signed, verifier)
	require.NoError(t, err, "the untouched signed pack with coverage must verify")

	tamper := func(mutate func(*CoverageEntry)) {
		var manifest PackManifest
		require.NoError(t, json.Unmarshal(signed, &manifest))
		mutate(&manifest.Coverage[0])
		data, marshalErr := json.Marshal(manifest)
		require.NoError(t, marshalErr)
		_, err := DecodePackManifestWithVerifier(data, verifier)
		require.Error(t, err, "coverage is part of the signed payload — post-signing mutation must fail verification")
		require.Contains(t, err.Error(), "signature verification failed")
	}
	t.Run("rule-id-substituted", func(t *testing.T) {
		tamper(func(e *CoverageEntry) { e.RuleID = "other-rule" })
	})
	t.Run("ev-id-substituted", func(t *testing.T) {
		tamper(func(e *CoverageEntry) { e.EvIDs = []string{"EV-A05"} })
	})
	t.Run("evidence-swapped", func(t *testing.T) {
		tamper(func(e *CoverageEntry) { e.EvidenceTest = "TestNeverRan" })
	})
	t.Run("row-dropped", func(t *testing.T) {
		var manifest PackManifest
		require.NoError(t, json.Unmarshal(signed, &manifest))
		manifest.Coverage = nil
		data, err := json.Marshal(manifest)
		require.NoError(t, err)
		_, err = DecodePackManifestWithVerifier(data, verifier)
		require.Error(t, err, "removing a signed coverage row is a mutation too")
		require.Contains(t, err.Error(), "signature verification failed")
	})
}

func TestPackCoverageVerifySignedNoCoverageRoundtrip(t *testing.T) {
	// A signed pack WITHOUT coverage (the pre-W03 shape) must still verify
	// under the new code: the canonical payload for nil coverage is
	// byte-identical to the pre-W03 projection (pinned in coverage_test.go).
	signed, verifier := signedCoverageManifest(t, nil)
	manifest, err := DecodePackManifestWithVerifier(signed, verifier)
	require.NoError(t, err, "pre-W03 signed packs must keep verifying")
	require.False(t, manifest.DeclaresCoverage())
}

func TestPackCoverageVerifyUnknownRuleIDMakesPackInvalid(t *testing.T) {
	// Load-time enforcement: a coverage row pointing at a rule the pack does
	// not declare is invalid AT LOAD — the only place manifest and
	// detector.json coexist.
	root, manifestBytes := writeCoveragePack(t, []CoverageEntry{
		{RuleID: "rule-that-does-not-exist", EvIDs: []string{"EV-A01"}, EvidenceTest: "TestX"},
	})
	_, _, err := LoadDetectorPackWithVerifier(root, manifestBytes, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not declared by this pack's detector.json")

	// The same pack with the row pointing at its own rule loads, and the
	// declaration round-trips through VerifiedPack.Manifest.
	rootOK, manifestOK := writeCoveragePack(t, []CoverageEntry{
		{RuleID: "cov-rule", EvIDs: []string{"EV-A04"}, EvidenceTest: "TestCovEvidence"},
	})
	verified, _, err := LoadDetectorPackWithVerifier(rootOK, manifestOK, nil)
	require.NoError(t, err)
	require.True(t, verified.Manifest.DeclaresCoverage())
	require.Equal(t, "cov-rule", verified.Manifest.Coverage[0].RuleID)
}

func TestPackCoverageVerifyIdempotentDecode(t *testing.T) {
	// Repeat variant: decoding the same manifest bytes twice yields the
	// same verdict — valid stays valid, invalid fails with a stable error.
	root, manifestBytes := writeCoveragePack(t, []CoverageEntry{
		{RuleID: "cov-rule", EvIDs: []string{"EV-A06"}, EvidenceTest: "TestCovEvidence"},
	})
	first, firstErr := DecodePackManifest(manifestBytes)
	second, secondErr := DecodePackManifest(manifestBytes)
	require.NoError(t, firstErr)
	require.NoError(t, secondErr)
	require.Equal(t, first, second)

	loadOne, _, loadErrOne := LoadDetectorPackWithVerifier(root, manifestBytes, nil)
	loadTwo, _, loadErrTwo := LoadDetectorPackWithVerifier(root, manifestBytes, nil)
	require.NoError(t, loadErrOne)
	require.NoError(t, loadErrTwo)
	require.Equal(t, loadOne, loadTwo)

	// And the invalid case fails identically twice.
	badRoot, badBytes := writeCoveragePack(t, []CoverageEntry{
		{RuleID: "ghost-rule", EvIDs: []string{"EV-A06"}, EvidenceTest: "TestCovEvidence"},
	})
	_, _, errOne := LoadDetectorPackWithVerifier(badRoot, badBytes, nil)
	_, _, errTwo := LoadDetectorPackWithVerifier(badRoot, badBytes, nil)
	require.Error(t, errOne)
	require.Equal(t, errOne.Error(), errTwo.Error())
}

func TestPackCoverageVerifyNoRulesNoCoverageInvalidUnknown(t *testing.T) {
	// Empty variant (DISPATCH §8): a pack with rules but NO coverage
	// declaration loads valid and means UNKNOWN. (A pack with no detector
	// rules at all is rejected by the pre-existing loader check — that is a
	// different, older invalidity, not a coverage statement.)
	root, manifestBytes := writeCoveragePack(t, nil)
	verified, _, err := LoadDetectorPackWithVerifier(root, manifestBytes, nil)
	require.NoError(t, err)
	require.False(t, verified.Manifest.DeclaresCoverage(), "no declaration ⇒ coverage unknown, never full")

	// Cross-check: a pack whose detector.json is empty is rejected by the
	// pre-existing rule (documented boundary of the empty variant).
	emptyRoot := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(emptyRoot, "detector.json"), []byte(`{"detectors":[]}`), 0o600))
	emptyManifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "covpack", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files: []PackFile{{Path: "detector.json", SHA256: sha256Sum([]byte(`{"detectors":[]}`))}},
	}
	data, err := json.Marshal(emptyManifest)
	require.NoError(t, err)
	_, _, err = LoadDetectorPackWithVerifier(emptyRoot, data, nil)
	require.ErrorContains(t, err, "no detectors")
}

func TestPackCoverageVerifySignatureSchemeStillGated(t *testing.T) {
	// The signature envelope gates run BEFORE the verifier: a coverage
	// bearing manifest with an unknown scheme is rejected explicitly (the
	// pre-W03 fail-closed behavior is unchanged by the coverage block).
	f := newSigningFixture(t)
	detector := []byte(`{"detectors":[{"rule_id":"cov-rule","rule_version":"1","category":"secret","pattern":"MARKER_[0-9]+"}]}`)
	manifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "covpack", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files:    []PackFile{{Path: "detector.json", SHA256: sha256Sum(detector)}},
		Coverage: []CoverageEntry{{RuleID: "cov-rule", EvIDs: []string{"EV-A04"}, EvidenceTest: "TestX"}},
	}
	signed := f.signManifest(t, manifest, testSignKeyID)
	var parsed PackManifest
	require.NoError(t, json.Unmarshal(signed, &parsed))
	parsed.Signature.Version = "guardpack-sig.v9"
	data, err := json.Marshal(parsed)
	require.NoError(t, err)
	_, err = DecodePackManifestWithVerifier(data, testVerifier(t, f))
	require.ErrorContains(t, err, "unsupported signature scheme version")
}
