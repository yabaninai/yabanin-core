package guardhooks

// The manifest coverage block — additive field, old-pack decode
// back-compat, canonical-payload byte identity for coverage-less packs,
// shape validation (closed EV registry, bounded unique rule ids, evidence
// references) and the absence-means-unknown semantics. Signature tamper and
// load-time rule_id enforcement live in coverage_verify_test.go.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// coverageManifestFixture builds a minimal VALID manifest with the given
// coverage block (possibly nil) as it would sit in manifest.json.
func coverageManifestFixture(coverage []CoverageEntry) []byte {
	detector := `{"detectors":[{"rule_id":"cov-rule","rule_version":"1","category":"secret","pattern":"MARKER_[0-9]+"}]}`
	return []byte(fmt.Sprintf(`{
		"schema_version": %q,
		"pack_id": "covpack",
		"pack_version": "1",
		"runtime_api": %q,
		"files": [{"path": "detector.json", "sha256": "%s"}],
		"coverage": %s
	}`, GuardPackManifestVersion, RuntimeVersion, sha256Sum([]byte(detector)), coverageJSON(coverage)))
}

// coverageJSON marshals the coverage block the way PackManifest would (nil ⇒
// JSON null so the fixture omits nothing implicitly).
func coverageJSON(coverage []CoverageEntry) string {
	if coverage == nil {
		return "null"
	}
	data, err := json.Marshal(coverage)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func validCoverageEntry() CoverageEntry {
	return CoverageEntry{RuleID: "cov-rule", EvIDs: []string{"EV-A04"}, EvidenceTest: "TestCoverageExample"}
}

func TestPackCoverageOldManifestDecodesUnchanged(t *testing.T) {
	// Byte-level old shape: EXACTLY the pre-W03 fields, nothing else —
	// decodes under DisallowUnknownFields, Coverage nil, and the manifest
	// does not claim coverage.
	old := fmt.Sprintf(`{"schema_version":%q,"pack_id":"oldpack","pack_version":"3","runtime_api":%q,"files":[{"path":"detector.json","sha256":"%s"}]}`,
		GuardPackManifestVersion, RuntimeVersion, strings.Repeat("ab", 32))
	manifest, err := DecodePackManifest([]byte(old))
	require.NoError(t, err, "a pre-W03 manifest without the coverage field must decode unchanged")
	require.Nil(t, manifest.Coverage)
	require.False(t, manifest.DeclaresCoverage(), "absence of a declaration must not read as a coverage statement")
}

func TestPackCoverageRoundtrip(t *testing.T) {
	entries := []CoverageEntry{
		{RuleID: "cov-rule", EvIDs: []string{"EV-A01", "EV-A04"}, EvidenceTest: "TestInputsMatrix/injection-en"},
		{RuleID: "cov-rule-2", EvIDs: []string{"EV-A04"}, EvidenceTest: "TestInputsMatrix/secret-aws-access-key"},
	}
	data := coverageManifestFixture(entries)
	decoded, err := DecodePackManifest(data)
	require.NoError(t, err)
	require.True(t, decoded.DeclaresCoverage())
	require.Equal(t, entries, decoded.Coverage)

	// Decode(marshal(decoded)) is stable: the block survives a full
	// serialize/deserialize cycle byte-for-byte.
	again, err := json.Marshal(decoded)
	require.NoError(t, err)
	redecoded, err := DecodePackManifest(again)
	require.NoError(t, err)
	require.Equal(t, decoded, redecoded)

	// The same EV id may legitimately appear on several rules (two rules
	// covering one scenario is a claim about each rule, not a duplicate).
	require.Equal(t, "EV-A04", decoded.Coverage[0].EvIDs[1])
	require.Equal(t, "EV-A04", decoded.Coverage[1].EvIDs[0])
}

func TestPackCoverageCanonicalPayloadBackCompat(t *testing.T) {
	// A nil Coverage must marshal the canonical payload BYTE-IDENTICALLY to
	// the pre-W03 projection — this is what keeps existing signatures valid.
	files := []PackFile{{Path: "detector.json", SHA256: strings.Repeat("ab", 32)}}
	with := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: files}
	require.Nil(t, with.Coverage)

	preW03, err := json.Marshal(struct {
		SchemaVersion string     `json:"schema_version"`
		PackID        string     `json:"pack_id"`
		PackVersion   string     `json:"pack_version"`
		RuntimeAPI    string     `json:"runtime_api"`
		Files         []PackFile `json:"files"`
	}{with.SchemaVersion, with.PackID, with.PackVersion, with.RuntimeAPI, with.Files})
	require.NoError(t, err)

	now, err := canonicalPackPayload(with)
	require.NoError(t, err)
	require.True(t, bytes.Equal(preW03, now), "canonical payload changed for coverage-less packs: old signatures would break (pre-W03=%s now=%s)", preW03, now)
}

func TestPackCoverageSignedIntoCanonicalPayload(t *testing.T) {
	// A declared coverage block IS part of the signed projection: the
	// canonical bytes must contain the declared rule and scenario ids.
	with := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files:    []PackFile{{Path: "detector.json", SHA256: strings.Repeat("ab", 32)}},
		Coverage: []CoverageEntry{{RuleID: "sig-cov-rule", EvIDs: []string{"EV-A02"}, EvidenceTest: "TestX"}},
	}
	payload, err := canonicalPackPayload(with)
	require.NoError(t, err)
	require.Contains(t, string(payload), `"coverage"`)
	require.Contains(t, string(payload), "sig-cov-rule")
	require.Contains(t, string(payload), "EV-A02")
}

func TestPackCoverageUnknownEvIDRejected(t *testing.T) {
	entry := validCoverageEntry()
	entry.EvIDs = []string{"EV-A09"}
	_, err := DecodePackManifest(coverageManifestFixture([]CoverageEntry{entry}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown scenario id")
	require.Contains(t, err.Error(), "EV-A09")
}

func TestPackCoverageEmptyEvIDsRejected(t *testing.T) {
	entry := validCoverageEntry()
	entry.EvIDs = nil
	_, err := DecodePackManifest(coverageManifestFixture([]CoverageEntry{entry}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one ev_id")
}

func TestPackCoverageDuplicateEvIDInRowRejected(t *testing.T) {
	entry := validCoverageEntry()
	entry.EvIDs = []string{"EV-A01", "EV-A01"}
	_, err := DecodePackManifest(coverageManifestFixture([]CoverageEntry{entry}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "repeats scenario id")
}

func TestPackCoverageBadRuleIDRejected(t *testing.T) {
	for _, ruleID := range []string{"", "otherpack:cov-rule", "a/b", "a\\b", strings.Repeat("x", MaxCoverageRuleIDLen+1)} {
		entry := validCoverageEntry()
		entry.RuleID = ruleID
		_, err := DecodePackManifest(coverageManifestFixture([]CoverageEntry{entry}))
		require.Error(t, err, "rule_id %q must be rejected", ruleID)
	}
}

func TestPackCoverageDuplicateRuleIDRejected(t *testing.T) {
	entries := []CoverageEntry{validCoverageEntry(), validCoverageEntry()}
	_, err := DecodePackManifest(coverageManifestFixture(entries))
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate coverage rule_id")
}

func TestPackCoverageMissingEvidenceRejected(t *testing.T) {
	entry := validCoverageEntry()
	entry.EvidenceTest = ""
	_, err := DecodePackManifest(coverageManifestFixture([]CoverageEntry{entry}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "evidence_test")
	long := validCoverageEntry()
	long.EvidenceTest = strings.Repeat("t", MaxCoverageEvidenceLen+1)
	_, err = DecodePackManifest(coverageManifestFixture([]CoverageEntry{long}))
	require.Error(t, err)
}

func TestPackCoverageEntryLimitRejected(t *testing.T) {
	entries := make([]CoverageEntry, MaxCoverageEntries+1)
	for i := range entries {
		entries[i] = CoverageEntry{RuleID: fmt.Sprintf("rule-%d", i), EvIDs: []string{"EV-A01"}, EvidenceTest: "TestX"}
	}
	_, err := DecodePackManifest(coverageManifestFixture(entries))
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds the 64-entry limit")
}

func TestPackCoverageAbsenceIsUnknownNeverFull(t *testing.T) {
	// The acceptance semantics of W03-C01: a manifest without coverage
	// decodes fine and declares NOTHING — "unknown", not "covered". The only
	// code-level surface allowed to express this is DeclaresCoverage.
	manifest, err := DecodePackManifest(coverageManifestFixture(nil))
	require.NoError(t, err)
	require.False(t, manifest.DeclaresCoverage())

	withCoverage, err := DecodePackManifest(coverageManifestFixture([]CoverageEntry{validCoverageEntry()}))
	require.NoError(t, err)
	require.True(t, withCoverage.DeclaresCoverage())
}
