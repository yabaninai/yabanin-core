package guardhooks

// The manifest not_covered block: additive section, old-pack decode
// back-compat, canonical-payload byte identity for section-less packs,
// shape validation (closed EV registry, denial state, mandatory bounded
// reason, unique rows) and signing — a denial row is part of the signed
// payload, so post-signing tampering breaks verification.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// gapNotCoveredRows carries the three gap rows of the scenario map
// (EV-A05 partial; EV-A07 all four behavioral codes; EV-A08 LLM09 with
// the LLM10 budget nuance) expressed in the manifest vocabulary.
func gapNotCoveredRows() []NotCoveredEntry {
	return []NotCoveredEntry{
		{EvID: "EV-A05", State: CoverageStatePartial, Reason: "text signatures for system-prompt-leak patterns are coverable; the behavioral part (authority misrepresentation, misleading explanations) is not a text signal"},
		{EvID: "EV-A07", State: CoverageStateNotCovered, Reason: "code execution, inter-agent messages, cascades and rogue behavior are behavioral/system planes, not content signals of observable text"},
		{EvID: "EV-A08", State: CoverageStateNotCovered, Reason: "misinformation is not a claim; unbounded consumption is partially the core budget plane, outside detector packs"},
	}
}

// writeNotCoveredPack writes an UNSIGNED one-detector pack (rule
// "cov-rule") whose manifest declares the given blocks, and returns the
// pack root plus manifest bytes.
func writeNotCoveredPack(t *testing.T, coverage []CoverageEntry, notCovered []NotCoveredEntry) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	detector := []byte(`{"detectors":[{"rule_id":"cov-rule","rule_version":"1","category":"secret","pattern":"MARKER_[0-9]+"}]}`)
	require.NoError(t, os.WriteFile(filepath.Join(root, "detector.json"), detector, 0o600))
	manifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "ncpack", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files:      []PackFile{{Path: "detector.json", SHA256: sha256Sum(detector)}},
		Coverage:   coverage,
		NotCovered: notCovered,
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	return root, data
}

// signedNotCoveredManifest returns a SIGNED manifest plus its verifier.
func signedNotCoveredManifest(t *testing.T, coverage []CoverageEntry, notCovered []NotCoveredEntry) ([]byte, SignatureVerifier) {
	t.Helper()
	f := newSigningFixture(t)
	detector := []byte(`{"detectors":[{"rule_id":"cov-rule","rule_version":"1","category":"secret","pattern":"MARKER_[0-9]+"}]}`)
	manifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "ncpack", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files:      []PackFile{{Path: "detector.json", SHA256: sha256Sum(detector)}},
		Coverage:   coverage,
		NotCovered: notCovered,
	}
	return f.signManifest(t, manifest, testSignKeyID), testVerifier(t, f)
}

func TestNotCoveredOldManifestDecodesUnchanged(t *testing.T) {
	// Byte-level old shape: exactly the pre-coverage fields — decodes
	// under DisallowUnknownFields with NotCovered nil, and the manifest
	// makes no denial statement.
	old := fmt.Sprintf(`{"schema_version":%q,"pack_id":"oldpack","pack_version":"3","runtime_api":%q,"files":[{"path":"detector.json","sha256":"%s"}]}`,
		GuardPackManifestVersion, RuntimeVersion, strings.Repeat("ab", 32))
	manifest, err := DecodePackManifest([]byte(old))
	require.NoError(t, err, "a manifest without the not_covered field must decode unchanged")
	require.Nil(t, manifest.NotCovered)
	require.False(t, manifest.DeclaresNotCovered(), "absence of a denial must not read as a statement")
}

func TestNotCoveredRoundtrip(t *testing.T) {
	rows := gapNotCoveredRows()
	root, data := writeNotCoveredPack(t, nil, rows)
	decoded, err := DecodePackManifest(data)
	require.NoError(t, err)
	require.True(t, decoded.DeclaresNotCovered())
	require.Equal(t, rows, decoded.NotCovered)

	// marshal(decode(x)) is stable.
	again, err := json.Marshal(decoded)
	require.NoError(t, err)
	redecoded, err := DecodePackManifest(again)
	require.NoError(t, err)
	require.Equal(t, decoded, redecoded)

	// The section rides a full load untouched: denials constrain claims,
	// not the loader.
	verified, _, err := LoadDetectorPackWithVerifier(root, data, nil)
	require.NoError(t, err)
	require.Equal(t, rows, verified.Manifest.NotCovered)
}

func TestNotCoveredRowWithoutReasonInvalid(t *testing.T) {
	rows := gapNotCoveredRows()
	rows[0].Reason = ""
	_, data := writeNotCoveredPack(t, nil, rows)
	_, err := DecodePackManifest(data)
	require.Error(t, err, "a denial row without a reason is invalid")
	require.Contains(t, err.Error(), "requires a reason")

	long := gapNotCoveredRows()
	long[1].Reason = strings.Repeat("r", MaxNotCoveredReasonLen+1)
	_, longData := writeNotCoveredPack(t, nil, long)
	_, err = DecodePackManifest(longData)
	require.Error(t, err)
}

func TestNotCoveredBadStateInvalid(t *testing.T) {
	for _, state := range []string{"", "covered", "full", "not-covered", "PARTIAL"} {
		rows := gapNotCoveredRows()
		rows[0].State = state
		_, data := writeNotCoveredPack(t, nil, rows)
		_, err := DecodePackManifest(data)
		require.Error(t, err, "state %q must be rejected", state)
		if state != "" {
			require.Contains(t, err.Error(), "invalid state")
		}
	}
}

func TestNotCoveredUnknownEvIDRejected(t *testing.T) {
	rows := gapNotCoveredRows()
	rows[0].EvID = "EV-A09"
	_, data := writeNotCoveredPack(t, nil, rows)
	_, err := DecodePackManifest(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not in the scenario registry")
	require.Contains(t, err.Error(), "EV-A09")
}

func TestNotCoveredDuplicateEvIDRejected(t *testing.T) {
	rows := gapNotCoveredRows()
	repeat := rows[2]
	rows = append(rows, repeat)
	_, data := writeNotCoveredPack(t, nil, rows)
	_, err := DecodePackManifest(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate not_covered ev_id")
}

func TestNotCoveredEntryLimitRejected(t *testing.T) {
	rows := make([]NotCoveredEntry, MaxNotCoveredEntries+1)
	for i := range rows {
		rows[i] = NotCoveredEntry{EvID: "EV-A01", State: CoverageStateNotCovered, Reason: "x"}
	}
	// Unique ids are impossible with a 8-id registry at this size; the
	// duplicate check would fire first, so probe the cap directly.
	err := validateNotCoveredShape(rows)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds the 64-entry limit")
}

func TestNotCoveredGapRowsValidate(t *testing.T) {
	// The three gap rows of the scenario map, verbatim, decode clean.
	_, data := writeNotCoveredPack(t, nil, gapNotCoveredRows())
	manifest, err := DecodePackManifest(data)
	require.NoError(t, err)
	require.Len(t, manifest.NotCovered, 3)
	require.Equal(t, CoverageStatePartial, manifest.NotCovered[0].State)
	require.Equal(t, CoverageStateNotCovered, manifest.NotCovered[1].State)
	require.Equal(t, CoverageStateNotCovered, manifest.NotCovered[2].State)
}

func TestNotCoveredCanonicalPayloadBackCompat(t *testing.T) {
	// A nil NotCovered must marshal the canonical payload
	// BYTE-IDENTICALLY to the projection without the field — this is
	// what keeps existing signatures valid.
	files := []PackFile{{Path: "detector.json", SHA256: strings.Repeat("ab", 32)}}
	with := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: files}
	require.Nil(t, with.NotCovered)

	withoutSection, err := json.Marshal(struct {
		SchemaVersion string          `json:"schema_version"`
		PackID        string          `json:"pack_id"`
		PackVersion   string          `json:"pack_version"`
		RuntimeAPI    string          `json:"runtime_api"`
		Files         []PackFile      `json:"files"`
		Coverage      []CoverageEntry `json:"coverage,omitempty"`
	}{with.SchemaVersion, with.PackID, with.PackVersion, with.RuntimeAPI, with.Files, with.Coverage})
	require.NoError(t, err)

	now, err := canonicalPackPayload(with)
	require.NoError(t, err)
	require.True(t, bytes.Equal(withoutSection, now), "canonical payload changed for not_covered-less packs: old signatures would break (without=%s now=%s)", withoutSection, now)
}

func TestNotCoveredSignedIntoCanonicalPayload(t *testing.T) {
	with := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files:      []PackFile{{Path: "detector.json", SHA256: strings.Repeat("ab", 32)}},
		NotCovered: []NotCoveredEntry{{EvID: "EV-A07", State: CoverageStateNotCovered, Reason: "behavioral plane"}},
	}
	payload, err := canonicalPackPayload(with)
	require.NoError(t, err)
	require.Contains(t, string(payload), `"not_covered"`)
	require.Contains(t, string(payload), "behavioral plane")
}

func TestNotCoveredTamperFailsVerify(t *testing.T) {
	signed, verifier := signedNotCoveredManifest(t, nil, gapNotCoveredRows())
	_, err := DecodePackManifestWithVerifier(signed, verifier)
	require.NoError(t, err, "the untouched signed pack with not_covered must verify")

	tamper := func(mutate func(*NotCoveredEntry)) {
		var manifest PackManifest
		require.NoError(t, json.Unmarshal(signed, &manifest))
		mutate(&manifest.NotCovered[0])
		data, marshalErr := json.Marshal(manifest)
		require.NoError(t, marshalErr)
		_, err := DecodePackManifestWithVerifier(data, verifier)
		require.Error(t, err, "not_covered is part of the signed payload — post-signing mutation must fail verification")
		require.Contains(t, err.Error(), "signature verification failed")
	}
	t.Run("ev-id-substituted", func(t *testing.T) {
		tamper(func(e *NotCoveredEntry) { e.EvID = "EV-A06" })
	})
	t.Run("state-flip", func(t *testing.T) {
		tamper(func(e *NotCoveredEntry) {
			if e.State == CoverageStatePartial {
				e.State = CoverageStateNotCovered
			} else {
				e.State = CoverageStatePartial
			}
		})
	})
	t.Run("reason-softened", func(t *testing.T) {
		tamper(func(e *NotCoveredEntry) { e.Reason = "no reason" })
	})
	t.Run("row-dropped", func(t *testing.T) {
		var manifest PackManifest
		require.NoError(t, json.Unmarshal(signed, &manifest))
		manifest.NotCovered = nil
		data, err := json.Marshal(manifest)
		require.NoError(t, err)
		_, err = DecodePackManifestWithVerifier(data, verifier)
		require.Error(t, err, "removing a signed denial row is a mutation too")
		require.Contains(t, err.Error(), "signature verification failed")
	})
}

func TestNotCoveredOldSignedPackStillVerifies(t *testing.T) {
	// A signed pack WITHOUT not_covered (a coverage-bearing and a bare
	// pre-coverage one) must keep verifying: the section-less canonical
	// payload is byte-identical, so old signatures survive.
	withCoverage, coverageVerifier := signedNotCoveredManifest(t, []CoverageEntry{
		{RuleID: "cov-rule", EvIDs: []string{"EV-A04"}, EvidenceTest: "TestCovEvidence"},
	}, nil)
	_, err := DecodePackManifestWithVerifier(withCoverage, coverageVerifier)
	require.NoError(t, err, "coverage-bearing packs without not_covered must keep verifying")

	bare, bareVerifier := signedNotCoveredManifest(t, nil, nil)
	manifest, err := DecodePackManifestWithVerifier(bare, bareVerifier)
	require.NoError(t, err, "pre-coverage signed packs must keep verifying")
	require.False(t, manifest.DeclaresNotCovered())
}
