package handlers_test

// Coverage surfacing on GET /api/guard-packs. Contract pinned here:
//
//	coverage present   row carries the declared entries verbatim
//	coverage absent    key ABSENT (never null) — absence = unknown,
//	                   never "full coverage"
//	broken coverage    decode/shape/load validation failure ⇒ the pack is
//	                   an error row (honest failure, no partial claim)
//	permissions        the field rides the endpoint's existing root-only
//	                   mount: anon 401 / non-root 403 (RoutingContract
//	                   parity — coverage must never leak unauthenticated)
//
// Host API fixed by fact: the admin contract hosts guard-packs
// (admin.openapi.yaml listGuardPacks, frozen) — delta recorded in
// docs/api/OPENAPI-DELTA.md.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/stretchr/testify/require"
)

const gpListCoveragePath = "/api/guard-packs"

// writeGuardPackCoverageFixture writes a one-detector pack whose manifest
// declares rawCoverage (a raw JSON array, possibly "null") so this file can
// pin BOTH the well-formed and the invalid shapes at the exact bytes level.
func writeGuardPackCoverageFixture(t *testing.T, root, id, rawCoverage string) {
	t.Helper()
	dir := filepath.Join(root, id)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	payload := fmt.Sprintf(`{"detectors":[{"rule_id":%q,"rule_version":"1","category":"secret","pattern":"GP_COV_[A-Z]+"}]}`, id)
	sum := sha256.Sum256([]byte(payload))
	manifest := fmt.Sprintf(`{"schema_version":%q,"pack_id":%q,"pack_version":"7","runtime_api":%q,"files":[{"path":"detector.json","sha256":"%s"}],"coverage":%s}`,
		guardhooks.GuardPackManifestVersion, id, guardhooks.RuntimeVersion, hex.EncodeToString(sum[:]), rawCoverage)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "detector.json"), []byte(payload), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600))
}

const gpCoverageRowJSON = `[{"rule_id":"%s","ev_ids":["EV-A04","EV-A01"],"evidence_test":"TestCovEvidence"}]`

// guardPackCoverageRows decodes the list body preserving per-row key
// presence (map-of-raw), which is what the absence-not-null pin needs.
func guardPackCoverageRows(t *testing.T, w *httptest.ResponseRecorder) map[string]map[string]json.RawMessage {
	t.Helper()
	var body struct {
		Packs []map[string]json.RawMessage `json:"packs"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	rows := make(map[string]map[string]json.RawMessage, len(body.Packs))
	for _, row := range body.Packs {
		var dir string
		require.NoError(t, json.Unmarshal(row["dir"], &dir))
		rows[dir] = row
	}
	return rows
}

func TestGuardPackCoverageListing(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	// withcov: declares coverage for its own rule.
	writeGuardPackCoverageFixture(t, packRoot, "withcov", fmt.Sprintf(gpCoverageRowJSON, "withcov"))
	// nocov: same shape, no declaration (pre-W03 manifest).
	writeGuardPackCoverageFixture(t, packRoot, "nocov", "null")

	router := guardPackRouter(t, &guardCASStub{}, packRoot)
	w := guardPackRequest(t, router, http.MethodGet, gpListCoveragePath, rootCookie, "")
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	rows := guardPackCoverageRows(t, w)

	t.Run("declared coverage is surfaced verbatim", func(t *testing.T) {
		raw, ok := rows["withcov"]["coverage"]
		require.True(t, ok, "a pack declaring coverage must surface the field: %v", rows["withcov"])
		var got []guardhooks.CoverageEntry
		require.NoError(t, json.Unmarshal(raw, &got))
		require.Equal(t, []guardhooks.CoverageEntry{
			{RuleID: "withcov", EvIDs: []string{"EV-A04", "EV-A01"}, EvidenceTest: "TestCovEvidence"},
		}, got)
	})
	t.Run("absent coverage is unknown, key absent not null", func(t *testing.T) {
		raw, ok := rows["nocov"]["coverage"]
		require.False(t, ok, "packs without a declaration must OMIT the key (unknown, never null/full): %v", rows["nocov"])
		require.Nil(t, raw)
		_, hasErr := rows["nocov"]["error"]
		require.False(t, hasErr, "nocov is a healthy pack that simply declares nothing")
	})
}

func TestGuardPackCoverageBrokenDeclarationIsErrorRow(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	// Unknown scenario id: shape validation fails at MANIFEST DECODE — the
	// listing (manifest-level) reports an error row, no partial claim.
	writeGuardPackCoverageFixture(t, packRoot, "badev", `[{"rule_id":"badev","ev_ids":["EV-A99"],"evidence_test":"T"}]`)
	// Rule the pack does not declare: passes decode (the listing is
	// manifest-level and surfaces the declaration verbatim) but fails LOAD
	// — validate/activate/status reject it via the W03-C02 anchor.
	writeGuardPackCoverageFixture(t, packRoot, "badrule", `[{"rule_id":"other-rule","ev_ids":["EV-A01"],"evidence_test":"T"}]`)
	// Healthy declaration: loads and validates.
	writeGuardPackCoverageFixture(t, packRoot, "withcov", fmt.Sprintf(gpCoverageRowJSON, "withcov"))

	router := guardPackRouter(t, &guardCASStub{}, packRoot)
	w := guardPackRequest(t, router, http.MethodGet, gpListCoveragePath, rootCookie, "")
	require.Equal(t, http.StatusOK, w.Code)
	rows := guardPackCoverageRows(t, w)

	t.Run("decode-shape failure is an error row", func(t *testing.T) {
		var errText string
		require.NoError(t, json.Unmarshal(rows["badev"]["error"], &errText))
		require.Contains(t, errText, "unknown scenario id")
		_, hasCoverage := rows["badev"]["coverage"]
		require.False(t, hasCoverage, "an unloadable pack must not surface a (partial) coverage claim: %v", rows["badev"])
	})
	t.Run("load-level failure lists verbatim, validate rejects 409", func(t *testing.T) {
		// The listing is manifest-level: the declaration is surfaced as
		// declared (the UI shows what the pack CLAIMS)...
		raw, ok := rows["badrule"]["coverage"]
		require.True(t, ok, "manifest-level listing surfaces the declaration verbatim: %v", rows["badrule"])
		var got []guardhooks.CoverageEntry
		require.NoError(t, json.Unmarshal(raw, &got))
		require.Equal(t, "other-rule", got[0].RuleID)
		_, hasErr := rows["badrule"]["error"]
		require.False(t, hasErr, "decode passed — the pack is listable")

		// ...and the claim is enforced where manifest and detector.json
		// coexist: the loader. Validate = the activate path's dry run, so
		// the UI preview CANNOT pass where activation would fail.
		body := `{"pack_id":"badrule","version":"7"}`
		vw := guardPackRequest(t, router, http.MethodPost, "/api/guard-packs/validate", rootCookie, body)
		require.Equal(t, http.StatusConflict, vw.Code, "body: %s", vw.Body.String())
		require.Contains(t, vw.Body.String(), "not declared by this pack's detector.json")

		okBody := `{"pack_id":"withcov","version":"7"}`
		okw := guardPackRequest(t, router, http.MethodPost, "/api/guard-packs/validate", rootCookie, okBody)
		require.Equal(t, http.StatusOK, okw.Code, "body: %s", okw.Body.String())
	})
}

func TestGuardPackCoverageRequiresRoot(t *testing.T) {
	adminCookie := makeSessionCookie(t, "admin@x.test", false, gpSecret)
	packRoot := t.TempDir()
	writeGuardPackCoverageFixture(t, packRoot, "withcov", fmt.Sprintf(gpCoverageRowJSON, "withcov"))

	router := guardPackRouter(t, &guardCASStub{}, packRoot)
	// Unauthenticated and non-root callers get the endpoint's standing
	// 401/403 (RoutingContract parity) — coverage rides the existing
	// permission model and never leaks below root.
	if w := guardPackRequest(t, router, http.MethodGet, gpListCoveragePath, "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("anon = %d, want 401 (coverage must not leak unauthenticated)", w.Code)
	}
	if w := guardPackRequest(t, router, http.MethodGet, gpListCoveragePath, adminCookie, ""); w.Code != http.StatusForbidden {
		t.Errorf("non-root = %d, want 403 (coverage is root-only like the whole endpoint)", w.Code)
	}
}
