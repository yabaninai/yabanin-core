package historyarchive

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// rootMigrationsFS locates the canonical migrations directory (two levels up
// from this package, same convention as pkg/migrate/migrations_sync_test).
const rootMigrationsDir = "../../migrations"

// parseRequestLogsSchema extracts the ordered column list (name + raw type
// token) from CREATE TABLE public.request_logs in the given 0001 schema.
// Modifiers (NOT NULL / DEFAULT) are stripped; the type token stays verbatim
// so the manifest can byte-compare it.
func parseRequestLogsSchema(t *testing.T, path string) []HistoryColumn {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read migration schema: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "CREATE TABLE public.request_logs (") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("CREATE TABLE public.request_logs not found in %s", path)
	}
	var cols []HistoryColumn
	for i := start; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == ");" {
			break
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "CONSTRAINT") {
			continue
		}
		fields := strings.SplitN(trimmed, " ", 2)
		if len(fields) != 2 {
			t.Fatalf("unparseable request_logs column line %q (line %d)", trimmed, i+1)
		}
		typ := fields[1]
		// Strip column modifiers; keep the raw type token verbatim.
		if cut := strings.Index(typ, " NOT NULL"); cut >= 0 {
			typ = typ[:cut]
		}
		if cut := strings.Index(typ, " DEFAULT"); cut >= 0 {
			typ = typ[:cut]
		}
		typ = strings.TrimSuffix(strings.TrimSpace(typ), ",")
		cols = append(cols, HistoryColumn{Name: fields[0], DBType: typ})
	}
	if len(cols) == 0 {
		t.Fatalf("no columns parsed from request_logs block in %s", path)
	}
	return cols
}

// TestHistoryColumns_MatchMigratedSchema is the schema-fix tooth: the
// manifest must equal the live request_logs schema byte-for-byte (names,
// types, order). A schema change that does not update the manifest in the
// same change fails here, which is exactly how N10-P02-T02 «fixes» the
// history schema for the archive: drift becomes impossible to merge
// unnoticed.
func TestHistoryColumns_MatchMigratedSchema(t *testing.T) {
	live := parseRequestLogsSchema(t, filepath.Join(rootMigrationsDir, "0001_init.up.sql"))
	if len(live) != len(HistoryColumns) {
		t.Fatalf("history schema drifted: live schema has %d columns, manifest has %d — update HistoryColumns in the same change",
			len(live), len(HistoryColumns))
	}
	for i, lc := range live {
		mc := HistoryColumns[i]
		if lc.Name != mc.Name {
			t.Fatalf("history schema drifted at position %d: live column %q, manifest column %q", i, lc.Name, mc.Name)
		}
		if lc.DBType != mc.DBType {
			t.Fatalf("history schema drifted at column %q: live type %q, manifest type %q — update HistoryColumns in the same change",
				mc.Name, lc.DBType, mc.DBType)
		}
	}
}

// TestNoLateColumnAddsToRequestLogs closes the ALTER TABLE loophole: no
// migration may add request_logs columns outside the 0001 CREATE TABLE,
// because the manifest (and therefore every archive batch digest) is defined
// against that single column source.
func TestNoLateColumnAddsToRequestLogs(t *testing.T) {
	entries, err := os.ReadDir(rootMigrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	alterAdd := regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(ONLY\s+)?(public\.)?request_logs\s+ADD`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(rootMigrationsDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for lineNo, line := range strings.Split(string(data), "\n") {
			if alterAdd.MatchString(line) {
				t.Fatalf("%s:%d adds a request_logs column outside the pinned manifest — update HistoryColumns and this test's allowance in the same change", e.Name(), lineNo+1)
			}
		}
	}
}

// TestAuthzColumnsPinned pins the permission-parity requirement (archive
// negative criterion «запрет доступа … сохраняются в архиве»): the columns
// the payload-authorization predicates filter on must be present and
// classified authz, i.e. never dropped or redacted by transfer.
func TestAuthzColumnsPinned(t *testing.T) {
	authz := ColumnsOfKind(KindAuthz)
	got := map[string]bool{}
	for _, c := range authz {
		got[c.Name] = true
	}
	for _, name := range []string{"org_id", "team_id", "user_id", "api_key_id"} {
		if !got[name] {
			t.Fatalf("authz column %q missing from manifest or misclassified (authz set: %v)", name, authz)
		}
	}
	if len(authz) != 4 {
		t.Fatalf("authz classification changed: got %d columns, want exactly org_id/team_id/user_id/api_key_id", len(authz))
	}
}

// TestContentColumnsClassification pins the chosen redaction policy (I63)
// structurally: exactly two original-capture columns (fail-closed NULL
// unless org opt-in) and one processed content column.
func TestContentColumnsClassification(t *testing.T) {
	originals := ColumnsOfKind(KindContentOriginal)
	if len(originals) != 2 {
		t.Fatalf("content-original classification: got %d columns, want upstream_request+upstream_response", len(originals))
	}
	for _, c := range originals {
		if c.Name != "upstream_request" && c.Name != "upstream_response" {
			t.Fatalf("unexpected content-original column %q", c.Name)
		}
		if c.DBType != "jsonb" {
			t.Fatalf("content-original column %q must stay jsonb (NULL-compatible with the fail-closed strip), got %q", c.Name, c.DBType)
		}
	}
	processed := ColumnsOfKind(KindContentProcessed)
	if len(processed) != 1 || processed[0].Name != "response" || processed[0].DBType != "jsonb" {
		t.Fatalf("content-processed classification drifted: %+v, want exactly response jsonb", processed)
	}
}

// TestMediaPolicyStructurallyPinned pins I62 at the schema level: no column
// of the history schema may carry bytes (media enters the archive as
// metadata only, never bytes/base64/data URLs).
func TestMediaPolicyStructurallyPinned(t *testing.T) {
	for _, c := range HistoryColumns {
		if isMediaByteCarrier(c.DBType) {
			t.Fatalf("column %q carries bytes (%s): violates media policy %q — media metadata goes to N10-P06, not the hot schema", c.Name, c.DBType, MediaPolicyMetadataOnly)
		}
	}
	if _, err := ValidateManifest([]HistoryColumn{{Name: "payload", DBType: "bytea", Kind: KindMetadata}}); err == nil {
		t.Fatalf("ValidateManifest accepted a bytea column — media-policy pin lost its teeth")
	}
}

// TestValidateManifestInvariants covers the manifest guard rails: empty,
// duplicate names, missing types, unknown kinds, and digest agreement.
func TestValidateManifestInvariants(t *testing.T) {
	digest, err := ValidateManifest(HistoryColumns)
	if err != nil {
		t.Fatalf("live manifest must validate: %v", err)
	}
	if digest != Digest(HistoryColumns) {
		t.Fatalf("ValidateManifest digest disagrees with Digest")
	}
	if len(digest) != 64 {
		t.Fatalf("digest must be 64-char hex, got %d chars", len(digest))
	}

	cases := map[string][]HistoryColumn{
		"empty":            {},
		"unnamed":          {{Name: "", DBType: "text", Kind: KindMetadata}},
		"duplicate":        {{Name: "a", DBType: "text", Kind: KindMetadata}, {Name: "a", DBType: "text", Kind: KindMetadata}},
		"missing-type":     {{Name: "a", DBType: "", Kind: KindMetadata}},
		"unknown-kind":     {{Name: "a", DBType: "text", Kind: ColumnKind("surprise")}},
		"bytea-media-type": {{Name: "a", DBType: "bytea", Kind: KindMetadata}},
	}
	for name, cols := range cases {
		if _, err := ValidateManifest(cols); err == nil {
			t.Fatalf("%s: ValidateManifest accepted an invalid manifest", name)
		}
	}
}

// TestDigestSensitivity proves the schema-generation digest actually moves
// on every dimension a schema evolution can touch (name, type, kind).
func TestDigestSensitivity(t *testing.T) {
	base := Digest(HistoryColumns)

	rename := append([]HistoryColumn(nil), HistoryColumns...)
	rename[0] = HistoryColumn{Name: "renamed", DBType: rename[0].DBType, Kind: rename[0].Kind}
	retyped := append([]HistoryColumn(nil), HistoryColumns...)
	retyped[0] = HistoryColumn{Name: retyped[0].Name, DBType: "text", Kind: retyped[0].Kind}
	reclassed := append([]HistoryColumn(nil), HistoryColumns...)
	reclassed[0] = HistoryColumn{Name: reclassed[0].Name, DBType: reclassed[0].DBType, Kind: KindContentOriginal}

	for name, variant := range map[string][]HistoryColumn{
		"rename": rename, "retype": retyped, "reclassify": reclassed,
	} {
		if Digest(variant) == base {
			t.Fatalf("%s did not change the schema-generation digest", name)
		}
	}
	if Digest(HistoryColumns) != base {
		t.Fatalf("Digest is not deterministic over the live manifest")
	}
}

// TestHotRetentionDaysThreshold pins the threshold value and the boundary
// math on a fixed clock (deterministic; no wall clock). 90 days is a tier
// boundary: strictly-before is eligible, the boundary instant itself and
// anything younger stay hot.
func TestHotRetentionDaysThreshold(t *testing.T) {
	if HotRetentionDays != 90 {
		t.Fatalf("hot threshold drifted: %d, contract fixes 90 days", HotRetentionDays)
	}
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	cutoff := HotCutoff(now)
	want := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC) // now − 90 days
	if !cutoff.Equal(want) {
		t.Fatalf("HotCutoff = %v, want %v", cutoff, want)
	}

	if !TierEligible(want.Add(-time.Nanosecond), now) {
		t.Fatalf("row one nanosecond older than the boundary must be tier-eligible")
	}
	if TierEligible(want, now) {
		t.Fatalf("row exactly at the boundary is still hot — eligibility is strictly-before")
	}
	if TierEligible(now.Add(-time.Hour), now) {
		t.Fatalf("fresh row must never be tier-eligible")
	}
}

// TestColumnLookup helpers used by the adminstore read model.
func TestColumnLookup(t *testing.T) {
	if c, ok := Column("org_id"); !ok || c.Kind != KindAuthz {
		t.Fatalf("Column(org_id) = %+v, %v", c, ok)
	}
	if _, ok := Column("media_blob"); ok {
		t.Fatalf("unknown column lookup must miss")
	}
	if len(ColumnsOfKind(KindMetadata)) == 0 {
		t.Fatalf("metadata classification must cover the operational columns")
	}
	if len(ColumnsOfKind(KindMetadata))+len(ColumnsOfKind(KindAuthz))+
		len(ColumnsOfKind(KindContentOriginal))+len(ColumnsOfKind(KindContentProcessed)) != len(HistoryColumns) {
		t.Fatalf("every manifest column must carry exactly one classification")
	}
}

// TestPinnedPolicyVocabulary keeps the policy string values the transfer
// writer persists with archive batches stable (archive readers key on them).
func TestPinnedPolicyVocabulary(t *testing.T) {
	if MediaPolicyMetadataOnly != "metadata-only" || RedactionPolicyOriginalsOrgOptIn != "originals-org-opt-in" {
		t.Fatalf("policy vocabulary drifted: %q / %q", MediaPolicyMetadataOnly, RedactionPolicyOriginalsOrgOptIn)
	}
	if !RedactContentDefault {
		t.Fatalf("RedactContentDefault must stay true (export-safe default)")
	}
}
