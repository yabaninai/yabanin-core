package historyarchive

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

// sanctionedAddRegex parses a sanctioned ADD COLUMN statement into its
// column name and raw type token (same trimming rules as the 0001 parser).
var sanctionedAddRegex = regexp.MustCompile(
	`(?i)^ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?request_logs\s+ADD\s+COLUMN\s+([a-z_][a-z0-9_]*)\s+([^;]+);$`)

// parseSanctionedAdd extracts the column a sanctioned DDL statement adds.
func parseSanctionedAdd(t *testing.T, ddl string) HistoryColumn {
	t.Helper()
	m := sanctionedAddRegex.FindStringSubmatch(strings.TrimSpace(ddl))
	if m == nil {
		t.Fatalf("sanctioned DDL does not parse as a request_logs ADD COLUMN statement: %q", ddl)
	}
	return HistoryColumn{Name: m[1], DBType: strings.TrimSpace(m[2])}
}

// TestHistoryColumns_MatchMigratedSchema is the schema-fix tooth: the
// manifest must equal the cumulative migrated schema byte-for-byte — 0001's
// CREATE TABLE columns in order, then each sanctioned additive migration's
// column in migration order. A schema change that does not update the
// manifest in the same change fails here, which is exactly how N10-P02-T02
// «fixes» the history schema for the archive: drift becomes impossible to
// merge unnoticed. Released migrations are immutable, so the comparison
// source is the pinned SQL bytes, never an edited history.
func TestHistoryColumns_MatchMigratedSchema(t *testing.T) {
	cumulative := parseRequestLogsSchema(t, filepath.Join(rootMigrationsDir, "0001_init.up.sql"))
	for _, add := range SanctionedRequestLogsAdds {
		cumulative = append(cumulative, parseSanctionedAdd(t, add.DDL))
	}
	if len(cumulative) != len(HistoryColumns) {
		t.Fatalf("history schema drifted: cumulative schema has %d columns, manifest has %d — extend SanctionedRequestLogsAdds (and the generation) in the same change",
			len(cumulative), len(HistoryColumns))
	}
	for i, lc := range cumulative {
		mc := HistoryColumns[i]
		if lc.Name != mc.Name {
			t.Fatalf("history schema drifted at position %d: live column %q, manifest column %q", i, lc.Name, mc.Name)
		}
		if lc.DBType != mc.DBType {
			t.Fatalf("history schema drifted at column %q: live type %q, manifest type %q — update the sanctioned registry in the same change",
				mc.Name, lc.DBType, mc.DBType)
		}
	}
}

// TestNoLateColumnAddsToRequestLogs closes the ALTER TABLE loophole: no
// migration may add request_logs columns outside the 0001 CREATE TABLE
// unless it is a registered sanctioned add — exact filename, exact DDL
// bytes. Anything else (unknown file, unknown statement, edited bytes)
// fails here, so a column can never silently reach the live schema without
// also reaching the manifest and a new generation.
func TestNoLateColumnAddsToRequestLogs(t *testing.T) {
	alterAdd := regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(ONLY\s+)?(public\.)?request_logs\s+ADD`)
	paths, err := filepath.Glob(filepath.Join(rootMigrationsDir, "*.up.sql"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	var found []SanctionedRequestLogsAdd
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Clean(path))
		require.NoError(t, err)
		for _, line := range strings.Split(string(data), "\n") {
			ddl := strings.TrimSpace(line)
			if alterAdd.MatchString(ddl) {
				col := parseSanctionedAdd(t, ddl)
				found = append(found, SanctionedRequestLogsAdd{Migration: filepath.Base(path), DDL: ddl, Column: col})
			}
		}
	}
	require.Len(t, found, len(SanctionedRequestLogsAdds))
	for i, got := range found {
		want := SanctionedRequestLogsAdds[i]
		require.Equal(t, want.Migration, got.Migration)
		require.Equal(t, want.DDL, got.DDL)
		require.Equal(t, want.Column.Name, got.Column.Name)
		require.Equal(t, want.Column.DBType, got.Column.DBType)
	}
}

// legacyManifestDigest is the manifest digest of generation 1 — the
// 46-column pre-invocation manifest shipped at 03cfedc — pinned as an
// external literal (independently computed from that revision). It anchors
// history: no edit to the base column list, the freezing logic or the
// digest function can silently rewrite what generation 1 was.
const legacyManifestDigest = "4e8d9ee60cbd0f4285d4ccc40ff22ebef74db2145ab209ceb39f86a6ed32d207"

// TestSchemaGenerationRegistry pins the version-handling half of the
// contract: generation 1 equals the externally pinned legacy digest and
// column count, every generation validates, older generations are strict
// prefixes of newer ones (evolution appends only), digests are distinct,
// the current generation is HistoryColumns, historical generations resolve
// by digest (contract-scope artifact resolution — Core ships no live batch
// writer/reader today), and unknown digests fail closed.
func TestSchemaGenerationRegistry(t *testing.T) {
	gs := Generations()
	require.Len(t, gs, len(SanctionedRequestLogsAdds)+1)
	require.Equal(t, legacyManifestDigest, gs[0].Digest)
	require.Len(t, gs[0].Columns, 46)
	for i, g := range gs {
		require.Equal(t, i+1, g.Version)
		digest, err := ValidateManifest(g.Columns)
		require.NoError(t, err)
		require.Equal(t, g.Digest, digest)
		resolved, err := GenerationForDigest(digest)
		require.NoError(t, err)
		require.Equal(t, g, resolved)
		if i > 0 {
			prev := gs[i-1]
			require.Len(t, g.Columns, len(prev.Columns)+1)
			require.Equal(t, prev.Columns, g.Columns[:len(prev.Columns)])
			require.NotEqual(t, prev.Digest, digest)
		}
	}
	require.Equal(t, HistoryColumns, CurrentGeneration().Columns)
	require.Equal(t, Digest(HistoryColumns), CurrentGeneration().Digest)
	_, err := GenerationForDigest(legacyManifestDigest + "00")
	require.Error(t, err)
}

func TestReturnedGenerationColumnsAreIsolated(t *testing.T) {
	old, err := GenerationForDigest(legacyManifestDigest)
	require.NoError(t, err)
	old.Columns[0].Name = "caller edit"
	CurrentGeneration().Columns[0].DBType = "caller edit"
	for _, g := range Generations() {
		g.Columns[0].Name = "caller edit"
	}
	fresh, err := GenerationForDigest(legacyManifestDigest)
	require.NoError(t, err)
	require.Equal(t, legacyManifestDigest, Digest(fresh.Columns))
	require.Equal(t, HistoryColumns, CurrentGeneration().Columns)
}

// TestInvocationIdentityPinned pins the 0028 addition's manifest shape:
// invocation_id is the appended (last) column, uuid, metadata — never an
// authz column, since the payload-authorization predicates do not filter
// on it (TestAuthzColumnsPinned holds the exact authz set).
func TestInvocationIdentityPinned(t *testing.T) {
	last := HistoryColumns[len(HistoryColumns)-1]
	if last.Name != "invocation_id" || last.DBType != "uuid" || last.Kind != KindMetadata {
		t.Fatalf("invocation_id must be the appended uuid metadata column, got %+v", last)
	}
	if c, ok := Column("invocation_id"); !ok || c.Kind != KindMetadata || c.DBType != "uuid" {
		t.Fatalf("Column(invocation_id) = %+v, %v — must resolve as uuid metadata", c, ok)
	}
	// The pre-invocation generation (what archive batches written before
	// 0028 carry) must not know the column.
	v1 := Generations()[0]
	if _, ok := func() (HistoryColumn, bool) {
		for _, c := range v1.Columns {
			if c.Name == "invocation_id" {
				return c, true
			}
		}
		return HistoryColumn{}, false
	}(); ok {
		t.Fatalf("generation 1 must not carry invocation_id — it predates 0028")
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
