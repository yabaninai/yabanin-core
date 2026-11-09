package migrate

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// N10-P01-T04: the expand-contract upgrade discipline for the migration set
// after the consolidated 0001_init baseline, recorded in migrations/README.md
// and enforced here as always-on structural checks (same posture as
// mirror_numbering_test.go for the mirror+numbering contract).
//
// The discipline: an upgrade never destroys in one step what has no shipped
// replacement yet. Additive work goes into an expand migration; removal of the
// superseded shape goes into a later contract migration that cites the expand
// that introduced the replacement. Because a fresh install and the stamp-1
// upgrade cohort apply the same embedded set (0002..head), both stories walk
// the same phases and converge to the same schema, so the baseline parity pin
// (TestRun_FreshAndStamp1CohortsConvergeToIdenticalSchema) stays valid as head
// grows.
//
// This file enforces the halves of the contract that had no guard:
//
//  1. an up migration is expand-only — the destructive statement classes live
//     in a contract phase (or in the audited pre-policy exemptions);
//  2. a contract phase cites the predecessor expand: a version strictly less
//     than its own, with a stem present in the embedded set;
//  3. from the policy version the README pins, every up migration carries the
//     phase marker, and the README must state the policy with the same pinned
//     version as this guard.

// expandContractFirstVersion is the first migration version required to carry
// an expand-contract phase marker. The policy landed while the embedded head
// was 0015, so 0016 is the first post-policy migration. The README policy
// section must pin the same number (TestExpandContractREADMEStatesPolicy pins
// the agreement), and a future real migration 0016 is the first file the
// marker requirement bites on.
const expandContractFirstVersion = "0016"

// baselineVersion is the consolidated 0001_init baseline. It IS the schema of
// record (a pg_dump of the squashed history), not an upgrade step, so the
// expand-contract discipline governs the versions after it.
const baselineVersion = "0001"

// prePolicyContractSwaps records the audited pre-policy up migrations that
// contain contract-phase removals from before the expand-contract policy
// existed. Each entry states why the removal is structure-only and
// data-preserving. The map is closed: the guard flags any destructive
// statement outside these entries, and TestPrePolicyExemptionsStayLive fails
// when an entry stops matching any destructive statement — a stale exemption
// must be deleted, not silently kept.
var prePolicyContractSwaps = map[string]string{
	"0005": "chk_provider drop+recreate in one file: strictly widening CHECK (adds azure-openai), structure-only swap, no rows touched (R108-02 pre-policy history)",
}

// destructiveStatementRes are the statement classes an expand-phase up
// migration must not contain. Each is a structural removal or an in-place
// conversion that can strand running readers/writers or destroy data; they
// belong to a contract phase (or to the audited pre-policy exemptions above).
// Backfill UPDATE stays allowed — bounded, idempotent data backfill is part of
// the canonical expand shape; DELETE/TRUNCATE (unbounded removal) do not.
//
// The scan is a best-effort lexical pass over comment-stripped SQL: it is
// biased toward false positives over false negatives, so a destructive edit
// worded as prose inside a live statement still trips it.
var destructiveStatementRes = []struct {
	label string
	re    *regexp.Regexp
}{
	{"DROP <object>", regexp.MustCompile(`(?i)\bDROP\s+(TABLE|SCHEMA|COLUMN|INDEX|CONSTRAINT|POLICY|VIEW|MATERIALIZED|SEQUENCE|TYPE|FUNCTION|TRIGGER|DOMAIN|DEFAULT|DATABASE|ROLE)\b`)},
	{"TRUNCATE", regexp.MustCompile(`(?i)\bTRUNCATE\b`)},
	{"DELETE FROM", regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`)},
	{"ALTER COLUMN <col> TYPE", regexp.MustCompile(`(?i)\bALTER\s+COLUMN\s+\S+\s+TYPE\b`)},
	{"RENAME", regexp.MustCompile(`(?i)\bRENAME\s+(TO|COLUMN)\b`)},
	{"SET NOT NULL", regexp.MustCompile(`(?i)\bSET\s+NOT\s+NULL\b`)},
}

// phaseHeaderRe matches the one-line phase marker an up migration carries:
//
//	-- expand-contract: expand — <what it adds>
//	-- expand-contract: contract — replaces expand NNNN_<stem>; <what it removes>
var phaseHeaderRe = regexp.MustCompile(`(?m)^--[ \t]*expand-contract:[ \t]*(expand|contract)\b(.*)$`)

// replacesExpandRe extracts the predecessor-expand citation a contract header
// must carry: the embedded migration that introduced the replacement shape.
var replacesExpandRe = regexp.MustCompile(`(?i)replaces\s+expand\s+(\d{4})_([a-z0-9_]+)`)

// upMigration is one embedded up migration with its parsed expand-contract
// phase header (phase "" = unmarked, the pre-policy norm).
type upMigration struct {
	version      string
	stem         string
	name         string
	content      string
	phase        string
	replacesVer  string
	replacesStem string
	headers      int
}

// parsePhaseHeader reads the phase marker from the raw content (headers are
// comment lines and must be parsed before any comment stripping). The
// replaces citation is taken from the first header; a second header is itself
// a violation surfaced via the headers count.
func (u *upMigration) parsePhaseHeader() {
	ms := phaseHeaderRe.FindAllStringSubmatch(u.content, -1)
	u.headers = len(ms)
	if len(ms) == 0 {
		return
	}
	u.phase = ms[0][1]
	if r := replacesExpandRe.FindStringSubmatch(ms[0][2]); r != nil {
		u.replacesVer, u.replacesStem = r[1], r[2]
	}
}

// stripSQLLineComments removes full-line -- comments. Documentation prose must
// not trip the destructive scan; statement text (including trailing comments
// after live code) stays scanned, which keeps the detector conservative.
func stripSQLLineComments(sql string) string {
	var kept []string
	for _, line := range strings.Split(sql, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// destructiveStatements returns the destructive statement classes found in
// comment-stripped SQL, each reported as "label at line N" (N counts the
// original file's live lines after stripping; line numbers are diagnostics,
// not a contract).
func destructiveStatements(sql string) []string {
	stripped := stripSQLLineComments(sql)
	var hits []string
	for _, d := range destructiveStatementRes {
		for _, loc := range d.re.FindAllStringIndex(stripped, -1) {
			hits = append(hits, fmt.Sprintf("%s at line %d",
				d.label, 1+strings.Count(stripped[:loc[0]], "\n")))
		}
	}
	return hits
}

// scanEmbeddedUpMigrations walks the embedded migrations and parses each up
// file's phase header. The embedded set is byte-synced with ../../migrations
// by TestEmbeddedMigrationsInSyncWithRoot, so scanning the embed is scanning
// the canonical directory.
func scanEmbeddedUpMigrations(t *testing.T) []upMigration {
	t.Helper()
	var ups []upMigration
	err := fs.WalkDir(migrationsFS, "migrations", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		m := migrationFileNameRe.FindStringSubmatch(d.Name())
		if m == nil || m[3] != "up" {
			return nil
		}
		data, err := fs.ReadFile(migrationsFS, path)
		if err != nil {
			return err
		}
		up := upMigration{version: m[1], stem: m[2], name: d.Name(), content: string(data)}
		up.parsePhaseHeader()
		ups = append(ups, up)
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded migrations: %v", err)
	}
	sort.Slice(ups, func(i, j int) bool { return ups[i].version < ups[j].version })
	return ups
}

// classifyUpMigration returns the expand-contract violations for one up
// migration: stems is the embedded version->stem map (for citation checks),
// firstMarkerVersion the version from which the phase header is mandatory.
// Pure over its inputs — the real-set test drives it with the embedded set,
// the sensitivity test with synthetic fixtures.
func classifyUpMigration(u upMigration, stems map[string]string, firstMarkerVersion string) []string {
	var bad []string
	if u.headers > 1 {
		bad = append(bad, fmt.Sprintf(
			"%s: %d expand-contract headers, at most one phase marker per file",
			u.name, u.headers))
	}
	if u.version >= firstMarkerVersion && u.phase == "" {
		bad = append(bad, fmt.Sprintf(
			"%s: missing phase header (mandatory since %s: "+
				"-- expand-contract: expand|contract — ...)", u.name, firstMarkerVersion))
	}
	if hits := destructiveStatements(u.content); len(hits) > 0 {
		if _, exempt := prePolicyContractSwaps[u.version]; u.phase != "contract" && !exempt {
			bad = append(bad, fmt.Sprintf(
				"%s: destructive statements outside a contract phase — %v "+
					"(split a contract migration or cite one)", u.name, hits))
		}
	}
	if u.phase == "contract" {
		if u.replacesVer == "" {
			bad = append(bad, fmt.Sprintf(
				"%s: contract header must cite the predecessor expand "+
					"(replaces expand NNNN_<stem>)", u.name))
		} else {
			self, _ := strconv.Atoi(u.version)
			cited, _ := strconv.Atoi(u.replacesVer)
			stem, known := stems[u.replacesVer]
			switch {
			case cited >= self:
				bad = append(bad, fmt.Sprintf(
					"%s: contract cites expand %s_%s not earlier than itself — "+
						"the replacement must expand first", u.name, u.replacesVer, u.replacesStem))
			case !known:
				bad = append(bad, fmt.Sprintf(
					"%s: contract cites expand %s_%s which is not in the embedded set",
					u.name, u.replacesVer, u.replacesStem))
			case stem != u.replacesStem:
				bad = append(bad, fmt.Sprintf(
					"%s: contract cites expand %s_%s but the embedded stem of %s is %s_%s",
					u.name, u.replacesVer, u.replacesStem, u.replacesVer, u.replacesVer, stem))
			}
		}
	}
	return bad
}

// TestUpMigrationsExpandOnlyUnlessContract — the expand-contract discipline
// over the real embedded set: every up migration after the baseline is
// expand-only unless it carries a valid contract citation or is one of the
// audited pre-policy exemptions; the exemption map itself is closed to the
// pre-policy range (nothing exempted may equal the baseline or reach the
// marker-mandatory era).
func TestUpMigrationsExpandOnlyUnlessContract(t *testing.T) {
	scan := scanEmbeddedNumbering(t)
	ups := scanEmbeddedUpMigrations(t)
	if len(ups) == 0 {
		t.Fatal("no up migrations found in embedded set")
	}
	firstMarker, _ := strconv.Atoi(expandContractFirstVersion)

	var bad []string
	for _, u := range ups {
		if u.version == baselineVersion {
			continue // 0001_init is the baseline itself, not an upgrade step
		}
		bad = append(bad, classifyUpMigration(u, scan.stems, expandContractFirstVersion)...)
	}
	for ver := range prePolicyContractSwaps {
		n, err := strconv.Atoi(ver)
		if err != nil {
			bad = append(bad, "pre-policy exemption "+ver+" is not a 4-digit version")
			continue
		}
		if ver == baselineVersion || n >= firstMarker {
			bad = append(bad, fmt.Sprintf(
				"pre-policy exemption %s is outside the pre-policy range (%s, %04d) — "+
					"post-policy removals need a contract header, not an exemption",
				ver, baselineVersion, firstMarker-1))
		}
	}
	if len(bad) > 0 {
		t.Fatalf("expand-contract violations:\n  - %s", strings.Join(bad, "\n  - "))
	}
}

// TestPrePolicyExemptionsStayLive — an exemption whose migration no longer
// contains any destructive statement is stale: it would silently widen the
// guard's blind spot. Each entry must match a live destructive statement in
// the embedded migration it cites, and the cited version must exist.
func TestPrePolicyExemptionsStayLive(t *testing.T) {
	ups := scanEmbeddedUpMigrations(t)
	byVersion := map[string]upMigration{}
	for _, u := range ups {
		byVersion[u.version] = u
	}
	vers := make([]string, 0, len(prePolicyContractSwaps))
	for ver := range prePolicyContractSwaps {
		vers = append(vers, ver)
	}
	sort.Strings(vers)
	for _, ver := range vers {
		u, ok := byVersion[ver]
		if !ok {
			t.Fatalf("pre-policy exemption %s cites a version absent from the embedded set: %s",
				ver, prePolicyContractSwaps[ver])
		}
		if len(destructiveStatements(u.content)) == 0 {
			t.Fatalf("pre-policy exemption %s is stale — the migration no longer contains "+
				"any destructive statement, delete the exemption: %s",
				ver, prePolicyContractSwaps[ver])
		}
	}
}

// TestExpandContractREADMEStatesPolicy — migrations/README.md is the contract
// of record for the discipline (as it is for mirror+numbering); the policy
// section must state the first marker version equal to this guard's constant,
// so the documented contract and the enforced contract cannot drift apart.
func TestExpandContractREADMEStatesPolicy(t *testing.T) {
	readme, err := fs.ReadFile(migrateRootFS, "README.md")
	if err != nil {
		t.Fatalf("read migrations/README.md: %v", err)
	}
	first, err := parseExpandContractPolicy(string(readme))
	if err != nil {
		t.Fatalf("migrations/README.md must carry the expand-contract policy: %v", err)
	}
	if first != expandContractFirstVersion {
		t.Fatalf("README pins the first marker version %s, the guard enforces %s — "+
			"update the policy claim and the guard constant in one change",
			first, expandContractFirstVersion)
	}
}

// readmePolicyHeadingRe anchors the policy section of migrations/README.md.
var readmePolicyHeadingRe = regexp.MustCompile(
	`(?m)^## Upgrade discipline after the baseline: expand-contract\s*$`)

// readmePolicyFirstMarkerRe anchors the claim that pins the first marker
// version inside the policy section.
var readmePolicyFirstMarkerRe = regexp.MustCompile(
	`(?m)^- Every new up migration from \*\*(\d{4})\*\* starts with a phase marker`)

// readmeNextHeadingRe finds the end of the policy section.
var readmeNextHeadingRe = regexp.MustCompile(`(?m)^## `)

// parseExpandContractPolicy extracts the expand-contract claims from the
// README: the first marker version, with both marker forms documented. An
// error means the README no longer states the policy in the documented shape
// and must be re-anchored together with this test.
func parseExpandContractPolicy(readme string) (string, error) {
	start := readmePolicyHeadingRe.FindStringIndex(readme)
	if start == nil {
		return "", fmt.Errorf("README has no '## Upgrade discipline after the baseline: expand-contract' section")
	}
	section := readme
	if next := readmeNextHeadingRe.FindStringIndex(readme[start[0]+1:]); next != nil {
		section = readme[start[0] : start[0]+1+next[0]]
	}
	m := readmePolicyFirstMarkerRe.FindStringSubmatch(section)
	if m == nil {
		return "", fmt.Errorf("expand-contract section does not pin the first marker version " +
			"(Every new up migration from **NNNN** starts with a phase marker)")
	}
	for _, form := range []string{
		"-- expand-contract: expand",
		"-- expand-contract: contract",
		"replaces expand",
	} {
		if !strings.Contains(section, form) {
			return "", fmt.Errorf("expand-contract section must document the %q marker form", form)
		}
	}
	return m[1], nil
}

// TestExpandContractDetectorCatchesViolationClasses — sensitivity arm so the
// discipline cannot pass vacuously (same pattern as
// TestNumberingContractCheckDetectsDrift): every detector class is driven with
// a synthetic up migration and must be flagged with its diagnosis, the clean
// shapes must pass, and the README guard must reject a missing section and a
// wrong pinned version.
func TestExpandContractDetectorCatchesViolationClasses(t *testing.T) {
	stems := map[string]string{"0016": "add_fee_column"}
	const first = "0016"

	clean := upMigration{version: "0016", stem: "add_fee_column",
		name: "0016_add_fee_column.up.sql",
		content: "-- expand-contract: expand — fee column plus bounded idempotent backfill\n" +
			"ALTER TABLE public.invoices ADD COLUMN fee_cents integer;\n" +
			"UPDATE public.invoices SET fee_cents = 0 WHERE fee_cents IS NULL;\n",
		phase: "expand"}
	if bad := classifyUpMigration(clean, stems, first); len(bad) != 0 {
		t.Fatalf("clean expand must pass, got: %v", bad)
	}

	valid := upMigration{version: "0017", stem: "drop_legacy_fee",
		name: "0017_drop_legacy_fee.up.sql",
		content: "-- expand-contract: contract — replaces expand 0016_add_fee_column; " +
			"removes the superseded legacy integer column (structure only)\n" +
			"ALTER TABLE public.invoices DROP COLUMN legacy_fee;\n",
		phase: "contract", replacesVer: "0016", replacesStem: "add_fee_column"}
	if bad := classifyUpMigration(valid, stems, first); len(bad) != 0 {
		t.Fatalf("valid contract with a live citation must pass, got: %v", bad)
	}

	// The audited pre-policy swap passes through the exemption map, not the
	// header path: version 0005 predates markers and its header is absent.
	swap := upMigration{version: "0005", stem: "cloud_providers",
		name: "0005_cloud_providers.up.sql",
		content: "-- R108-02 prose header\n" +
			"ALTER TABLE public.models_registry DROP CONSTRAINT chk_provider;\n" +
			"ALTER TABLE public.models_registry ADD CONSTRAINT chk_provider CHECK (provider <> '');\n"}
	if bad := classifyUpMigration(swap, stems, first); len(bad) != 0 {
		t.Fatalf("audited pre-policy swap must pass via the exemption map, got: %v", bad)
	}

	classes := []struct {
		diagnosis string
		up        upMigration
		want      string
	}{
		{
			"unmarked up migration at the marker era",
			upMigration{version: "0018", stem: "later_thing", name: "0018_later_thing.up.sql",
				content: "CREATE TABLE public.t (x integer);\n"},
			"missing phase header",
		},
		{
			"DROP COLUMN outside a contract phase",
			upMigration{version: "0019", stem: "oopsy", name: "0019_oopsy.up.sql",
				content: "-- expand-contract: expand — misc\nALTER TABLE public.t DROP COLUMN x;\n",
				phase:   "expand"},
			"DROP <object>",
		},
		{
			"TRUNCATE outside a contract phase",
			upMigration{version: "0019", stem: "oopsy", name: "0019_oopsy.up.sql",
				content: "TRUNCATE public.t;\n"},
			"TRUNCATE",
		},
		{
			"DELETE FROM outside a contract phase",
			upMigration{version: "0019", stem: "oopsy", name: "0019_oopsy.up.sql",
				content: "DELETE FROM public.t WHERE x = 1;\n"},
			"DELETE FROM",
		},
		{
			"column type conversion outside a contract phase",
			upMigration{version: "0019", stem: "oopsy", name: "0019_oopsy.up.sql",
				content: "ALTER TABLE public.t ALTER COLUMN x TYPE bigint;\n"},
			"ALTER COLUMN <col> TYPE",
		},
		{
			"RENAME outside a contract phase",
			upMigration{version: "0019", stem: "oopsy", name: "0019_oopsy.up.sql",
				content: "ALTER TABLE public.t RENAME TO t2;\n"},
			"RENAME",
		},
		{
			"SET NOT NULL outside a contract phase",
			upMigration{version: "0019", stem: "oopsy", name: "0019_oopsy.up.sql",
				content: "ALTER TABLE public.t ALTER COLUMN x SET NOT NULL;\n"},
			"SET NOT NULL",
		},
		{
			"unmarked pre-policy destructive statement without an exemption",
			upMigration{version: "0009", stem: "historic", name: "0009_historic.up.sql",
				content: "DROP INDEX public.i;\n"},
			"destructive statements outside a contract phase",
		},
		{
			"two phase markers in one file",
			upMigration{version: "0016", stem: "ambiguous", name: "0016_ambiguous.up.sql",
				content: "-- expand-contract: expand — a\n-- expand-contract: contract — b\nCREATE TABLE t (x int);\n",
				phase:   "expand", headers: 2},
			"at most one phase marker",
		},
		{
			"contract without a predecessor citation",
			upMigration{version: "0017", stem: "no_cite", name: "0017_no_cite.up.sql",
				content: "-- expand-contract: contract — removes stuff\nDROP TABLE public.t;\n",
				phase:   "contract"},
			"must cite the predecessor expand",
		},
		{
			"contract citing a version absent from the embedded set",
			upMigration{version: "0017", stem: "bad_cite", name: "0017_bad_cite.up.sql",
				content: "-- expand-contract: contract — replaces expand 0013_ghost; drop\nDROP TABLE public.t;\n",
				phase:   "contract", replacesVer: "0013", replacesStem: "ghost"},
			"not in the embedded set",
		},
		{
			"contract citing its own version (replacement must expand first)",
			upMigration{version: "0017", stem: "self_cite", name: "0017_self_cite.up.sql",
				content: "-- expand-contract: contract — replaces expand 0017_self_expand; drop\nDROP TABLE public.t;\n",
				phase:   "contract", replacesVer: "0017", replacesStem: "self_expand"},
			"not earlier than itself",
		},
		{
			"contract citing the wrong stem of a real version",
			upMigration{version: "0017", stem: "wrong_stem", name: "0017_wrong_stem.up.sql",
				content: "-- expand-contract: contract — replaces expand 0016_not_this; drop\nDROP TABLE public.t;\n",
				phase:   "contract", replacesVer: "0016", replacesStem: "not_this"},
			"the embedded stem of 0016 is 0016_add_fee_column",
		},
	}
	for _, tc := range classes {
		bad := classifyUpMigration(tc.up, stems, first)
		if len(bad) == 0 {
			t.Fatalf("detector missed the violation class %q", tc.diagnosis)
		}
		if !strings.Contains(strings.Join(bad, "; "), tc.want) {
			t.Fatalf("violation class %q: want diagnosis containing %q, got %v",
				tc.diagnosis, tc.want, bad)
		}
	}

	// Comment prose must not trip the destructive scan: the marker header
	// above is documentation, not a statement.
	prose := upMigration{version: "0020", stem: "prose_safe", name: "0020_prose_safe.up.sql",
		content: "-- expand-contract: expand — replaces nothing yet; the old column is dropped later\n" +
			"CREATE TABLE public.new_shape (id integer);\n",
		phase: "expand"}
	if bad := classifyUpMigration(prose, stems, first); len(bad) != 0 {
		t.Fatalf("full-line comment prose must not trip the destructive scan, got: %v", bad)
	}

	// README guard sensitivity: a README without the section, and a section
	// pinning a different version, must both be rejected.
	if _, err := parseExpandContractPolicy("# Migrations\n\nSomething else entirely.\n"); err == nil {
		t.Fatal("README guard must reject a README without the expand-contract section")
	}
	stale := "## Upgrade discipline after the baseline: expand-contract\n\n" +
		"- Every new up migration from **0002** starts with a phase marker: " +
		"`-- expand-contract: expand — ...` or `-- expand-contract: contract — replaces expand NNNN_<stem>`.\n" +
		"- End of section.\n\n## Another section\n\nText.\n"
	got, err := parseExpandContractPolicy(stale)
	if err != nil {
		t.Fatalf("realistic policy prose must parse: %v", err)
	}
	if got != "0002" {
		t.Fatalf("the guard must read the pinned version from the prose, got %q", got)
	}
	if got == expandContractFirstVersion {
		t.Fatal("sensitivity fixture pinned the guard's own version; the drift arm proves nothing")
	}
}
