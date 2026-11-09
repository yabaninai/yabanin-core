package migrate

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// N10-P01-T05: the packet's negative scenario — a down migration never
// promises to restore deleted data. The down side of the migration set is a
// structural reverse only (drop what the corresponding up created); it must
// never bring rows back. A down migration that re-inserts "restored" or seed
// rows fabricates data and lies about what a downgrade preserves, so the
// contract is enforced here as always-on checks (same posture as
// mirror_numbering_test.go and expand_contract_test.go):
//
//  1. no down migration contains a data-restoring statement class (INSERT
//     INTO, SELECT … INTO, CREATE … AS SELECT, COPY … FROM);
//  2. migrations/README.md states the down-side rule and names these guards,
//     so the documented contract and the enforced contract cannot drift apart;
//  3. the detector itself is sensitivity-checked so the scan cannot pass
//     vacuously.
//
// The live (real-Postgres) arm of the scenario is
// TestRun_DownLeavesDeletedDataDeleted (down_side_integration_test.go):
// up → seed → down → re-up must return the structure without the deleted
// rows. Note on scope: DELETE and UPDATE in a down migration are not
// restoration — removing rows (e.g. un-seeding the rows the corresponding up
// inserted, the shipped 0005 precedent) or correcting in place never
// resurrects deleted data, so they stay outside this detector.

// restorationStatementRes are the statement classes a down migration must not
// contain: each one creates or imports rows, i.e. promises data restoration.
// The scan is a best-effort lexical pass over comment-stripped SQL, biased
// toward false positives over false negatives — the remedy for a trip is
// rewording or removing the statement, never weakening the detector.
var restorationStatementRes = []struct {
	label string
	re    *regexp.Regexp
}{
	{"INSERT INTO (row restoration)", regexp.MustCompile(`(?i)\bINSERT\s+INTO\b`)},
	{"SELECT … INTO (table fabrication)", regexp.MustCompile(`(?i)\bSELECT\b[^;]*\bINTO\b`)},
	{"CREATE … AS SELECT (row fabrication)", regexp.MustCompile(`(?i)\bCREATE\s+(?:(?:MATERIALIZED|GLOBAL|LOCAL|TEMPORARY|TEMP|UNLOGGED)\s+)*(?:TABLE|VIEW)\b[^;]*\bAS\s+SELECT\b`)},
	{"COPY … FROM (data import)", regexp.MustCompile(`(?i)\bCOPY\s+[^;]*\bFROM\s+(?:STDIN|PROGRAM|'|"|[0-9])`)},
}

// downMigration is one embedded down migration file.
type downMigration struct {
	version string
	stem    string
	name    string
	content string
}

// scanEmbeddedDownMigrations walks the embedded migrations and returns the
// down files sorted by version. The embedded set is byte-synced with
// ../../migrations by TestEmbeddedMigrationsInSyncWithRoot, so scanning the
// embed is scanning the canonical directory.
func scanEmbeddedDownMigrations(t *testing.T) []downMigration {
	t.Helper()
	var downs []downMigration
	err := fs.WalkDir(migrationsFS, "migrations", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		m := migrationFileNameRe.FindStringSubmatch(d.Name())
		if m == nil || m[3] != "down" {
			return nil
		}
		data, err := fs.ReadFile(migrationsFS, path)
		if err != nil {
			return err
		}
		downs = append(downs, downMigration{version: m[1], stem: m[2], name: d.Name(), content: string(data)})
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded migrations: %v", err)
	}
	sort.Slice(downs, func(i, j int) bool { return downs[i].version < downs[j].version })
	return downs
}

// restorationStatements returns the data-restoring statement classes found in
// comment-stripped SQL, each reported as "label at line N" (N counts the
// original file's live lines after stripping; line numbers are diagnostics,
// not a contract). Pure over its inputs — the real-set test drives it with
// embedded down migrations, the sensitivity test with synthetic fixtures.
func restorationStatements(sql string) []string {
	stripped := stripSQLLineComments(sql)
	var hits []string
	for _, r := range restorationStatementRes {
		for _, loc := range r.re.FindAllStringIndex(stripped, -1) {
			hits = append(hits, fmt.Sprintf("%s at line %d",
				r.label, 1+strings.Count(stripped[:loc[0]], "\n")))
		}
	}
	return hits
}

// TestDownMigrationsNeverRestoreData — the negative scenario over the real
// embedded set: every down migration in the shipped set is a structural
// reverse with zero data-restoring statements. A violation is a loud failure
// naming the file, the class and the line, not a silent pass.
func TestDownMigrationsNeverRestoreData(t *testing.T) {
	downs := scanEmbeddedDownMigrations(t)
	if len(downs) == 0 {
		t.Fatal("no down migrations found in embedded set")
	}
	var bad []string
	for _, d := range downs {
		if hits := restorationStatements(d.content); len(hits) > 0 {
			bad = append(bad, fmt.Sprintf(
				"%s: down migration must not promise data restoration — %v "+
					"(a down is a structural reverse; deleted data stays deleted)",
				d.name, hits))
		}
	}
	if len(bad) > 0 {
		t.Fatalf("down-side restoration violations:\n  - %s", strings.Join(bad, "\n  - "))
	}
}

// readmeDownRuleRe anchors the down-side rule claim in migrations/README.md
// (the general rules section): the rule sentence must survive verbatim
// modulo line wraps.
var readmeDownRuleRe = regexp.MustCompile(
	`(?s)Down migrations do not restore\s+deleted\s+data;\s+they provide structural reversals only`)

// readmeDownGuardRe anchors the guard-naming bullet in the README policy
// section: the down-side guards and the live negative scenario must stay
// named where the discipline is documented.
var readmeDownGuardRe = regexp.MustCompile(
	`(?s)TestDownMigrationsNeverRestoreData.*TestDownSideDetectorCatchesRestorationClasses.*TestRun_DownLeavesDeletedDataDeleted`)

// parseDownSideContract extracts the down-side claims from the README. An
// error means the README no longer states the rule in the documented shape
// and must be re-anchored together with this guard.
func parseDownSideContract(readme string) error {
	if !readmeDownRuleRe.MatchString(readme) {
		return fmt.Errorf("README does not state the down-side rule " +
			"(«Down migrations do not restore deleted data; they provide structural reversals only»)")
	}
	if !readmeDownGuardRe.MatchString(readme) {
		return fmt.Errorf("README does not name the down-side guards " +
			"(TestDownMigrationsNeverRestoreData, TestDownSideDetectorCatchesRestorationClasses, " +
			"TestRun_DownLeavesDeletedDataDeleted)")
	}
	return nil
}

// TestDownSideREADMEMatchesGuard — migrations/README.md is the contract of
// record; the down-side rule and the guard names must stay stated there so
// the negative scenario cannot be silently unenforced or undocumented.
func TestDownSideREADMEMatchesGuard(t *testing.T) {
	readme, err := fs.ReadFile(migrateRootFS, "README.md")
	if err != nil {
		t.Fatalf("read migrations/README.md: %v", err)
	}
	if err := parseDownSideContract(string(readme)); err != nil {
		t.Fatalf("migrations/README.md must carry the down-side contract: %v", err)
	}
}

// TestDownSideDetectorCatchesRestorationClasses — sensitivity arm so the
// down-side guard cannot pass vacuously (same pattern as
// TestExpandContractDetectorCatchesViolationClasses): every restoration class
// is driven with a synthetic down migration and must be flagged with its
// diagnosis and a line number; the legitimate down shapes (structural
// reverse, seed-removal reversal) must pass; the README guard must reject a
// missing rule sentence and a missing guard bullet.
func TestDownSideDetectorCatchesRestorationClasses(t *testing.T) {
	// Legitimate shapes.
	structural := downMigration{version: "0016", stem: "drop_probe",
		name: "0016_drop_probe.down.sql",
		content: "-- Reverse of 0016_drop_probe.up.sql: structural reverse only.\n" +
			"DROP INDEX IF EXISTS probe_subject_idx;\n" +
			"DROP TABLE IF EXISTS probe;\n"}
	if hits := restorationStatements(structural.content); len(hits) != 0 {
		t.Fatalf("clean structural reverse must pass, got: %v", hits)
	}

	seedReversal := downMigration{version: "0005", stem: "cloud_providers",
		name: "0005_cloud_providers.down.sql",
		content: "-- R108-02 down: restore the 18-value chk_provider and remove the\n" +
			"-- cloud provider jurisdiction seed rows.\n" +
			"DELETE FROM public.provider_jurisdictions\n" +
			"    WHERE provider IN ('azure-openai', 'bedrock', 'vertex');\n" +
			"ALTER TABLE public.models_registry DROP CONSTRAINT chk_provider;\n"}
	if hits := restorationStatements(seedReversal.content); len(hits) != 0 {
		t.Fatalf("seed-removal reversal (shipped 0005 shape) must pass, got: %v", hits)
	}

	classes := []struct {
		diagnosis string
		content   string
		want      string
	}{
		{
			"INSERT INTO re-inserting deleted rows",
			"DROP TABLE IF EXISTS probe;\nINSERT INTO probe (id) VALUES (1);\n",
			"INSERT INTO (row restoration)",
		},
		{
			"INSERT INTO as the second statement after comment prose",
			"-- Reverse of the up.\nDROP TABLE IF EXISTS other;\nINSERT INTO public.other (id) VALUES (7);\n",
			"INSERT INTO (row restoration)",
		},
		{
			"SELECT … INTO fabricating a table",
			"SELECT id, name INTO probe_copy FROM probe;\n",
			"SELECT … INTO (table fabrication)",
		},
		{
			"CREATE TABLE AS SELECT fabricating rows",
			"CREATE TABLE probe_restored AS SELECT * FROM probe;\n",
			"CREATE … AS SELECT (row fabrication)",
		},
		{
			"CREATE MATERIALIZED VIEW AS SELECT",
			"CREATE MATERIALIZED VIEW probe_mv AS SELECT id FROM probe;\n",
			"CREATE … AS SELECT (row fabrication)",
		},
		{
			"COPY FROM STDIN importing rows",
			"COPY probe (id) FROM STDIN;\n",
			"COPY … FROM (data import)",
		},
	}
	for _, tc := range classes {
		hits := restorationStatements(tc.content)
		if len(hits) == 0 {
			t.Fatalf("detector missed the restoration class %q", tc.diagnosis)
		}
		if !strings.Contains(strings.Join(hits, "; "), tc.want) {
			t.Fatalf("restoration class %q: want diagnosis containing %q, got %v",
				tc.diagnosis, tc.want, hits)
		}
		if !strings.Contains(strings.Join(hits, "; "), "at line ") {
			t.Fatalf("restoration class %q: diagnosis must carry a line number, got %v",
				tc.diagnosis, hits)
		}
	}

	// Comment prose must not trip the restoration scan.
	prose := downMigration{version: "0017", stem: "prose_safe",
		name: "0017_prose_safe.down.sql",
		content: "-- Reverse of 0017: no data is restored here; the up's seed INSERT\n" +
			"-- is not replayed by the down.\nDROP TABLE IF EXISTS probe;\n"}
	if hits := restorationStatements(prose.content); len(hits) != 0 {
		t.Fatalf("full-line comment prose must not trip the restoration scan, got: %v", hits)
	}

	// README guard sensitivity: a README without the rule sentence and a
	// README without the guard bullet must both be rejected.
	if err := parseDownSideContract("# Migrations\n\nSomething else entirely.\n"); err == nil {
		t.Fatal("README guard must reject a README without the down-side rule")
	}
	noGuards := "Down migrations do not restore deleted data; they provide structural reversals only.\n"
	if err := parseDownSideContract(noGuards); err == nil {
		t.Fatal("README guard must reject a README that states the rule but does not name the guards")
	}
}
