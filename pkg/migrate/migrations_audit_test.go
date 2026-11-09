package migrate

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// S04: migration audit. The mirror (embedded vs canonical) is covered by
// migrations_sync_test.go. This test adds the structural half of the audit
// that does NOT need a database: every version must have exactly one up and
// one down migration with identical version prefixes, and no version may be
// duplicated. It runs in the normal (non-integration) gate.

var migrationNameRe = regexp.MustCompile(`^(\d+)_.*\.(up|down)\.sql$`)

// migrationPair groups the up/down file names for one version.
type migrationPair struct {
	version string
	up      string
	down    string
}

// collectMigrationPairs walks the embedded migrations and groups files by
// version. It returns the pairs plus any structural violations.
func collectMigrationPairs(t *testing.T) ([]migrationPair, []string) {
	t.Helper()
	byVersion := map[string]*migrationPair{}
	var violations []string

	err := fs.WalkDir(migrationsFS, "migrations", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".sql") {
			return nil
		}
		m := migrationNameRe.FindStringSubmatch(name)
		if m == nil {
			violations = append(violations, "unrecognized migration name: "+name)
			return nil
		}
		ver, dir := m[1], m[2]
		pair, ok := byVersion[ver]
		if !ok {
			pair = &migrationPair{version: ver}
			byVersion[ver] = pair
		}
		switch dir {
		case "up":
			if pair.up != "" {
				violations = append(violations, "duplicate up for version "+ver+": "+pair.up+" and "+name)
			}
			pair.up = name
		case "down":
			if pair.down != "" {
				violations = append(violations, "duplicate down for version "+ver+": "+pair.down+" and "+name)
			}
			pair.down = name
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded migrations: %v", err)
	}

	var pairs []migrationPair
	for _, p := range byVersion {
		if p.up == "" {
			violations = append(violations, "version "+p.version+" has a down but no up migration")
		}
		if p.down == "" {
			violations = append(violations, "version "+p.version+" has an up but no down migration")
		}
		pairs = append(pairs, *p)
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].version < pairs[j].version })
	return pairs, violations
}

// foundationalUpOnly historically exempted the up-only 0001–0008 schema
// migrations. After the squash (single consolidated 0001_init baseline with a
// full down), every version must be paired — no exceptions.
var foundationalUpOnly = map[string]bool{}

// TestMigrations_PairedUpDown asserts the structural invariant: no duplicate
// up or down per version, and every version — including the consolidated
// 0001_init baseline — has exactly one matching down. Since the squash there
// are no up-only exceptions (foundationalUpOnly is the kept, empty
// exemption map). This is the no-database half of the S04 audit.
func TestMigrations_PairedUpDown(t *testing.T) {
	pairs, violations := collectMigrationPairs(t)
	// Duplicate up/down and missing-up are always violations.
	for _, v := range violations {
		if strings.Contains(v, "duplicate") || strings.Contains(v, "no up migration") {
			t.Fatalf("migration structure violation: %s", v)
		}
	}
	if len(pairs) == 0 {
		t.Fatal("no migrations found in embedded set")
	}
	// Every non-foundational version must be paired up+down.
	var unpaired []string
	for _, p := range pairs {
		if p.down == "" && !foundationalUpOnly[p.version] {
			unpaired = append(unpaired, p.version)
		}
	}
	sort.Strings(unpaired)
	if len(unpaired) > 0 {
		t.Fatalf("versions missing a down migration (every version must be paired): %v", unpaired)
	}
}

// TestMigrations_NoDuplicateVersions asserts version numbers are unique across
// the embedded set (the duplicate that currently gates the integration test).
func TestMigrations_NoDuplicateVersions(t *testing.T) {
	pairs, violations := collectMigrationPairs(t)
	for _, v := range violations {
		if strings.Contains(v, "duplicate") {
			t.Fatalf("duplicate version detected: %s", v)
		}
	}
	// Also assert uniqueness directly from the pair set.
	seen := map[string]bool{}
	for _, p := range pairs {
		if seen[p.version] {
			t.Fatalf("version %s appears more than once", p.version)
		}
		seen[p.version] = true
	}
}
