package migrate

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// golang-migrate requires each (version, direction) to be unique. The repo's
// migrations are normally applied by raw psql (compose job) which ignores
// version numbers, so a numbering collision is latent until the golang-migrate
// in-process path (pkg/migrate.Run) is exercised. This guard fails fast when a
// version number is reused for two distinct migrations, turning that landmine
// into a visible, always-on invariant.
var upMigrationRe = regexp.MustCompile(`^([0-9]{4})_.*\.up\.sql$`)

// duplicateUpVersions returns, for each duplicated version, the pair of .up.sql
// files that collide. Empty when the embedded set has unique versions.
func duplicateUpVersions() []string {
	seen := map[string]string{} // version -> first migration name
	var dups []string
	_ = fs.WalkDir(migrationsFS, "migrations", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		m := upMigrationRe.FindStringSubmatch(d.Name())
		if m == nil {
			return nil
		}
		ver := m[1]
		if prev, ok := seen[ver]; ok {
			dups = append(dups, prev+" and "+d.Name())
			return nil
		}
		seen[ver] = d.Name()
		return nil
	})
	return dups
}

func TestEmbeddedMigrationsHaveUniqueVersions(t *testing.T) {
	dups := duplicateUpVersions()
	if len(dups) > 0 {
		sort.Strings(dups)
		t.Fatalf("duplicate migration version(s) — golang-migrate cannot run these in-process: %s",
			strings.Join(dups, "; "))
	}
}
