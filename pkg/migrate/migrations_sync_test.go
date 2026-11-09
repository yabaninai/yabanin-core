package migrate

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// migrateRootFS is the canonical migrations directory at repo root. From
// pkg/migrate the root is two levels up.
var migrateRootFS = os.DirFS("../../migrations")

// TestEmbeddedMigrationsInSyncWithRoot fails when the migrations embedded
// in this package drift from the canonical ../../migrations directory.
func TestEmbeddedMigrationsInSyncWithRoot(t *testing.T) {
	rootFiles := map[string][]byte{}
	err := fs.WalkDir(migrateRootFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		data, err := fs.ReadFile(migrateRootFS, path) // no traversal: path comes from WalkDir of a fixed root
		if err != nil {
			return err
		}
		rootFiles[path] = data
		return nil
	})
	if err != nil {
		t.Fatalf("walk root migrations: %v", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}

	var missingFromEmbed, extraInEmbed, contentDiff []string
	for _, e := range entries {
		name := filepath.Join("migrations", e.Name())
		rootData, ok := rootFiles[e.Name()]
		if !ok {
			extraInEmbed = append(extraInEmbed, e.Name())
			continue
		}
		emb, err := migrationsFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", name, err)
		}
		delete(rootFiles, e.Name())
		if string(rootData) != string(emb) {
			contentDiff = append(contentDiff, e.Name())
		}
	}
	for name := range rootFiles {
		missingFromEmbed = append(missingFromEmbed, name)
	}

	sort.Strings(missingFromEmbed)
	sort.Strings(extraInEmbed)
	sort.Strings(contentDiff)
	if len(missingFromEmbed)+len(extraInEmbed)+len(contentDiff) > 0 {
		t.Fatalf("embedded migrations out of sync with ../../migrations — "+
			"missing from embed: %v, extra in embed: %v, content differs: %v",
			missingFromEmbed, extraInEmbed, contentDiff)
	}
}
