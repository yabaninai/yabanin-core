package catalogs

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// repoRoot walks up from this test file to the directory containing go.mod
// (same technique as pkg/pricing/consumers_test.go), so the corpus tests
// run hermetically from any working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("go.mod not found above test directory")
	return ""
}

// readCorpusFile reads a committed in-repo file by repo-root-relative path.
func readCorpusFile(t *testing.T, rel string) []byte {
	t.Helper()
	// #nosec G304 -- the path is a compile-time pinned in-repo corpus
	// location (no user input); reading the committed corpus IS the test
	// input contract.
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read committed corpus file %s: %v", rel, err)
	}
	return b
}

// corpusInputs loads only the independently verified primary record.
func corpusInputs(t *testing.T) BuildInput {
	t.Helper()
	return BuildInput{
		NebiusRecord: readCorpusFile(t, "scripts/stand-agenteval/nebius-catalog.json"),
	}
}

// writeFile creates (or replaces) a repo file from test code; used only by
// the golden-file -update flow.
func writeFile(path string, content []byte) error {
	// #nosec G304 -- the path is a compile-time pinned repo location (no
	// user input); writing it IS the golden-update operation.
	// 0o600 satisfies gosec G306; git stores file content, not mode, so the
	// committed pin and the repo checkout are unaffected.
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return err
	}
	return nil
}

// importedInputs is authored test data, not sampled upstream prices. It keeps
// optional import conversion, provenance and ordering coverage independent of
// the small primary-only shipped catalog.
func importedInputs(t *testing.T) BuildInput {
	t.Helper()
	in := corpusInputs(t)
	in.TokenSnapshot = []byte(`{"source":"github.com/BerriAI/litellm@synthetic-test-only","date":"2026-09-30","currency":"USD","units":"per_1m_tokens","models":[{"provider":"fixture","model":"priced","input":17,"output":29,"cache_r":5},{"provider":"fixture","model":"unknown-input","input":0,"output":31}]}`)
	in.UnitSnapshot = []byte(`{"source":"synthetic unit fixture","date":"2026-09-30","currency":"USD","units":[{"provider":"fixture","model":"image","unit":"per_image","rate":0.123456}]}`)
	return in
}
