package delegation

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHotPathPackagesDoNotImportDelegation(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	roots := []string{
		filepath.Join(root, "pkg", "gateway"),
		filepath.Join(root, "pkg", "provider"),
		filepath.Join(root, "pkg", "upstream"),
		filepath.Join(root, "pkg", "resolver"),
	}
	needle := "github.com/reireirei/yabanin/pkg/delegation"
	for _, dir := range roots {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			b, rerr := os.ReadFile(path) //nolint:gosec // WalkDir only visits *.go under fixed repo packages
			if rerr != nil {
				return rerr
			}
			if strings.Contains(string(b), needle) {
				t.Errorf("%s imports pkg/delegation", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
