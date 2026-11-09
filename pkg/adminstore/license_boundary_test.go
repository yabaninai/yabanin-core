package adminstore

// N04-P06 boundary regression: the provisioning store is the plane where the
// cancelled seat cap (owner answers I16–I20, superseded by I22) could return
// unnoticed — a background account-count enforcement would have to import the
// license package to consult seat entitlements. Core has no account limit, so
// this package must not depend on licensing at all. If a future change
// reintroduces such an import, this test fails and the change must justify
// the account-limit semantics explicitly against the product contract.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminstoreNeverImportsLicense(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "github.com/reireirei/yabanin/pkg/license" {
				t.Errorf("%s imports %s: the account-provisioning plane must not consult licensing (core has no account limit)", name, path)
			}
		}
	}
}
