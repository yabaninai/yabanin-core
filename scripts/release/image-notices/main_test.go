package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func put(t *testing.T, root, name, value string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReplacementBuildInfo(t *testing.T) {
	text := "/private/build/yabanin: go1.27.3\n\tpath\texample.org/app\n\tmod\texample.org/app\t(devel)\t\n\tdep\texample.org/Original\tv1.0.0\th1:original\n\t=>\texample.org/Fork\tv1.2.0\th1:fork\n\n\tbuild\tCGO_ENABLED=0\n"
	version, modules, err := parseModules(text)
	if err != nil {
		t.Fatal(err)
	}
	if version != "go1.27.3" || len(modules) != 1 {
		t.Fatalf("unexpected parsed modules: %s %#v", version, modules)
	}
	record, key, err := moduleSource(modules[0])
	if err != nil {
		t.Fatal(err)
	}
	if key != "example.org/!fork@v1.2.0" || record.SourcePath != "example.org/Fork" || record.Sum != "h1:fork" || record.Path != "example.org/Original" {
		t.Fatalf("replacement lost: %#v %s", record, key)
	}
}

func TestInvalidModuleInputs(t *testing.T) {
	for _, value := range []string{"../outside", "/absolute", "x/../outside", "x\\outside", "x\nother", "x@v1", "x!escape"} {
		t.Run(value, func(t *testing.T) {
			if _, err := escaped(value); err == nil {
				t.Fatal("unsafe identity accepted")
			}
		})
	}
	if _, _, err := parseModules("binary: no build info"); err == nil {
		t.Fatal("missing build info accepted")
	}
	m := &debug.Module{Path: "example.org/mod", Version: "v1.0.0", Replace: &debug.Module{Path: "../local", Version: "(devel)"}}
	if _, _, err := moduleSource(m); err == nil {
		t.Fatal("unversioned local replacement accepted")
	}
}

func fixture(t *testing.T) (string, string, string, []*debug.Module) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	cache := filepath.Join(root, "cache")
	goroot := filepath.Join(root, "go")
	for _, n := range []string{"LICENSE", "NOTICE", "LICENSING.md", "pkg/pricing/NOTICE-litellm.txt"} {
		put(t, source, n, "project text "+n)
	}
	put(t, source, "scripts/release/image-os-notices/notices/COPYING", "original OS legal text")
	put(t, source, "scripts/release/image-os-notices/MANIFEST.json", "{\"scope\":\"fixture\"}")
	put(t, goroot, "LICENSE", "Go original license")
	put(t, goroot, "src/internal/copyright/copyright_test.go", "not shipped copyright test source")
	put(t, source, "scripts/release/image-os-notices/notices/empty-LICENSE", "")
	put(t, goroot, "src/vendor/example/LICENSE", "stdlib vendor original license")
	put(t, cache, "example.org/!fork@v1.2.0/LICENSE", "replacement license")
	put(t, cache, "example.org/!fork@v1.2.0/nested/NOTICE.txt", "retained upstream attribution")
	put(t, cache, "example.org/!fork@v1.2.0/PATENTS", "original patent text")
	put(t, cache, "example.org/!fork@v1.2.0/source.go", "not shipped in legal payload")
	put(t, cache, "example.org/!fork@v1.2.0/notice.go", "not shipped driver source")
	put(t, goroot, "src/internal/copyright/copyright.go", "not shipped copyright source")
	put(t, cache, "example.org/!original@v1.0.0/LICENSE", "WRONG original license")
	put(t, cache, "example.org/unlinked@v1.0.0/LICENSE", "UNLINKED license")
	modules := []*debug.Module{{Path: "example.org/Original", Version: "v1.0.0", Replace: &debug.Module{Path: "example.org/Fork", Version: "v1.2.0", Sum: "h1:fork"}}}
	return source, cache, goroot, modules
}

func TestDeterministicExactLinkedPayload(t *testing.T) {
	source, cache, goroot, modules := fixture(t)
	first := filepath.Join(t.TempDir(), "one")
	second := filepath.Join(t.TempDir(), "two")
	for _, output := range []string{first, second} {
		if err := collect(source, cache, goroot, output, modules, "go1.27.3", "binary-hash", 1234567890); err != nil {
			t.Fatal(err)
		}
	}
	var inv inventory
	data, err := readRegular(filepath.Join(first, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &inv); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), source) || strings.Contains(string(data), cache) || strings.Contains(string(data), goroot) {
		t.Fatal("host path leaked")
	}
	if len(inv.Modules) != 1 || inv.Modules[0].SourcePath != "example.org/Fork" {
		t.Fatalf("wrong modules: %#v", inv.Modules)
	}
	if len(inv.Files) != 12 {
		t.Fatalf("unexpected inventory: %#v", inv.Files)
	}
	if err = filepath.Walk(first, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(first, path)
		if relErr != nil {
			return relErr
		}
		if info.ModTime().Unix() != 1234567890 {
			t.Errorf("mtime not normalized: %s", rel)
		}
		if info.IsDir() {
			return nil
		}
		a, readErr := readRegular(path)
		if readErr != nil {
			return readErr
		}
		b, readErr := readRegular(filepath.Join(second, rel))
		if readErr != nil {
			return readErr
		}
		if string(a) != string(b) {
			t.Errorf("nondeterministic bytes: %s", rel)
		}
		if strings.Contains(string(a), "WRONG original") || strings.Contains(string(a), "UNLINKED") || strings.Contains(string(a), "not shipped") {
			t.Errorf("unselected input copied: %s", rel)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = collect(source, cache, goroot, first, modules, "go1.27.3", "binary-hash", 1234567890); err == nil {
		t.Fatal("existing output accepted")
	}
}

func TestMissingOrUnsafeLegalInputs(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "symlink", "only-notice"} {
		t.Run(kind, func(t *testing.T) {
			source, cache, goroot, modules := fixture(t)
			license := filepath.Join(cache, "example.org/!fork@v1.2.0/LICENSE")
			if err := os.Remove(license); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "empty":
				put(t, cache, "example.org/!fork@v1.2.0/LICENSE", "")
			case "symlink":
				if err := os.Symlink(filepath.Join(goroot, "LICENSE"), license); err != nil {
					t.Fatal(err)
				}
			case "missing":
				modules[0].Replace.Version = "v9.9.9"
			}
			if err := collect(source, cache, goroot, filepath.Join(t.TempDir(), "out"), modules, "go1.27.3", "hash", 123); err == nil {
				t.Fatal("invalid legal input accepted")
			}
		})
	}
}
