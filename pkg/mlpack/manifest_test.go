package mlpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePack creates a pack directory with the given manifest and file
// contents and returns the dir path. Files are keyed by manifest path.
func writePack(t *testing.T, dir string, m PackManifest, contents map[string][]byte) string {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestName), raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", ManifestName, err)
	}
	for path, data := range contents {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("MkdirAll for %q: %v", path, err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}
	return dir
}

// sha256Of is the test-side digest the pack fixtures are built from.
func sha256Of(t *testing.T, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// validPackManifest returns a structurally valid manifest for a registry
// model; callers break one field at a time for the negative tests.
func validPackManifest() PackManifest {
	return PackManifest{
		ID:       "BAAI/bge-small-en-v1.5",
		Version:  "v1.5",
		Revision: "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a",
		License:  "MIT",
		Files: []PackFile{
			{Path: "model.safetensors", SHA256: "3c9f31665447c8911517620762200d2245a2518d6e7208acc78cd9db317e21ad"},
		},
	}
}

// TestPackManifest_LoadValidPack mirrors TestManifestFor_KnownModels: a
// well-formed pack manifest loads, round-trips its provenance fields and
// passes Validate.
func TestPackManifest_LoadValidPack(t *testing.T) {
	dir := writePack(t, "", validPackManifest(), nil)

	m, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%q) error = %v, want nil", dir, err)
	}
	want := validPackManifest()
	if m.ID != want.ID || m.Version != want.Version || m.Revision != want.Revision || m.License != want.License {
		t.Errorf("Load round-trip = %+v, want %+v", m, want)
	}
	if len(m.Files) != 1 || m.Files[0].Path != "model.safetensors" || len(m.Files[0].SHA256) != 64 {
		t.Errorf("Load files = %+v, want one 64-hex digest entry for model.safetensors", m.Files)
	}
	if err := m.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
	if m.Revision != "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a" {
		t.Errorf("Revision = %q, want the pinned upstream commit", m.Revision)
	}
}

// TestPackManifest_RejectsPartialStates mirrors
// TestModelManifest_RejectsPartialStates: a manifest that is correct except
// for one required field never passes, and every rejection names its cause.
func TestPackManifest_RejectsPartialStates(t *testing.T) {
	cases := []struct {
		name    string
		breakIt func(m *PackManifest)
		wantErr string
	}{
		{"empty id", func(m *PackManifest) { m.ID = "" }, "pack id is empty"},
		{"empty version", func(m *PackManifest) { m.Version = "" }, "pack version is empty"},
		{"floating revision main", func(m *PackManifest) { m.Revision = "main" }, "revision"},
		{"short revision", func(m *PackManifest) { m.Revision = "abc123" }, "revision"},
		{"empty license", func(m *PackManifest) { m.License = "" }, "license is unconfirmed"},
		{"no files", func(m *PackManifest) { m.Files = nil }, "declares no files (weights missing)"},
		{"empty file path", func(m *PackManifest) {
			m.Files = []PackFile{{Path: "", SHA256: strings.Repeat("a", 64)}}
		}, "path is empty"},
		{"uppercase digest", func(m *PackManifest) {
			m.Files = []PackFile{{Path: "model.safetensors", SHA256: strings.ToUpper(m.Files[0].SHA256)}}
		}, "not a 64-hex lowercase value"},
		{"short digest", func(m *PackManifest) {
			m.Files = []PackFile{{Path: "model.safetensors", SHA256: "deadbeef"}}
		}, "not a 64-hex lowercase value"},
		{"absolute path", func(m *PackManifest) {
			m.Files = []PackFile{{Path: "/etc/passwd", SHA256: strings.Repeat("a", 64)}}
		}, "absolute paths are not allowed"},
		{"parent traversal", func(m *PackManifest) {
			m.Files = []PackFile{{Path: "../weights.bin", SHA256: strings.Repeat("a", 64)}}
		}, "parent traversal is not allowed"},
		{"nested traversal", func(m *PackManifest) {
			m.Files = []PackFile{{Path: "sub/../../escape.bin", SHA256: strings.Repeat("a", 64)}}
		}, "parent traversal is not allowed"},
		{"duplicate path", func(m *PackManifest) {
			m.Files = []PackFile{
				{Path: "model.safetensors", SHA256: strings.Repeat("a", 64)},
				{Path: "model.safetensors", SHA256: strings.Repeat("b", 64)},
			}
		}, "duplicate path"},
	}
	for _, tc := range cases {
		m := validPackManifest()
		tc.breakIt(&m)
		err := m.Validate()
		if err == nil {
			t.Errorf("%s: Validate() = nil, want error (partial provenance must not count as provenance)", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: Validate() = %v, want error mentioning %q", tc.name, err, tc.wantErr)
		}
	}
}

// TestPackManifest_LoadRefusals covers the load-time boundary: a missing or
// malformed manifest is a refusal, never an empty pass.
func TestPackManifest_LoadRefusals(t *testing.T) {
	t.Run("no manifest file", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := Load(dir); err == nil {
			t.Fatal("Load(dir without pack.json) = nil, want error")
		} else if !strings.Contains(err.Error(), ManifestName) {
			t.Errorf("error = %v, want it to name %s", err, ManifestName)
		}
	})
	t.Run("malformed json", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ManifestName), []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write malformed manifest: %v", err)
		}
		m, err := Load(dir)
		if err == nil {
			t.Fatalf("Load(malformed) = %+v, want error", m)
		}
		if !strings.Contains(err.Error(), "not a valid pack manifest") {
			t.Errorf("error = %v, want malformed-manifest wording", err)
		}
	})
	t.Run("empty dir value", func(t *testing.T) {
		if _, err := Load("   "); err == nil || !strings.Contains(err.Error(), "pack dir is empty") {
			t.Fatalf("Load(whitespace) error = %v, want empty-dir refusal", err)
		}
	})
	t.Run("valid json with incomplete provenance refuses naming the pack", func(t *testing.T) {
		m := validPackManifest()
		m.License = ""
		dir := writePack(t, "", m, nil)
		_, err := Load(dir)
		if err == nil {
			t.Fatal("Load(incomplete) = nil, want error")
		}
		for _, want := range []string{"unconfirmed provenance", "must not enter the distribution", "license"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %v, want it to mention %q", err, want)
			}
		}
	})
}
