package mlpack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const packWeights = "fake-weights-bytes-for-tests"

// packFixture writes a pack whose declared digests match its file contents.
// Overrides adjust the manifest after the digests were computed so negative
// tests break exactly one thing.
func packFixture(t *testing.T, mutate func(m *PackManifest)) (dir string, m PackManifest) {
	t.Helper()
	m = validPackManifest()
	m.Files[0].SHA256 = sha256Of(t, []byte(packWeights))
	if mutate != nil {
		mutate(&m)
	}
	return writePack(t, "", m, map[string][]byte{"model.safetensors": []byte(packWeights)}), m
}

// TestVerify_ConfirmedPack is the working pack path (acceptance example 2,
// unit level): weights present, digests match, manifest validates — and
func TestVerify_ConfirmedPack(t *testing.T) {
	dir, want := packFixture(t, nil)

	m, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify(%q) error = %v, want nil", dir, err)
	}
	if m.ID != want.ID || len(m.Files) != 1 {
		t.Errorf("Verify = %+v, want manifest %+v", m, want)
	}

	attached, err := AttachDir(dir)
	if err != nil {
		t.Fatalf("AttachDir(%q) error = %v, want nil", dir, err)
	}
	if attached.Manifest.ID != want.ID || attached.Dir != dir {
		t.Errorf("AttachDir = %+v, want manifest %q from %q", attached, want.ID, dir)
	}
}

// TestVerify_WeightsMissing is the negative branch "no weights" (acceptance
// example 3): a declared file that is absent refuses with explicit wording.
func TestVerify_WeightsMissing(t *testing.T) {
	dir, _ := packFixture(t, nil)
	if err := removePackFile(t, dir, "model.safetensors"); err != nil {
		t.Fatalf("remove weights: %v", err)
	}

	_, err := Verify(dir)
	if err == nil {
		t.Fatal("Verify(missing weights) = nil, want refusal")
	}
	for _, want := range []string{"weights missing", "model.safetensors"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

// TestVerify_WeightsMissing_DirWithoutManifest covers the wholly empty dir:
// neither manifest nor weights — refusal, not a silent pass.
func TestVerify_WeightsMissing_DirWithoutManifest(t *testing.T) {
	dir := t.TempDir()
	if _, err := Verify(dir); err == nil {
		t.Fatal("Verify(empty dir) = nil, want refusal")
	} else if !strings.Contains(err.Error(), "missing or unreadable") {
		t.Errorf("error = %v, want missing-manifest wording", err)
	}
}

// TestVerify_DigestMismatch is the negative branch "digest mismatch"
// (acceptance example 4): actual sha256 ≠ manifest digest refuses with the
func TestVerify_DigestMismatch(t *testing.T) {
	dir, want := packFixture(t, nil)
	if err := rewritePackFile(t, dir, "model.safetensors", []byte("tampered-weights")); err != nil {
		t.Fatalf("rewrite weights: %v", err)
	}

	_, err := Verify(dir)
	if err == nil {
		t.Fatal("Verify(tampered weights) = nil, want refusal")
	}
	for _, wantSub := range []string{"digest mismatch", want.Files[0].SHA256, "must not enter the distribution"} {
		if !strings.Contains(err.Error(), wantSub) {
			t.Errorf("error = %v, want it to mention %q", err, wantSub)
		}
	}
}

// TestVerify_NoResourceSizeGate pins owner decision D3 (2026-10-14): pack
// verification is content-based (sha256 digests) and deliberately has NO
// resource adequacy check — a multi-megabyte weight file verifies exactly
// like a small one. A size- or resource-based refusal appearing here would
// be a regression against the ratified decision.
func TestVerify_NoResourceSizeGate(t *testing.T) {
	weights := []byte(strings.Repeat(packWeights, 1<<18)) // ~8 MB
	dir, _ := packFixture(t, func(m *PackManifest) {
		m.Files[0].SHA256 = sha256Of(t, weights)
	})
	if err := rewritePackFile(t, dir, "model.safetensors", weights); err != nil {
		t.Fatalf("rewrite weights: %v", err)
	}

	m, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify(%d-byte weights) error = %v, want nil (D3: no resource/size gate)", len(weights), err)
	}
	if m.ID != "BAAI/bge-small-en-v1.5" {
		t.Errorf("Verify id = %q, want the registry id", m.ID)
	}
}

// TestVerify_WeightsNotARegularFile covers the invalid-input shape where the
// declared weights path exists but is not a regular file (a directory standing
// in for model.safetensors): refusal before hashing — a non-file can never
// produce a comparable digest, so it must not pass as "weights present".
func TestVerify_WeightsNotARegularFile(t *testing.T) {
	dir, _ := packFixture(t, nil)
	if err := removePackFile(t, dir, "model.safetensors"); err != nil {
		t.Fatalf("remove weights: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "model.safetensors"), 0o750); err != nil {
		t.Fatalf("mkdir in place of weights: %v", err)
	}

	if _, err := Verify(dir); err == nil {
		t.Fatal("Verify(directory as weights) = nil, want refusal")
	} else if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("error = %v, want the non-regular-file refusal", err)
	}
}

// TestVerify_PathTraversalRefused proves the manifest boundary: a doctored
// manifest with a traversal path is refused at load (structural validation)
// with the distribution wording — nothing outside the pack root is addressed.
func TestVerify_PathTraversalRefused(t *testing.T) {
	dir, m := packFixture(t, nil)
	m.Files[0].Path = "../outside.bin"
	m.Files[0].SHA256 = sha256Of(t, []byte(packWeights))
	if err := rewriteManifest(t, dir, m); err != nil {
		t.Fatalf("rewrite manifest: %v", err)
	}

	_, err := Verify(dir)
	if err == nil {
		t.Fatal("Verify(traversal path) = nil, want refusal")
	}
	for _, wantSub := range []string{"parent traversal is not allowed", "must not enter the distribution"} {
		if !strings.Contains(err.Error(), wantSub) {
			t.Errorf("error = %v, want it to mention %q", err, wantSub)
		}
	}
}

// TestVerify_SymlinkEscapeRefused guards containment after symlink
// resolution: a lexically-safe manifest path that is a symlink leaving the
// pack directory must refuse — verification never hashes anything outside
// the pack root.
func TestVerify_SymlinkEscapeRefused(t *testing.T) {
	dir, _ := packFixture(t, nil)
	outside := filepath.Join(t.TempDir(), "outside.bin")
	if err := os.WriteFile(outside, []byte(packWeights), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "model.safetensors")); err != nil {
		t.Fatalf("remove weights: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "model.safetensors")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := Verify(dir)
	if err == nil {
		t.Fatal("Verify(symlink escape) = nil, want refusal")
	}
	if !strings.Contains(err.Error(), "resolves outside the pack directory") {
		t.Errorf("error = %v, want containment refusal", err)
	}
}

// TestAttach_UnknownOrigin is the negative branch "foreign id" (acceptance
// example 5): an unregistered id, an adjacent version and any case change
// perfectly intact weights.
func TestAttach_UnknownOrigin(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   string
	}{
		{"unregistered vendor", "some-vendor/mystery-embed"},
		{"adjacent version v1.4", "BAAI/bge-small-en-v1.4"},
		{"lowercase id", "baai/bge-small-en-v1.5"},
		{"empty id is structural", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := packFixture(t, func(m *PackManifest) { m.ID = tc.id })

			m, err := Verify(dir)
			if tc.id == "" {
				if err == nil {
					t.Fatal("Verify(empty id) = nil, want structural refusal")
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify(%q) error = %v, want structural pass (origin is attach-time)", tc.id, err)
			}
			if m.ID != tc.id {
				t.Errorf("Verify id = %q, want %q", m.ID, tc.id)
			}
			attached, attachErr := AttachDir(dir)
			if attachErr == nil {
				t.Fatalf("AttachDir(%q) = %+v, want unknown-origin refusal", tc.id, attached)
			}
			for _, wantSub := range []string{"unknown origin", "must not enter the distribution", tc.id} {
				if !strings.Contains(attachErr.Error(), wantSub) {
					t.Errorf("error = %v, want it to mention %q", attachErr, wantSub)
				}
			}
		})
	}
}

// TestAttach_UppercaseDigestRefused proves the digest convention holds on
// disk: an uppercase-hex digest in the manifest is a structural refusal
// before any origin question arises (pattern
// TestModelProvenance_RejectsUppercaseHex).
func TestAttach_UppercaseDigestRefused(t *testing.T) {
	dir, _ := packFixture(t, func(mm *PackManifest) {
		mm.Files[0].SHA256 = strings.ToUpper(mm.Files[0].SHA256)
	})

	if _, err := Verify(dir); err == nil {
		t.Fatal("Verify(uppercase digest) = nil, want refusal")
	} else if !strings.Contains(err.Error(), "not a 64-hex lowercase value") {
		t.Errorf("error = %v, want uppercase-digest refusal", err)
	}
}

// TestVerify_RepeatAndConcurrent mirrors TestManifestFor_RepeatAndConcurrent:
// verification is a pure, repeatable read over immutable fixture files.
func TestVerify_RepeatAndConcurrent(t *testing.T) {
	dir, want := packFixture(t, nil)

	first, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify error = %v, want nil", err)
	}
	if first.ID != want.ID {
		t.Fatalf("Verify = %+v, want %+v", first, want)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := Verify(dir)
			if err != nil {
				t.Errorf("concurrent Verify error = %v, want nil", err)
				return
			}
			if m.ID != first.ID || len(m.Files) != len(first.Files) {
				t.Errorf("concurrent Verify = %+v, want identical %+v", m, first)
			}
		}()
	}
	wg.Wait()
}

func removePackFile(t *testing.T, dir, path string) error {
	t.Helper()
	return os.Remove(filepath.Join(dir, filepath.FromSlash(path)))
}

func rewritePackFile(t *testing.T, dir, path string, data []byte) error {
	t.Helper()
	return os.WriteFile(filepath.Join(dir, filepath.FromSlash(path)), data, 0o600)
}

func rewriteManifest(t *testing.T, dir string, m PackManifest) error {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ManifestName), raw, 0o600)
}
