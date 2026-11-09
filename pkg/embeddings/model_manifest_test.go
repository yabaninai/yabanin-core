package embeddings

import (
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestManifestFor_KnownModels(t *testing.T) {
	for _, id := range []string{
		"BAAI/bge-small-en-v1.5",
		"Xenova/bge-small-en-v1.5",
		"intfloat/multilingual-e5-small",
	} {
		m, err := ManifestFor(id)
		if err != nil {
			t.Fatalf("ManifestFor(%q) error = %v, want nil", id, err)
		}
		if m.ID != id {
			t.Errorf("ManifestFor(%q).ID = %q, want %q", id, m.ID, id)
		}
		if err := m.Validate(); err != nil {
			t.Errorf("ManifestFor(%q).Validate() = %v, want nil", id, err)
		}
		if len(m.Revision) != 40 {
			t.Errorf("ManifestFor(%q).Revision = %q, want a pinned 40-hex commit", id, m.Revision)
		}
		if len(m.SHA256) != 64 {
			t.Errorf("ManifestFor(%q).SHA256 = %q, want a 64-hex digest", id, m.SHA256)
		}
		if !strings.Contains(m.License, "MIT") {
			t.Errorf("ManifestFor(%q).License = %q, want MIT disposition", id, m.License)
		}
		if len(m.Datasets) == 0 {
			t.Errorf("ManifestFor(%q).Datasets must record upstream-declared grounds or an explicit no-data disposition", id)
		}
	}

	bge, err := ManifestFor("BAAI/bge-small-en-v1.5")
	if err != nil {
		t.Fatalf("ManifestFor(BAAI/bge-small-en-v1.5) error = %v, want nil", err)
	}
	if bge.Revision != "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a" {
		t.Errorf("BAAI revision = %q, want pinned upstream commit", bge.Revision)
	}
	if bge.SHA256 != "3c9f31665447c8911517620762200d2245a2518d6e7208acc78cd9db317e21ad" {
		t.Errorf("BAAI digest = %q, want verified model.safetensors digest", bge.SHA256)
	}

	xenova, err := ManifestFor("Xenova/bge-small-en-v1.5")
	if err != nil {
		t.Fatalf("ManifestFor(Xenova/bge-small-en-v1.5) error = %v, want nil", err)
	}
	if xenova.SHA256 != "828e1496d7fabb79cfa4dcd84fa38625c0d3d21da474a00f08db0f559940cf35" {
		t.Errorf("Xenova digest = %q, want verified onnx/model.onnx digest", xenova.SHA256)
	}
}

func TestManifestFor_UnknownModel(t *testing.T) {
	m, err := ManifestFor("some-vendor/mystery-embed")
	if err == nil {
		t.Fatalf("ManifestFor(unknown) = %+v, want error", m)
	}
	if m.ID != "" {
		t.Errorf("ManifestFor(unknown) manifest = %+v, want zero value", m)
	}
	for _, want := range []string{"some-vendor/mystery-embed", "no provenance manifest"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ManifestFor(unknown) error = %v, want it to mention %q", err, want)
		}
	}
}

func TestManifestFor_RejectsIncompleteEntry(t *testing.T) {
	orig := modelManifests
	modelManifests = map[string]ModelManifest{
		"test/broken": {
			ID:   "test/broken",
			Repo: "https://example.invalid/test/broken",
		},
	}
	t.Cleanup(func() { modelManifests = orig })

	m, err := ManifestFor("test/broken")
	if err == nil {
		t.Fatalf("ManifestFor(incomplete entry) = %+v, want error", m)
	}
	if m.ID != "" {
		t.Errorf("ManifestFor(incomplete entry) manifest = %+v, want zero value", m)
	}
	for _, want := range []string{"unconfirmed rights", "revision", "digest", "license"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ManifestFor(incomplete entry) error = %v, want it to mention %q", err, want)
		}
	}
}

// TestManifestFor_UnknownInputs verifies the invalid-input boundary: ids are
// matched exactly, so case changes, surrounding whitespace and empty inputs
// are all unknown origin and must yield an error plus a zero-value manifest.
func TestManifestFor_UnknownInputs(t *testing.T) {
	for _, id := range []string{
		"",
		"   ",
		"baai/bge-small-en-v1.5",
		"BAAI/BGE-SMALL-EN-V1.5",
		"BAAI/bge-small-en-v1.5 ",
		" BAAI/bge-small-en-v1.5",
		"BAAI/bge-small-en-v1.4",
	} {
		m, err := ManifestFor(id)
		if err == nil {
			t.Errorf("ManifestFor(%q) = %+v, want unknown-origin error", id, m)
			continue
		}
		if m.ID != "" || m.Revision != "" || m.SHA256 != "" {
			t.Errorf("ManifestFor(%q) manifest = %+v, want zero value", id, m)
		}
		if !strings.Contains(err.Error(), "no provenance manifest") || !strings.Contains(err.Error(), "must not enter the distribution") {
			t.Errorf("ManifestFor(%q) error = %v, want unknown-origin exclusion wording", id, err)
		}
	}
}

// TestRegistryEntries_ConfirmedRights guards the registry itself: every
// shipped entry must pass Validate, so a future incomplete entry cannot
// enter a distribution silently.
func TestRegistryEntries_ConfirmedRights(t *testing.T) {
	if len(modelManifests) == 0 {
		t.Fatal("modelManifests is empty")
	}
	for id, m := range modelManifests {
		if m.ID != id {
			t.Errorf("registry key %q has entry with ID %q, want them equal", id, m.ID)
		}
		if err := m.Validate(); err != nil {
			t.Errorf("registry entry %q fails Validate: %v; it must not enter a distribution", id, err)
		}
	}
}

// TestModelManifest_RejectsPartialStates verifies that a manifest which is
// correct except for one required field never passes: partial provenance must
// not count as success, and each rejection must name its cause.
func TestModelManifest_RejectsPartialStates(t *testing.T) {
	valid, err := ManifestFor("BAAI/bge-small-en-v1.5")
	if err != nil {
		t.Fatalf("ManifestFor(BAAI/bge-small-en-v1.5) error = %v, want nil", err)
	}
	cases := []struct {
		name    string
		breakIt func(m *ModelManifest)
		wantErr string
	}{
		{"empty id", func(m *ModelManifest) { m.ID = "" }, "model id is empty"},
		{"empty repo", func(m *ModelManifest) { m.Repo = "" }, "repo is empty"},
		{"floating revision main", func(m *ModelManifest) { m.Revision = "main" }, "revision"},
		{"empty digest", func(m *ModelManifest) { m.SHA256 = "" }, "digest"},
		{"uppercase digest", func(m *ModelManifest) { m.SHA256 = strings.ToUpper(valid.SHA256) }, "digest"},
		{"empty license", func(m *ModelManifest) { m.License = "" }, "license is unconfirmed"},
		{"no aup disposition", func(m *ModelManifest) {
			m.AUPURL = ""
			m.Note = "revision and digest pinned 2026-10-12"
		}, "acceptable-use policy disposition missing"},
	}
	for _, tc := range cases {
		m := valid
		tc.breakIt(&m)
		err := m.Validate()
		if err == nil {
			t.Errorf("%s: Validate() = nil, want error (partial provenance must not count as success)", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: Validate() = %v, want error mentioning %q", tc.name, err, tc.wantErr)
		}
	}
}

// TestManifestFor_RepeatAndConcurrent verifies the lookup is a pure,
// repeatable read: repeated and concurrent calls return identical manifests
// and never mutate shared state (no retry, cancellation or interrupt paths
// exist because the manifest data is compile-time and no I/O occurs).
func TestManifestFor_RepeatAndConcurrent(t *testing.T) {
	first, err := ManifestFor("intfloat/multilingual-e5-small")
	if err != nil {
		t.Fatalf("ManifestFor(intfloat/multilingual-e5-small) error = %v, want nil", err)
	}
	repeat, err := ManifestFor("intfloat/multilingual-e5-small")
	if err != nil {
		t.Fatalf("repeated ManifestFor error = %v, want nil", err)
	}
	if !reflect.DeepEqual(first, repeat) {
		t.Errorf("repeated ManifestFor = %+v, want identical %+v", repeat, first)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := ManifestFor("intfloat/multilingual-e5-small")
			if err != nil {
				t.Errorf("concurrent ManifestFor error = %v, want nil", err)
				return
			}
			if !reflect.DeepEqual(m, first) {
				t.Errorf("concurrent ManifestFor = %+v, want identical %+v", m, first)
			}
		}()
	}
	wg.Wait()
}
