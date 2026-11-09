package classifier

import (
	"strings"
	"testing"
)

const (
	wantBGERevision = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"
	wantBGEDigest   = "3c9f31665447c8911517620762200d2245a2518d6e7208acc78cd9db317e21ad"
)

func TestModelProvenance_Valid(t *testing.T) {
	mp := ModelProvenance()
	if err := mp.Validate(); err != nil {
		t.Fatalf("ModelProvenance().Validate() = %v, want nil", err)
	}
	if mp.ID != "BAAI/bge-small-en-v1.5" {
		t.Errorf("ID = %q, want %q", mp.ID, "BAAI/bge-small-en-v1.5")
	}
	if mp.Revision != wantBGERevision {
		t.Errorf("Revision = %q, want pinned %q", mp.Revision, wantBGERevision)
	}
	if mp.SHA256 != wantBGEDigest {
		t.Errorf("SHA256 = %q, want verified %q", mp.SHA256, wantBGEDigest)
	}
	if mp.License != "MIT" {
		t.Errorf("License = %q, want %q", mp.License, "MIT")
	}
	if mp.LicenseURL == "" {
		t.Error("LicenseURL is empty")
	}
	if len(mp.Datasets) == 0 {
		t.Error("Datasets must record the upstream-declared grounds or an explicit no-data disposition")
	}
	if !strings.Contains(mp.Note, "3-class") {
		t.Errorf("Note = %q, must describe the locally built 3-class head disposition", mp.Note)
	}
}

func TestModelProvenance_RejectsEmptyRevision(t *testing.T) {
	for _, revision := range []string{"", "main", "v1.5", wantBGERevision + "0"} {
		mp := ModelProvenance()
		mp.Revision = revision
		err := mp.Validate()
		if err == nil {
			t.Fatalf("Validate() with revision %q = nil, want error", revision)
		}
		if !strings.Contains(err.Error(), "revision") {
			t.Fatalf("Validate() with revision %q = %v, want error mentioning revision", revision, err)
		}
	}
}

func TestModelProvenance_RejectsBadDigest(t *testing.T) {
	for _, digest := range []string{"", "abc", wantBGEDigest[:63], strings.Repeat("g", 64)} {
		mp := ModelProvenance()
		mp.SHA256 = digest
		err := mp.Validate()
		if err == nil {
			t.Fatalf("Validate() with digest %q = nil, want error", digest)
		}
		if !strings.Contains(err.Error(), "digest") {
			t.Fatalf("Validate() with digest %q = %v, want error mentioning digest", digest, err)
		}
	}
}

// TestModelProvenance_RejectsPartialStates verifies that a manifest which is
// correct except for one required field never passes: partial provenance must
// not count as success, and each rejection must name its cause.
func TestModelProvenance_RejectsPartialStates(t *testing.T) {
	base := ModelProvenance()
	cases := []struct {
		name    string
		breakIt func(m *ModelManifest)
		wantErr string
	}{
		{"empty id", func(m *ModelManifest) { m.ID = "" }, "model id is empty"},
		{"whitespace id", func(m *ModelManifest) { m.ID = "   " }, "model id is empty"},
		{"empty repo", func(m *ModelManifest) { m.Repo = "" }, "repo is empty"},
		{"floating revision main", func(m *ModelManifest) { m.Revision = "main" }, "revision"},
		{"non-hex revision", func(m *ModelManifest) { m.Revision = strings.Repeat("g", 40) }, "revision"},
		{"empty digest", func(m *ModelManifest) { m.SHA256 = "" }, "digest"},
		{"truncated digest", func(m *ModelManifest) { m.SHA256 = wantBGEDigest[:63] }, "digest"},
		{"empty license", func(m *ModelManifest) { m.License = "" }, "license is unconfirmed"},
		{"whitespace license", func(m *ModelManifest) { m.License = "   " }, "license is unconfirmed"},
		{"no aup disposition", func(m *ModelManifest) {
			m.AUPURL = ""
			m.Note = "revision and digest pinned 2026-10-12"
		}, "acceptable-use policy disposition missing"},
	}
	for _, tc := range cases {
		m := base
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

// TestModelProvenance_RejectsUppercaseHex documents the canonical pinned
// forms: revisions and digests are lowercase hex as emitted by git and
// sha256sum; uppercase spellings are rejected rather than silently accepted.
func TestModelProvenance_RejectsUppercaseHex(t *testing.T) {
	mp := ModelProvenance()
	mp.Revision = strings.ToUpper(mp.Revision)
	if err := mp.Validate(); err == nil || !strings.Contains(err.Error(), "revision") {
		t.Errorf("Validate() with uppercase revision = %v, want revision error", err)
	}

	mp = ModelProvenance()
	mp.SHA256 = strings.ToUpper(mp.SHA256)
	if err := mp.Validate(); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("Validate() with uppercase digest = %v, want digest error", err)
	}
}
