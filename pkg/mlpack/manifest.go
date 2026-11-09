// explicitly attached directory of model weights plus a pack manifest that
// records provenance and per-file sha256 digests. A pack is the air-gap
// alternative to hub downloads — the core never downloads; attaching a pack
// verifies the weights on disk before anything is served from them.
//
// Owner decisions (2026-10-14): D1 — the pack manifest is JSON on disk with
// sha256 digests and is UNSIGNED; the digest chain is a perimeter model, a
// cryptographic signature would be a separate decision. D2 — the pack
// directory is resolved from YABANIN_ML_PACK_DIR. D3 — resource adequacy is
// explicitly NOT checked here. D4 — embedder serving is a baked TEI image
// (existing compose profile); the gateway only verifies the pack the
// serving image mounts.
package mlpack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManifestName is the file name of the pack manifest inside a pack directory.
const ManifestName = "pack.json"

// PackFile declares one file shipped in the pack: its path relative to the
// pack directory and the sha256 digest of its contents. Digests are 64-hex
type PackFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// PackManifest describes a model pack; its fields are mandatory: a pack whose origin, revision, digest or license
// dispositions are incomplete must not enter a distribution.
type PackManifest struct {
	// ID is the model id the pack serves, matching the upstream repository
	// id used in embedder configuration (e.g. "BAAI/bge-small-en-v1.5").
	ID string `json:"id"`
	// Version is the pack's own version label (e.g. "v1.5" or "2026-10-14").
	Version string `json:"version"`
	// Revision is the pinned 40-hex git commit of the upstream repository.
	// Floating refs (e.g. "main") are not acceptable.
	Revision string `json:"revision"`
	// License is the recorded license of the model.
	License string `json:"license"`
	// Files lists every file the pack ships, weights included, each with its
	// sha256 digest. At least one file is required.
	Files []PackFile `json:"files"`
}

// Load reads and structurally validates pack.json from dir. It does NOT look
// at the declared files — use Verify for the full weights check. A malformed
// or incomplete manifest is a refusal: partial provenance must not count as
// provenance.
func Load(dir string) (PackManifest, error) {
	if strings.TrimSpace(dir) == "" {
		return PackManifest{}, fmt.Errorf("mlpack: pack dir is empty — set YABANIN_ML_PACK_DIR to a pack directory")
	}
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName)) //nolint:gosec // G304: dir is operator configuration (YABANIN_ML_PACK_DIR — the operator's supply chain), not request input; the manifest path is anchored inside that dir
	if err != nil {
		return PackManifest{}, fmt.Errorf("mlpack: %s missing or unreadable in %q: %w", ManifestName, dir, err)
	}
	var m PackManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return PackManifest{}, fmt.Errorf("mlpack: %s in %q is not a valid pack manifest: %w", ManifestName, dir, err)
	}
	if err := m.Validate(); err != nil {
		return PackManifest{}, fmt.Errorf("mlpack: pack %q manifest has unconfirmed provenance (%v); pack must not enter the distribution", m.ID, err)
	}
	return m, nil
}

// Validate reports whether the manifest records confirmed pack provenance: a
// non-empty id and version, a pinned revision, a license, and a non-empty
// file list with safe relative paths and lowercase 64-hex digests. All
// problems are reported together.
func (m PackManifest) Validate() error {
	var problems []string
	if strings.TrimSpace(m.ID) == "" {
		problems = append(problems, "pack id is empty")
	}
	if strings.TrimSpace(m.Version) == "" {
		problems = append(problems, "pack version is empty (packs are versioned)")
	}
	if !isHexN(m.Revision, 40) {
		problems = append(problems, fmt.Sprintf("revision must be a pinned 40-hex git commit, got %q (floating refs like %q are rejected)", m.Revision, "main"))
	}
	if strings.TrimSpace(m.License) == "" {
		problems = append(problems, "license is unconfirmed (not recorded)")
	}
	if len(m.Files) == 0 {
		problems = append(problems, "pack declares no files (weights missing)")
	}
	seen := make(map[string]bool, len(m.Files))
	for i, f := range m.Files {
		if strings.TrimSpace(f.Path) == "" {
			problems = append(problems, fmt.Sprintf("files[%d]: path is empty", i))
			continue
		}
		if seen[f.Path] {
			problems = append(problems, fmt.Sprintf("files[%d]: duplicate path %q", i, f.Path))
			continue
		}
		seen[f.Path] = true
		if reason := unsafePackPath(f.Path); reason != "" {
			problems = append(problems, fmt.Sprintf("files[%d]: unsafe path %q: %s", i, f.Path, reason))
		}
		if !isHexN(f.SHA256, 64) {
			problems = append(problems, fmt.Sprintf("files[%d]: sha256 digest of %q is unknown or not a 64-hex lowercase value", i, f.Path))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(problems, "; "))
}

// unsafePackPath reports why a manifest path must not be resolved inside the
// pack directory, or "" when it is a safe relative path. Absolute paths,
// parent traversal and path separators that escape the pack root are
// refused — a pack manifest must never address files outside its directory.
func unsafePackPath(p string) string {
	if filepath.IsAbs(p) {
		return "absolute paths are not allowed"
	}
	clean := filepath.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "parent traversal is not allowed"
	}
	if strings.Contains(p, "\x00") {
		return "nul byte is not allowed"
	}
	return ""
}

// isHexN reports whether s is exactly n lowercase hex characters.
func isHexN(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
