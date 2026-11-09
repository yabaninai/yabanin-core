package mlpack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Verify loads the pack manifest from dir and confirms every declared file:
// it must exist as a regular file inside the pack directory (no symlink
// escape) and its sha256 must equal the manifest digest. All file problems
// are reported together. Refusal wording names the branch of the negative
// scenario: "weights missing" for absent files, "digest mismatch" for
// content that does not hash to the manifest value.
func Verify(dir string) (PackManifest, error) {
	m, err := Load(dir)
	if err != nil {
		return PackManifest{}, err
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return PackManifest{}, fmt.Errorf("mlpack: pack dir %q cannot be resolved: %w", dir, err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return PackManifest{}, fmt.Errorf("mlpack: pack dir %q is missing or unreadable: %w", dir, err)
	}

	var problems []string
	for _, f := range m.Files {
		full := filepath.Join(realRoot, filepath.FromSlash(f.Path))
		if !hasPathPrefix(full, realRoot) {
			problems = append(problems, fmt.Sprintf("file %q resolves outside the pack directory — refused", f.Path))
			continue
		}
		info, err := os.Stat(full)
		if err != nil {
			problems = append(problems, fmt.Sprintf("file %q declared by %s is missing (weights missing): %v", f.Path, ManifestName, err))
			continue
		}
		if !info.Mode().IsRegular() {
			problems = append(problems, fmt.Sprintf("file %q is not a regular file", f.Path))
			continue
		}
		// Containment must hold after symlink resolution: a pack file that
		// is (or walks through) a symlink leaving the pack directory is a
		// refusal, so verification can never address anything outside root.
		real, err := filepath.EvalSymlinks(full)
		if err != nil {
			problems = append(problems, fmt.Sprintf("file %q cannot be resolved: %v", f.Path, err))
			continue
		}
		if !hasPathPrefix(real, realRoot) {
			problems = append(problems, fmt.Sprintf("file %q resolves outside the pack directory — refused", f.Path))
			continue
		}
		actual, err := sha256File(real)
		if err != nil {
			problems = append(problems, fmt.Sprintf("file %q cannot be hashed: %v", f.Path, err))
			continue
		}
		if actual != f.SHA256 {
			problems = append(problems, fmt.Sprintf("file %q digest mismatch: manifest %s, actual %s — must not enter the distribution", f.Path, f.SHA256, actual))
		}
	}
	if len(problems) > 0 {
		return PackManifest{}, fmt.Errorf("mlpack: pack %q failed on-disk verification in %q: %s", m.ID, dir, strings.Join(problems, "; "))
	}
	return m, nil
}

// sha256File streams a file through sha256 and returns the lowercase hex
// digest.
func sha256File(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path is containment-checked against the pack root in Verify
	if err != nil {
		return "", err
	}
	defer f.Close() // read-only handle; close errors cannot corrupt the digest already computed
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hasPathPrefix reports whether path is root itself or lies underneath it
// (lexically, after both sides were cleaned/symlink-resolved).
func hasPathPrefix(path, root string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}
