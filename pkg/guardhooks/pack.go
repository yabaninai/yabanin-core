package guardhooks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// GuardPackManifestVersion identifies the supported offline manifest schema.
const GuardPackManifestVersion = "guardpacks.v1"

// Signature scheme v1: ed25519 over the canonical pack payload (the exact
// bytes sha256 of which is the VerifiedPack.Digest). The scheme version is
// declared inside the signature envelope so a future scheme change is an
// explicit, fail-closed rejection — never a silent re-interpretation of an
// old signature.
const (
	// SignatureVersionV1 is the only supported signature scheme version.
	SignatureVersionV1 = "guardpack-sig.v1"
	// SignatureAlgorithmEd25519 is the only v1 signing algorithm.
	SignatureAlgorithmEd25519 = "ed25519"
)

const (
	// MaxPackManifestBytes bounds JSON decoding and canonical verification.
	MaxPackManifestBytes = 1 << 20
	// MaxDetectorFileBytes bounds detector.json reads before decoding.
	MaxDetectorFileBytes = 4 << 20
	// MaxPackManifestFiles bounds how many files one manifest may declare.
	// The supported pack shape is a single detector.json; the cap keeps
	// manifest decoding and any verification work cheap and bounded even for
	// a hostile manifest that lists thousands of entries.
	MaxPackManifestFiles = 64
)

// PackFile is one offline-verified file in a user-authored detector pack.
type PackFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// PackManifest describes a versioned detector artifact. Unsigned local user
// packs are accepted by default; a declared signature is never treated as
// decorative metadata and must be verified by an explicitly configured verifier.
type PackManifest struct {
	SchemaVersion string     `json:"schema_version"`
	PackID        string     `json:"pack_id"`
	PackVersion   string     `json:"pack_version"`
	RuntimeAPI    string     `json:"runtime_api"`
	Files         []PackFile `json:"files"`
	// Coverage optionally declares, per detector rule, which
	// OWASP-2026 scenarios the pack's evidence tests cover. Additive and
	// optional: manifests without it (all pre-W03 packs) decode unchanged
	// and mean "coverage unknown", never "full coverage". Signed packs
	// cover the block through the canonical payload (see canonicalPackPayload).
	Coverage []CoverageEntry `json:"coverage,omitempty"`
	// NotCovered optionally declares, per scenario id, that the pack
	// does NOT cover it (fully or partially) and why. Additive and
	// optional like Coverage: manifests without it decode unchanged.
	// Signed through the canonical payload; a row without a reason is
	// invalid at decode, and the same id may not appear both here and
	// in Coverage.
	NotCovered []NotCoveredEntry `json:"not_covered,omitempty"`
	Signature  *Signature        `json:"signature,omitempty"`
}

// Signature is the signing envelope declared by a signed pack. Verification
// is integrity (proving the pack author's identity), not licensing: the
// verifier is core functionality and works for any signed pack without
// proprietary code or license checks. A declared signature requires an
// explicitly configured verifier.
type Signature struct {
	// Version is the signature scheme version; only SignatureVersionV1
	// ("guardpack-sig.v1": ed25519 over the canonical pack payload) is
	// supported. Unknown versions are rejected explicitly.
	Version   string `json:"version"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// SignatureVerifier authenticates a signed manifest. SHA-256 file integrity
// checks alone do not establish the author's identity.
type SignatureVerifier interface {
	Verify(manifest PackManifest, canonicalPayload []byte) error
}

// VerifiedPack is immutable verification metadata; it does not activate a
// pack or alter gateway policy state.
type VerifiedPack struct {
	Manifest PackManifest
	Digest   string
}

// DecodePackManifest strictly decodes a manifest and checks schema/runtime
// compatibility before any pack is considered loadable. The core permits an
// absent signature for local user packs. A present signature cannot be
// accepted without an explicitly configured verifier.
func DecodePackManifest(data []byte) (PackManifest, error) {
	return DecodePackManifestWithVerifier(data, nil)
}

// DecodePackManifestWithVerifier applies the explicit signature policy:
//
//	manifest        verifier configured   result
//	--------------  --------------------  -------------------------------------
//	unsigned        no                    loads (free/BYO local pack cycle)
//	unsigned        yes                   loads (the verifier is not consulted)
//	signed, valid   yes                   loads
//	signed, bad     yes                   rejected fail-closed, loud error,
//	                                      nothing staged
//	signed (any)    no                    rejected fail-closed: "signature
//	                                      declared but no verifier configured"
//	signed, unknown scheme/algorithm  any  rejected explicitly (never silently
//	                                      activated)
//
// The signature covers the canonical pack payload (schema version, pack id
// and version, runtime API and every declared file digest), so any content
// change after signing invalidates it.
func DecodePackManifestWithVerifier(data []byte, verifier SignatureVerifier) (PackManifest, error) {
	if len(data) > MaxPackManifestBytes {
		return PackManifest{}, fmt.Errorf("guard pack manifest: size %d exceeds %d-byte limit", len(data), MaxPackManifestBytes)
	}
	var manifest PackManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return PackManifest{}, fmt.Errorf("guard pack manifest: decode: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return PackManifest{}, errors.New("guard pack manifest: trailing JSON data")
	}
	if manifest.SchemaVersion != GuardPackManifestVersion {
		return PackManifest{}, fmt.Errorf("guard pack manifest: incompatible schema version %q", manifest.SchemaVersion)
	}
	if manifest.PackID == "" || manifest.PackVersion == "" {
		return PackManifest{}, errors.New("guard pack manifest: pack_id and pack_version are required")
	}
	if manifest.RuntimeAPI != RuntimeVersion {
		return PackManifest{}, fmt.Errorf("guard pack manifest: incompatible runtime API %q", manifest.RuntimeAPI)
	}
	if len(manifest.Files) == 0 {
		return PackManifest{}, errors.New("guard pack manifest: files must not be empty")
	}
	if manifest.Signature != nil {
		if verifier == nil {
			return PackManifest{}, errors.New("guard pack manifest: signature declared but no verifier configured")
		}
		// The scheme gates run before the verifier so an envelope this build
		// cannot understand is rejected explicitly even if a custom verifier
		// implementation would have accepted it — a declared signature is
		// never silently re-interpreted under a scheme it was not made for.
		if manifest.Signature.Version != SignatureVersionV1 {
			return PackManifest{}, fmt.Errorf("guard pack manifest: unsupported signature scheme version %q", manifest.Signature.Version)
		}
		if manifest.Signature.Algorithm != SignatureAlgorithmEd25519 {
			return PackManifest{}, fmt.Errorf("guard pack manifest: unsupported signature algorithm %q", manifest.Signature.Algorithm)
		}
		canonical, err := canonicalPackPayload(manifest)
		if err != nil {
			return PackManifest{}, fmt.Errorf("guard pack manifest: encode signature payload: %w", err)
		}
		if err := verifier.Verify(manifest, canonical); err != nil {
			return PackManifest{}, fmt.Errorf("guard pack manifest: signature verification failed: %w", err)
		}
	}
	if len(manifest.Files) > MaxPackManifestFiles {
		return PackManifest{}, fmt.Errorf("guard pack manifest: %d files exceeds the %d-file limit", len(manifest.Files), MaxPackManifestFiles)
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, file := range manifest.Files {
		if err := validatePackPath(file.Path); err != nil {
			return PackManifest{}, err
		}
		if _, ok := seen[file.Path]; ok {
			return PackManifest{}, fmt.Errorf("guard pack manifest: duplicate file %q", file.Path)
		}
		seen[file.Path] = struct{}{}
		decoded, err := hex.DecodeString(file.SHA256)
		if err != nil || len(decoded) != sha256.Size {
			return PackManifest{}, fmt.Errorf("guard pack manifest: invalid sha256 for %q", file.Path)
		}
	}
	// Coverage block: manifest-level shape validation — ev_ids
	// from the closed EV-A01…A08 registry, bounded unique rule_ids, evidence
	// references present. Runs on every decode path (signed and unsigned):
	// a malformed claim makes the manifest invalid before anything loads it.
	if err := validateCoverageShape(manifest.Coverage); err != nil {
		return PackManifest{}, err
	}
	// not_covered block: shape validation plus the coverage∩not_covered=∅
	// contradiction rule — both run on every decode path, so an invalid
	// denial makes the manifest invalid before anything loads it.
	if err := validateNotCoveredShape(manifest.NotCovered); err != nil {
		return PackManifest{}, err
	}
	if err := validateCoverageNotCoveredConsistency(manifest.Coverage, manifest.NotCovered); err != nil {
		return PackManifest{}, err
	}
	return manifest, nil
}

// canonicalPackPayload marshals the signature-covered manifest projection:
// every field that defines what the pack means (schema version, identity,
// runtime contract, the content digest of each declared file and — since
// the coverage work — the optional coverage and not_covered blocks) and
// nothing else. The signature is made over these exact bytes; sha256 over
// them is the VerifiedPack.Digest. A nil Coverage or NotCovered omits the
// key entirely, so packs without those blocks marshal byte-identically and
// their existing signatures keep verifying.
func canonicalPackPayload(manifest PackManifest) ([]byte, error) {
	return json.Marshal(struct {
		SchemaVersion string            `json:"schema_version"`
		PackID        string            `json:"pack_id"`
		PackVersion   string            `json:"pack_version"`
		RuntimeAPI    string            `json:"runtime_api"`
		Files         []PackFile        `json:"files"`
		Coverage      []CoverageEntry   `json:"coverage,omitempty"`
		NotCovered    []NotCoveredEntry `json:"not_covered,omitempty"`
	}{manifest.SchemaVersion, manifest.PackID, manifest.PackVersion, manifest.RuntimeAPI, manifest.Files, manifest.Coverage, manifest.NotCovered})
}

// VerifyPack performs a fully offline SHA-256 check for every declared file.
func VerifyPack(root string, manifest PackManifest) (VerifiedPack, error) {
	if manifest.SchemaVersion != GuardPackManifestVersion || manifest.RuntimeAPI != RuntimeVersion || manifest.PackID == "" || manifest.PackVersion == "" || len(manifest.Files) == 0 {
		return VerifiedPack{}, errors.New("guard pack verification: invalid or incompatible manifest")
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return VerifiedPack{}, fmt.Errorf("guard pack verification: encode manifest: %w", err)
	}
	if len(manifestBytes) > MaxPackManifestBytes {
		return VerifiedPack{}, fmt.Errorf("guard pack verification: manifest size %d exceeds %d-byte limit", len(manifestBytes), MaxPackManifestBytes)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return VerifiedPack{}, fmt.Errorf("guard pack verification: resolve root: %w", err)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return VerifiedPack{}, fmt.Errorf("guard pack verification: resolve root: %w", err)
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, file := range manifest.Files {
		if err := validatePackPath(file.Path); err != nil {
			return VerifiedPack{}, err
		}
		if _, ok := seen[file.Path]; ok {
			return VerifiedPack{}, fmt.Errorf("guard pack verification: duplicate file %q", file.Path)
		}
		seen[file.Path] = struct{}{}
		fullPath := filepath.Join(rootReal, filepath.FromSlash(file.Path))
		realPath, err := filepath.EvalSymlinks(fullPath)
		if err != nil {
			return VerifiedPack{}, fmt.Errorf("guard pack verification: file %q: %w", file.Path, err)
		}
		rel, err := filepath.Rel(rootReal, realPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return VerifiedPack{}, fmt.Errorf("guard pack verification: file %q escapes pack root", file.Path)
		}
		handle, err := os.Open(realPath)
		if err != nil {
			return VerifiedPack{}, fmt.Errorf("guard pack verification: read %q: %w", file.Path, err)
		}
		contents, readErr := io.ReadAll(io.LimitReader(handle, MaxDetectorFileBytes+1))
		closeErr := handle.Close()
		if readErr != nil {
			return VerifiedPack{}, fmt.Errorf("guard pack verification: read %q: %w", file.Path, readErr)
		}
		if closeErr != nil {
			return VerifiedPack{}, fmt.Errorf("guard pack verification: close %q: %w", file.Path, closeErr)
		}
		if len(contents) > MaxDetectorFileBytes {
			return VerifiedPack{}, fmt.Errorf("guard pack verification: file %q exceeds %d-byte limit", file.Path, MaxDetectorFileBytes)
		}
		sum := sha256.Sum256(contents)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), file.SHA256) {
			return VerifiedPack{}, fmt.Errorf("guard pack verification: sha256 mismatch for %q", file.Path)
		}
	}
	canonical, err := canonicalPackPayload(manifest)
	if err != nil {
		return VerifiedPack{}, fmt.Errorf("guard pack verification: encode manifest: %w", err)
	}
	manifestDigest := sha256.Sum256(canonical)
	return VerifiedPack{Manifest: manifest, Digest: hex.EncodeToString(manifestDigest[:])}, nil
}

func validatePackPath(path string) error {
	if path == "" || strings.ContainsRune(path, '\x00') || filepath.IsAbs(path) || strings.Contains(path, `\`) {
		return fmt.Errorf("guard pack manifest: invalid relative path %q", path)
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean != filepath.FromSlash(path) {
		return fmt.Errorf("guard pack manifest: invalid relative path %q", path)
	}
	return nil
}
