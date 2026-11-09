package guardhooks

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signingFixture is one ed25519 author keypair used to produce signed packs.
type signingFixture struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSigningFixture(t *testing.T) signingFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return signingFixture{priv: priv, pub: pub}
}

const (
	testSignKeyID     = "release-2026"
	customPackPattern = `CUSTOM_SIGNED_MARKER_[0-9]+`
)

// signManifest returns the manifest JSON with a v1 signature over its
// canonical payload made by this fixture's key under keyID.
func (f signingFixture) signManifest(t *testing.T, manifest PackManifest, keyID string) []byte {
	t.Helper()
	canonical, err := canonicalPackPayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(f.priv, canonical)
	manifest.Signature = &Signature{
		Version:   SignatureVersionV1,
		KeyID:     keyID,
		Algorithm: SignatureAlgorithmEd25519,
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// writeSignedPack writes a one-detector pack to a temp dir and returns the
// pack root plus the signed manifest bytes.
func writeSignedPack(t *testing.T, f signingFixture, packID, packVersion, keyID string) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	content := []byte(`{"detectors":[{"rule_id":"signed-rule","rule_version":"1","category":"secret","pattern":"` + customPackPattern + `"}]}`)
	if err := os.WriteFile(filepath.Join(root, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256Sum(content)
	manifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: packID, PackVersion: packVersion, RuntimeAPI: RuntimeVersion,
		Files: []PackFile{{Path: "detector.json", SHA256: sum}},
	}
	return root, f.signManifest(t, manifest, keyID)
}

func testVerifier(t *testing.T, f signingFixture) SignatureVerifier {
	t.Helper()
	verifier, err := NewEd25519Verifier(map[string]ed25519.PublicKey{testSignKeyID: f.pub})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

type stubGuardCAS struct{ from, to string }

func (c *stubGuardCAS) CompareAndSwap(_ context.Context, from, to string) error {
	c.from, c.to = from, to
	return nil
}

// TestSignedPackVerifiesAndActivates is the positive path: a correctly signed
// pack decodes, stages and activates through the existing lifecycle (the same
// path the startup and admin wiring drive), and its detector enforces after
// activation without displacing the built-in core chain.
func TestSignedPackVerifiesAndActivates(t *testing.T) {
	f := newSigningFixture(t)
	root, manifestBytes := writeSignedPack(t, f, "sigpack", "1", testSignKeyID)
	verifier := testVerifier(t, f)

	if _, err := DecodePackManifestWithVerifier(manifestBytes, verifier); err != nil {
		t.Fatalf("correctly signed manifest must verify: %v", err)
	}

	cas := &stubGuardCAS{}
	lifecycle := NewPackLifecycleWithVerifier(BuiltinChainVersion, ModeDeny, cas, verifier)
	verified, err := lifecycle.Stage(root, manifestBytes)
	if err != nil {
		t.Fatalf("signed pack must stage: %v", err)
	}
	if verified.Manifest.PackID != "sigpack" || verified.Digest == "" {
		t.Fatalf("unexpected verified pack: %#v", verified)
	}
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatalf("signed pack must activate: %v", err)
	}
	if cas.from != BuiltinChainVersion || cas.to != "sigpack@1" {
		t.Fatalf("activation CAS = %q -> %q, want core -> sigpack@1", cas.from, cas.to)
	}

	if _, _, err := lifecycle.ActiveHook().Apply("see CUSTOM_SIGNED_MARKER_42 now"); !errors.Is(err, ErrDenied) {
		t.Fatalf("signed pack detector must deny after activation, got %v", err)
	}
	// The signed pack is additive: core built-in authorization stays armed.
	if _, _, err := lifecycle.ActiveHook().Apply("token sk-abcdef0123456789abcdef"); !errors.Is(err, ErrDenied) {
		t.Fatalf("built-in secret detection must stay armed alongside a signed pack, got %v", err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("innocent text"); err != nil {
		t.Fatalf("innocent text must pass, got %v", err)
	}
}

// TestTamperedContentAfterSigningRejected: any content change after signing
// invalidates the signature — both a forged manifest digest and modified
// on-disk content are rejected and nothing is staged.
func TestTamperedContentAfterSigningRejected(t *testing.T) {
	f := newSigningFixture(t)
	root, manifestBytes := writeSignedPack(t, f, "tamper", "1", testSignKeyID)
	verifier := testVerifier(t, f)

	// (a) A manifest file digest edited after signing: the canonical payload
	// no longer matches the signed bytes.
	var forged PackManifest
	if err := json.Unmarshal(manifestBytes, &forged); err != nil {
		t.Fatal(err)
	}
	forged.Files[0].SHA256 = strings.Repeat("ab", 32)
	forgedBytes, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePackManifestWithVerifier(forgedBytes, verifier); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("tampered manifest digest must be rejected, got %v", err)
	}

	// (b) On-disk content changed after signing: SHA-256 file verification
	// rejects it and the lifecycle stages nothing.
	if err := os.WriteFile(filepath.Join(root, "detector.json"), []byte(`{"detectors":[{"rule_id":"evil","rule_version":"1","category":"secret","pattern":"EVIL_.*"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	lifecycle := NewPackLifecycleWithVerifier(BuiltinChainVersion, ModeDeny, &stubGuardCAS{}, verifier)
	if _, err := lifecycle.Stage(root, manifestBytes); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("tampered on-disk content must be rejected, got %v", err)
	}
	if lifecycle.ShadowHook() != nil || lifecycle.StagedVersion() != "" {
		t.Fatalf("failed verification must stage nothing: shadow=%v staged=%q", lifecycle.ShadowHook(), lifecycle.StagedVersion())
	}
}

// TestWrongKeySignatureRejected: a signature from a key outside the
// configured trusted set fails — both an unknown key id and a forged
// signature attributed to a known key id.
func TestWrongKeySignatureRejected(t *testing.T) {
	author := newSigningFixture(t)
	other := newSigningFixture(t)
	_, manifestBytes := writeSignedPack(t, author, "wrongkey", "1", testSignKeyID)

	t.Run("unknown key id", func(t *testing.T) {
		verifier, err := NewEd25519Verifier(map[string]ed25519.PublicKey{"someone-else": other.pub})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodePackManifestWithVerifier(manifestBytes, verifier); err == nil || !strings.Contains(err.Error(), "not in the configured trusted set") {
			t.Fatalf("unknown key id must be rejected, got %v", err)
		}
	})
	t.Run("known key id, wrong private key", func(t *testing.T) {
		forged := other.signManifest(t, mustDecodeManifest(t, manifestBytes), testSignKeyID)
		if _, err := DecodePackManifestWithVerifier(forged, testVerifier(t, author)); err == nil || !strings.Contains(err.Error(), "does not match the canonical pack payload") {
			t.Fatalf("forged signature under a known key id must be rejected, got %v", err)
		}
	})
	t.Run("wrong key material for declared id", func(t *testing.T) {
		verifier, err := NewEd25519Verifier(map[string]ed25519.PublicKey{testSignKeyID: other.pub})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodePackManifestWithVerifier(manifestBytes, verifier); err == nil || !strings.Contains(err.Error(), "does not match the canonical pack payload") {
			t.Fatalf("mismatched key material must be rejected, got %v", err)
		}
	})
}

// TestSignatureSchemeVersionMismatchRejected: signature envelopes this build
// does not understand are rejected explicitly — including in front of a
// custom verifier that would accept anything, so a future scheme can never
// be silently re-interpreted.
func TestSignatureSchemeVersionMismatchRejected(t *testing.T) {
	f := newSigningFixture(t)
	base := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "schemapack", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files: []PackFile{{Path: "detector.json", SHA256: strings.Repeat("0", 64)}},
	}
	build := func(sig Signature) []byte {
		t.Helper()
		manifest := base
		manifest.Signature = &sig
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for name, sig := range map[string]Signature{
		"unknown scheme version": {Version: "guardpack-sig.v2", KeyID: testSignKeyID, Algorithm: SignatureAlgorithmEd25519, Value: "c2ln"},
		"empty scheme version":   {Version: "", KeyID: testSignKeyID, Algorithm: SignatureAlgorithmEd25519, Value: "c2ln"},
		"unknown algorithm":      {Version: SignatureVersionV1, KeyID: testSignKeyID, Algorithm: "rsa-sha256", Value: "c2ln"},
	} {
		data := build(sig)
		if _, err := DecodePackManifestWithVerifier(data, testVerifier(t, f)); err == nil {
			t.Fatalf("%s: signed manifest must be rejected", name)
		}
		// The gate is the decode layer itself: even a permissive custom
		// verifier cannot bless an envelope from another scheme era.
		if _, err := DecodePackManifestWithVerifier(data, okVerifier{}); err == nil {
			t.Fatalf("%s: custom verifier must not bypass the scheme gate", name)
		}
	}
	// The supported scheme still verifies end to end.
	signed := f.signManifest(t, base, testSignKeyID)
	if _, err := DecodePackManifestWithVerifier(signed, testVerifier(t, f)); err != nil {
		t.Fatalf("v1 signed manifest must verify: %v", err)
	}
}

// TestSignatureOverPartialContentRejected: a signature that covers only part
// of the manifest content (a file subset, or an older identity field) does
// not verify against the full canonical payload.
func TestSignatureOverPartialContentRejected(t *testing.T) {
	f := newSigningFixture(t)
	verifier := testVerifier(t, f)
	full := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "partial", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files: []PackFile{
			{Path: "detector.json", SHA256: strings.Repeat("11", 32)},
			{Path: "extra.txt", SHA256: strings.Repeat("22", 32)},
		},
	}

	sign := func(payload PackManifest) []byte {
		t.Helper()
		canonical, err := canonicalPackPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(f.priv, canonical)
		signed := full
		signed.Signature = &Signature{
			Version: SignatureVersionV1, KeyID: testSignKeyID,
			Algorithm: SignatureAlgorithmEd25519, Value: base64.StdEncoding.EncodeToString(sig),
		}
		data, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	t.Run("file subset", func(t *testing.T) {
		partial := full
		partial.Files = full.Files[:1]
		if _, err := DecodePackManifestWithVerifier(sign(partial), verifier); err == nil || !strings.Contains(err.Error(), "does not match the canonical pack payload") {
			t.Fatalf("signature over a file subset must be rejected, got %v", err)
		}
	})
	t.Run("stale pack identity", func(t *testing.T) {
		stale := full
		stale.PackVersion = "0.9"
		if _, err := DecodePackManifestWithVerifier(sign(stale), verifier); err == nil || !strings.Contains(err.Error(), "does not match the canonical pack payload") {
			t.Fatalf("signature over a stale identity must be rejected, got %v", err)
		}
	})
	t.Run("runtime contract omitted", func(t *testing.T) {
		partial := full
		partial.RuntimeAPI = ""
		if _, err := DecodePackManifestWithVerifier(sign(partial), verifier); err == nil || !strings.Contains(err.Error(), "does not match the canonical pack payload") {
			t.Fatalf("signature omitting the runtime contract must be rejected, got %v", err)
		}
	})
}

// TestFreeCyclePreservedWithoutVerifier is the T05 negative invariant: with
// no verifier configured, unsigned local packs keep loading and activating
// through the plain lifecycle and the built-in core stays armed — absence of
// paid/signed packs never disables base authorization.
func TestFreeCyclePreservedWithoutVerifier(t *testing.T) {
	root := t.TempDir()
	content := []byte(`{"detectors":[{"rule_id":"free-rule","rule_version":"1","category":"secret","pattern":"FREE_LOCAL_MARKER_[0-9]+"}]}`)
	if err := os.WriteFile(filepath.Join(root, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "freepack", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files: []PackFile{{Path: "detector.json", SHA256: sha256Sum(content)}},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodePackManifest(manifestBytes)
	if err != nil || decoded.Signature != nil {
		t.Fatalf("unsigned pack must load without a verifier: %#v, %v", decoded.Signature, err)
	}
	lifecycle := NewPackLifecycle(BuiltinChainVersion, ModeDeny, &stubGuardCAS{})
	if _, err := lifecycle.Stage(root, manifestBytes); err != nil {
		t.Fatalf("unsigned pack must stage with no verifier configured: %v", err)
	}
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatalf("unsigned pack must activate with no verifier configured: %v", err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("x FREE_LOCAL_MARKER_7"); !errors.Is(err, ErrDenied) {
		t.Fatalf("free pack detector must enforce, got %v", err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("secret ghp_" + strings.Repeat("a", 20)); !errors.Is(err, ErrDenied) {
		t.Fatalf("core built-ins must stay armed with no verifier configured, got %v", err)
	}

	// The other half of the invariant: with no verifier configured, a
	// DECLARED signature still fails closed on this same path.
	f := newSigningFixture(t)
	_, signedBytes := writeSignedPack(t, f, "signedpack", "1", testSignKeyID)
	if _, err := lifecycle.Stage(t.TempDir(), signedBytes); err == nil || !strings.Contains(err.Error(), "signature declared but no verifier configured") {
		t.Fatalf("signed pack without verifier must fail closed at staging, got %v", err)
	}
	if got := lifecycle.StagedVersion(); got != "" {
		t.Fatalf("failed signed staging must leave nothing staged, got %q", got)
	}
}

// TestLoadDetectorPackWithVerifierAndLoadPackHookSeam covers the exported
// loader seams the gateway/admin wiring calls: signed packs load only through
// the WithVerifier variants and enforce through the returned hook.
func TestLoadDetectorPackWithVerifierAndLoadPackHookSeam(t *testing.T) {
	f := newSigningFixture(t)
	root, manifestBytes := writeSignedPack(t, f, "seam", "1", testSignKeyID)
	verifier := testVerifier(t, f)

	verified, detectors, err := LoadDetectorPackWithVerifier(root, manifestBytes, verifier)
	if err != nil {
		t.Fatalf("signed pack must load through the verifier seam: %v", err)
	}
	if len(detectors) != 1 || verified.Manifest.PackID != "seam" {
		t.Fatalf("unexpected loader result: %#v, %d detectors", verified, len(detectors))
	}
	if _, _, err := LoadDetectorPackWithVerifier(root, manifestBytes, nil); err == nil || !strings.Contains(err.Error(), "signature declared but no verifier configured") {
		t.Fatalf("nil verifier must keep failing closed, got %v", err)
	}

	hook, err := LoadPackHookWithVerifier(ModeDeny, verifier, []PackSource{{Root: root, Manifest: manifestBytes}})
	if err != nil {
		t.Fatalf("LoadPackHookWithVerifier must accept a signed pack: %v", err)
	}
	if _, _, err := hook.Apply("hit CUSTOM_SIGNED_MARKER_9"); !errors.Is(err, ErrDenied) {
		t.Fatalf("signed hook must enforce its detector, got %v", err)
	}
	badRoot, badManifest := writeSignedPack(t, f, "seam", "1", "unconfigured")
	if _, err := LoadPackHookWithVerifier(ModeDeny, testVerifier(t, f), []PackSource{{Root: badRoot, Manifest: badManifest}}); err == nil || !strings.Contains(err.Error(), "not in the configured trusted set") {
		t.Fatalf("LoadPackHookWithVerifier must reject unknown keys, got %v", err)
	}
}

func mustDecodeManifest(t *testing.T, data []byte) PackManifest {
	t.Helper()
	var manifest PackManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

// TestLoadDetectorPackRehashClosesTOCTOUWindow pins the review-F1 fix: the
// bytes the loader hands to the evaluators are re-hashed against the
// manifest's declared digest at read time, so content swapped between
// VerifyPack's hash pass and the detector.json read fails closed instead of
// compiling into the enforced chain. The read+re-hash half is exercised
// directly (loadVerifiedDetectorFile) because the verify→load interleaving
// itself cannot be reproduced deterministically in-process; the full loader
// runs through exactly this helper, so the invariant holds by construction.
func TestLoadDetectorPackRehashClosesTOCTOUWindow(t *testing.T) {
	root := t.TempDir()
	good := []byte(`{"detectors":[{"rule_id":"r0","rule_version":"1","category":"secret","pattern":"TOCTOU_GOOD_[A-Z]+"}]}`)
	if err := os.WriteFile(filepath.Join(root, "detector.json"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "toctou", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files: []PackFile{{Path: "detector.json", SHA256: sha256Sum(good)}},
	}

	// Matching content loads, and the returned bytes are exactly the hashed
	// content (nothing is re-read between the check and the return).
	data, err := loadVerifiedDetectorFile(root, manifest)
	if err != nil {
		t.Fatalf("matching detector.json must load: %v", err)
	}
	if !bytes.Equal(data, good) {
		t.Fatal("loaded bytes must be the verified bytes verbatim")
	}

	// Swap the on-disk content for a hostile catch-all while the manifest
	// still declares the good digest — exactly the state a verify→load race
	// produces. The re-hash must fail closed with nothing staged.
	hostile := []byte(`{"detectors":[{"rule_id":"r0","rule_version":"1","category":"secret","pattern":"."}]}`)
	if err := os.WriteFile(filepath.Join(root, "detector.json"), hostile, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifiedDetectorFile(root, manifest); err == nil || !strings.Contains(err.Error(), "changed between verification and load") {
		t.Fatalf("content swapped after verification must fail closed at the re-hash, got %v", err)
	}
}

// TestLoadDetectorPackSymlinkedRootUsesOneResolvedPath pins the other half
// of review F1: a symlinked pack root is resolved once and the SAME resolved
// directory serves file verification and the detector.json read — a valid
// signed pack keeps loading through a symlinked root.
func TestLoadDetectorPackSymlinkedRootUsesOneResolvedPath(t *testing.T) {
	f := newSigningFixture(t)
	realRoot, manifestBytes := writeSignedPack(t, f, "linkpack", "1", testSignKeyID)
	linkRoot := filepath.Join(t.TempDir(), "pack-link")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlinks unavailable in this environment: %v", err)
	}
	verified, detectors, err := LoadDetectorPackWithVerifier(linkRoot, manifestBytes, testVerifier(t, f))
	if err != nil {
		t.Fatalf("valid signed pack must load through a symlinked root: %v", err)
	}
	if verified.Manifest.PackID != "linkpack" || len(detectors) != 1 {
		t.Fatalf("unexpected load through symlinked root: %#v, %d detectors", verified.Manifest, len(detectors))
	}
}

func sha256Sum(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// TestEd25519VerifierValidatesKeySet pins the constructor contract: an empty
// set, a malformed key or a bad key id is a configuration error, never a
// silently degenerate verifier.
func TestEd25519VerifierValidatesKeySet(t *testing.T) {
	if _, err := NewEd25519Verifier(nil); err == nil || !strings.Contains(err.Error(), "at least one trusted public key") {
		t.Fatalf("empty key set must be rejected, got %v", err)
	}
	other := newSigningFixture(t)
	if _, err := NewEd25519Verifier(map[string]ed25519.PublicKey{testSignKeyID: []byte("short")}); err == nil || !strings.Contains(err.Error(), "ed25519 public key") {
		t.Fatalf("wrong key size must be rejected, got %v", err)
	}
	if _, err := NewEd25519Verifier(map[string]ed25519.PublicKey{"bad id!": other.pub}); err == nil || !strings.Contains(err.Error(), "invalid characters") {
		t.Fatalf("invalid key id must be rejected, got %v", err)
	}
	if _, err := NewEd25519Verifier(map[string]ed25519.PublicKey{testSignKeyID: other.pub}); err != nil {
		t.Fatalf("valid set must build: %v", err)
	}
	var nilVerifier *Ed25519Verifier
	if err := nilVerifier.Verify(PackManifest{}, nil); err == nil || !strings.Contains(err.Error(), "no verifier configured") {
		t.Fatalf("nil verifier must report the misconfiguration, got %v", err)
	}
}

// TestEd25519VerifierRejectsMalformedSignatureValues covers the envelope
// checks the crypto layer performs for directly driven Verify calls.
func TestEd25519VerifierRejectsMalformedSignatureValues(t *testing.T) {
	f := newSigningFixture(t)
	verifier := testVerifier(t, f)
	base := PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion,
		Files: []PackFile{{Path: "detector.json", SHA256: strings.Repeat("0", 64)}},
	}
	canonical, err := canonicalPackPayload(base)
	if err != nil {
		t.Fatal(err)
	}
	build := func(sig Signature) PackManifest {
		m := base
		m.Signature = &sig
		return m
	}
	unsigned := base
	if err := verifier.Verify(unsigned, canonical); err != nil {
		t.Fatalf("unsigned manifest must pass without consultation, got %v", err)
	}
	for name, sig := range map[string]Signature{
		"non-base64 value": {Version: SignatureVersionV1, KeyID: testSignKeyID, Algorithm: SignatureAlgorithmEd25519, Value: "!!!not base64!!!"},
		"wrong length":     {Version: SignatureVersionV1, KeyID: testSignKeyID, Algorithm: SignatureAlgorithmEd25519, Value: base64.StdEncoding.EncodeToString([]byte("tooshort"))},
		"empty key id":     {Version: SignatureVersionV1, KeyID: "", Algorithm: SignatureAlgorithmEd25519, Value: "c2ln"},
	} {
		if err := verifier.Verify(build(sig), canonical); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

// TestPublicKeyMaterialParsing covers the accepted key encodings.
func TestPublicKeyMaterialParsing(t *testing.T) {
	f := newSigningFixture(t)
	b64 := base64.StdEncoding.EncodeToString(f.pub)
	hexed := hex.EncodeToString(f.pub)
	for name, material := range map[string]string{"base64": b64, "hex": hexed, "base64 with newline": b64 + "\n"} {
		key, err := ParseEd25519PublicKey(material)
		if err != nil {
			t.Fatalf("%s key must parse: %v", name, err)
		}
		if string(key) != string(f.pub) {
			t.Fatalf("%s key mismatch", name)
		}
	}
	for name, material := range map[string]string{"empty": "  ", "wrong size": base64.StdEncoding.EncodeToString([]byte("short")), "garbage": "!!!not a key!!!"} {
		if _, err := ParseEd25519PublicKey(material); err == nil {
			t.Fatalf("%s key must be rejected", name)
		}
	}
}

// TestLoadEd25519VerifierKeyDir covers the static key-directory source.
func TestLoadEd25519VerifierKeyDir(t *testing.T) {
	f := newSigningFixture(t)
	other := newSigningFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k1.pub"), []byte(base64.StdEncoding.EncodeToString(f.pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k2.pub"), []byte(hex.EncodeToString(other.pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadEd25519VerifierKeyDir(dir)
	if err != nil {
		t.Fatalf("key dir must load: %v", err)
	}
	if len(keys) != 2 || string(keys["k1"]) != string(f.pub) || string(keys["k2"]) != string(other.pub) {
		t.Fatalf("unexpected key set: %v", keys)
	}

	empty := t.TempDir()
	if _, err := LoadEd25519VerifierKeyDir(empty); err == nil || !strings.Contains(err.Error(), "no .pub key files") {
		t.Fatalf("keyless dir must fail loud, got %v", err)
	}
	if _, err := LoadEd25519VerifierKeyDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing dir must fail loud")
	}
	if _, err := LoadEd25519VerifierKeyDir(""); err == nil {
		t.Fatal("empty dir config must fail loud")
	}
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "bad.pub"), []byte("!!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEd25519VerifierKeyDir(broken); err == nil || !strings.Contains(err.Error(), "key file") {
		t.Fatalf("broken key material must fail loud, got %v", err)
	}
}

// TestParseInlineVerifierKey covers the inline key-id=material source.
func TestParseInlineVerifierKey(t *testing.T) {
	f := newSigningFixture(t)
	id, key, err := ParseInlineVerifierKey("inline-key=" + base64.StdEncoding.EncodeToString(f.pub))
	if err != nil || id != "inline-key" || string(key) != string(f.pub) {
		t.Fatalf("valid inline entry must parse: id=%q err=%v", id, err)
	}
	for name, entry := range map[string]string{
		"missing =":    "justakey",
		"missing id":   "=" + base64.StdEncoding.EncodeToString(f.pub),
		"missing key":  "id=",
		"bad material": "id=!!!",
		"invalid id":   "bad id=" + base64.StdEncoding.EncodeToString(f.pub),
		"oversized id": strings.Repeat("k", MaxVerifierKeyIDLen+1) + "=" + base64.StdEncoding.EncodeToString(f.pub),
	} {
		if _, _, err := ParseInlineVerifierKey(entry); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

// TestNewVerifierFromConfig covers the wiring seam resolution rules: no
// sources resolve to the explicit not-configured state; any configured
// source must yield a usable key set or fail loud; key ids must stay unique
// across sources.
func TestNewVerifierFromConfig(t *testing.T) {
	f := newSigningFixture(t)
	other := newSigningFixture(t)

	t.Run("nothing configured means no verifier", func(t *testing.T) {
		verifier, configured, err := NewVerifierFromConfig("", nil)
		if verifier != nil || configured || err != nil {
			t.Fatalf("no sources = (nil, false, nil), got %v, %v, %v", verifier, configured, err)
		}
		verifier, configured, err = NewVerifierFromConfig("   ", []string{" ", ""})
		if verifier != nil || configured || err != nil {
			t.Fatalf("blank sources = (nil, false, nil), got %v, %v, %v", verifier, configured, err)
		}
	})
	t.Run("inline source builds a working verifier", func(t *testing.T) {
		verifier, configured, err := NewVerifierFromConfig("", []string{"k=" + base64.StdEncoding.EncodeToString(f.pub)})
		if err != nil || !configured || verifier == nil {
			t.Fatalf("configured inline source must build a verifier: %v, %v, %v", verifier, configured, err)
		}
		root, manifestBytes := writeSignedPack(t, f, "cfg", "1", "k")
		if _, err := DecodePackManifestWithVerifier(manifestBytes, verifier); err != nil {
			t.Fatalf("inline-sourced verifier must accept the signed pack: %v", err)
		}
		_ = root
	})
	t.Run("dir and inline merge", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "d1.pub"), []byte(base64.StdEncoding.EncodeToString(f.pub)), 0o600); err != nil {
			t.Fatal(err)
		}
		verifier, configured, err := NewVerifierFromConfig(dir, []string{"i1=" + base64.StdEncoding.EncodeToString(other.pub)})
		if err != nil || !configured {
			t.Fatalf("both sources must build: %v, %v", configured, err)
		}
		_, manifestBytes := writeSignedPack(t, f, "cfg", "1", "d1")
		if _, err := DecodePackManifestWithVerifier(manifestBytes, verifier); err != nil {
			t.Fatalf("dir-sourced key must verify: %v", err)
		}
	})
	t.Run("duplicate id across sources fails loud", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "dup.pub"), []byte(base64.StdEncoding.EncodeToString(f.pub)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := NewVerifierFromConfig(dir, []string{"dup=" + base64.StdEncoding.EncodeToString(other.pub)}); err == nil || !strings.Contains(err.Error(), "duplicate key id") {
			t.Fatalf("duplicate ids must be rejected, got %v", err)
		}
	})
	t.Run("broken configured source fails loud", func(t *testing.T) {
		if _, _, err := NewVerifierFromConfig(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
			t.Fatal("missing dir must be an error, not a silent no-verifier")
		}
		if _, _, err := NewVerifierFromConfig("", []string{"id=notakey"}); err == nil {
			t.Fatal("broken inline key must be an error")
		}
	})
}
