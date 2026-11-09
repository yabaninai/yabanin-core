package cli

// Guard pack-signature verifier wiring (N02-P08 T05, review F1 follow-up):
// the verifier resolved once at startup from the three-state env config is
// applied to EVERY load surface — startup reconciliation, durable prior /
// hydration loads and the runtime watcher's materializations — and the admin
// surface resolves its own instance from the same config. Locked semantics:
//
//	verifier env            signed pack            unsigned pack
//	----------------------  ---------------------  --------------------
//	configured + valid      verifies + enforces    loads (free cycle)
//	configured + broken     startup REFUSES        startup REFUSES
//	                                                  (fail loud: the
//	                                                  operator asked for
//	                                                  verification)
//	not configured          fail closed (existing) loads (byte-identical
//	                                                  legacy behavior)
//
// A tampered signed pack fails at every surface (startup stage, watcher
// materialization, hydration) instead of ever reaching an evaluator.

import (
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

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policystore"
)

const wiredSignedPattern = `WIRED_SIGNED_MARKER_[0-9]+`

// signingKeyFixture is one ed25519 author keypair for gateway-side signed
// pack fixtures (the guardhooks-local fixture is not importable from here).
func signingKeyFixture(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return priv, pub
}

// writeSignedGuardPackFixture materialises one valid SIGNED local pack
// (writeVersionedPack parity): <root>/<id>/manifest.json + detector.json,
// the manifest declaring the detector.json digest plus a guardpack-sig.v1
// ed25519 signature by priv under keyID. While manifest.Signature is unset,
// json.Marshal(manifest) IS the canonical payload the scheme signs.
func writeSignedGuardPackFixture(t *testing.T, root, id, version, pattern string, priv ed25519.PrivateKey, keyID string) {
	t.Helper()
	packDir := filepath.Join(root, id)
	if err := os.MkdirAll(packDir, 0o700); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"detectors": []map[string]string{{
		"rule_id": id + "-r0", "rule_version": "1", "category": "secret", "pattern": pattern,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "detector.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	manifest := guardhooks.PackManifest{
		SchemaVersion: guardhooks.GuardPackManifestVersion,
		PackID:        id,
		PackVersion:   version,
		RuntimeAPI:    guardhooks.RuntimeVersion,
		Files:         []guardhooks.PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}},
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, canonical)
	manifest.Signature = &guardhooks.Signature{
		Version:   guardhooks.SignatureVersionV1,
		KeyID:     keyID,
		Algorithm: guardhooks.SignatureAlgorithmEd25519,
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "manifest.json"), manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeVerifierKeyDir materialises a trusted-key directory holding one
// `<keyID>.pub` raw public key (standard base64), the verifier config source.
func writeVerifierKeyDir(t *testing.T, keyID string, pub ed25519.PublicKey) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keyID+".pub"), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// signedWiringEnv pins the pack + verifier env for one startup test.
func signedWiringEnv(t *testing.T, packRoot, keysDir string) {
	t.Helper()
	t.Setenv("YABANIN_GUARD_PACK_DIR", packRoot)
	t.Setenv("YABANIN_GUARD_ACTIVE_PACKS", "signed")
	t.Setenv("YABANIN_GUARD_PACK_MODE", "")
	t.Setenv("YABANIN_GUARD_PACK_VERIFY_KEYS_DIR", keysDir)
	t.Setenv("YABANIN_GUARD_PACK_VERIFY_KEYS", "")
}

// TestLoadGuardHooksSignedPackVerifiesAndEnforces is the normal-path
// acceptance: on a verifier-configured deployment a signed, valid env pack
// activates at startup and its detector enforces on the request path.
func TestLoadGuardHooksSignedPackVerifiesAndEnforces(t *testing.T) {
	priv, pub := signingKeyFixture(t)
	packRoot := t.TempDir()
	writeSignedGuardPackFixture(t, packRoot, "signed", "1", wiredSignedPattern, priv, "release-2026")
	signedWiringEnv(t, packRoot, writeVerifierKeyDir(t, "release-2026", pub))

	w := &gatewayWiring{cfg: config.Gateway{GatewayCompliance: config.GatewayCompliance{GuardMode: "deny"}}, l: testLogger()}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	if err := loadGuardHooks(context.Background(), w, gw); err != nil {
		t.Fatalf("valid signed pack must activate under the configured verifier: %v", err)
	}
	if _, err := gw.applyEgressGuards([]byte("WIRED_SIGNED_MARKER_42")); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("activated signed detector must enforce: %v", err)
	}
}

// TestLoadGuardHooksTamperedSignedPackRefusesStartup is the adversarial
// acceptance: a signed-but-tampered env pack refuses the startup fail-closed
// (no built-ins downgrade, no partial activation).
func TestLoadGuardHooksTamperedSignedPackRefusesStartup(t *testing.T) {
	priv, pub := signingKeyFixture(t)
	packRoot := t.TempDir()
	writeSignedGuardPackFixture(t, packRoot, "signed", "1", wiredSignedPattern, priv, "release-2026")
	signedWiringEnv(t, packRoot, writeVerifierKeyDir(t, "release-2026", pub))
	// Swap the detector content AFTER signing: the manifest's signature and
	// declared digest still name the original bytes.
	hostile := []byte(`{"detectors":[{"rule_id":"signed-r0","rule_version":"1","category":"secret","pattern":"."}]}`)
	if err := os.WriteFile(filepath.Join(packRoot, "signed", "detector.json"), hostile, 0o600); err != nil {
		t.Fatal(err)
	}

	w := &gatewayWiring{cfg: config.Gateway{GatewayCompliance: config.GatewayCompliance{GuardMode: "deny"}}, l: testLogger()}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	err := loadGuardHooks(context.Background(), w, gw)
	if err == nil {
		t.Fatal("a tampered signed pack must refuse the startup")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("tamper must surface as a content-digest failure, got: %v", err)
	}
}

// TestLoadGuardHooksSignedPackWithoutVerifierFailsClosed pins the existing
// fail-closed semantics: a declared signature with NO verifier configured
// refuses the startup (never silently loads unsigned).
func TestLoadGuardHooksSignedPackWithoutVerifierFailsClosed(t *testing.T) {
	priv, _ := signingKeyFixture(t)
	packRoot := t.TempDir()
	writeSignedGuardPackFixture(t, packRoot, "signed", "1", wiredSignedPattern, priv, "release-2026")
	t.Setenv("YABANIN_GUARD_PACK_DIR", packRoot)
	t.Setenv("YABANIN_GUARD_ACTIVE_PACKS", "signed")
	t.Setenv("YABANIN_GUARD_PACK_MODE", "")
	t.Setenv("YABANIN_GUARD_PACK_VERIFY_KEYS_DIR", "")
	t.Setenv("YABANIN_GUARD_PACK_VERIFY_KEYS", "")

	w := &gatewayWiring{cfg: config.Gateway{GatewayCompliance: config.GatewayCompliance{GuardMode: "deny"}}, l: testLogger()}
	err := loadGuardHooks(context.Background(), w, &gateway{gatewayCore: gatewayCore{log: testLogger()}})
	if err == nil || !strings.Contains(err.Error(), "no verifier configured") {
		t.Fatalf("signed pack without a verifier must fail closed, got: %v", err)
	}
}

// TestLoadGuardHooksBrokenVerifierConfigRefusesStartup pins the fail-loud
// three-state branch: a configured-but-broken key set (empty/missing
// directory) refuses the startup — never a silent downgrade to no verifier.
func TestLoadGuardHooksBrokenVerifierConfigRefusesStartup(t *testing.T) {
	priv, _ := signingKeyFixture(t)
	packRoot := t.TempDir()
	writeSignedGuardPackFixture(t, packRoot, "signed", "1", wiredSignedPattern, priv, "release-2026")
	t.Setenv("YABANIN_GUARD_PACK_DIR", packRoot)
	t.Setenv("YABANIN_GUARD_ACTIVE_PACKS", "signed")
	t.Setenv("YABANIN_GUARD_PACK_MODE", "")
	t.Setenv("YABANIN_GUARD_PACK_VERIFY_KEYS_DIR", filepath.Join(t.TempDir(), "does-not-exist"))
	t.Setenv("YABANIN_GUARD_PACK_VERIFY_KEYS", "")

	w := &gatewayWiring{cfg: config.Gateway{GatewayCompliance: config.GatewayCompliance{GuardMode: "deny"}}, l: testLogger()}
	err := loadGuardHooks(context.Background(), w, &gateway{gatewayCore: gatewayCore{log: testLogger()}})
	if err == nil || !strings.Contains(err.Error(), "guard pack verifier") {
		t.Fatalf("broken verifier configuration must refuse the startup fail-loud, got: %v", err)
	}
}

// TestGuardPackWatcherMaterializesSignedPackUnderVerifier pins the watcher
// half of the wiring: a signed durable pack materializes (and enforces)
// through the watcher's verifier, a tampered one fails closed (keeping the
// last known-good hook per the C3 contract), and the built-in chain keeps
// materializing regardless.
func TestGuardPackWatcherMaterializesSignedPackUnderVerifier(t *testing.T) {
	priv, pub := signingKeyFixture(t)
	packRoot := t.TempDir()
	writeSignedGuardPackFixture(t, packRoot, "wmsigned", "1", wiredSignedPattern, priv, "release-2026")
	verifier, configured, err := guardhooks.NewVerifierFromConfig(writeVerifierKeyDir(t, "release-2026", pub), nil)
	if err != nil || !configured {
		t.Fatalf("verifier must resolve from the key dir: configured=%v err=%v", configured, err)
	}
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "wmsigned@1", PreviousVersion: "core"}}
	w := newGuardPackWatcher(store, testLogger(), guardhooks.ModeDeny, packRoot, nil, verifier)

	hook, err := w.materialize("wmsigned@1")
	if err != nil {
		t.Fatalf("valid signed durable pack must materialize under the verifier: %v", err)
	}
	if _, _, err := hook.Apply("WIRED_SIGNED_MARKER_7"); !isGuardDenied(err) {
		t.Fatalf("materialized signed detector must enforce, got %v", err)
	}

	// Tamper on disk: the same requested version must now fail closed.
	hostile := []byte(`{"detectors":[{"rule_id":"wmsigned-r0","rule_version":"1","category":"secret","pattern":"."}]}`)
	if err := os.WriteFile(filepath.Join(packRoot, "wmsigned", "detector.json"), hostile, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.materialize("wmsigned@1"); err == nil {
		t.Fatal("tampered signed durable pack must fail materialization (C3 keeps the last known-good hook)")
	}
	// The built-in chain is independent of pack content and still resolves.
	if hook, err := w.materialize("core"); err != nil || hook == nil {
		t.Fatalf("built-in chain must keep materializing: %v", err)
	}
}

// TestHydrateGuardPackLifecycleSignedPackUnderVerifier pins the admin
// hydration half: a signed durable pack degrades (loud, no active hook)
// without a verifier and hydrates with full enforcement when the verifier
// matches — the durable record itself never becomes the trust anchor.
func TestHydrateGuardPackLifecycleSignedPackUnderVerifier(t *testing.T) {
	priv, pub := signingKeyFixture(t)
	root := t.TempDir()
	writeSignedGuardPackFixture(t, root, "hydrated", "1", wiredSignedPattern, priv, "release-2026")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "hydrated@1", PreviousVersion: "core"}}

	t.Run("without a verifier the signed durable pack fails closed", func(t *testing.T) {
		lifecycle, err := hydrateGuardPackLifecycle(context.Background(), store, testLogger(), guardhooks.ModeDeny, root, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := lifecycle.ActiveHook().Apply("WIRED_SIGNED_MARKER_1"); isGuardDenied(err) {
			t.Fatal("a signed durable pack must not hydrate into enforcement without a verifier")
		}
	})
	t.Run("with the matching verifier the signed durable pack hydrates and enforces", func(t *testing.T) {
		verifier, configured, err := guardhooks.NewVerifierFromConfig(writeVerifierKeyDir(t, "release-2026", pub), nil)
		if err != nil || !configured {
			t.Fatalf("verifier must resolve: configured=%v err=%v", configured, err)
		}
		lifecycle, err := hydrateGuardPackLifecycle(context.Background(), store, testLogger(), guardhooks.ModeDeny, root, verifier)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := lifecycle.ActiveHook().Apply("WIRED_SIGNED_MARKER_1"); !isGuardDenied(err) {
			t.Fatalf("hydrated signed detector must enforce, got %v", err)
		}
	})
}
