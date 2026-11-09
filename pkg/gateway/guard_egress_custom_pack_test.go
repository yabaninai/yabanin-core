package cli

// FIX-01 (CA-01) gateway-egress integration: a loaded custom guard pack must
// actually redact egress bodies through the real applyEgressGuards path (not
// only guardhooks.Hook), and an unsafe pack span must fail closed instead of
// forwarding a body that still carries the secret or was corrupted.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/guardhooks"
)

// TestFIX01EgressCustomPackRedactsBody drives a real custom pack through
// startup wiring and applyEgressGuards in redact mode.
func TestFIX01EgressCustomPackRedactsBody(t *testing.T) {
	root := t.TempDir()
	writeStartupGuardPack(t, root, "fix01", `PACK_SECRET_[A-Z]+`, 1)
	t.Setenv("YABANIN_GUARD_PACK_DIR", root)
	t.Setenv("YABANIN_GUARD_ACTIVE_PACKS", "fix01")
	t.Setenv("YABANIN_GUARD_PACK_MODE", "")

	w := &gatewayWiring{cfg: config.Gateway{GatewayCompliance: config.GatewayCompliance{GuardMode: "redact"}}, l: testLogger()}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	if err := loadGuardHooks(context.Background(), w, gw); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"messages":[{"role":"user","content":"leak PACK_SECRET_VALUE now"}]}`)
	out, err := gw.applyEgressGuards(body)
	if err != nil {
		t.Fatalf("redact mode must not fail a redactable body: %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("redacted body is not valid JSON: %q", out)
	}
	if bytes.Contains(out, []byte("PACK_SECRET_VALUE")) {
		t.Fatalf("custom pack secret survived egress redaction: %q", out)
	}
	if !bytes.Contains(out, []byte("[REDACTED_SECRET]")) {
		t.Fatalf("expected redaction token in %q", out)
	}
	want := []byte(`{"messages":[{"role":"user","content":"leak [REDACTED_SECRET] now"}]}`)
	if !bytes.Equal(out, want) {
		t.Fatalf("unexpected egress body:\n got %q\nwant %q", out, want)
	}
}

// TestFIX01EgressJSONCorruptingSpanFailsClosed loads a pack whose span would
// corrupt a valid JSON body; the gateway must deny the request (fail closed)
// instead of forwarding broken bytes or the untouched secret.
func TestFIX01EgressJSONCorruptingSpanFailsClosed(t *testing.T) {
	root := t.TempDir()
	// The pattern consumes the closing quote plus the following JSON keys so a
	// naive replacement would leave the body with an unterminated string.
	corruptPayload := []byte(`{"detectors":[{"rule_id":"corrupt","rule_version":"1","category":"secret","pattern":"PACKX\",\"b\":"}]}`)
	writeStartupGuardPackWithPayload(t, root, "corrupt", corruptPayload)
	t.Setenv("YABANIN_GUARD_PACK_DIR", root)
	t.Setenv("YABANIN_GUARD_ACTIVE_PACKS", "corrupt")
	t.Setenv("YABANIN_GUARD_PACK_MODE", "")

	w := &gatewayWiring{cfg: config.Gateway{GatewayCompliance: config.GatewayCompliance{GuardMode: "redact"}}, l: testLogger()}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	if err := loadGuardHooks(context.Background(), w, gw); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"a":"PACKX","b":2}`)
	if !json.Valid(body) {
		t.Fatalf("test body must start as valid JSON: %q", body)
	}
	out, err := gw.applyEgressGuards(body)
	if !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("JSON-corrupting span must fail closed, got err=%v out=%q", err, out)
	}
	if out != nil {
		t.Fatalf("no body may be forwarded on a failed redaction, got %q", out)
	}
}

// writeStartupGuardPackWithPayload materialises a pack with a caller-provided
// detector.json payload (for patterns the shared helper cannot express).
func writeStartupGuardPackWithPayload(t *testing.T, root, packID string, detectorPayload []byte) {
	t.Helper()
	packDir := filepath.Join(root, packID)
	if err := os.MkdirAll(packDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "detector.json"), detectorPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(detectorPayload)
	manifest, err := json.Marshal(guardhooks.PackManifest{
		SchemaVersion: guardhooks.GuardPackManifestVersion,
		PackID:        packID,
		PackVersion:   "1",
		RuntimeAPI:    guardhooks.RuntimeVersion,
		Files:         []guardhooks.PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
}
