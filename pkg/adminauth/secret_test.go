package adminauth

// Session-secret policy at startup. Unset → generate ≥32 crypto/rand
// bytes; weak (short or a known dev constant) in production → refuse to start;
// weak in dev/test → warn (generated=true) and generate; strong → as-is.

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestResolveSessionSecret_GeneratesWhenUnset(t *testing.T) {
	secret, generated, err := ResolveSessionSecret("", false)
	if err != nil {
		t.Fatalf("unset secret in dev: unexpected error: %v", err)
	}
	if !generated {
		t.Error("unset secret must be generated (generated=true)")
	}
	raw, err := hex.DecodeString(secret)
	if err != nil || len(raw) < MinSessionSecretLen {
		t.Fatalf("generated secret must be ≥%d random bytes hex-encoded, got len=%d err=%v", MinSessionSecretLen, len(raw), err)
	}

	again, _, err := ResolveSessionSecret("", true)
	if err != nil {
		t.Fatalf("unset secret must generate in production too, got error: %v", err)
	}
	if again == secret {
		t.Error("two generated secrets must differ")
	}
}

func TestResolveSessionSecret_WeakShortInProductionRefused(t *testing.T) {
	for _, weak := range []string{"short", strings.Repeat("a", MinSessionSecretLen-1)} {
		secret, _, err := ResolveSessionSecret(weak, true)
		if err == nil {
			t.Errorf("weak secret (len %d) in production must refuse to start", len(weak))
		}
		if secret != "" {
			t.Errorf("refused start must not yield a secret, got len %d", len(secret))
		}
	}
}

func TestResolveSessionSecret_KnownDevConstantInProductionRefused(t *testing.T) {
	for _, constant := range []string{"changeme", "CHANGEME", "secret", "dev-secret", "password"} {
		if _, _, err := ResolveSessionSecret(constant, true); err == nil {
			t.Errorf("known dev constant %q in production must refuse to start", constant)
		}
	}
}

func TestResolveSessionSecret_WeakInDevWarnsAndGenerates(t *testing.T) {
	secret, generated, err := ResolveSessionSecret("changeme", false)
	if err != nil {
		t.Fatalf("weak secret in dev must not refuse start, got: %v", err)
	}
	if !generated {
		t.Error("weak secret in dev must be replaced (generated=true)")
	}
	if secret == "changeme" {
		t.Error("weak secret in dev must be replaced by a generated one")
	}
}

func TestResolveSessionSecret_StrongAccepted(t *testing.T) {
	strong := strings.Repeat("x", MinSessionSecretLen)
	secret, generated, err := ResolveSessionSecret(strong, true)
	if err != nil {
		t.Fatalf("strong secret in production must be accepted: %v", err)
	}
	if generated {
		t.Error("strong secret must not be regenerated")
	}
	if secret != strong {
		t.Error("strong secret must be used as-is")
	}
}

func TestWeakSessionSecret_LengthBoundary(t *testing.T) {
	if WeakSessionSecret(strings.Repeat("a", MinSessionSecretLen)) {
		t.Errorf("len %d must be considered strong", MinSessionSecretLen)
	}
	if !WeakSessionSecret(strings.Repeat("a", MinSessionSecretLen-1)) {
		t.Errorf("len %d must be considered weak", MinSessionSecretLen-1)
	}
	if !WeakSessionSecret("") {
		t.Error("empty is weak")
	}
}
