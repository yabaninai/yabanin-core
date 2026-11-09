package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// TestVendorPublicKey_IsValidEd25519Key is the regression guard for I1.2: the
// embedded key must be exactly 32 raw bytes. The old code cast the hex STRING to
// ed25519.PublicKey, producing 64 ASCII bytes that ed25519.Verify silently
// rejected for every token. This test fails on that representation.
func TestVendorPublicKey_IsValidEd25519Key(t *testing.T) {
	if len(VendorPublicKey) != ed25519.PublicKeySize {
		t.Fatalf("embedded VendorPublicKey must be %d bytes, got %d — hex-string cast regression",
			ed25519.PublicKeySize, len(VendorPublicKey))
	}
}

// TestVendorPublicKey_RoundTripVerify proves a signature made against a
// correctly-decoded 32-byte key verifies, while the 64-byte ASCII string the old
// code produced is rejected (in Go 1.26+ ed25519.Verify panics on a non-32-byte
// key, so we assert it does not return true). This documents why the
// decoded-bytes form is required.
func TestVendorPublicKey_RoundTripVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	msg := []byte("license-payload")
	sig := ed25519.Sign(priv, msg)

	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("ed25519 verify failed for a freshly generated keypair")
	}

	// The ASCII hex-string cast (the old buggy representation) is 64 bytes and
	// must NOT verify. Go 1.26+ panics on a non-32-byte key; older versions
	// return false. Either way it is unusable.
	hexStr := ed25519.PublicKey([]byte(hex.EncodeToString(pub)))
	func() {
		defer func() { _ = recover() }()
		if ed25519.Verify(hexStr, msg, sig) {
			t.Fatal("64-byte ASCII string unexpectedly verified as an ed25519 key — test premise broken")
		}
	}()
}

// TestMustVendorKey_DecodesValidKey confirms the helper round-trips a valid key.
func TestMustVendorKey_DecodesValidKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	got := mustVendorKey(hex.EncodeToString(pub))
	if !bytes.Equal(got, pub) {
		t.Fatal("mustVendorKey did not round-trip the key bytes")
	}
}

// TestMustVendorKey_PanicsOnBadInput confirms malformed or wrong-length values
// fail fast at init rather than yielding an unusable key.
func TestMustVendorKey_PanicsOnBadInput(t *testing.T) {
	for name, bad := range map[string]string{
		"invalid hex":  "zz!!",
		"wrong length": "ab",
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("mustVendorKey(%q) did not panic", bad)
				}
			}()
			_ = mustVendorKey(bad)
		})
	}
}
