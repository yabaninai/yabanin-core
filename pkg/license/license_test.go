package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeToken(t *testing.T, priv ed25519.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	payload, _ := json.Marshal(claims)
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerify_ValidToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	old := VendorPublicKey
	VendorPublicKey = pub
	defer func() { VendorPublicKey = old }()
	token := makeToken(t, priv, map[string]interface{}{
		"org_id":     "acme",
		"seats":      10,
		"expires_at": time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		"issued_at":  time.Now().Format(time.RFC3339),
	})
	c, err := Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.OrgID != "acme" || c.Seats != 10 {
		t.Errorf("unexpected claims: %+v", c)
	}
}

func TestVerify_TamperedPayload_Rejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	old := VendorPublicKey
	VendorPublicKey = pub
	defer func() { VendorPublicKey = old }()
	token := makeToken(t, priv, map[string]interface{}{
		"org_id":     "acme",
		"expires_at": time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		"issued_at":  time.Now().Format(time.RFC3339),
	})
	// Flip a char in the payload half.
	tampered := token[:5] + "X" + token[6:]
	if _, err := Verify(tampered); err == nil {
		t.Error("expected signature rejection for tampered token")
	}
}

func TestVerify_ExpiredInGrace_Allowed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	old := VendorPublicKey
	VendorPublicKey = pub
	defer func() { VendorPublicKey = old }()
	token := makeToken(t, priv, map[string]interface{}{
		"org_id":     "acme",
		"expires_at": time.Now().Add(-2 * 24 * time.Hour).Format(time.RFC3339), // expired 2d ago
		"issued_at":  time.Now().Add(-40 * 24 * time.Hour).Format(time.RFC3339),
	})
	c, err := Verify(token)
	if err != nil {
		t.Fatalf("expected grace-period pass, got: %v", err)
	}
	st := StateFromClaims(c)
	if !st.Expired || st.HardExpired {
		t.Errorf("expected Expired=true HardExpired=false, got %+v", st)
	}
}

func TestVerify_HardExpired_Rejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	old := VendorPublicKey
	VendorPublicKey = pub
	defer func() { VendorPublicKey = old }()
	token := makeToken(t, priv, map[string]interface{}{
		"org_id":     "acme",
		"expires_at": time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339), // past grace
		"issued_at":  time.Now().Add(-60 * 24 * time.Hour).Format(time.RFC3339),
	})
	if _, err := Verify(token); err == nil {
		t.Error("expected hard-expire rejection")
	}
}

func TestVerify_BadFormat_Rejected(t *testing.T) {
	if _, err := Verify("not-a-token"); err == nil {
		t.Error("expected format error")
	}
}

func TestServer_LoadsTokenFromFile(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	old := VendorPublicKey
	VendorPublicKey = pub
	defer func() { VendorPublicKey = old }()
	token := makeToken(t, priv, map[string]interface{}{
		"org_id":     "acme",
		"seats":      3,
		"expires_at": time.Now().Add(10 * 24 * time.Hour).Format(time.RFC3339),
		"issued_at":  time.Now().Format(time.RFC3339),
	})
	path := filepath.Join(t.TempDir(), "license")
	_ = os.WriteFile(path, []byte(token), 0o600)
	srv := NewServer(path)
	defer srv.Close(context.TODO())
	st := srv.State()
	if !st.Active || st.OrgID != "acme" || st.Seats != 3 {
		t.Errorf("unexpected state: %+v", st)
	}
}

func TestServer_MissingToken_Inactive(t *testing.T) {
	srv := NewServer(filepath.Join(t.TempDir(), "nope"))
	defer srv.Close(context.TODO())
	if srv.State().Active {
		t.Error("expected inactive for missing token")
	}
}
