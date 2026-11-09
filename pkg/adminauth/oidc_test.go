package adminauth

// In-package OIDC client tests against a fake provider (real discovery/JWKS/
// token shapes). The full HTTP flow is additionally exercised end-to-end in
// services/admin/handlers/oidc_test.go; these tests pin the client surface
// itself: discovery, redirect shape, exchange+verify, fail-closed issuer
// validation and the cookie codec.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeProvider struct {
	server     *httptest.Server
	key        *rsa.PrivateKey
	stripEmail bool

	clientID        string
	nonceToEmbed    string
	wrongAudience   bool
	foreignIssuer   bool // id_token carries a foreign iss claim
	emailVerified   bool
	expirySkewSecs  int64
	extraIDTokenErr bool
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	p := &fakeProvider{key: key, clientID: "cid", emailVerified: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		wj(w, map[string]any{
			"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/auth",
			"token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := &p.key.PublicKey
		wj(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if p.extraIDTokenErr {
			wj(w, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		aud := p.clientID
		if p.wrongAudience {
			aud = "other"
		}
		iss := p.server.URL
		if p.foreignIssuer {
			iss = "https://other-issuer.invalid"
		}
		claims := map[string]any{
			"iss": iss, "aud": aud, "sub": "s-1",
			"email": "u@test.io", "email_verified": p.emailVerified,
			"exp": time.Now().Unix() + 600 + p.expirySkewSecs, "iat": time.Now().Unix(),
			"nonce": p.nonceToEmbed,
		}
		if p.stripEmail {
			delete(claims, "email")
		}
		wj(w, map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": p.sign(t, claims),
		})
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakeProvider) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	cb, _ := json.Marshal(claims)
	si := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	d := sha256.Sum256([]byte(si))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return si + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func wj(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestOIDCClient_AuthCodeURLShape(t *testing.T) {
	p := newFakeProvider(t)
	c, err := NewOIDCClient(context.Background(), p.server.URL, p.clientID, "sec", "https://adm/cb")
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}
	f, err := NewOIDCFlow()
	if err != nil {
		t.Fatal(err)
	}
	f.Next = "/#keys?org=acme"
	raw := c.AuthCodeURL(f)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"client_id": p.clientID, "state": f.State, "nonce": f.Nonce,
		"code_challenge": f.PKCEChallengeS256(), "code_challenge_method": "S256",
		"response_type": "code", "scope": "openid email",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s: got %q, want %q", k, got, want)
		}
	}
	if !strings.HasPrefix(raw, p.server.URL) {
		t.Errorf("redirect must target the issuer: %s", raw)
	}
}

func TestOIDCClient_ExchangeAndVerify_Happy(t *testing.T) {
	p := newFakeProvider(t)
	p.nonceToEmbed = "the-nonce"
	c, _ := NewOIDCClient(context.Background(), p.server.URL, p.clientID, "sec", "https://adm/cb")

	id, err := c.ExchangeAndVerify(context.Background(), "code-1", "the-nonce", "verifier-xyz")
	if err != nil {
		t.Fatalf("ExchangeAndVerify: %v", err)
	}
	if id.Email != "u@test.io" || !id.EmailVerified || id.Subject != "s-1" {
		t.Fatalf("identity: %+v", id)
	}
}

func TestOIDCClient_ExchangeAndVerify_FailClosed(t *testing.T) {
	p := newFakeProvider(t)
	p.nonceToEmbed = "the-nonce"
	c, _ := NewOIDCClient(context.Background(), p.server.URL, p.clientID, "sec", "https://adm/cb")

	cases := []struct {
		name  string
		mut   func()
		nonce string
	}{
		{"nonce mismatch", func() {}, "a-different-nonce"},
		{"wrong audience", func() { p.wrongAudience = true }, "the-nonce"},
		{"wrong issuer", func() { p.foreignIssuer = true }, "the-nonce"},
		{"expired token", func() { p.expirySkewSecs = -3600 }, "the-nonce"},
		{"no id_token in response", func() { p.extraIDTokenErr = true }, "the-nonce"},
		{"no email claim", func() { p.stripEmail = true }, "the-nonce"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.mut()
			defer func() {
				p.wrongAudience, p.foreignIssuer, p.expirySkewSecs = false, false, 0
				p.extraIDTokenErr, p.stripEmail = false, false
			}()
			if _, err := c.ExchangeAndVerify(context.Background(), "c", tc.nonce, "v"); err == nil {
				t.Fatal("verification must fail closed")
			}
		})
	}
}

func TestOIDCClient_IssuerValidation(t *testing.T) {
	ctx := context.Background()
	// Partial tuple fails.
	if _, err := NewOIDCClient(ctx, "https://idp", "cid", "sec", ""); err == nil {
		t.Fatal("partial tuple must be rejected")
	}
	// Unparsable issuer fails.
	if _, err := NewOIDCClient(ctx, "not a url", "cid", "sec", "r"); err == nil {
		t.Fatal("garbage issuer must be rejected")
	}
	// Non-https non-loopback fails.
	if _, err := NewOIDCClient(ctx, "http://idp.example.com", "cid", "sec", "r"); err == nil {
		t.Fatal("plain http non-loopback issuer must be rejected")
	}
	// Unreachable https issuer fails (nothing listens there).
	if _, err := NewOIDCClient(ctx, "https://127.0.0.1:1", "cid", "sec", "r"); err == nil {
		t.Fatal("unreachable issuer must fail discovery")
	}
}

func TestOIDCFlow_PKCEAndCookie(t *testing.T) {
	f, err := NewOIDCFlow()
	if err != nil {
		t.Fatal(err)
	}
	chal := f.PKCEChallengeS256()
	if chal == f.PKCEVerifier || len(chal) != 43 {
		t.Fatalf("S256 challenge shape wrong: %q", chal)
	}
	c, err := NewOIDCFlowCookie(f)
	if err != nil {
		t.Fatal(err)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 600 {
		t.Fatalf("cookie flags: %+v", c)
	}
	back, err := ParseOIDCFlowCookie(c.Value)
	if err != nil || back != f {
		t.Fatalf("round-trip: %v %+v", err, back)
	}
	if _, err := ParseOIDCFlowCookie(fmt.Sprintf("x%s", c.Value)); err == nil {
		t.Fatal("malformed cookie must fail")
	}
	if _, err := ParseOIDCFlowCookie(base64.RawURLEncoding.EncodeToString([]byte("not json"))); err == nil {
		t.Fatal("non-JSON cookie must fail")
	}
	if ClearOIDCFlowCookie().MaxAge != -1 {
		t.Fatal("clear cookie must expire")
	}
}
