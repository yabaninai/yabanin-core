package provider

// Tests for the Vertex ADC credential chain: fail-closed resolution order,
// once-per-adapter source pinning, secret-free errors, per-binding token
// cache, refresh alignment (skew window, short-TTL parity) and the bounded
// 429 cooldown.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// genVertexRSAKeyPEM generates a throwaway RSA key in the PKCS#8 PEM form
// Google key files use.
func genVertexRSAKeyPEM(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func vertexRSAPrivateKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// writeVertexSAKeyFile writes a service_account ADC key file whose token_uri
// points at tokenServerURL.
func writeVertexSAKeyFile(t *testing.T, tokenServerURL string) (path, clientEmail string, key *rsa.PrivateKey) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "sa-key.json")
	path, clientEmail, key = writeVertexSAKeyFileAt(t, path, tokenServerURL)
	return path, clientEmail, key
}

// writeVertexSAKeyFileAt writes a service_account ADC key file at an exact
// path (for tests that must control the file lifecycle, e.g. late mounts).
func writeVertexSAKeyFileAt(t *testing.T, path, tokenServerURL string) (pathOut, clientEmail string, key *rsa.PrivateKey) {
	t.Helper()
	key = genVertexRSAKeyPEM(t)
	clientEmail = "vertex-test-sa@api-proj-0001.iam.gserviceaccount.com"
	file := map[string]string{
		"type":         "service_account",
		"client_email": clientEmail,
		"private_key":  vertexRSAPrivateKeyPEM(t, key),
		"token_uri":    tokenServerURL,
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal SA key: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write SA key file: %v", err)
	}
	return path, clientEmail, key
}

func writeVertexUserKeyFile(t *testing.T, dir string) {
	t.Helper()
	file := map[string]string{
		"type":          "authorized_user",
		"client_id":     "test-user-client.apps.googleusercontent.com",
		"client_secret": "test-user-secret",
		"refresh_token": "test-refresh-token-1",
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal user key: %v", err)
	}
	path := filepath.Join(dir, vertexWellKnownRelPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir gcloud dir: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write well-known file: %v", err)
	}
}

// vertexSwapHome overrides the user-home seam for the well-known file step.
func vertexSwapHome(t *testing.T, dir string, err error) {
	t.Helper()
	old := osUserHomeDir
	osUserHomeDir = func() (string, error) { return dir, err }
	t.Cleanup(func() { osUserHomeDir = old })
}

// decodeVertexJWTPart decodes one base64url JWT segment into a map.
func decodeVertexJWTPart(t *testing.T, token string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatalf("decode JWT segment %d: %v", index, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal JWT segment %d: %v", index, err)
	}
	return m
}

// vertexTokenRecorder is a token-endpoint test double with hit counting and
// form capture.
type vertexTokenRecorder struct {
	srv       *httptest.Server
	hits      atomic.Int64
	lastForm  atomic.Value // url.Values
	status    atomic.Int64 // 0 → 200
	retryAft  atomic.Value // string Retry-After header
	delay     atomic.Int64 // response delay ms
	bodyToken atomic.Value // string access token to hand out
	shortTTL  atomic.Bool  // hand out expires_in=60 (inside the refresh skew)
}

func newVertexTokenRecorder(t *testing.T) *vertexTokenRecorder {
	t.Helper()
	rec := &vertexTokenRecorder{}
	rec.bodyToken.Store("VT-1")
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.hits.Add(1)
		if d := rec.delay.Load(); d > 0 {
			time.Sleep(time.Duration(d) * time.Millisecond)
		}
		_ = r.ParseForm()
		rec.lastForm.Store(r.PostForm)
		if status := rec.status.Load(); status != 0 {
			if ra := rec.retryAft.Load(); ra != nil && ra.(string) != "" {
				w.Header().Set("Retry-After", ra.(string))
			}
			w.WriteHeader(int(status))
			return
		}
		expiresIn := 3600
		if rec.shortTTL.Load() {
			expiresIn = 60
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": rec.bodyToken.Load().(string),
			"expires_in":   expiresIn,
		})
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

func (r *vertexTokenRecorder) form(t *testing.T) url.Values {
	t.Helper()
	v, ok := r.lastForm.Load().(url.Values)
	if !ok {
		t.Fatal("no token form captured")
	}
	return v
}

func plainVertexADC(tokenSrv *httptest.Server) *vertexADC {
	adc := newVertexADC(nil)
	adc.httpClient = tokenSrv.Client() // loopback test double, no SSRF guard
	return adc
}

// TestVertexRetryAfterSeconds pins the Retry-After parser: numeric deltas,
// clamp at the cooldown max, garbage → 0 (default cooldown).
func TestVertexRetryAfterSeconds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want time.Duration
	}{
		{"5", 5 * time.Second},
		{"60", 60 * time.Second},
		{"61", 60 * time.Second},             // clamped
		{"99999999999999", 60 * time.Second}, // clamped, no overflow
		{"abc", 0},
		{"", 0},
		{"-3", 0},
		{"0", 0},
		{" 7 ", 7 * time.Second}, // surrounding whitespace trimmed (azure precedent)
	}
	for _, tc := range cases {
		if got := vertexRetryAfterSeconds(tc.in); got != tc.want {
			t.Errorf("vertexRetryAfterSeconds(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestVertexADCChain_EnvServiceAccountWins pins step 1: an explicit
// GOOGLE_APPLICATION_CREDENTIALS service-account file is used and a
// simultaneously present gcloud well-known file is never consulted.
func TestVertexADCChain_EnvServiceAccountWins(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	keyPath, clientEmail, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)

	// A competing well-known file with its own endpoint must be ignored.
	home := t.TempDir()
	writeVertexUserKeyFile(t, home)
	vertexSwapHome(t, home, nil)
	userSrv := newVertexTokenRecorder(t)

	adc := plainVertexADC(tokenSrv.srv)
	adc.oauthTokenURL = userSrv.srv.URL // would be used if chain fell through

	tok, err := adc.token(VertexCredentials{Project: "api-proj-0001", Location: "us-central1"})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok != "VT-1" {
		t.Fatalf("token = %q", tok)
	}
	if tokenSrv.hits.Load() != 1 || userSrv.hits.Load() != 0 {
		t.Fatalf("hits SA=%d user=%d, want SA=1 user=0 (env file wins, no fallthrough)",
			tokenSrv.hits.Load(), userSrv.hits.Load())
	}

	// JWT-bearer grant shape: signed by the key file's SA.
	form := tokenSrv.form(t)
	if got := form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Fatalf("grant_type = %q", got)
	}
	assertion := form.Get("assertion")
	header := decodeVertexJWTPart(t, assertion, 0)
	if header["alg"] != "RS256" {
		t.Fatalf("JWT alg = %v, want RS256", header["alg"])
	}
	claims := decodeVertexJWTPart(t, assertion, 1)
	if claims["iss"] != clientEmail {
		t.Fatalf("JWT iss = %v, want %q", claims["iss"], clientEmail)
	}
	if claims["scope"] != vertexCloudPlatformScope {
		t.Fatalf("JWT scope = %v", claims["scope"])
	}
	if claims["aud"] != tokenSrv.srv.URL {
		t.Fatalf("JWT aud = %v, want the token endpoint", claims["aud"])
	}
}

// TestVertexADCChain_EnvSetButBroken_NoFallback pins the packet negative:
// an explicitly configured but broken credential source NEVER falls through
// to the weaker well-known user credential.
func TestVertexADCChain_EnvSetButBroken_NoFallback(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing-key.json"))

	home := t.TempDir()
	writeVertexUserKeyFile(t, home)
	vertexSwapHome(t, home, nil)
	userSrv := newVertexTokenRecorder(t)

	adc := plainVertexADC(tokenSrv.srv)
	adc.oauthTokenURL = userSrv.srv.URL

	_, err := adc.token(VertexCredentials{Project: "api-proj-0001", Location: "us-central1"})
	if err == nil {
		t.Fatal("broken GOOGLE_APPLICATION_CREDENTIALS must fail hard")
	}
	if !strings.Contains(err.Error(), "GOOGLE_APPLICATION_CREDENTIALS is set but unusable") ||
		!strings.Contains(err.Error(), "no fallback") {
		t.Fatalf("error = %v, want explicit no-fallback message", err)
	}
	if userSrv.hits.Load() != 0 {
		t.Fatalf("user token endpoint hit %d times; broken env file must not fall through", userSrv.hits.Load())
	}
}

// TestVertexADCChain_WellKnownAuthorizedUser pins step 2: without env, the
// gcloud ADC well-known authorized_user file performs the refresh-token
// grant at the fixed Google endpoint (seamed in tests) and caches.
func TestVertexADCChain_WellKnownAuthorizedUser(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	home := t.TempDir()
	writeVertexUserKeyFile(t, home)
	vertexSwapHome(t, home, nil)

	adc := plainVertexADC(tokenSrv.srv)
	adc.oauthTokenURL = tokenSrv.srv.URL // prod: https://oauth2.googleapis.com/token

	tok, err := adc.token(VertexCredentials{Project: "api-proj-0001", Location: "europe-west4"})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok != "VT-1" {
		t.Fatalf("token = %q", tok)
	}
	form := tokenSrv.form(t)
	if form.Get("grant_type") != "refresh_token" ||
		form.Get("refresh_token") != "test-refresh-token-1" ||
		form.Get("client_id") != "test-user-client.apps.googleusercontent.com" ||
		form.Get("client_secret") != "test-user-secret" {
		t.Fatalf("refresh grant form = %v", form)
	}

	// Cache: the second call must not re-exchange.
	if _, err := adc.token(VertexCredentials{Project: "api-proj-0001", Location: "europe-west4"}); err != nil {
		t.Fatalf("second token: %v", err)
	}
	if tokenSrv.hits.Load() != 1 {
		t.Fatalf("token endpoint hits = %d, want 1 (cache)", tokenSrv.hits.Load())
	}
}

// TestVertexADCChain_WellKnownBroken_NoMetadataFallback pins step 2's hard
// error: a PRESENT but corrupt well-known file must not silently go keyless
// into the metadata server.
func TestVertexADCChain_WellKnownBroken_NoMetadataFallback(t *testing.T) {
	metadataSrv := newVertexTokenRecorder(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	home := t.TempDir()
	path := filepath.Join(home, vertexWellKnownRelPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	vertexSwapHome(t, home, nil)

	adc := newVertexADC(nil)
	adc.metadataURL = metadataSrv.srv.URL
	adc.metadataClient = metadataSrv.srv.Client()

	_, err := adc.token(VertexCredentials{Project: "api-proj-0001", Location: "us-central1"})
	if err == nil {
		t.Fatal("corrupt well-known file must fail hard")
	}
	if !strings.Contains(err.Error(), "well-known file is present but unusable") {
		t.Fatalf("error = %v, want well-known hard error", err)
	}
	if metadataSrv.hits.Load() != 0 {
		t.Fatalf("metadata server hit %d times; corrupt well-known file must not fall through", metadataSrv.hits.Load())
	}
}

// TestVertexADCChain_MetadataFallback pins step 3: with no env file and no
// home config, the GCE metadata server is the credential — queried at the
// documented path with Metadata-Flavor: Google.
func TestVertexADCChain_MetadataFallback(t *testing.T) {
	metadataSrv := newVertexTokenRecorder(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	vertexSwapHome(t, "", errors.New("no home dir in test"))

	adc := newVertexADC(nil)
	adc.metadataURL = metadataSrv.srv.URL
	adc.metadataClient = metadataSrv.srv.Client()

	tok, err := adc.token(VertexCredentials{Project: "api-proj-0001", Location: "asia-southeast1"})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok != "VT-1" {
		t.Fatalf("token = %q", tok)
	}
	// Metadata identity is shared; project/location binding still applies
	// to the CACHE key, so a second binding reuses the token exchange only
	// once resolved — assert single exchange + cache hit.
	if _, err := adc.token(VertexCredentials{Project: "api-proj-0001", Location: "asia-southeast1"}); err != nil {
		t.Fatalf("second token: %v", err)
	}
	if metadataSrv.hits.Load() != 1 {
		t.Fatalf("metadata hits = %d, want 1", metadataSrv.hits.Load())
	}
}

// TestVertexADC429Cooldown pins the bounded cooldown: a 429 from the token
// endpoint fails closed immediately for the binding without further HTTP
// (no sleeping in the request path).
func TestVertexADC429Cooldown(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	tokenSrv.status.Store(http.StatusTooManyRequests)
	tokenSrv.retryAft.Store("60")

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	home := t.TempDir()
	writeVertexUserKeyFile(t, home)
	vertexSwapHome(t, home, nil)

	adc := plainVertexADC(tokenSrv.srv)
	adc.oauthTokenURL = tokenSrv.srv.URL

	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-east4"}
	_, err := adc.token(creds)
	if err == nil || !strings.Contains(err.Error(), "rate-limited") {
		t.Fatalf("first token error = %v, want rate-limited", err)
	}
	// Immediate retry: cooldown fail-fast, NO second HTTP exchange.
	_, err = adc.token(creds)
	if err == nil || !strings.Contains(err.Error(), "retry allowed in") {
		t.Fatalf("second token error = %v, want cooldown fail-fast", err)
	}
	if tokenSrv.hits.Load() != 1 {
		t.Fatalf("token endpoint hits = %d, want 1 (cooldown suppresses retries)", tokenSrv.hits.Load())
	}
}

// TestVertexADCUnsupportedKeyType fails closed on unknown ADC file types.
func TestVertexADCUnsupportedKeyType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(path, []byte(`{"type":"external_account"}`), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)

	adc := newVertexADC(nil)
	_, err := adc.token(VertexCredentials{Project: "api-proj-0001", Location: "us-central1"})
	if err == nil || !strings.Contains(err.Error(), "unsupported key file type") {
		t.Fatalf("error = %v, want unsupported key file type", err)
	}
}

// TestVertexADCTokenEndpointHostPinned fails closed when a key file's
// token_uri is not an http(s) URL (defense in depth behind the guarded
// transport).
func TestVertexADCTokenEndpointHostPinned(t *testing.T) {
	// Structurally complete except token_uri: field-presence validation
	// runs first by design, so the scheme rejection needs a real key body.
	file := map[string]string{ //nolint:gosec // G101: synthetic ADC fixture, not a credential
		"type":         "service_account",
		"client_email": "x@y.iam.gserviceaccount.com",
		"private_key":  vertexRSAPrivateKeyPEM(t, genVertexRSAKeyPEM(t)),
		"token_uri":    "ftp://evil.example/token",
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)

	adc := newVertexADC(nil)
	_, err = adc.token(VertexCredentials{Project: "api-proj-0001", Location: "us-central1"})
	if err == nil || !strings.Contains(err.Error(), "token_uri must be an http(s) URL") {
		t.Fatalf("error = %v, want token_uri scheme rejection", err)
	}
}

// vertexSoleCacheKey returns the single binding key in the ADC token cache
// (tests populate exactly one) so expiry forcing stays independent of the
// identity-string format.
func vertexSoleCacheKey(t *testing.T, adc *vertexADC) string {
	t.Helper()
	adc.mu.Lock()
	defer adc.mu.Unlock()
	if len(adc.tokens) != 1 {
		t.Fatalf("token cache has %d entries, want exactly 1", len(adc.tokens))
	}
	for k := range adc.tokens {
		return k
	}
	return "" // unreachable
}

// TestVertexADCRefresh_OnExpiry pins the refresh alignment: a cached token
// is served without an exchange only while it sits OUTSIDE the refresh
// skew; inside the skew window and after expiry the next request performs
// exactly one exchange and serves the NEW token.
func TestVertexADCRefresh_OnExpiry(t *testing.T) {
	cases := []struct {
		name       string
		forceExp   time.Duration // cached tokenExp = now+forceExp before the second call
		wantHits   int64
		wantSecond string
	}{
		{"fresh token is served from cache", 30 * time.Minute, 1, "VT-1"},
		{"inside skew window refreshes once", 2 * time.Minute, 2, "VT-2"},
		{"expired token refreshes once", -time.Minute, 2, "VT-2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenSrv := newVertexTokenRecorder(t)
			keyPath, _, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
			adc := plainVertexADC(tokenSrv.srv)
			creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

			tok, err := adc.token(creds)
			if err != nil || tok != "VT-1" {
				t.Fatalf("first token = %q, err %v; want VT-1", tok, err)
			}

			// Force the binding's cached token into the expiry state under
			// test (the first exchange set ~1h — always outside the skew).
			key := vertexSoleCacheKey(t, adc)
			adc.mu.Lock()
			adc.tokens[key] = vertexToken{accessToken: "VT-1", tokenExp: time.Now().Add(tc.forceExp)}
			adc.mu.Unlock()
			tokenSrv.bodyToken.Store("VT-2")

			tok, err = adc.token(creds)
			if err != nil {
				t.Fatalf("second token: %v", err)
			}
			if tok != tc.wantSecond {
				t.Fatalf("second token = %q, want %q", tok, tc.wantSecond)
			}
			if hits := tokenSrv.hits.Load(); hits != tc.wantHits {
				t.Fatalf("token endpoint hits = %d, want %d", hits, tc.wantHits)
			}
		})
	}
}

// TestVertexADCShortTTLToken_NeverServedInsideSkew pins the azure-parity
// refresh rule: a token whose expires_in does not exceed the refresh skew
// (5 min) is NEVER treated as fresh — every request re-exchanges instead of
// riding a token that is effectively already stale.
func TestVertexADCShortTTLToken_NeverServedInsideSkew(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	tokenSrv.shortTTL.Store(true)
	keyPath, _, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	adc := plainVertexADC(tokenSrv.srv)
	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

	for i := 1; i <= 2; i++ {
		tok, err := adc.token(creds)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if tok != "VT-1" {
			t.Fatalf("call %d token = %q", i, tok)
		}
	}
	if hits := tokenSrv.hits.Load(); hits != 2 {
		t.Fatalf("token exchanges = %d, want 2 (a TTL inside the skew window must never be reused)", hits)
	}

	// The stored entry still carries the short TTL verbatim — the adapter
	// never inflates a provider-reported lifetime.
	key := vertexSoleCacheKey(t, adc)
	adc.mu.Lock()
	tok := adc.tokens[key]
	adc.mu.Unlock()
	if d := time.Until(tok.tokenExp); d <= 0 || d > time.Minute {
		t.Fatalf("cached token TTL = %s, want (0,1m] — provider-reported expiry kept", d)
	}
}

// TestVertexADCSourcePinned_AcrossCacheHits pins the once-per-adapter
// resolution: after the first walk, token cache hits perform NO
// credential-file I/O — deleting the key file must not fail (or re-resolve)
// a request that still holds a fresh token.
func TestVertexADCSourcePinned_AcrossCacheHits(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	keyPath, _, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	adc := plainVertexADC(tokenSrv.srv)
	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

	if _, err := adc.token(creds); err != nil {
		t.Fatalf("first token: %v", err)
	}
	adc.mu.Lock()
	pinned := adc.pinned
	adc.mu.Unlock()
	if !pinned {
		t.Fatal("source must be pinned after the first successful walk")
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove key file: %v", err)
	}

	tok, err := adc.token(creds)
	if err != nil {
		t.Fatalf("cache hit after key-file removal: %v", err)
	}
	if tok != "VT-1" {
		t.Fatalf("token = %q, want the cached VT-1", tok)
	}
	if hits := tokenSrv.hits.Load(); hits != 1 {
		t.Fatalf("token endpoint hits = %d, want 1 (cache hit, no re-exchange)", hits)
	}
}

// TestVertexADCResolutionFailure_NotPinned pins the retry semantics of the
// pinned-source design: a FAILED chain walk is never pinned — the next
// request re-walks fail-closed, so a credential file that appears after the
// first (too-early) request recovers without an adapter restart. No weaker
// chain step may fill in for the explicitly configured source (packet
// negative) on either attempt.
func TestVertexADCResolutionFailure_NotPinned(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	keyPath := filepath.Join(t.TempDir(), "late-key.json")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)

	home := t.TempDir()
	writeVertexUserKeyFile(t, home)
	vertexSwapHome(t, home, nil)
	userSrv := newVertexTokenRecorder(t)

	adc := plainVertexADC(tokenSrv.srv)
	adc.oauthTokenURL = userSrv.srv.URL // must never be consulted (no fallback)
	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

	if _, err := adc.token(creds); err == nil ||
		!strings.Contains(err.Error(), "GOOGLE_APPLICATION_CREDENTIALS is set but unusable") {
		t.Fatalf("first token error = %v, want hard no-fallback resolution failure", err)
	}

	// The credential appears (volume mount, provisioning completes); the
	// SAME adapter must recover on the next request.
	writeVertexSAKeyFileAt(t, keyPath, tokenSrv.srv.URL)
	tok, err := adc.token(creds)
	if err != nil {
		t.Fatalf("second token: %v", err)
	}
	if tok != "VT-1" {
		t.Fatalf("token = %q, want VT-1", tok)
	}
	if userSrv.hits.Load() != 0 {
		t.Fatalf("user token endpoint hit %d times; failed resolution must not fall through", userSrv.hits.Load())
	}
}
