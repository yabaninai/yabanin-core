package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// --- test scaffolding ---------------------------------------------------------

// jwkPair is one signing key plus its JWKS form.
type jwkPair struct {
	priv jose.JSONWebKey // private (signing)
	pub  jose.JSONWebKey // public (JWKS)
}

func mustRSAJWK(t *testing.T, kid string) jwkPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	priv := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
	return jwkPair{priv: priv, pub: priv.Public()}
}

func mustESJWK(t *testing.T, kid string) jwkPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}
	priv := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
	return jwkPair{priv: priv, pub: priv.Public()}
}

// jwksServer serves the public halves of a mutable key set.
type jwksServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	keys    []jose.JSONWebKey
	fetches atomic.Int64
	// gate optionally blocks fetches once its free passes are used up;
	// closed on release (async non-blocking test). Nil = never block.
	gate *jwksGate
}

// jwksGate admits `free` fetches, then blocks each fetch until release is
// closed. The channel (not a dead-end receive) keeps httptest.Server.Close
// from hanging on parked handlers.
type jwksGate struct {
	free    atomic.Int64
	release chan struct{}
}

func (g *jwksGate) enter() {
	if g == nil {
		return
	}
	if g.free.Add(-1) >= 0 {
		return
	}
	<-g.release
}

func newJWKSServer(t *testing.T, keys ...jwkPair) *jwksServer {
	t.Helper()
	s := &jwksServer{}
	for _, k := range keys {
		s.keys = append(s.keys, k.pub)
	}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.gate.enter()
		s.mu.Lock()
		set := jose.JSONWebKeySet{Keys: append([]jose.JSONWebKey(nil), s.keys...)}
		s.mu.Unlock()
		s.fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *jwksServer) setKeys(keys ...jwkPair) {
	s.mu.Lock()
	s.keys = s.keys[:0]
	for _, k := range keys {
		s.keys = append(s.keys, k.pub)
	}
	s.mu.Unlock()
}

func (s *jwksServer) fetchCount() int64 { return s.fetches.Load() }

// signToken serializes one signed compact JWT with the given claims.
func signToken(t *testing.T, k jwkPair, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(k.priv.Algorithm), Key: k.priv.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.priv.KeyID))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func baseClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":    "https://idp.example",
		"sub":    "svc-account-1",
		"aud":    "yabanin-gateway",
		"iat":    now.Unix(),
		"nbf":    now.Add(-time.Minute).Unix(),
		"exp":    now.Add(time.Hour).Unix(),
		"org_id": "org-42",
	}
}

func newTestJWTAuth(t *testing.T, srv *jwksServer, mutate func(*JWTWiring)) *JWTAuthenticator {
	t.Helper()
	w := JWTWiring{
		JWKSURL:       srv.srv.URL,
		Issuer:        "https://idp.example",
		Audience:      "yabanin-gateway",
		OrgClaim:      "org_id",
		KeyLabelClaim: "key_labels",
	}
	if mutate != nil {
		mutate(&w)
	}
	a := NewJWTAuthenticator(w, nil)
	if a == nil {
		t.Fatal("authenticator nil")
	}
	// Deterministic refresh timing; the jitter path has its own assertions.
	a.cache.jitter = func(int) int { return 0 }
	return a
}

func jwtMiddleware(a *JWTAuthenticator) *AuthMiddleware {
	mw := NewAuthMiddleware(config.Gateway{AuthMode: "header"}, nil)
	mw.SetJWTAuthenticator(a)
	return mw
}

func jwtValidations(outcome string) float64 {
	return testutil.ToFloat64(metrics.GatewayJWTValidationsTotal.WithLabelValues(outcome))
}

func jwtErrors(reason string) float64 {
	return testutil.ToFloat64(metrics.GatewayJWTErrorsTotal.WithLabelValues(reason))
}

// --- authenticate-level tests ---------------------------------------------------

func TestJWTAuthenticateRS256HappyPath(t *testing.T) {
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	auth := newTestJWTAuth(t, srv, nil)

	p, err := auth.Authenticate(context.Background(), signToken(t, k, baseClaims()))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p.OrgID != "org-42" || p.Subject != "svc-account-1" {
		t.Fatalf("principal: %+v", p)
	}
	if n := jwtValidations("ok"); n < 1 {
		t.Fatalf("validations(ok) = %v, want >= 1", n)
	}
}

func TestJWTAuthenticateES256HappyPath(t *testing.T) {
	k := mustESJWK(t, "ec1")
	srv := newJWKSServer(t, k)
	auth := newTestJWTAuth(t, srv, nil)

	p, err := auth.Authenticate(context.Background(), signToken(t, k, baseClaims()))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p.OrgID != "org-42" {
		t.Fatalf("principal: %+v", p)
	}
}

func TestJWTRejections(t *testing.T) {
	k := mustRSAJWK(t, "k1")
	// Same kid, different key material → kid resolves but the signature
	// cannot verify.
	other := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	auth := newTestJWTAuth(t, srv, nil)

	mut := func(f func(map[string]any)) map[string]any {
		c := baseClaims()
		f(c)
		return c
	}
	cases := []struct {
		name   string
		token  string
		reason string
	}{
		{"expired", signToken(t, k, mut(func(c map[string]any) { c["exp"] = time.Now().Add(-2 * time.Minute).Unix() })), "expired"},
		{"nbf future", signToken(t, k, mut(func(c map[string]any) { c["nbf"] = time.Now().Add(2 * time.Minute).Unix() })), "not_yet_valid"},
		{"wrong aud", signToken(t, k, mut(func(c map[string]any) { c["aud"] = "other-service" })), "audience"},
		{"wrong iss", signToken(t, k, mut(func(c map[string]any) { c["iss"] = "https://evil.example" })), "issuer"},
		{"missing exp", signToken(t, k, mut(func(c map[string]any) { delete(c, "exp") })), "missing_exp"},
		{"missing org claim", signToken(t, k, mut(func(c map[string]any) { delete(c, "org_id") })), "org_claim"},
		{"blank org claim", signToken(t, k, mut(func(c map[string]any) { c["org_id"] = "  " })), "org_claim"},
		{"signed by same-kid other key", signToken(t, other, baseClaims()), "signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := auth.Authenticate(context.Background(), tc.token)
			ae, ok := err.(*jwtAuthError)
			if !ok {
				t.Fatalf("want jwtAuthError, got %v", err)
			}
			if ae.status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", ae.status)
			}
			if ae.reason != tc.reason {
				t.Fatalf("reason = %q, want %q", ae.reason, tc.reason)
			}
			if n := jwtErrors(tc.reason); n < 1 {
				t.Fatalf("errors(%s) = %v, want >= 1", tc.reason, n)
			}
		})
	}
}

func TestJWTAlgAllowlist(t *testing.T) {
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	auth := newTestJWTAuth(t, srv, nil)

	t.Run("none alg", func(t *testing.T) {
		b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
		hdr, _ := json.Marshal(map[string]string{"alg": "none", "kid": "k1"})
		body, _ := json.Marshal(baseClaims())
		// Three-segment form with a dummy signature: the alg allow-list
		// rejects "none" before any key is consulted.
		tok := b64(string(hdr)) + "." + b64(string(body)) + "." + b64("x")
		_, err := auth.Authenticate(context.Background(), tok)
		ae, ok := err.(*jwtAuthError)
		if !ok || ae.reason != "alg" || ae.status != http.StatusUnauthorized {
			t.Fatalf("want alg 401, got %v", err)
		}
	})

	t.Run("HS256 confusion with planted RSA public key", func(t *testing.T) {
		// Attacker signs an HMAC token using the PUBLIC RSA key as the HMAC
		// secret under the victim kid. The allow-list must reject it before
		// any key material is consulted.
		pubBytes, err := json.Marshal(k.pub)
		if err != nil {
			t.Fatal(err)
		}
		plainSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: pubBytes},
			(&jose.SignerOptions{}).WithHeader("kid", "k1"))
		if err != nil {
			t.Fatal(err)
		}
		tok, err := jwt.Signed(plainSigner).Claims(baseClaims()).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		_, err = auth.Authenticate(context.Background(), tok)
		ae, ok := err.(*jwtAuthError)
		if !ok || ae.reason != "alg" || ae.status != http.StatusUnauthorized {
			t.Fatalf("want alg 401, got %v", err)
		}
	})

	t.Run("ES256 token against an RSA kid", func(t *testing.T) {
		// The EC key claims the RSA key's kid; only the RSA key is served.
		// Key-type filtering must leave no verification candidate.
		ec := mustESJWK(t, "k1")
		_, err := auth.Authenticate(context.Background(), signToken(t, ec, baseClaims()))
		ae, ok := err.(*jwtAuthError)
		if !ok || ae.reason != "signature" || ae.status != http.StatusUnauthorized {
			t.Fatalf("want signature 401, got %v", err)
		}
	})
}

func TestJWKSKidCollisionBothKeysAttempted(t *testing.T) {
	k1 := mustRSAJWK(t, "dup")
	k2 := mustRSAJWK(t, "dup")
	srv := newJWKSServer(t, k1, k2)
	auth := newTestJWTAuth(t, srv, nil)
	for i, k := range []jwkPair{k1, k2} {
		if _, err := auth.Authenticate(context.Background(), signToken(t, k, baseClaims())); err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
	}
}

func TestJWTKeyLabelClaimShapes(t *testing.T) {
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	auth := newTestJWTAuth(t, srv, nil)

	cases := []struct {
		name  string
		claim any
		want  []string
	}{
		{"string", "prod", []string{"prod"}},
		{"array", []any{"prod", "team-a"}, []string{"prod", "team-a"}},
		{"object", map[string]any{"env": "prod"}, []string{"env"}},
		{"malformed ignored", []any{1, 2}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseClaims()
			c["key_labels"] = tc.claim
			p, err := auth.Authenticate(context.Background(), signToken(t, k, c))
			if err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			if tc.want == nil {
				if len(p.KeyLabels) != 0 {
					t.Fatalf("labels = %v, want none", p.KeyLabels)
				}
				return
			}
			for _, want := range tc.want {
				if _, ok := p.KeyLabels[want]; !ok {
					t.Fatalf("labels = %v, missing %q", p.KeyLabels, want)
				}
			}
		})
	}
}

// --- JWKS cache behaviour -------------------------------------------------------

func TestJWKSRotation(t *testing.T) {
	k1 := mustRSAJWK(t, "k1")
	k2 := mustRSAJWK(t, "k2")
	srv := newJWKSServer(t, k1)
	auth := newTestJWTAuth(t, srv, nil)
	ctx := context.Background()

	tok1 := signToken(t, k1, baseClaims())
	if _, err := auth.Authenticate(ctx, tok1); err != nil {
		t.Fatalf("token1: %v", err)
	}
	fetchesAfterFirst := srv.fetchCount()

	// Rotation: k2 joins the live set (several keys alive at once). The new
	// kid is a cache miss → one inline fetch → accepted.
	srv.setKeys(k1, k2)
	tok2 := signToken(t, k2, baseClaims())
	if _, err := auth.Authenticate(ctx, tok2); err != nil {
		t.Fatalf("token2 after rotation: %v", err)
	}
	if got := srv.fetchCount(); got != fetchesAfterFirst+1 {
		t.Fatalf("fetches = %d, want %d (one inline miss fetch)", got, fetchesAfterFirst+1)
	}

	// The old token stays valid while its key is still served.
	if _, err := auth.Authenticate(ctx, tok1); err != nil {
		t.Fatalf("token1 after rotation: %v", err)
	}

	// Eviction: the refreshed set drops k1 → old token fails closed, new
	// token keeps working.
	srv.setKeys(k2)
	before := srv.fetchCount()
	if _, err := auth.Authenticate(ctx, tok1); err != nil {
		t.Fatalf("token1 before eviction: %v", err)
	}
	if err := auth.cache.refreshSync(ctx); err != nil {
		t.Fatalf("refreshSync: %v", err)
	}
	if _, err := auth.Authenticate(ctx, tok1); err == nil {
		t.Fatal("evicted token accepted")
	} else {
		ae, ok := err.(*jwtAuthError)
		if !ok || ae.reason != "unknown_kid" {
			t.Fatalf("want unknown_kid, got %v", err)
		}
	}
	if _, err := auth.Authenticate(ctx, tok2); err != nil {
		t.Fatalf("token2 after eviction: %v", err)
	}
	// refreshSync + one kid-miss fetch for the evicted token.
	if got := srv.fetchCount(); got != before+2 {
		t.Fatalf("fetches = %d, want %d", got, before+2)
	}
}

func TestJWKSDownFailClosed(t *testing.T) {
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	auth := newTestJWTAuth(t, srv, nil)
	ctx := context.Background()
	tok := signToken(t, k, baseClaims())

	// Warm the cache, then kill the endpoint.
	if _, err := auth.Authenticate(ctx, tok); err != nil {
		t.Fatalf("warm: %v", err)
	}
	srv.srv.Close()

	// Known kid: the (stale) cache serves — not a 503.
	if _, err := auth.Authenticate(ctx, tok); err != nil {
		t.Fatalf("stale serve: %v", err)
	}

	// Unknown kid with a warm but incomplete cache → 401 (the cache is the
	// source of truth; only an EMPTY cache yields 503).
	unknown := mustRSAJWK(t, "never-seen")
	_, err := auth.Authenticate(ctx, signToken(t, unknown, baseClaims()))
	ae, ok := err.(*jwtAuthError)
	if !ok || ae.status != http.StatusUnauthorized || ae.reason != "unknown_kid" {
		t.Fatalf("want unknown_kid 401, got %v", err)
	}

	// Past the max-stale bound the cache stops serving → fail closed 503.
	auth.cache.mu.Lock()
	auth.cache.fetchedAt = auth.cache.now().Add(-auth.cache.maxStale - time.Minute)
	auth.cache.mu.Unlock()
	_, err = auth.Authenticate(ctx, tok)
	ae, ok = err.(*jwtAuthError)
	if !ok || ae.status != http.StatusServiceUnavailable || ae.reason != "jwks_unavailable" {
		t.Fatalf("want jwks_unavailable 503, got %v", err)
	}
}

func TestJWKSDownEmptyCache503(t *testing.T) {
	srv := newJWKSServer(t)
	auth := newTestJWTAuth(t, srv, nil)
	srv.srv.Close() // never reachable

	k := mustRSAJWK(t, "k1") // never fetched
	_, err := auth.Authenticate(context.Background(), signToken(t, k, baseClaims()))
	ae, ok := err.(*jwtAuthError)
	if !ok || ae.status != http.StatusServiceUnavailable || ae.reason != "jwks_unavailable" {
		t.Fatalf("want jwks_unavailable 503, got %v", err)
	}
}

func TestJWKSAsyncRefreshDoesNotBlockHotPath(t *testing.T) {
	k1 := mustRSAJWK(t, "k1")
	k2 := mustRSAJWK(t, "k2")
	srv := newJWKSServer(t, k1)
	// Admit exactly one (the warm-up) fetch; later fetches block until the
	// gate is released — a synchronous refresh would stall the lookup.
	srv.gate = &jwksGate{release: make(chan struct{})}
	srv.gate.free.Store(1)
	auth := newTestJWTAuth(t, srv, nil)
	ctx := context.Background()

	if _, err := auth.Authenticate(ctx, signToken(t, k1, baseClaims())); err != nil {
		t.Fatalf("warm: %v", err)
	}
	if got := srv.fetchCount(); got != 1 {
		t.Fatalf("warm fetches = %d, want 1", got)
	}

	// Age the set past its refresh point and rotate the server while the
	// refresh endpoint is blocked. A stale-cache lookup must return the
	// cached key immediately — the hot path never waits on the IdP.
	srv.setKeys(k2)
	auth.cache.mu.Lock()
	auth.cache.refreshDue = auth.cache.now().Add(-time.Minute)
	auth.cache.mu.Unlock()

	start := time.Now()
	ks, err := auth.cache.keys(ctx, "k1")
	if err != nil || len(ks) != 1 {
		t.Fatalf("stale serve: keys=%d err=%v", len(ks), err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stale lookup blocked on the refresh: %s", elapsed)
	}
	if got := srv.fetchCount(); got != 1 {
		t.Fatalf("stale lookup fetched: %d", got)
	}

	// Kick the background refresh: it parks on the blocked gate while the
	// cache keeps serving.
	auth.cache.scheduleRefresh(ctx)
	if got := srv.fetchCount(); got != 1 {
		t.Fatalf("background refresh completed before the gate: %d", got)
	}

	// Release the refresh; once it lands the rotated set is cached: k1 is
	// evicted and k2 accepted, without any lookup having waited.
	close(srv.gate.release)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		auth.cache.mu.RLock()
		n := len(auth.cache.set.Key("k2"))
		auth.cache.mu.RUnlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	auth.cache.mu.RLock()
	n := len(auth.cache.set.Key("k2"))
	auth.cache.mu.RUnlock()
	if n == 0 {
		t.Fatal("background refresh never landed")
	}
	if _, err := auth.Authenticate(ctx, signToken(t, k2, baseClaims())); err != nil {
		t.Fatalf("token2 after background refresh: %v", err)
	}
	if _, err := auth.Authenticate(ctx, signToken(t, k1, baseClaims())); err == nil {
		t.Fatal("evicted token1 accepted")
	} else {
		ae, ok := err.(*jwtAuthError)
		if !ok || ae.reason != "unknown_kid" {
			t.Fatalf("want unknown_kid, got %v", err)
		}
	}
}

func TestJWKSCacheConcurrentAccess(t *testing.T) {
	k1 := mustRSAJWK(t, "k1")
	k2 := mustRSAJWK(t, "k2")
	srv := newJWKSServer(t, k1)
	auth := newTestJWTAuth(t, srv, nil)
	ctx := context.Background()

	token := signToken(t, k1, baseClaims())
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_, _ = auth.Authenticate(ctx, token)
			}
		}()
	}
	// Concurrent rotation while readers hammer the cache.
	srv.setKeys(k1, k2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 25; j++ {
			_ = auth.cache.refreshSync(ctx)
		}
	}()
	wg.Wait()
}

// --- middleware fork ------------------------------------------------------------

func TestJWTMiddlewareOrgAndKeyLabelsReachDownstream(t *testing.T) {
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	auth := newTestJWTAuth(t, srv, nil)
	mw := jwtMiddleware(auth)

	c := baseClaims()
	c["key_labels"] = map[string]any{"env": "prod"}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+signToken(t, k, c))

	var gotOrg string
	var gotSources []labels.Source
	var gotKeyLabels []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// X-Org-Id is the org-context channel the event publisher and the
		// policy runtime read (request events, gateway_policy orgID) — the
		// same contract API-key auth uses, so the org lands in cc/event.
		gotOrg = r.Header.Get("X-Org-Id")
		gotSources = principalLabelSources(r.Context())
		gotKeyLabels = principalKeyLabels(r.Context())
	})
	mw.ServeHTTP(next).ServeHTTP(httptest.NewRecorder(), req)

	if gotOrg != "org-42" {
		t.Fatalf("X-Org-Id = %q", gotOrg)
	}
	foundKeySource := false
	for _, src := range gotSources {
		if src.Name == "key" {
			foundKeySource = true
			if !src.Locked {
				t.Fatal("jwt key label source must be locked")
			}
		}
	}
	if !foundKeySource {
		t.Fatalf("no key label source attached: %+v", gotSources)
	}
	// The attachment selector (matchKeyLabel) matches keys AND values.
	if len(gotKeyLabels) == 0 {
		t.Fatal("principalKeyLabels empty — policy attachments cannot match")
	}
}

func TestJWTMiddlewareForkAndLegacyBitForBit(t *testing.T) {
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	auth := newTestJWTAuth(t, srv, nil)
	goodToken := signToken(t, k, baseClaims())

	t.Run("jwt wired: token routes to the JWT path", func(t *testing.T) {
		mw := jwtMiddleware(auth)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+goodToken)
		mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Org-Id") != "org-42" {
				t.Fatalf("X-Org-Id = %q", r.Header.Get("X-Org-Id"))
			}
		})).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("jwt wired: invalid token rejected at the fork (no legacy fallthrough)", func(t *testing.T) {
		unknown := mustRSAJWK(t, "k-unknown")
		mw := jwtMiddleware(auth)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+signToken(t, unknown, baseClaims()))
		mw.ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("next reached")
		})).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "unknown token key") {
			t.Fatalf("jwt-path error body expected, got %s", rec.Body.String())
		}
	})

	t.Run("jwt off: identical requests keep legacy behaviour bit-for-bit", func(t *testing.T) {
		mw := NewAuthMiddleware(config.Gateway{AuthMode: "header"}, nil) // no jwt
		if mw.jwt != nil {
			t.Fatal("jwt path must be nil by default")
		}
		// A JWT-shaped token is just an unknown API key → legacy 401 body.
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+goodToken)
		mw.ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("next reached")
		})).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "invalid API key") {
			t.Fatalf("legacy error body changed: %s", rec.Body.String())
		}

		// The static-key path still authenticates without any JWT wiring.
		mwKey := NewAuthMiddleware(config.Gateway{AuthMode: "header", APIKey: "sk-static"}, nil)
		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
		req2.Header.Set("Authorization", "Bearer sk-static")
		mwKey.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusOK {
			t.Fatalf("static key broken: %d %s", rec2.Code, rec2.Body.String())
		}
	})
}

func TestJWTBearerSchemeRequired(t *testing.T) {
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	auth := newTestJWTAuth(t, srv, nil)
	mw := jwtMiddleware(auth)

	// No Authorization at all → legacy missing-header 401.
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	mw.ServeHTTP(http.HandlerFunc(http.NotFound)).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}

	// Non-Bearer scheme → legacy path (no JWT fork).
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req2.Header.Set("Authorization", "Basic "+signToken(t, k, baseClaims()))
	mw.ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("JWT path must not trigger for non-Bearer schemes")
	})).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec2.Code)
	}
}

func TestJWTIssuerAudienceOptional(t *testing.T) {
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	auth := newTestJWTAuth(t, srv, func(w *JWTWiring) {
		w.Issuer = ""
		w.Audience = ""
		w.KeyLabelClaim = ""
	})
	c := baseClaims()
	c["iss"] = "whatever"
	c["aud"] = []string{"nope"}
	if _, err := auth.Authenticate(context.Background(), signToken(t, k, c)); err != nil {
		t.Fatalf("unconfigured iss/aud must not be enforced: %v", err)
	}
}
