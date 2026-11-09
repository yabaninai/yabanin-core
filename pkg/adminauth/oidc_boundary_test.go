package adminauth

// N04-P01-T07 boundary regressions for the OIDC client surface (T06 was the
// lifecycle acceptance; this file pins the EDGE semantics the product ships
// on top of go-oidc v3.21):
//
//   - token time boundaries: the minimal TTL the exchange can honor, the
//     first expired second, and the nbf (not-before) leeway window go-oidc
//     grants for IdP clock skew (5 minutes);
//   - kid rotation race: TWO unknown kids in flight concurrently — go-oidc's
//     RemoteKeySet deduplicates the refetch (singleflight); the production
//     client must survive the burst and verify every token;
//   - retirement asymmetry: a long-lived client keeps a cached retired key
//     (documented go-oidc behavior), a freshly constructed client rejects
//     the retired kid — the card's "old key is rejected" negative, pinned at
//     mock level (the live-IdP equivalent runs in keycloak_live_boundary_test.go);
//   - issuer boundaries: a discovery document whose issuer claim differs from
//     the constructed issuer (trailing slash) must fail client construction.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// boundaryProvider is a standalone multi-kid fake IdP: a keyring with a
// controllable published subset (JWKS mutations at runtime), a per-response
// signing kid (alternating for concurrent bursts) and claim knobs for the
// time boundaries.
type boundaryProvider struct {
	server *httptest.Server

	mu        sync.Mutex
	keys      map[string]*rsa.PrivateKey // kid → key; k1..k4 exist, publication is controlled
	published []string                   // kids currently served by /jwks
	signKid   string                     // kid the /token endpoint signs with
	issuerDoc string                     // issuer claim inside the discovery document

	expirySkewSecs int64  // added to exp
	nbfSecs        *int64 // nbf = now + nbfSecs when non-nil
	iatSecs        *int64 // iat override when non-nil

	altCount atomic.Int64 // alternates the signing kid when signKidAlternates
	alt      atomic.Bool  // when true, /token alternates k2/k3 per response
	minted   map[string]int
}

func newBoundaryProvider(t *testing.T) *boundaryProvider {
	t.Helper()
	keys := map[string]*rsa.PrivateKey{}
	for _, kid := range []string{"k1", "k2", "k3", "k4"} {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa keygen %s: %v", kid, err)
		}
		keys[kid] = key
	}
	p := &boundaryProvider{
		keys:      keys,
		published: []string{"k1"},
		signKid:   "k1",
		minted:    map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		issuer := p.issuerDoc
		p.mu.Unlock()
		if issuer == "" {
			issuer = p.server.URL
		}
		wj(w, map[string]any{
			"issuer": issuer, "authorization_endpoint": p.server.URL + "/auth",
			"token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		kids := append([]string(nil), p.published...)
		p.mu.Unlock()
		jwks := make([]map[string]any, 0, len(kids))
		for _, kid := range kids {
			pub := &p.keys[kid].PublicKey
			jwks = append(jwks, map[string]any{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			})
		}
		wj(w, map[string]any{"keys": jwks})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		kid := p.currentSignKid()
		p.mu.Lock()
		p.minted[kid]++
		claims := map[string]any{
			"iss": p.server.URL, "aud": "cid", "sub": "s-1",
			"email": "u@test.io", "email_verified": true,
			"exp": time.Now().Unix() + 600 + p.expirySkewSecs, "iat": time.Now().Unix(),
			"nonce": "boundary-nonce",
		}
		nbf, iat := p.nbfSecs, p.iatSecs
		p.mu.Unlock()
		if nbf != nil {
			claims["nbf"] = time.Now().Unix() + *nbf
		}
		if iat != nil {
			claims["iat"] = *iat
		}
		wj(w, map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": p.sign(t, kid, claims),
		})
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *boundaryProvider) currentSignKid() string {
	if p.alt.Load() {
		if p.altCount.Add(1)%2 == 0 {
			return "k2"
		}
		return "k3"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signKid
}

func (p *boundaryProvider) setPublished(kids ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.published = kids
}

func (p *boundaryProvider) setSignKid(kid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signKid = kid
}

// sign builds an RS256 JWT with the named keyring key.
func (p *boundaryProvider) sign(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	cb, _ := json.Marshal(claims)
	si := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	d := sha256.Sum256([]byte(si))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.keys[kid], crypto.SHA256, d[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return si + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// exchange runs one production ExchangeAndVerify round trip with a client
// constructed for the call; ok reports whether the caller expects acceptance.
func exchange(t *testing.T, p *boundaryProvider, ok bool, label string) {
	t.Helper()
	c, err := NewOIDCClient(context.Background(), p.server.URL, "cid", "sec", "https://adm/cb")
	if err != nil {
		t.Fatalf("%s: NewOIDCClient: %v", label, err)
	}
	exchangeWith(t, c, ok, label)
}

func exchangeWith(t *testing.T, c *OIDCClient, ok bool, label string) {
	t.Helper()
	_, err := c.ExchangeAndVerify(context.Background(), "code", "boundary-nonce", "verifier")
	if ok && err != nil {
		t.Fatalf("%s: must verify, got %v", label, err)
	}
	if !ok && err == nil {
		t.Fatalf("%s: must fail closed", label)
	}
}

// exchangeMinimalTTL runs the same production round trip until a fresh
// exp=now+1 token verifies inside its one-second validity window. Each
// attempt mints a NEW token, so a verification that stalls across the second
// boundary races only that attempt's token, not the pinned boundary itself.
// Only the go-oidc expiry error is retried: signature, kid, issuer and nonce
// failures abort immediately, and an expiry error on every attempt still
// fails the test — the retry cannot mask a real expiry-check regression.
func exchangeMinimalTTL(t *testing.T, p *boundaryProvider, label string) {
	t.Helper()
	const attempts = 4
	for i := 0; i < attempts; i++ {
		c, err := NewOIDCClient(context.Background(), p.server.URL, "cid", "sec", "https://adm/cb")
		if err != nil {
			t.Fatalf("%s: NewOIDCClient: %v", label, err)
		}
		_, err = c.ExchangeAndVerify(context.Background(), "code", "boundary-nonce", "verifier")
		if err == nil {
			return
		}
		var expired *oidc.TokenExpiredError
		if !errors.As(err, &expired) {
			t.Fatalf("%s: must verify, got %v", label, err)
		}
		if i == attempts-1 {
			t.Fatalf("%s: expired on all %d fresh exp=now+1 tokens (last: %v)", label, attempts, err)
		}
	}
}

func TestOIDCBoundary_TokenTimeBoundaries(t *testing.T) {
	t.Run("minimal TTL: exp one second ahead is accepted", func(t *testing.T) {
		p := newBoundaryProvider(t)
		p.expirySkewSecs = -599 // exp = now + 1
		exchangeMinimalTTL(t, p, "exp now+1")
	})
	t.Run("first expired second: exp one second behind is rejected", func(t *testing.T) {
		p := newBoundaryProvider(t)
		p.expirySkewSecs = -601 // exp = now - 1
		exchange(t, p, false, "exp now-1")
	})
	t.Run("nbf exactly now is accepted", func(t *testing.T) {
		p := newBoundaryProvider(t)
		zero := int64(0)
		p.nbfSecs = &zero
		exchange(t, p, true, "nbf now")
	})
	t.Run("nbf inside the clock-skew leeway is accepted", func(t *testing.T) {
		p := newBoundaryProvider(t)
		soon := int64(30)
		p.nbfSecs = &soon
		exchange(t, p, true, "nbf now+30s")
	})
	t.Run("nbf beyond the leeway is rejected", func(t *testing.T) {
		p := newBoundaryProvider(t)
		far := int64(360) // 6 min > go-oidc's 5 min leeway
		p.nbfSecs = &far
		exchange(t, p, false, "nbf now+6min")
	})
	t.Run("future iat without nbf is not policed (documented)", func(t *testing.T) {
		p := newBoundaryProvider(t)
		future := time.Now().Add(10 * time.Hour).Unix()
		p.iatSecs = &future
		exchange(t, p, true, "iat now+10h")
	})
}

func TestOIDCBoundary_TwoUnknownKidsConcurrentRefetch(t *testing.T) {
	// Two unknown kids in flight at once: after the cache holds only k1, the
	// JWKS publishes k1+k2+k3 and concurrent exchanges alternate between
	// k2-signed and k3-signed tokens. go-oidc deduplicates the refetch
	// (singleflight) and every token verifies — the rotation race the
	// console can hit mid-rotation. Run under -race by the test gate.
	p := newBoundaryProvider(t)
	exchange(t, p, true, "warmup k1") // the shared client's cache holds k1

	p.setPublished("k1", "k2", "k3")
	p.alt.Store(true) // /token alternates k2/k3 per response

	// The console process is ONE long-lived client: its cache holds k1 only,
	// and k2-signed plus k3-signed tokens arrive in the same instant. Both
	// kids miss the cache concurrently; go-oidc deduplicates the refetch
	// (singleflight) against the stable published set and every token
	// verifies. Run under -race by the test gate.
	c, err := NewOIDCClient(context.Background(), p.server.URL, "cid", "sec", "https://adm/cb")
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}
	const goroutines = 16
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ExchangeAndVerify(context.Background(), "code", "boundary-nonce", "verifier"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent unknown-kid verification failed: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.minted["k2"] == 0 || p.minted["k3"] == 0 {
		t.Fatalf("burst must mint BOTH unknown kids, got %v", p.minted)
	}
}

func TestOIDCBoundary_RetiredKidCacheAsymmetry(t *testing.T) {
	// go-oidc v3.21 RemoteKeySet semantics, pinned end to end with ONE
	// persistent client (the console process):
	//
	//   - the keyset cache is REPLACED on every refetch, and a refetch fires
	//     whenever a token's kid is not in the cache — so a retired kid is
	//     accepted only TRANSIENTLY: from the moment the client sees the
	//     next rotation, the stale key is evicted and its tokens fail;
	//   - a freshly constructed client (a restarted console) never saw the
	//     retired key and rejects its tokens immediately — the card's
	//     "old key is rejected" negative, pinned at mock level. The
	//     live-IdP equivalent runs in keycloak_live_boundary_test.go.
	p := newBoundaryProvider(t)
	c, err := NewOIDCClient(context.Background(), p.server.URL, "cid", "sec", "https://adm/cb")
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}

	exchangeWith(t, c, true, "warmup k1") // cache: [k1]

	p.setPublished("k1", "k2")
	p.setSignKid("k2")
	exchangeWith(t, c, true, "forward rotation adopts k2") // refetch; cache: [k1, k2]

	p.setPublished("k2") // retire k1
	p.setSignKid("k1")
	exchangeWith(t, c, true, "retired kid still verifies from cache (transient retention, cache untouched)")

	p.setPublished("k2", "k4") // next rotation lands
	p.setSignKid("k4")
	exchangeWith(t, c, true, "unknown kid k4 forces a refetch") // cache: [k2, k4] — k1 EVICTED

	p.setSignKid("k1")
	exchangeWith(t, c, false, "evicted retired kid now fails closed on the same long-lived client")

	// Fresh client on the retired-key world: rejects without ever caching it.
	exchange(t, p, false, "fresh client rejects the retired kid")
	p.setSignKid("k2")
	exchange(t, p, true, "fresh client accepts the current kid")
}

func TestOIDCBoundary_NeverPublishedKidFailsClosed(t *testing.T) {
	// A token whose kid never appears in the JWKS must fail even though the
	// keyring key exists: trust comes from the published set only.
	p := newBoundaryProvider(t)
	exchange(t, p, true, "warmup k1")
	p.setSignKid("k4")
	exchange(t, p, false, "kid absent from the JWKS")
}

func TestOIDCBoundary_IssuerTrailingSlashMismatchFailsClosed(t *testing.T) {
	// The discovery document's issuer claim must match the constructed
	// issuer byte-for-byte: a trailing slash is a different issuer, and a
	// document claiming it must fail client construction in both directions.
	t.Run("document issuer carries a trailing slash", func(t *testing.T) {
		p := newBoundaryProvider(t)
		p.mu.Lock()
		p.issuerDoc = p.server.URL + "/"
		p.mu.Unlock()
		if _, err := NewOIDCClient(context.Background(), p.server.URL, "cid", "sec", "https://adm/cb"); err == nil {
			t.Fatal("discovery issuer with trailing slash must fail client construction")
		}
	})
	t.Run("constructed issuer carries a trailing slash", func(t *testing.T) {
		p := newBoundaryProvider(t)
		if _, err := NewOIDCClient(context.Background(), p.server.URL+"/", "cid", "sec", "https://adm/cb"); err == nil {
			t.Fatal("constructed issuer with trailing slash must fail against the exact document issuer")
		}
	})
}
