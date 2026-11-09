package provider

// N08-P01-T03 — tenant-keyed Entra token cache VERIFICATION record (in
// tests). The cache itself predates this card (T01/T02, singleflight +
// per-credential cooldowns); this file pins the tenant-keying contract the
// packet negative criterion demands ("Ошибка Entra не раскрывает secret и не
// использует токен чужой org"):
//
//   - cache-key injectivity: the "tenant|client" key is injective over the
//     credential space admitted by ParseAzureEntraCredentials ('|' rejected
//     in tenant_id/client_id), so two identities can never alias one slot;
//   - concurrent multi-credential isolation: one shared adapter, many
//     credentials (different tenants AND same tenant/different clients),
//     every caller gets exactly its own token, exactly one exchange each;
//   - per-key cooldown isolation: a 429 penalty for one credential never
//     throttles another;
//   - prune safety: an exchange for one credential never evicts another
//     org's fresh token, only fully expired entries;
//   - cross-tenant failure honesty: a failed exchange for org A surfaces no
//     token (its own or org B's) and no secret material;
//   - secret rotation semantics: same tenant+client keeps its cache slot;
//     the rotated secret appears on the wire only at the NEXT exchange —
//     never another identity's token.
//
// Honest limits: httptest stubs prove the adapter mechanics, not Microsoft
// attestation; the env-gated live smoke lives in
// azure_openai_contract_test.go (provider_test).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blobFor assembles a fake credential blob at runtime (gosec G101 hygiene;
// values are obvious fixtures, never real credentials).
func blobFor(tenant, client, secret string) string {
	return fmt.Sprintf(`{"tenant_id":%q,"client_id":%q,"client_secret":%q}`, tenant, client, secret)
}

// tenantCacheStub is one shared Entra authority serving client-credentials
// endpoints for a WHOLE SET of credentials (the multi-tenant reality the
// upstream Pool's shared adapter sees). Requests are answered by
// (tenant-from-path, client_id-from-form); an unknown pair is rejected 400
// invalid_client exactly like real Entra. Per-credential exchange counters
// are recorded for assertions.
type tenantCacheStub struct {
	srv   *httptest.Server
	calls map[string]*atomic.Int32 // "tenant|client" → exchanges
}

// newTenantCacheStub builds the authority: creds maps credential identity →
// the access token that identity's exchanges return.
func newTenantCacheStub(t *testing.T, creds map[AzureEntraCredentials]string) *tenantCacheStub {
	t.Helper()
	stub := &tenantCacheStub{calls: map[string]*atomic.Int32{}}
	for c := range creds {
		stub.calls[entraCacheKey(c)] = &atomic.Int32{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("entra form parse: %v", err)
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		tenant := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/oauth2/v2.0/token")
		client := r.PostForm.Get("client_id")
		tok, ok := creds[AzureEntraCredentials{TenantID: tenant, ClientID: client}]
		if !ok {
			// Unknown identity: Entra-shaped invalid_client refusal. The
			// body carries only the OAuth error code, never echoed input.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"Unknown client"}`))
			return
		}
		if counter := stub.calls[entraCacheKey(AzureEntraCredentials{TenantID: tenant, ClientID: client})]; counter != nil {
			counter.Add(1)
		}
		if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.PostForm.Get("scope"); got != azureEntraScope {
			t.Errorf("scope = %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"` + tok + `","expires_in":3600}`))
	})
	stub.srv = httptest.NewServer(mux)
	t.Cleanup(stub.srv.Close)
	return stub
}

// exchanges reports the exchange count for one credential identity.
func (s *tenantCacheStub) exchanges(c AzureEntraCredentials) int32 {
	if counter, ok := s.calls[entraCacheKey(c)]; ok {
		return counter.Load()
	}
	return 0
}

// TestAzureOpenAI_ParseCredentials_RejectKeySeparator: the cache-key
// separator '|' must be rejected in tenant_id/client_id at parse time —
// fail-fast with a field-named error (I51) and NEVER a silently aliased
// cache slot. The error names the field, never a value.
func TestAzureOpenAI_ParseCredentials_RejectKeySeparator(t *testing.T) {
	t.Parallel()
	secretCanary := fmt.Sprintf("sep-canary-%s", "4d81")
	cases := []struct {
		name   string
		blob   string
		errMsg string
	}{
		{"separator in tenant_id", blobFor("real-tenant|extra", "client-1", secretCanary), "tenant_id"},
		{"separator in client_id", blobFor("real-tenant", "client|extra", secretCanary), "client_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// No server is wired: if the rejection ever regressed into a
			// parse success, the follow-up token exchange would panic on a
			// nil client — the test cannot silently pass through the old
			// aliased-slot behavior.
			a := NewAzureOpenAIWithClient(nil, "https://entra.example.com")
			_, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
				[]byte(`{"model":"gpt-4o"}`), tc.blob, false)
			if err == nil {
				t.Fatal("credential containing the cache-key separator must be rejected")
			}
			if !strings.Contains(err.Error(), tc.errMsg) {
				t.Fatalf("error = %q, want a %s-named diagnostic", err, tc.errMsg)
			}
			if strings.Contains(err.Error(), secretCanary) {
				t.Fatalf("error leaks secret value: %q", err)
			}
		})
	}
}

// TestAzureOpenAI_TenantCacheKey_Injective: over the admitted credential
// space (no '|' in ids) distinct identities produce distinct cache keys and
// equal identities produce equal keys. This is the property that makes
// "never uses another org's token" hold by construction rather than by
// convention.
func TestAzureOpenAI_TenantCacheKey_Injective(t *testing.T) {
	t.Parallel()
	pairs := []AzureEntraCredentials{
		{TenantID: "tenant-a", ClientID: "client-a"},
		{TenantID: "tenant-a", ClientID: "client-b"}, // same tenant, other client
		{TenantID: "tenant-b", ClientID: "client-a"}, // other tenant, same client
		{TenantID: "guid-0e0aa7d6", ClientID: "guid-93ff21cc"},
		{TenantID: "contoso.onmicrosoft.com", ClientID: "guid-77aa01bb"},
	}
	seen := map[string]AzureEntraCredentials{}
	for _, c := range pairs {
		k := entraCacheKey(c)
		if prev, dup := seen[k]; dup {
			t.Fatalf("key collision: (%q,%q) and (%q,%q) both map to %q",
				prev.TenantID, prev.ClientID, c.TenantID, c.ClientID, k)
		}
		seen[k] = c
		// Round-trip: the single '|' in a key over ADMITTED ids splits back
		// into exactly the identity it was built from.
		parts := strings.SplitN(k, "|", 2)
		if len(parts) != 2 || parts[0] != c.TenantID || parts[1] != c.ClientID {
			t.Fatalf("key %q does not round-trip identity (%q,%q)", k, c.TenantID, c.ClientID)
		}
	}
	// The pre-fix collision shape (the reason for the parse rejection): the
	// raw join of two DIFFERENT identities aliases one slot —
	//   {tenant-a, client-b|client-a} and {tenant-a|client-b, client-a}
	// both map to "tenant-a|client-b|client-a". Both identities are now
	// refused by the parser BEFORE any cache touch, so no admitted
	// credential can ever reach the aliased state.
	hostile := []AzureEntraCredentials{
		{TenantID: "tenant-a", ClientID: "client-b|client-a"},
		{TenantID: "tenant-a|client-b", ClientID: "client-a"},
	}
	if k1, k2 := entraCacheKey(hostile[0]), entraCacheKey(hostile[1]); k1 != k2 {
		t.Fatalf("expected the unadmitted alias demo to collide: %q vs %q", k1, k2)
	}
	for _, c := range hostile {
		if _, err := ParseAzureEntraCredentials(blobFor(c.TenantID, c.ClientID, "s")); err == nil {
			t.Fatalf("hostile identity (%q,%q) must be refused by the parser", c.TenantID, c.ClientID)
		}
	}
}

// TestAzureOpenAI_MultiTenant_Concurrent_Isolation: THE tenant-keyed cache
// contract under race. One shared adapter (the pool reality), four
// credentials — different tenants AND same-tenant/different-client — eight
// concurrent cold callers each. Every caller must receive exactly its own
// credential's bearer, and each identity must collapse into exactly one
// exchange (singleflight is per KEY, not global).
func TestAzureOpenAI_MultiTenant_Concurrent_Isolation(t *testing.T) {
	t.Parallel()
	identities := []AzureEntraCredentials{
		{TenantID: "tenant-a", ClientID: "client-a1"},
		{TenantID: "tenant-a", ClientID: "client-a2"}, // same tenant, second app
		{TenantID: "tenant-b", ClientID: "client-b1"},
		{TenantID: "tenant-c", ClientID: "client-c1"},
	}
	creds := map[AzureEntraCredentials]string{}
	for i, c := range identities {
		creds[c] = fmt.Sprintf("AT-T%d-OWN-9f%da", i, i) // deterministic per-identity token
	}
	stub := newTenantCacheStub(t, creds)
	a := NewAzureOpenAIWithClient(stub.srv.Client(), stub.srv.URL)

	const callersPerCred = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, callersPerCred*len(identities))
	for _, c := range identities {
		for j := 0; j < callersPerCred; j++ {
			wg.Add(1)
			go func(c AzureEntraCredentials) {
				defer wg.Done()
				<-start
				req, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
					[]byte(`{"model":"gpt-4o"}`), blobFor(c.TenantID, c.ClientID, "secret-"+c.ClientID), false)
				if err != nil {
					errs <- fmt.Errorf("%s/%s: %w", c.TenantID, c.ClientID, err)
					return
				}
				want := "Bearer " + creds[c]
				if got := req.Header.Get("Authorization"); got != want {
					errs <- fmt.Errorf("%s/%s: auth = %q, want own token %q (cross-tenant token use!)",
						c.TenantID, c.ClientID, got, want)
					return
				}
				errs <- nil
			}(c)
		}
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Exactly one exchange per identity — and no identity shares another's.
	for i, c := range identities {
		if got := stub.exchanges(c); got != 1 {
			t.Fatalf("identity %d (%s/%s): exchanges = %d, want exactly 1", i, c.TenantID, c.ClientID, got)
		}
	}
	a.mu.Lock()
	cached := len(a.tokens)
	a.mu.Unlock()
	if cached != len(identities) {
		t.Fatalf("cached slots = %d, want %d (one per identity)", cached, len(identities))
	}
}

// TestAzureOpenAI_TenantCooldown_IsolatedPerKey: a rate-limited exchange for
// org A puts ONLY A's key into cooldown — org B on the same shared adapter
// exchanges normally inside A's window, and A's later retry still carries
// only A's own state.
func TestAzureOpenAI_TenantCooldown_IsolatedPerKey(t *testing.T) {
	t.Parallel()
	aCreds := AzureEntraCredentials{TenantID: "tenant-a", ClientID: "client-a"}
	bCreds := AzureEntraCredentials{TenantID: "tenant-b", ClientID: "client-b"}
	stub := newTenantCacheStub(t, map[AzureEntraCredentials]string{bCreds: fmt.Sprintf("AT-B-%s", "COOLDOWN")})
	// tenant-a always answers 429 with a 2s Retry-After.
	cooledMux := http.NewServeMux()
	aCalls := &atomic.Int32{}
	cooledMux.HandleFunc("/tenant-a/oauth2/v2.0/token", func(w http.ResponseWriter, _ *http.Request) {
		aCalls.Add(1)
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"temporarily_throttled"}`))
	})
	cooledMux.Handle("/tenant-b/oauth2/v2.0/token", stub.srv.Config.Handler)
	throttled := httptest.NewServer(cooledMux)
	t.Cleanup(throttled.Close)

	a := NewAzureOpenAIWithClient(throttled.Client(), throttled.URL)
	_, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), blobFor(aCreds.TenantID, aCreds.ClientID, "a-canary"), false)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("error = %v, want A's 429 diagnostic", err)
	}
	if aCalls.Load() != 1 {
		t.Fatalf("tenant-a exchanges = %d, want 1", aCalls.Load())
	}

	// B must NOT inherit A's cooldown.
	req, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), blobFor(bCreds.TenantID, bCreds.ClientID, "b-canary"), false)
	if err != nil {
		t.Fatalf("tenant B inside A's cooldown window must exchange normally: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer AT-B-COOLDOWN" {
		t.Fatalf("tenant B auth = %q, want its own token", got)
	}
	// A stays cooled: immediate retry fails fast with ZERO new exchanges.
	_, err = a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), blobFor(aCreds.TenantID, aCreds.ClientID, "a-canary"), false)
	if err == nil || !strings.Contains(err.Error(), "rate-limited") {
		t.Fatalf("error = %v, want A's cooldown diagnostic", err)
	}
	if aCalls.Load() != 1 {
		t.Fatalf("tenant-a exchanges = %d, want still 1 inside its cooldown", aCalls.Load())
	}
	// Map-level proof: only A carries a cooldown entry.
	a.mu.Lock()
	aCooled, bCooled := a.cooldowns[entraCacheKey(aCreds)], a.cooldowns[entraCacheKey(bCreds)]
	a.mu.Unlock()
	if aCooled.IsZero() {
		t.Fatal("tenant-a must carry a cooldown entry")
	}
	if !bCooled.IsZero() {
		t.Fatal("tenant-b must not carry a cooldown entry — penalties are per key")
	}
	// Cooldown elapsed → A retries (still throttled) while B rides its cache.
	a.mu.Lock()
	a.cooldowns[entraCacheKey(aCreds)] = time.Now().Add(-time.Millisecond)
	a.mu.Unlock()
	if _, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), blobFor(aCreds.TenantID, aCreds.ClientID, "a-canary"), false); err == nil {
		t.Fatal("tenant-a retry after cooldown must still see the throttle")
	}
	if aCalls.Load() != 2 {
		t.Fatalf("tenant-a exchanges = %d, want 2 after cooldown expiry", aCalls.Load())
	}
	req, err = a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), blobFor(bCreds.TenantID, bCreds.ClientID, "b-canary"), false)
	if err != nil {
		t.Fatalf("tenant B re-request: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer AT-B-COOLDOWN" {
		t.Fatalf("tenant B auth = %q, want its cached token (no re-exchange)", got)
	}
	if stub.exchanges(bCreds) != 1 {
		t.Fatalf("tenant-b exchanges = %d, want 1 (cache hit, cooldown stayed per key)", stub.exchanges(bCreds))
	}
}

// TestAzureOpenAI_CachePrune_KeepsFreshForeignTokens_Bounded: the prune on a
// successful exchange removes only FULLY expired entries — another org's
// fresh token must survive untouched, and the map stays bounded by the
// number of active identities.
func TestAzureOpenAI_CachePrune_KeepsFreshForeignTokens_Bounded(t *testing.T) {
	t.Parallel()
	cCreds := AzureEntraCredentials{TenantID: "tenant-c", ClientID: "client-c"}
	stub := newTenantCacheStub(t, map[AzureEntraCredentials]string{cCreds: "AT-C-PRUNE"})
	a := NewAzureOpenAIWithClient(stub.srv.Client(), stub.srv.URL)

	keyA := entraCacheKey(AzureEntraCredentials{TenantID: "tenant-a", ClientID: "client-a"})
	keyB := entraCacheKey(AzureEntraCredentials{TenantID: "tenant-b", ClientID: "client-b"})
	a.mu.Lock()
	a.tokens[keyA] = azureToken{accessToken: "AT-A-FRESH", tokenExp: time.Now().Add(time.Hour)}
	a.tokens[keyB] = azureToken{accessToken: "AT-B-EXPIRED", tokenExp: time.Now().Add(-time.Minute)}
	a.mu.Unlock()

	if _, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), blobFor(cCreds.TenantID, cCreds.ClientID, "c-canary"), false); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if got := a.tokens[keyA].accessToken; got != "AT-A-FRESH" {
		t.Fatalf("org A fresh token after org C exchange = %q, want AT-A-FRESH untouched", got)
	}
	if _, still := a.tokens[keyB]; still {
		t.Fatal("fully expired entry must be pruned")
	}
	if got := a.tokens[entraCacheKey(cCreds)].accessToken; got != "AT-C-PRUNE" {
		t.Fatalf("org C cached token = %q, want AT-C-PRUNE", got)
	}
	if len(a.tokens) != 2 {
		t.Fatalf("cached slots = %d, want 2 (A fresh + C new; B expired pruned)", len(a.tokens))
	}
}

// TestAzureOpenAI_CrossTenantError_NeverCarriesOtherOrgToken: org A's failed
// exchange must surface neither A's secret nor org B's (still cached) token
// value — the packet negative criterion on the error path across tenants.
func TestAzureOpenAI_CrossTenantError_NeverCarriesOtherOrgToken(t *testing.T) {
	t.Parallel()
	bCreds := AzureEntraCredentials{TenantID: "tenant-b", ClientID: "client-b"}
	otherOrgToken := fmt.Sprintf("AT-B-CACHED-%s", "leak9f3a")
	stub := newTenantCacheStub(t, map[AzureEntraCredentials]string{bCreds: otherOrgToken})
	failMux := http.NewServeMux()
	failMux.HandleFunc("/tenant-a/oauth2/v2.0/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	})
	failMux.Handle("/tenant-b/oauth2/v2.0/token", stub.srv.Config.Handler)
	mixed := httptest.NewServer(failMux)
	t.Cleanup(mixed.Close)

	a := NewAzureOpenAIWithClient(mixed.Client(), mixed.URL)
	// Org B authenticates first: its token is now cached and fresh.
	req, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), blobFor(bCreds.TenantID, bCreds.ClientID, "b-canary-17c2"), false)
	if err != nil || req.Header.Get("Authorization") != "Bearer "+otherOrgToken {
		t.Fatalf("org B warm-up: err=%v auth=%q", err, req.Header.Get("Authorization"))
	}
	// Org A fails while B's token sits in the very same cache.
	_, err = a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), blobFor("tenant-a", "client-a", "a-canary-4d81"), false)
	if err == nil {
		t.Fatal("org A exchange must fail (invalid_client)")
	}
	if strings.Contains(err.Error(), otherOrgToken) {
		t.Fatalf("org A error leaks org B's cached token: %q", err)
	}
	if strings.Contains(err.Error(), "a-canary-4d81") || strings.Contains(err.Error(), "b-canary-17c2") {
		t.Fatalf("org A error leaks secret material: %q", err)
	}
	// B's cache entry is untouched by A's failure: still the same bearer,
	// zero re-exchange.
	req, err = a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), blobFor(bCreds.TenantID, bCreds.ClientID, "b-canary-17c2"), false)
	if err != nil {
		t.Fatalf("org B after A's failure: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+otherOrgToken {
		t.Fatalf("org B auth = %q, want its own untouched cached token", got)
	}
	if stub.exchanges(bCreds) != 1 {
		t.Fatalf("org B exchanges = %d, want 1 (A's failure must not invalidate B)", stub.exchanges(bCreds))
	}
}

// TestAzureOpenAI_SecretRotation_SameIdentity_SameSlot_NewSecretOnWire:
// rotating the client secret keeps the SAME cache slot (identity =
// tenant+client, never the secret). The still-valid cached bearer keeps
// being served until its natural refresh — Entra bearer tokens outlive the
// secret that minted them — and the rotated secret appears on the wire only
// at the NEXT exchange. No identity ever rides another org's slot.
func TestAzureOpenAI_SecretRotation_SameIdentity_SameSlot_NewSecretOnWire(t *testing.T) {
	t.Parallel()
	rotCreds := AzureEntraCredentials{TenantID: "rot-tenant", ClientID: "rot-client"}
	exchanges := &atomic.Int32{}
	var secretsMu sync.Mutex
	var postedSecrets []string
	rotMux := http.NewServeMux()
	rotMux.HandleFunc("/rot-tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		n := exchanges.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("entra form parse: %v", err)
		}
		secretsMu.Lock()
		postedSecrets = append(postedSecrets, r.PostForm.Get("client_secret"))
		secretsMu.Unlock()
		// Deterministic token per exchange: the wire assertion below proves
		// WHICH exchange served the caller.
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"access_token":"AT-ROT-%d","expires_in":3600}`, n)
	})
	rotSrv := httptest.NewServer(rotMux)
	t.Cleanup(rotSrv.Close)

	a := NewAzureOpenAIWithClient(rotSrv.Client(), rotSrv.URL)
	oldBlob := blobFor(rotCreds.TenantID, rotCreds.ClientID, "rot-old-canary")

	req, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), oldBlob, false)
	if err != nil || req.Header.Get("Authorization") != "Bearer AT-ROT-1" {
		t.Fatalf("first exchange: err=%v auth=%q, want AT-ROT-1", err, req.Header.Get("Authorization"))
	}
	// Rotate the secret (same tenant+client): the cached token is still
	// valid, so the SAME slot keeps serving it — no re-exchange, no new slot.
	newBlob := blobFor(rotCreds.TenantID, rotCreds.ClientID, "rot-new-canary")
	req, err = a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), newBlob, false)
	if err != nil {
		t.Fatalf("request with rotated secret: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer AT-ROT-1" {
		t.Fatalf("auth after rotation = %q, want the still-valid cached token AT-ROT-1", got)
	}
	if exchanges.Load() != 1 {
		t.Fatalf("exchanges = %d, want 1 (rotation alone must not force an exchange)", exchanges.Load())
	}
	// Natural expiry: the next exchange posts the ROTATED secret on the wire
	// and serves the new token from the same slot.
	a.mu.Lock()
	key := entraCacheKey(rotCreds)
	a.tokens[key] = azureToken{accessToken: a.tokens[key].accessToken, tokenExp: time.Now()}
	a.mu.Unlock()
	req, err = a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), newBlob, false)
	if err != nil || req.Header.Get("Authorization") != "Bearer AT-ROT-2" {
		t.Fatalf("post-expiry exchange: err=%v auth=%q, want AT-ROT-2", err, req.Header.Get("Authorization"))
	}
	// Wire honesty: exchange 1 posted the old secret, exchange 2 the rotated
	// one — the rotation changed the NEXT wire secret, nothing else.
	secretsMu.Lock()
	defer secretsMu.Unlock()
	if len(postedSecrets) != 2 {
		t.Fatalf("posted secrets = %v, want exactly 2 wire exchanges", postedSecrets)
	}
	if postedSecrets[0] != "rot-old-canary" || postedSecrets[1] != "rot-new-canary" {
		t.Fatalf("posted secrets = %v, want [old, rotated] in exchange order", postedSecrets)
	}
}
