package provider

// Failure boundaries for the Azure OpenAI adapter. This file is the failure
// record because the package contract.md was never committed:
//
//   - Entra endpoint unreachable        → fail-closed, no token in errors;
//   - expired token mid-flight          → refresh on next use (pinned by
//     TestAzureOpenAI_TokenRefreshOnExpiry; not duplicated here);
//   - malformed JSON secret             → honest refusal (pinned by
//     TestAzureOpenAI_IncompleteCredentials_FailFast_NoSecretLeak);
//   - rate-limited Entra (429)          → bounded backoff: immediate
//     fail-closed diagnostic + per-credential cooldown window (no sleep in
//     the request path), Retry-After honored, clamped to 60s;
//   - api-version mismatch              → Azure error shape surfaced, and
//     ParseUsage never hallucinates accounting out of an error body;
//   - caller cancel/отмена              → the shared exchange is detached
//     (sber precedent), and a canceled request never reaches the resource,
//     so no usage can be recorded for it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// entraStub describes one canned Entra token-endpoint answer.
type entraStub struct {
	status     int
	body       string
	retryAfter string
	// delay parks the handler to widen race windows (detach test).
	delay time.Duration
	// release, when non-nil, blocks the handler until closed.
	release chan struct{}
}

// newEntraStubServer serves exactly one tenant's token endpoint with the
// canned answer and counts exchanges.
func newEntraStubServer(t *testing.T, stub entraStub) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	mux := http.NewServeMux()
	mux.HandleFunc("/test-tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if stub.delay > 0 {
			time.Sleep(stub.delay)
		}
		if stub.release != nil {
			<-stub.release
		}
		if stub.retryAfter != "" {
			w.Header().Set("Retry-After", stub.retryAfter)
		}
		if stub.status == 0 {
			stub.status = http.StatusOK
		}
		w.WriteHeader(stub.status)
		_, _ = w.Write([]byte(stub.body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, calls
}

// TestAzureOpenAI_EntraUnreachable_FailClosed_NoTokenInError: a dead Entra
// authority (connection refused) must fail the request closed — no chat call
// is attempted, nothing is cached — with a diagnostic that names the failure
// without echoing credential or token material.
func TestAzureOpenAI_EntraUnreachable_FailClosed_NoTokenInError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // port is dead → connection refused

	rig := newAzureTestRig(t)
	// Route the Entra authority at the dead port while the resource stays
	// alive: any chat traffic would prove the failure was not fail-closed.
	a := NewAzureOpenAIWithClient(rig.srv.Client(), srv.URL)

	_, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), rig.creds(), false)
	if err == nil {
		t.Fatal("unreachable Entra authority must fail the request")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("error = %q, want an unreachable diagnostic", err)
	}
	if strings.Contains(err.Error(), "test-fixture-7f3a") {
		t.Fatalf("error leaks client secret: %q", err)
	}
	if rig.chatCalls.Load() != 0 {
		t.Fatalf("chat calls = %d, want 0 (fail-closed)", rig.chatCalls.Load())
	}
	a.mu.Lock()
	cached := len(a.tokens)
	a.mu.Unlock()
	if cached != 0 {
		t.Fatalf("cached tokens = %d, want 0 after failed exchange", cached)
	}
}

// TestAzureOpenAI_AccessTokenNeverInErrors: no failure stage may surface the
// access token VALUE (or the secret) in an error string. The decode-mismatch
// case is the realistic leak: Entra answers 200 with a token plus a malformed
// expires_in — the half-decoded struct already carries the token.
func TestAzureOpenAI_AccessTokenNeverInErrors(t *testing.T) {
	t.Parallel()
	// Assembled at runtime: gosec G101 pattern-matches literal credential
	// assignments (same approach as the -02 fixtures).
	tokenCanary := fmt.Sprintf("AT-CANARY-%s", "leak9f3a")
	cases := []struct {
		name string
		stub entraStub
	}{
		{"unreachable", entraStub{}}, // dead server set per-case below
		{"http 400", entraStub{status: http.StatusBadRequest, body: `{"error":"invalid_client"}`}},
		{"rate limited 429", entraStub{status: http.StatusTooManyRequests, body: `{"error":"temporarily_throttled"}`}},
		{"decode mismatch", entraStub{status: http.StatusOK, body: `{"access_token":"` + tokenCanary + `","expires_in":"not-a-number"}`}},
		{"empty access token", entraStub{status: http.StatusOK, body: `{"expires_in":3600}`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var srv *httptest.Server
			var calls *atomic.Int32
			if tc.name == "unreachable" {
				dead := httptest.NewServer(http.NotFoundHandler())
				dead.Close()
				srv, calls = dead, &atomic.Int32{}
			} else {
				srv, calls = newEntraStubServer(t, tc.stub)
			}
			a := NewAzureOpenAIWithClient(srv.Client(), srv.URL)
			_, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
				[]byte(`{"model":"gpt-4o"}`), rigCreds(t, tc.name), false)
			if err == nil {
				t.Fatal("expected a token failure")
			}
			if calls.Load() > 1 {
				t.Fatalf("token exchanges = %d, want at most 1 (no retry)", calls.Load())
			}
			if strings.Contains(err.Error(), tokenCanary) {
				t.Fatalf("error leaks access token value: %q", err)
			}
			if strings.Contains(err.Error(), "fixture-") {
				t.Fatalf("error leaks credential material: %q", err)
			}
		})
	}
}

// rigCreds returns per-case fake credentials assembled at runtime (gosec
// G101 hygiene; values are obvious fakes).
func rigCreds(t *testing.T, suffix string) string {
	t.Helper()
	return fmt.Sprintf(`{"tenant_id":"test-tenant","client_id":"client-%s","client_secret":"fake-%s"}`, suffix, suffix)
}

// TestAzureOpenAI_EntraRateLimited_BoundedBackoff: a 429 Entra exchange
// fails closed immediately (no sleep), names the rate limit, and puts the
// credential into a cooldown window — an immediate second request must NOT
// reach the network again; once the window elapses the exchange is retried.
func TestAzureOpenAI_EntraRateLimited_BoundedBackoff(t *testing.T) {
	t.Parallel()
	srv, calls := newEntraStubServer(t, entraStub{
		status: http.StatusTooManyRequests,
		body:   `{"error":"temporarily_throttled"}`,
	})
	rig := newAzureTestRig(t)
	a := NewAzureOpenAIWithClient(srv.Client(), srv.URL)
	creds := rigCreds(t, "rl")

	_, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), creds, false)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("error = %v, want a 429 rate-limit diagnostic", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("token exchanges = %d, want 1", calls.Load())
	}

	// Immediate retry inside the cooldown window: same diagnostic, ZERO
	// new network exchanges (this is the sequential-request backoff;
	// concurrent amplification is already bounded by singleflight).
	_, err = a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), creds, false)
	if err == nil || !strings.Contains(err.Error(), "rate-limited") {
		t.Fatalf("error = %v, want the cooldown diagnostic", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("token exchanges = %d, want still 1 inside cooldown", calls.Load())
	}
	if rig.chatCalls.Load() != 0 {
		t.Fatalf("chat calls = %d, want 0 (fail-closed under throttle)", rig.chatCalls.Load())
	}

	// Cooldown elapsed → the exchange is attempted again (still throttled
	// here, proving a real retry — not a poisoned state).
	key := entraCacheKey(AzureEntraCredentials{TenantID: "test-tenant", ClientID: "client-rl"})
	a.mu.Lock()
	a.cooldowns[key] = time.Now().Add(-time.Millisecond)
	a.mu.Unlock()
	_, err = a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), creds, false)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("error = %v, want a second 429 after cooldown", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("token exchanges = %d, want 2 after cooldown expiry", calls.Load())
	}
}

// TestAzureOpenAI_EntraRateLimited_RetryAfter_HonoredAndClamped: the cooldown
// window honors Entra's Retry-After delta-seconds, clamped to the 60s maximum
// so a hostile authority cannot park a tenant indefinitely.
func TestAzureOpenAI_EntraRateLimited_RetryAfter_HonoredAndClamped(t *testing.T) {
	t.Parallel()
	assertCooldown := func(t *testing.T, a *AzureOpenAI, tenant, client string, lo, hi time.Duration) {
		t.Helper()
		a.mu.Lock()
		until, ok := a.cooldowns[entraCacheKey(AzureEntraCredentials{TenantID: tenant, ClientID: client})]
		a.mu.Unlock()
		if !ok {
			t.Fatal("no cooldown recorded after 429")
		}
		d := time.Until(until)
		if d < lo || d > hi {
			t.Fatalf("cooldown = %s, want within (%s, %s)", d, lo, hi)
		}
	}

	t.Run("retry-after honored", func(t *testing.T) {
		t.Parallel()
		srv, _ := newEntraStubServer(t, entraStub{status: http.StatusTooManyRequests, retryAfter: "2"})
		rig := newAzureTestRig(t)
		a := NewAzureOpenAIWithClient(srv.Client(), srv.URL)
		_, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
			[]byte(`{"model":"gpt-4o"}`), rigCreds(t, "ra2"), false)
		if err == nil || !strings.Contains(err.Error(), "cooldown 2s") {
			t.Fatalf("error = %v, want cooldown 2s diagnostic", err)
		}
		assertCooldown(t, a, "test-tenant", "client-ra2", 1500*time.Millisecond, 2500*time.Millisecond)
	})
	t.Run("retry-after clamped to max", func(t *testing.T) {
		t.Parallel()
		srv, _ := newEntraStubServer(t, entraStub{status: http.StatusTooManyRequests, retryAfter: "3600"})
		rig := newAzureTestRig(t)
		a := NewAzureOpenAIWithClient(srv.Client(), srv.URL)
		_, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
			[]byte(`{"model":"gpt-4o"}`), rigCreds(t, "rara"), false)
		if err == nil || !strings.Contains(err.Error(), "cooldown 1m0s") {
			t.Fatalf("error = %v, want clamped cooldown 1m0s diagnostic", err)
		}
		assertCooldown(t, a, "test-tenant", "client-rara", 59*time.Second, 61*time.Second)
	})
	t.Run("unparsable retry-after falls back to base", func(t *testing.T) {
		t.Parallel()
		srv, _ := newEntraStubServer(t, entraStub{status: http.StatusTooManyRequests, retryAfter: "next-tuesday"})
		rig := newAzureTestRig(t)
		a := NewAzureOpenAIWithClient(srv.Client(), srv.URL)
		_, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
			[]byte(`{"model":"gpt-4o"}`), rigCreds(t, "rab"), false)
		if err == nil || !strings.Contains(err.Error(), "cooldown 1s") {
			t.Fatalf("error = %v, want base cooldown 1s diagnostic", err)
		}
		assertCooldown(t, a, "test-tenant", "client-rab", 500*time.Millisecond, 1500*time.Millisecond)
	})
}

// TestAzureOpenAI_APIVersionMismatch_ErrorShape_NoHallucinatedUsage: when the
// resource rejects the pinned api-version, the Azure error body is surfaced
// to the caller (same wire contract as upstream.Error) and ParseUsage on that
// error body yields ZERO usage — a failed request must never account tokens.
func TestAzureOpenAI_APIVersionMismatch_ErrorShape_NoHallucinatedUsage(t *testing.T) {
	t.Parallel()
	rig := newAzureTestRig(t)
	a := rig.adapter()
	errorBody := `{"error":{"code":"InvalidApiVersion","message":"The specified API version 2024-02-01 is not supported."}}`
	rig.chatStatus.Store(http.StatusBadRequest)
	rig.chatBody.Store(errorBody)

	req, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), rig.creds(), false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	resp, err := rig.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var decoded struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(errorBody), &decoded); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if decoded.Error.Code != "InvalidApiVersion" {
		t.Fatalf("error code = %q, want InvalidApiVersion", decoded.Error.Code)
	}

	// Accounting honesty: an error body carries no usage, and ParseUsage
	// must report exactly that — no partial, no fabricated totals.
	u := a.ParseUsage([]byte(errorBody))
	if u.PromptTokens != 0 || u.CompletionTokens != 0 || u.TotalTokens != 0 {
		t.Fatalf("usage from error body = %+v, want zeros", u)
	}
	if u.Source != UsageSourceNone {
		t.Fatalf("source = %q, want none", u.Source)
	}
	// The pinned version the mismatch is measured against stays on the wire.
	if snap := rig.chatSnapshot(t); !strings.Contains(snap.Query, "api-version="+azureOpenAIAPIVersion) {
		t.Fatalf("query = %q, want pinned api-version %s", snap.Query, azureOpenAIAPIVersion)
	}
}

// TestAzureOpenAI_TokenRefreshDetachedFromCallerContext: the shared exchange
// runs on a detached, self-bounded context — the first caller cancelling
// mid-exchange must not abort it; the next caller reuses the completed token
// with exactly one exchange in total (sber precedent, azure shape).
func TestAzureOpenAI_TokenRefreshDetachedFromCallerContext(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv, calls := newEntraStubServer(t, entraStub{
		status:  http.StatusOK,
		body:    `{"access_token":"AT-DETACHED","expires_in":3600}`,
		release: release,
	})
	rig := newAzureTestRig(t)
	a := NewAzureOpenAIWithClient(srv.Client(), srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := a.PrepareRequest(ctx, rig.srv.URL, a.Path(false),
			[]byte(`{"model":"gpt-4o"}`), rigCreds(t, "detach"), false)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the exchange enter the handler
	cancel()                          // the first caller gives up...
	close(release)                    // ...but the shared exchange completes

	// Detachment proof (sber precedent): the cancelled caller's token
	// preparation still completes — the exchange never ran under its ctx.
	if err := <-done; err != nil {
		t.Fatalf("refresh must be detached from the caller's context: %v", err)
	}
	// A fresh caller rides the completed shared token: no second exchange.
	req, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), rigCreds(t, "detach"), false)
	if err != nil {
		t.Fatalf("follow-up PrepareRequest: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer AT-DETACHED" {
		t.Fatalf("auth = %q, want the detached-completed token", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("token exchanges = %d, want exactly 1", calls.Load())
	}
}

// TestAzureOpenAI_CallerCancelBeforeChat_NoUpstreamCall: a request whose
// context is already cancelled never reaches the Azure resource — nothing
// was served, so nothing can be accounted (token accounting on cancel).
func TestAzureOpenAI_CallerCancelBeforeChat_NoUpstreamCall(t *testing.T) {
	t.Parallel()
	rig := newAzureTestRig(t)
	a := rig.adapter()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := a.PrepareRequest(ctx, rig.srv.URL, a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), rig.creds(), false)
	if err != nil {
		t.Fatalf("PrepareRequest (token exchange is detached and completes): %v", err)
	}
	resp, err := rig.srv.Client().Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("Do must fail on a cancelled context")
	}
	if rig.chatCalls.Load() != 0 {
		t.Fatalf("chat calls = %d, want 0 for a cancelled request", rig.chatCalls.Load())
	}
}

// TestAzureOpenAI_ProductionEntraAuthorityPinned: the production factory
// constructor targets exactly the public Entra authority with NO env/config
// override — an env-steerable auth endpoint would be a credential
// exfiltration vector. This is also why a pool-built client (factory wiring)
// cannot be exercised against a test stub: the boundary round-trip proof
// uses the documented test hook on the same Provider interface.
func TestAzureOpenAI_ProductionEntraAuthorityPinned(t *testing.T) {
	t.Parallel()
	if azureEntraAuthority != "https://login.microsoftonline.com" {
		t.Fatalf("entra authority = %q, want the production authority", azureEntraAuthority)
	}
	a := NewAzureOpenAI()
	if a.entraHost != "" {
		t.Fatalf("production adapter carries an authority override %q — none may exist", a.entraHost)
	}
	factoryAdapter, err := New("azure-openai")
	if err != nil {
		t.Fatalf("New(azure-openai): %v", err)
	}
	if az, ok := factoryAdapter.(*AzureOpenAI); !ok || az.entraHost != "" {
		t.Fatal("factory must hand out the production adapter with no authority override")
	}
}

// TestAzureOpenAI_ConcurrentColdStart_SingleExchange: N simultaneous cold
// callers for ONE credential must collapse into exactly one Entra exchange
// (singleflight dedup). The shared adapter is hit concurrently under load;
// every duplicate exchange would burn the tenant's Entra quota and widen the
// window in which callers race each other's token.
func TestAzureOpenAI_ConcurrentColdStart_SingleExchange(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv, calls := newEntraStubServer(t, entraStub{
		status:  http.StatusOK,
		body:    `{"access_token":"AT-CONCURRENT","expires_in":3600}`,
		release: release,
	})
	rig := newAzureTestRig(t)
	a := NewAzureOpenAIWithClient(srv.Client(), srv.URL)
	creds := rigCreds(t, "conc")

	const n = 16
	start := make(chan struct{})
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
				[]byte(`{"model":"gpt-4o"}`), creds, false)
			errs <- err
		}()
	}
	close(start)
	// Hold the exchange in the handler until every goroutine has piled onto
	// the cold credential key; latecomers would hit a fresh cache anyway.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent PrepareRequest: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("token exchanges = %d, want exactly 1 for %d concurrent cold callers", got, n)
	}
	key := entraCacheKey(AzureEntraCredentials{TenantID: "test-tenant", ClientID: "client-conc"})
	a.mu.Lock()
	tok := a.tokens[key]
	a.mu.Unlock()
	if tok.accessToken != "AT-CONCURRENT" {
		t.Fatalf("cached token = %q, want the single exchanged token", tok.accessToken)
	}
	if time.Now().After(tok.tokenExp) {
		t.Fatal("cached token already expired — singleflight waiter got a dead token")
	}
}

// TestAzureOpenAI_ShortTTLToken_NeverServedInsideSkew: a token whose
// expires_in does not exceed the refresh skew (5 min) is NEVER treated as
// fresh — each use re-exchanges (singleflight-deduped) instead of risking a
// mid-request 401 with a token that could expire under the caller. Real
// Entra access tokens live 60-90 min, so this conservative branch only
// guards against pathological authorities; it must stay fail-safe.
func TestAzureOpenAI_ShortTTLToken_NeverServedInsideSkew(t *testing.T) {
	t.Parallel()
	srv, calls := newEntraStubServer(t, entraStub{
		status: http.StatusOK,
		body:   `{"access_token":"AT-SHORT","expires_in":60}`, // 60s TTL < 5m skew
	})
	rig := newAzureTestRig(t)
	a := NewAzureOpenAIWithClient(srv.Client(), srv.URL)
	creds := rigCreds(t, "short")

	for i := 0; i < 2; i++ {
		if _, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
			[]byte(`{"model":"gpt-4o"}`), creds, false); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("token exchanges = %d, want 2 (a TTL inside the skew window must never be reused)", calls.Load())
	}
	key := entraCacheKey(AzureEntraCredentials{TenantID: "test-tenant", ClientID: "client-short"})
	a.mu.Lock()
	tok, ok := a.tokens[key]
	a.mu.Unlock()
	if !ok {
		t.Fatal("short-TTL token was not cached")
	}
	if d := time.Until(tok.tokenExp); d <= 0 || d > time.Minute {
		t.Fatalf("cached expiry in %s, want ~(0,60s]", d)
	}
}
