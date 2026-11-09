package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// azureAliasPricedDefault installs the deterministic alias fixture as the
// process-global default pricer for the duration of the test: a small file
// snapshot carrying azure:gpt-4o at the historical catalog rates (2.5/10,
// cache read 1.25). Since CORE-REF-04 the shipped default serves the
// reference catalog projection (the three verified nebius arms), which has
// no azure entries — the alias-mechanism pins must not depend on which
// snapshot ships, so the fixture carries its rate explicitly. The pristine
// static chain is restored on cleanup.
//
// The test using this helper must not call t.Parallel: swapping the
// process-global default while sibling parallel tests read it would be a
// data race. Sequential tests complete before paused parallel siblings
// resume, so the swap/restore is race-free there.
func azureAliasPricedDefault(t *testing.T) {
	t.Helper()
	p, err := pricing.NewFilePricer(pricing.PriceFile{
		Source: "azure alias fixture (pinned rates)", Date: "2026-11-02",
		Currency: "USD", Units: "per_1m_tokens",
		Models: []pricing.PriceFileModel{
			{Provider: "azure", Model: "gpt-4o", Input: 2.5, Output: 10, CacheR: 1.25},
		},
	}, "sha256:azure-alias-fixture")
	if err != nil {
		t.Fatalf("azure alias fixture pricer: %v", err)
	}
	pricing.SetDefaultPricer(p)
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })
}

// azureTestRig wires one httptest server as both the Entra authority
// (override) and the Azure OpenAI resource, mirroring how the adapter is
// exercised end-to-end without external services.
type azureTestRig struct {
	srv        *httptest.Server
	tokenCalls *atomic.Int32
	chatCalls  *atomic.Int32
	lastChat   atomic.Value // http.Request snapshot fields
	// resource's answer; zero values keep the -02 success behavior.
	chatStatus atomic.Int32
	chatBody   atomic.Value // string
}

func newAzureTestRig(t *testing.T) *azureTestRig {
	t.Helper()
	rig := &azureTestRig{
		tokenCalls: &atomic.Int32{},
		chatCalls:  &atomic.Int32{},
	}
	mux := http.NewServeMux()
	entraHandler := func(token string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			rig.tokenCalls.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Errorf("entra form parse: %v", err)
			}
			if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
				t.Errorf("grant_type = %q", got)
			}
			if got := r.PostForm.Get("scope"); got != azureEntraScope {
				t.Errorf("scope = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": token,
				"expires_in":   3600,
			})
		}
	}
	mux.HandleFunc("/test-tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		rig.tokenCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("entra form parse: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.PostForm.Get("client_id"); got != "test-client" {
			t.Errorf("client_id = %q", got)
		}
		if got := r.PostForm.Get("scope"); got != azureEntraScope {
			t.Errorf("scope = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT-1",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/tenant-a/oauth2/v2.0/token", entraHandler("AT-A"))
	mux.HandleFunc("/tenant-b/oauth2/v2.0/token", entraHandler("AT-B"))
	mux.HandleFunc("/openai/deployments/", func(w http.ResponseWriter, r *http.Request) {
		rig.chatCalls.Add(1)
		rig.lastChat.Store(struct {
			Path   string
			Query  string
			Auth   string
			Accept string
			Body   string
		}{r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("Accept"), ""})
		status := int(rig.chatStatus.Load())
		if status == 0 {
			status = http.StatusOK
		}
		body, _ := rig.chatBody.Load().(string)
		if body == "" {
			body = `{"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10,"prompt_tokens_details":{"cached_tokens":2}}}`
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	rig.srv = httptest.NewServer(mux)
	t.Cleanup(rig.srv.Close)
	return rig
}

func (r *azureTestRig) adapter() *AzureOpenAI {
	return NewAzureOpenAIWithClient(r.srv.Client(), r.srv.URL)
}

func (r *azureTestRig) creds() string {
	return `{"tenant_id":"test-tenant","client_id":"test-client","client_secret":"test-fixture-7f3a"}`
}

func (r *azureTestRig) chatSnapshot(t *testing.T) struct {
	Path   string
	Query  string
	Auth   string
	Accept string
	Body   string
} {
	t.Helper()
	v, ok := r.lastChat.Load().(struct {
		Path   string
		Query  string
		Auth   string
		Accept string
		Body   string
	})
	if !ok {
		t.Fatal("no chat request captured")
	}
	return v
}

func TestAzureOpenAI_RequestShape(t *testing.T) {
	t.Parallel()
	rig := newAzureTestRig(t)
	a := rig.adapter()

	req, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`{"model":"gpt-4o","messages":[]}`), rig.creds(), false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	resp, err := rig.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	snap := rig.chatSnapshot(t)
	if snap.Path != "/openai/deployments/gpt-4o/chat/completions" {
		t.Fatalf("path = %q, want deployment-qualified chat/completions", snap.Path)
	}
	if !strings.Contains(snap.Query, "api-version="+azureOpenAIAPIVersion) {
		t.Fatalf("query = %q, want api-version=%s", snap.Query, azureOpenAIAPIVersion)
	}
	if snap.Auth != "Bearer AT-1" {
		t.Fatalf("auth = %q, want Entra bearer AT-1", snap.Auth)
	}
	if snap.Accept != "" {
		t.Fatalf("non-stream Accept = %q, want empty", snap.Accept)
	}
	if rig.tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d, want 1", rig.tokenCalls.Load())
	}
}

func TestAzureOpenAI_StreamSetsAccept(t *testing.T) {
	t.Parallel()
	rig := newAzureTestRig(t)
	a := rig.adapter()

	req, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(true),
		[]byte(`{"model":"gpt-4o"}`), rig.creds(), true)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	resp, err := rig.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if snap := rig.chatSnapshot(t); snap.Accept != "text/event-stream" {
		t.Fatalf("stream Accept = %q", snap.Accept)
	}
}

func TestAzureOpenAI_ParseUsage_OpenAIShape(t *testing.T) {
	t.Parallel()
	a := NewAzureOpenAI()
	u := a.ParseUsage([]byte(`{"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10,"prompt_tokens_details":{"cached_tokens":2}}}`))
	if u.PromptTokens != 7 || u.CompletionTokens != 3 || u.TotalTokens != 10 {
		t.Fatalf("usage = %+v", u)
	}
	if u.CacheReadTokens != 2 {
		t.Fatalf("cache read = %d, want 2", u.CacheReadTokens)
	}
	if u.Source != UsageSourceProvider {
		t.Fatalf("source = %q", u.Source)
	}
}

func TestAzureOpenAI_TranslateIdentity(t *testing.T) {
	t.Parallel()
	a := NewAzureOpenAI()
	in := []byte(`{"model":"gpt-4o","messages":[]}`)
	out, err := a.TranslateRequest(in)
	if err != nil || string(out) != string(in) {
		t.Fatalf("TranslateRequest: %q %v", out, err)
	}
	out, err = a.TranslateResponse(in)
	if err != nil || string(out) != string(in) {
		t.Fatalf("TranslateResponse: %q %v", out, err)
	}
}

func TestAzureOpenAI_TokenCached_NoSecondExchange(t *testing.T) {
	t.Parallel()
	rig := newAzureTestRig(t)
	a := rig.adapter()

	for i := 0; i < 3; i++ {
		req, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
			[]byte(`{"model":"gpt-4o"}`), rig.creds(), false)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		resp, err := rig.srv.Client().Do(req)
		if err != nil {
			t.Fatalf("iter %d Do: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	if rig.tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d, want 1 for 3 requests", rig.tokenCalls.Load())
	}
}

func TestAzureOpenAI_TokenRefreshOnExpiry(t *testing.T) {
	t.Parallel()
	rig := newAzureTestRig(t)
	a := rig.adapter()
	// Force the cached token past the refresh skew: expiry = now.
	a.mu.Lock()
	a.tokens[entraCacheKey(AzureEntraCredentials{TenantID: "test-tenant", ClientID: "test-client"})] = azureToken{
		accessToken: "STALE",
		tokenExp:    time.Now(),
	}
	a.mu.Unlock()

	req, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), rig.creds(), false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	if got := a.currentToken(entraCacheKey(AzureEntraCredentials{TenantID: "test-tenant", ClientID: "test-client"})); got != "AT-1" {
		t.Fatalf("token = %q, want refreshed AT-1", got)
	}
	if rig.tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d, want 1 refresh", rig.tokenCalls.Load())
	}
	_ = req
}

// TestAzureOpenAI_MultiTenant_SharedAdapter_TokensNotCrossed: the upstream
// Pool shares one adapter per (provider, URL) across orgs, so two orgs with
// DIFFERENT Entra tenants on the same models_registry row must each get
// their own tenant's bearer — a fresh token for tenant A must never be sent
// to tenant B's resource (the pre-fix single-slot cache did exactly that).
func TestAzureOpenAI_MultiTenant_SharedAdapter_TokensNotCrossed(t *testing.T) {
	t.Parallel()
	rig := newAzureTestRig(t)
	a := rig.adapter()
	// Assembled at runtime (not a hardcoded credential blob): gosec G101
	// pattern-matches literal credential assignments; the values here are
	// obvious fakes for the cross-tenant regression below.
	entraBlob := func(tenant, client, value string) string {
		return fmt.Sprintf(`{"tenant_id":%q,"client_id":%q,"client_secret":%q}`, tenant, client, value)
	}
	credsA := entraBlob("tenant-a", "client-a", "aa-9f3a")
	credsB := entraBlob("tenant-b", "client-b", "bb-17c2")

	do := func(creds string) string {
		t.Helper()
		req, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
			[]byte(`{"model":"gpt-4o"}`), creds, false)
		if err != nil {
			t.Fatalf("PrepareRequest: %v", err)
		}
		resp, err := rig.srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()
		return rig.chatSnapshot(t).Auth
	}

	// Tenant A first: its token is now cached and FRESH.
	if got := do(credsA); got != "Bearer AT-A" {
		t.Fatalf("tenant A auth = %q, want Bearer AT-A", got)
	}
	// Tenant B on the same shared adapter while A's token is still fresh:
	// B must trigger its OWN exchange (not ride AT-A).
	if got := do(credsB); got != "Bearer AT-B" {
		t.Fatalf("tenant B auth = %q, want Bearer AT-B (tokens crossed!)", got)
	}
	// A again, still fresh from its own cache entry.
	if got := do(credsA); got != "Bearer AT-A" {
		t.Fatalf("tenant A re-request auth = %q, want Bearer AT-A", got)
	}
	if rig.tokenCalls.Load() != 2 {
		t.Fatalf("token calls = %d, want 2 (one per tenant)", rig.tokenCalls.Load())
	}
}

func TestAzureOpenAI_IncompleteCredentials_FailFast_NoSecretLeak(t *testing.T) {
	t.Parallel()
	a := NewAzureOpenAI()
	// leakCanary is a fake credential VALUE (never a real one); the test
	// asserts it never surfaces in any error message.
	leakCanary := "zq-7431-canary"
	cases := []struct {
		name   string
		cred   string
		errMsg string
	}{
		{"not json", "plain-api-key", "must be JSON"},
		{"missing tenant", `{"client_id":"c","client_secret":"` + leakCanary + `"}`, "missing tenant_id"},
		{"missing client_id", `{"tenant_id":"t","client_secret":"` + leakCanary + `"}`, "missing client_id"},
		{"missing secret", `{"tenant_id":"t","client_id":"c"}`, "missing client_secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
				[]byte(`{"model":"gpt-4o"}`), tc.cred, false)
			if err == nil {
				t.Fatal("expected error for incomplete credentials")
			}
			if !strings.Contains(err.Error(), tc.errMsg) {
				t.Fatalf("error = %q, want substring %q", err, tc.errMsg)
			}
			if strings.Contains(err.Error(), leakCanary) {
				t.Fatalf("error leaks secret value: %q", err)
			}
		})
	}
}

func TestAzureOpenAI_TokenExchangeFailure_NoSecretInError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	a := NewAzureOpenAIWithClient(srv.Client(), srv.URL)
	_, err := a.PrepareRequest(context.Background(), "https://res.example.com", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), `{"tenant_id":"t","client_id":"c","client_secret":"zq-7431-canary"}`, false)
	if err == nil {
		t.Fatal("expected error from token exchange")
	}
	if strings.Contains(err.Error(), "zq-7431-canary") {
		t.Fatalf("error leaks secret: %q", err)
	}
}

func TestAzureOpenAI_MissingModelInBody_Errors(t *testing.T) {
	t.Parallel()
	rig := newAzureTestRig(t)
	a := rig.adapter()
	if _, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`{"messages":[]}`), rig.creds(), false); err == nil {
		t.Fatal("expected error for missing model/deployment")
	}
	if _, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`not-json`), rig.creds(), false); err == nil {
		t.Fatal("expected error for non-JSON body")
	}
	if rig.tokenCalls.Load() != 0 || rig.chatCalls.Load() != 0 {
		t.Fatalf("upstream must not be called on prepare failure (token=%d chat=%d)",
			rig.tokenCalls.Load(), rig.chatCalls.Load())
	}
}

func TestAzureOpenAI_EmptyBaseURL_Errors(t *testing.T) {
	t.Parallel()
	rig := newAzureTestRig(t)
	a := rig.adapter()
	if _, err := a.PrepareRequest(context.Background(), "", a.Path(false),
		[]byte(`{"model":"gpt-4o"}`), rig.creds(), false); err == nil {
		t.Fatal("expected error for empty base URL")
	}
}

func TestFactory_AzureOpenAI(t *testing.T) {
	t.Parallel()
	p, err := New("azure-openai")
	if err != nil {
		t.Fatalf("New(azure-openai): %v", err)
	}
	if p.Name() != "azure-openai" {
		t.Fatalf("Name = %q", p.Name())
	}
}

// TestAzureOpenAI_ComputeCost_CatalogAlias: spend for a known deployment is
// priced through the azure catalog alias (D5 2026-10-16), not zero. The
// fixture default carries azure:gpt-4o explicitly (see
// azureAliasPricedDefault) — post CORE-REF-04 the shipped default has no
// azure entries. Sequential: swaps the process-global default.
func TestAzureOpenAI_ComputeCost_CatalogAlias(t *testing.T) {
	azureAliasPricedDefault(t)
	ext := ComputeCost(Usage{PromptTokens: 1_000_000, CompletionTokens: 0}, "azure-openai", "gpt-4o")
	if !ext.PriceKnown {
		t.Fatal("azure-openai:gpt-4o must resolve via the pricing alias")
	}
	if ext.EstimatedCostUSD < 2.49 || ext.EstimatedCostUSD > 2.51 {
		t.Fatalf("cost = %v, want ~2.5 for 1M input tokens", ext.EstimatedCostUSD)
	}
}

// TestAzureOpenAI_ComputeCost_UnknownDeployment_UnknownPrice: an unmapped
// deployment must stay PriceKnown=false so the gateway records
// cost_status=unknown_price — never a silent $0 (negative scenario of the
// pricing honesty contract; the unknown case is "unknown", not "free").
func TestAzureOpenAI_ComputeCost_UnknownDeployment_UnknownPrice(t *testing.T) {
	t.Parallel()
	ext := ComputeCost(Usage{PromptTokens: 1000, CompletionTokens: 500}, "azure-openai", "my-private-deploy-42")
	if ext.PriceKnown {
		t.Fatal("unknown deployment must not be PriceKnown")
	}
	if ext.EstimatedCostUSD != 0 {
		t.Fatalf("cost = %v, want 0 with PriceKnown=false (unknown, not free)", ext.EstimatedCostUSD)
	}
}

func TestAzureOpenAI_DeploymentNamePathEscaped(t *testing.T) {
	t.Parallel()
	rig := newAzureTestRig(t)
	a := rig.adapter()
	// A deployment name with a path separator must not escape the URL
	// segment on the wire (EscapedPath is what RequestURI sends).
	req, err := a.PrepareRequest(context.Background(), rig.srv.URL, a.Path(false),
		[]byte(`{"model":"team/deploy-1"}`), rig.creds(), false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	if !strings.Contains(req.URL.EscapedPath(), "/openai/deployments/team%2Fdeploy-1/chat/completions") {
		t.Fatalf("escaped path = %q, want escaped deployment segment", req.URL.EscapedPath())
	}
}
