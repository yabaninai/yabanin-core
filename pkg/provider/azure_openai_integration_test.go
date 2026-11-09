package provider_test

// Integration through the provider boundary for the Azure
// OpenAI adapter (ratified minimal scope). Honest limits, stated up front:
//
//   - This file makes NO live Azure calls (no quota, no cost): the Entra ID
//     authority and the Azure-shaped OpenAI resource below are httptest
//     STUBS with Azure-shaped wire contracts; they prove the
//     adapter/boundary plumbing, not Microsoft attestation.
//   - The production factory constructor (used by upstream.Pool) pins the
//     Entra authority to login.microsoftonline.com with NO env/config
//     override (deliberate: an env-steerable auth endpoint is a credential
//     exfiltration vector). A pool-built client therefore cannot exchange
//     tokens against a test stub; that pin is asserted separately in the
//     internal test file. The round-trip below uses the SAME Provider
//     interface the pool's clients consume, with the documented test hook.
//
// Residency (D6) is untouched by this card: country semantics stay in
// pkg/policy; pkg/policy/asia_packs/azure_r108_test.go is the pin (green in
// this tree's asia_packs suite).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// azureIntegRig is the production-shaped split: a dedicated Entra authority
// server and a separate Azure OpenAI resource server.
type azureIntegRig struct {
	entra     *httptest.Server
	resource  *httptest.Server
	chatCalls *atomic.Int32
}

func newAzureIntegRig(t *testing.T) *azureIntegRig {
	t.Helper()
	rig := &azureIntegRig{chatCalls: &atomic.Int32{}}

	// Entra ID authority: client-credentials v2.0 endpoint for one tenant.
	entraMux := http.NewServeMux()
	entraMux.HandleFunc("/integ-tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("entra form parse: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.PostForm.Get("scope"); got != "https://cognitiveservices.azure.com/.default" {
			t.Errorf("scope = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT-INTEG",
			"expires_in":   3600,
		})
	})
	rig.entra = httptest.NewServer(entraMux)
	t.Cleanup(rig.entra.Close)

	// Azure-shaped OpenAI resource: deployment-qualified chat completions.
	resMux := http.NewServeMux()
	resMux.HandleFunc("/openai/deployments/gpt-4o/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		rig.chatCalls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer AT-INTEG" {
			t.Errorf("resource auth = %q, want the Entra bearer", got)
		}
		if !strings.Contains(r.URL.RawQuery, "api-version=2024-10-21") {
			t.Errorf("query = %q, want pinned api-version", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"id":"chatcmpl-integ","object":"chat.completion","model":"gpt-4o",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":120,"completion_tokens":30,"total_tokens":150}}`))
	})
	resMux.HandleFunc("/openai/deployments/expired-deploy/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		rig.chatCalls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"401","message":"Access token expired"}}`))
	})
	rig.resource = httptest.NewServer(resMux)
	t.Cleanup(rig.resource.Close)
	return rig
}

func (r *azureIntegRig) creds() string {
	// Runtime-assembled fake credential (gosec G101 hygiene).
	return fmt.Sprintf(`{"tenant_id":%q,"client_id":%q,"client_secret":%q}`,
		"integ-tenant", "integ-client", "fake-integ-3c9b")
}

// TestAzureOpenAI_Integration_FullRoundTrip_ThroughProviderBoundary drives
// the exact consumption sequence pkg/upstream.Client.forward performs —
// TranslateRequest, the gateway's model override to the registry model_name
// (which doubles as the deployment), PrepareRequest, the HTTP round trip,
// TranslateResponse, ParseUsage, and pricing — entirely through the
// exported provider.Provider interface.
func TestAzureOpenAI_Integration_FullRoundTrip_ThroughProviderBoundary(t *testing.T) {
	rig := newAzureIntegRig(t)
	var p provider.Provider = provider.NewAzureOpenAIWithClient(rig.entra.Client(), rig.entra.URL)

	// 1. Client-visible body names a client model; the gateway overrides it.
	translated, err := p.TranslateRequest([]byte(`{"model":"client-model-x","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	translated = upstream.OverrideModel(translated, "gpt-4o")

	// 2. PrepareRequest: deployment-qualified URL + Entra bearer.
	req, err := p.PrepareRequest(context.Background(), rig.resource.URL, p.Path(false), translated, rig.creds(), false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}

	// 3. Real HTTP round trip to the Azure-shaped resource.
	resp, err := rig.resource.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	// 4. Translate + account through the interface.
	out, err := p.TranslateResponse(body)
	if err != nil {
		t.Fatalf("TranslateResponse: %v", err)
	}
	usage := p.ParseUsage(out)
	if usage.PromptTokens != 120 || usage.CompletionTokens != 30 || usage.TotalTokens != 150 {
		t.Fatalf("usage = %+v, want 120/30/150 from the resource", usage)
	}
	if usage.Source != provider.UsageSourceProvider {
		t.Fatalf("source = %q, want provider", usage.Source)
	}

	// 5. Pricing honesty through the alias: known deployment prices, unknown
	// stays unknown (never a silent zero). The fixture default carries
	// azure:gpt-4o explicitly (see azureAliasPricedDefault in
	// azure_openai_test.go): post CORE-REF-04 the shipped default has no
	// azure entries.
	azureAliasPricedDefault(t)
	ext := provider.ComputeCost(usage, "azure-openai", "gpt-4o")
	if !ext.PriceKnown {
		t.Fatal("azure-openai:gpt-4o must price via the alias in the integrated path")
	}
	extUnknown := provider.ComputeCost(usage, "azure-openai", "integ-unknown-deploy")
	if extUnknown.PriceKnown || extUnknown.EstimatedCostUSD != 0 {
		t.Fatalf("unknown deployment = known/%v, want unknown/0 (never free)", extUnknown.EstimatedCostUSD)
	}
	if rig.chatCalls.Load() != 1 {
		t.Fatalf("chat calls = %d, want 1", rig.chatCalls.Load())
	}
}

// TestAzureOpenAI_Integration_ExpiredTokenMidFlight_SurfacedNotFaked: the
// resource rejecting a (stale) bearer mid-flight is surfaced as-is — status
// plus Azure error body — and the error body accounts ZERO usage.
func TestAzureOpenAI_Integration_ExpiredTokenMidFlight_SurfacedNotFaked(t *testing.T) {
	rig := newAzureIntegRig(t)
	var p provider.Provider = provider.NewAzureOpenAIWithClient(rig.entra.Client(), rig.entra.URL)

	translated := upstream.OverrideModel([]byte(`{"model":"x"}`), "expired-deploy")
	req, err := p.PrepareRequest(context.Background(), rig.resource.URL, p.Path(false), translated, rig.creds(), false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	resp, err := rig.resource.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 surfaced", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Access token expired") {
		t.Fatalf("body = %q, want the Azure error message surfaced", body)
	}
	if u := p.ParseUsage(body); u.TotalTokens != 0 || u.Source != provider.UsageSourceNone {
		t.Fatalf("usage from 401 body = %+v, want zeros/none", u)
	}
}

// TestAzureOpenAI_Integration_PoolFactoryWiring: the real upstream pool +
// provider factory wiring. Get(url, "azure-openai") must build a client
// whose adapter is the Azure OpenAI adapter, shared across Get calls (the
// multi-tenant reality). The other cloud providers are registry stubs only —
// the pool must REFUSE them (unsupported не обещан). No network is performed
// by this test.
func TestAzureOpenAI_Integration_PoolFactoryWiring(t *testing.T) {
	rig := newAzureIntegRig(t)
	pool := upstream.NewPool(upstream.Options{
		BaseURL:          rig.resource.URL,
		ProviderName:     "azure-openai",
		AllowedUpstreams: []string{rig.resource.URL},
	})

	c1, err := pool.Get(rig.resource.URL, "azure-openai")
	if err != nil {
		t.Fatalf("pool.Get(azure-openai): %v", err)
	}
	if c1.Adapter().Name() != "azure-openai" {
		t.Fatalf("adapter = %q, want azure-openai", c1.Adapter().Name())
	}
	c2, err := pool.Get(rig.resource.URL, "azure-openai")
	if err != nil {
		t.Fatalf("second pool.Get: %v", err)
	}
	if c1 != c2 {
		t.Fatal("pool must share one client (hence one adapter) per (provider, url) — the multi-tenant reality")
	}

	// N08-P03-T02 (vertex) and N08-P02 (bedrock) each promoted their
	// provider from stub to a native adapter; no registry stub remains
	// routable here. Their pool routing lives in their own integration
	// tests (vertex_test.go / bedrock integration), and both factories
	// must produce adapters now.
	for _, real := range []string{"vertex", "bedrock"} {
		if _, err := provider.New(real); err != nil {
			t.Fatalf("factory must produce a %s adapter: %v", real, err)
		}
	}
}
