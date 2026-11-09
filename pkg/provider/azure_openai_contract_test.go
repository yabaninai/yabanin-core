package provider_test

// N08-P01-T03 — tenant-keyed token cache: CONTRACT and LIVE SMOKE through
// the exported provider.Provider interface (the surface pkg/upstream
// clients consume).
//
// Contract (deterministic, always runs): one SHARED adapter — the upstream
// Pool reality of one client per (provider, URL) — serves requests from
// multiple orgs, each carrying its OWN credential blob per request. Every
// wire request must bear the calling org's own Entra token, cached per
// tenant+client, with per-identity usage/pricing downstream.
//
// Live smoke (env-gated, cost-limited): the packet acceptance names "live
// smoke при лимите затрат". On this stand there is NO network egress and NO
// owner-approved Azure tenant/quota, so the smoke is GATED behind explicit
// environment credentials and skips LOUDLY when they are absent — the skip
// is a documented, honest limitation (see
// artifacts/internal-delivery-program/N08-P01/N08-P01-T03-record-2026-10-30.md), NOT a
// silent pass: the deterministic contract suite above carries the wire
// contract here. When the gate IS satisfied (operator-supplied real
// credentials), the smoke performs exactly one minimal completion with a
// hard spend ceiling asserted from the response's own usage accounting.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// azureAliasPricedDefault installs the deterministic alias fixture as the
// process-global default pricer for the duration of the test: a small file
// snapshot carrying azure:gpt-4o at the historical catalog rates (2.5/10,
// cache read 1.25). Since CORE-REF-04 the shipped default serves the
// reference catalog projection (the three verified nebius arms), which has
// no azure entries — the alias-mechanism pins must not depend on which
// snapshot ships, so the fixture carries its rate explicitly. The pristine
// static chain is restored on cleanup. Mirrors the same-package helper in
// azure_openai_test.go (internal test binary cannot share test helpers
// across the internal/external split).
//
// The tests using this helper run sequentially: swapping the process-global
// default while sibling parallel tests read it would be a data race.
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

// azureContractRig: one shared Entra authority (two tenants, distinct
// deterministic tokens) + one Azure-shaped resource that echoes the received
// Authorization header back inside the response (so the test can assert, per
// call, WHICH org's token reached the wire through the exported interface).
type azureContractRig struct {
	entra      *httptest.Server
	resource   *httptest.Server
	entraCalls atomic.Int32 // total token exchanges across BOTH tenants
	authSeen   []string     // bearer received per chat call, in order
}

func newAzureContractRig(t *testing.T) *azureContractRig {
	t.Helper()
	rig := &azureContractRig{}
	entraMux := http.NewServeMux()
	tokenFor := map[string]string{"tenant-con-a": "AT-CON-A", "tenant-con-b": "AT-CON-B"}
	for tenant := range tokenFor {
		token := tokenFor[tenant] // per-iteration capture
		entraMux.HandleFunc("/"+tenant+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
			rig.entraCalls.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Errorf("entra form parse: %v", err)
			}
			if r.PostForm.Get("client_id") == "" {
				t.Errorf("exchange for %q carries empty client_id", tenant)
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": token,
				"expires_in":   3600,
			})
		})
	}
	rig.entra = httptest.NewServer(entraMux)
	t.Cleanup(rig.entra.Close)

	resMux := http.NewServeMux()
	resMux.HandleFunc("/openai/deployments/gpt-4o/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		rig.authSeen = append(rig.authSeen, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"id":"chatcmpl-con","object":"chat.completion","model":"gpt-4o",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":11,"completion_tokens":2,"total_tokens":13}}`))
	})
	rig.resource = httptest.NewServer(resMux)
	t.Cleanup(rig.resource.Close)
	return rig
}

func (r *azureContractRig) creds(t *testing.T, tenant, client, secret string) string {
	t.Helper()
	// Runtime-assembled fixtures (gosec G101 hygiene; never real values).
	return fmt.Sprintf(`{"tenant_id":%q,"client_id":%q,"client_secret":%q}`, tenant, client, secret)
}

// driveOnce performs the exact pkg/upstream consumption sequence for one
// org's credential and returns the usage the gateway would account.
func driveOnce(t *testing.T, p provider.Provider, rig *azureContractRig, creds string) provider.Usage {
	t.Helper()
	translated, err := p.TranslateRequest([]byte(`{"model":"client-model-x","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	translated = upstream.OverrideModel(translated, "gpt-4o")
	req, err := p.PrepareRequest(context.Background(), rig.resource.URL, p.Path(false), translated, creds, false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	resp, err := rig.resource.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out, err := p.TranslateResponse(body)
	if err != nil {
		t.Fatalf("TranslateResponse: %v", err)
	}
	return p.ParseUsage(out)
}

// TestAzureOpenAI_Contract_SharedAdapter_MultiOrgCredentials: the tenant
// cache contract through the exported boundary — a shared adapter, orgs
// alternating per request, each wire call bearing the calling org's own
// token, exchanges deduped per identity, accounting and pricing intact for
// both orgs.
func TestAzureOpenAI_Contract_SharedAdapter_MultiOrgCredentials(t *testing.T) {
	rig := newAzureContractRig(t)
	// ONE adapter instance = the shared multi-tenant reality.
	var p provider.Provider = provider.NewAzureOpenAIWithClient(rig.entra.Client(), rig.entra.URL)

	orgA := rig.creds(t, "tenant-con-a", "client-con-a", "fake-con-a-2e51")
	orgB := rig.creds(t, "tenant-con-b", "client-con-b", "fake-con-b-5b93")

	// Alternate orgs; repeats must ride the per-identity cache.
	seq := []struct {
		org   string
		creds string
		want  string
	}{
		{"A", orgA, "Bearer AT-CON-A"},
		{"B", orgB, "Bearer AT-CON-B"},
		{"A", orgA, "Bearer AT-CON-A"},
		{"B", orgB, "Bearer AT-CON-B"},
	}
	for i, step := range seq {
		usage := driveOnce(t, p, rig, step.creds)
		if usage.TotalTokens != 13 || usage.Source != provider.UsageSourceProvider {
			t.Fatalf("step %d (org %s): usage = %+v, want 13/provider", i, step.org, usage)
		}
		if got := rig.authSeen[i]; got != step.want {
			t.Fatalf("step %d (org %s): wire auth = %q, want %q (cross-org token use!)",
				i, step.org, got, step.want)
		}
	}
	if len(rig.authSeen) != len(seq) {
		t.Fatalf("chat calls = %d, want %d", len(rig.authSeen), len(seq))
	}
	// Two identities, four requests: exactly two exchanges (one per org).
	if got := rig.entraCalls.Load(); got != 2 {
		t.Fatalf("entra exchanges = %d, want 2 (one per org identity)", got)
	}
	// Pricing honesty for both orgs through the same adapter. The fixture
	// default carries azure:gpt-4o explicitly (see
	// azureAliasPricedDefault in azure_openai_test.go): post CORE-REF-04
	// the shipped default has no azure entries.
	azureAliasPricedDefault(t)
	for _, deploy := range []string{"gpt-4o"} {
		ext := provider.ComputeCost(provider.Usage{PromptTokens: 11, CompletionTokens: 2}, "azure-openai", deploy)
		if !ext.PriceKnown {
			t.Fatalf("azure-openai:%s must price via the catalog alias", deploy)
		}
	}
}

// azureLiveSmokeEnv enumerates the environment contract of the gated live
// smoke (documented here and in the record file).
type azureLiveSmokeEnv struct {
	endpoint     string
	deployment   string
	tenantID     string
	clientID     string
	clientSecret string
}

// TestAzureOpenAI_LiveSmoke_EnvGated_CostLimited — the packet's "live smoke
// при лимите затрат", honestly gated:
//
//	skip conditions (loud, never silent):
//	  AZURE_OPENAI_LIVE_SMOKE != "1"      → skipped: live smoke not armed on
//	                                        this stand (no egress, no
//	                                        owner-approved tenant/spend).
//	  any AZURE_OPENAI_LIVE_{ENDPOINT,
//	  DEPLOYMENT,TENANT_ID,CLIENT_ID,
//	  CLIENT_SECRET} missing             → skipped with the exact missing names.
//	failure conditions (never skipped):
//	  AZURE_OPENAI_LIVE_MAX_USD unparsable → FAIL (a broken spend limit must
//	                                         not silently widen).
//	  accounted spend > limit              → FAIL (cost-limit breach).
//	  secret material in any error         → FAIL (packet negative).
func TestAzureOpenAI_LiveSmoke_EnvGated_CostLimited(t *testing.T) {
	if os.Getenv("AZURE_OPENAI_LIVE_SMOKE") != "1" {
		t.Skip("LIVE SMOKE UNAVAILABLE ON THIS STAND (loud-skip, documented): " +
			"AZURE_OPENAI_LIVE_SMOKE != 1 — no network egress and no owner-approved " +
			"Azure tenant/quota/spend authorization here. The deterministic contract " +
			"suite (TestAzureOpenAI_Contract_SharedAdapter_MultiOrgCredentials and the " +
			"pkg/provider stub suites) carries the wire contract. To arm the smoke on a " +
			"networked stand: AZURE_OPENAI_LIVE_SMOKE=1 plus AZURE_OPENAI_LIVE_ENDPOINT, " +
			"AZURE_OPENAI_LIVE_DEPLOYMENT, AZURE_OPENAI_LIVE_TENANT_ID, " +
			"AZURE_OPENAI_LIVE_CLIENT_ID, AZURE_OPENAI_LIVE_CLIENT_SECRET, and optionally " +
			"AZURE_OPENAI_LIVE_MAX_USD (default 0.05). See " +
			"artifacts/internal-delivery-program/N08-P01/N08-P01-T03-record-2026-10-30.md.")
	}
	env := azureLiveSmokeEnv{
		endpoint:     os.Getenv("AZURE_OPENAI_LIVE_ENDPOINT"),
		deployment:   os.Getenv("AZURE_OPENAI_LIVE_DEPLOYMENT"),
		tenantID:     os.Getenv("AZURE_OPENAI_LIVE_TENANT_ID"),
		clientID:     os.Getenv("AZURE_OPENAI_LIVE_CLIENT_ID"),
		clientSecret: os.Getenv("AZURE_OPENAI_LIVE_CLIENT_SECRET"),
	}
	var missing []string
	for _, kv := range []struct {
		name string
		val  string
	}{
		{"AZURE_OPENAI_LIVE_ENDPOINT", env.endpoint},
		{"AZURE_OPENAI_LIVE_DEPLOYMENT", env.deployment},
		{"AZURE_OPENAI_LIVE_TENANT_ID", env.tenantID},
		{"AZURE_OPENAI_LIVE_CLIENT_ID", env.clientID},
		{"AZURE_OPENAI_LIVE_CLIENT_SECRET", env.clientSecret},
	} {
		if strings.TrimSpace(kv.val) == "" {
			missing = append(missing, kv.name)
		}
	}
	if len(missing) > 0 {
		t.Skipf("LIVE SMOKE ARMED BUT INCOMPLETE (loud-skip): missing %s — set them with "+
			"owner-approved credentials; the deterministic contract suite carries the "+
			"wire contract meanwhile.", strings.Join(missing, ", "))
	}
	maxUSD := 0.05 // the cost limit: one minimal completion stays orders below it
	if raw := os.Getenv("AZURE_OPENAI_LIVE_MAX_USD"); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil || parsed <= 0 {
			t.Fatalf("AZURE_OPENAI_LIVE_MAX_USD = %q must be a positive number — a broken "+
				"spend limit must not silently widen (cost-limit contract)", raw)
		}
		maxUSD = parsed
	}

	// Production constructor: real Entra authority pin, SSRF-guarded
	// exchange client.
	var p provider.Provider = provider.NewAzureOpenAI()
	creds := fmt.Sprintf(`{"tenant_id":%q,"client_id":%q,"client_secret":%q}`,
		env.tenantID, env.clientID, env.clientSecret)

	translated, err := p.TranslateRequest([]byte(`{"model":"client-model-x","messages":[{"role":"user","content":"ping"}],"max_tokens":1}`))
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	translated = upstream.OverrideModel(translated, env.deployment)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := p.PrepareRequest(ctx, env.endpoint, p.Path(false), translated, creds, false)
	if err != nil {
		if strings.Contains(err.Error(), env.clientSecret) || strings.Contains(err.Error(), env.clientID) {
			t.Fatalf("PrepareRequest error leaks credential material: %v", err)
		}
		t.Fatalf("PrepareRequest (live): %v", err)
	}
	firstAuth := req.Header.Get("Authorization")
	if !strings.HasPrefix(firstAuth, "Bearer ") || len(firstAuth) <= len("Bearer ") {
		t.Fatalf("live Authorization = %q, want a non-empty Entra bearer", firstAuth)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), env.clientSecret) {
			t.Fatalf("live transport error leaks secret: %v", err)
		}
		t.Fatalf("live Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read live body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("live smoke status = %d body=%q — the operator-approved deployment "+
			"must answer 200 under the pinned api-version", resp.StatusCode, body)
	}
	out, err := p.TranslateResponse(body)
	if err != nil {
		t.Fatalf("TranslateResponse (live): %v", err)
	}
	usage := p.ParseUsage(out)
	if usage.Source != provider.UsageSourceProvider || usage.TotalTokens <= 0 {
		t.Fatalf("live usage = %+v, want provider-sourced positive totals", usage)
	}
	ext := provider.ComputeCost(usage, "azure-openai", env.deployment)
	if ext.EstimatedCostUSD > maxUSD {
		t.Fatalf("COST LIMIT BREACH: accounted $%.6f > limit $%.6f (usage %+v, PriceKnown=%v) "+
			"— live smoke fails closed on overspend", ext.EstimatedCostUSD, maxUSD, usage, ext.PriceKnown)
	}

	// Tenant-keyed cache observable live: a second prepared request for the
	// SAME credential must serve the SAME bearer from the cache slot
	// (identity-keyed reuse), not mint another token.
	req2, err := p.PrepareRequest(ctx, env.endpoint, p.Path(false), translated, creds, false)
	if err != nil {
		t.Fatalf("second PrepareRequest (live): %v", err)
	}
	if got := req2.Header.Get("Authorization"); got != firstAuth {
		t.Fatalf("second live bearer = %q, want the SAME cached token %q (cache must be "+
			"identity-keyed and reused)", got, firstAuth)
	}
}
