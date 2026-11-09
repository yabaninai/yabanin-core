package cli

// ratified contract: categories/scores passthrough, input form validation
// (string or array ≤256), explicit unsupported provider (D2), honest no_usage
// without a usage block (D3), and residency refusal before any upstream call
// (tenant isolation, contract example 3).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// TestModerations_HappyPathCategoriesPassthrough is the contract's working
// example 1 (moderations twin): the classification payload crosses the
// gateway byte-identically, the event reports the real provider usage and an
// honest unknown_price (no moderations price rows exist yet, D3).
func TestModerations_HappyPathCategoriesPassthrough(t *testing.T) {
	const upstreamBody = `{"id":"mod-1","model":"omni-moderation-canon","results":[` +
		`{"flagged":true,"categories":{"violence":true},"category_scores":{"violence":0.91}}],` +
		`"usage":{"prompt_tokens":9,"total_tokens":9}}`
	var upstreamPath atomic.Value
	var upstreamBodyGot atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath.Store(r.URL.Path)
		raw, _ := io.ReadAll(r.Body)
		upstreamBodyGot.Store(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer server.Close()

	info := resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := r105TestGateway(t, info)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postR105(t, gw, "/v1/moderations", `{"model":"m","input":"some text to classify"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(rec.Body.String()) != upstreamBody {
		t.Fatalf("passthrough body %q", rec.Body.String())
	}
	if got := upstreamPath.Load(); got != "/v1/moderations" {
		t.Fatalf("upstream path %v", got)
	}
	if body, _ := upstreamBodyGot.Load().(string); !strings.Contains(body, `"model":"omni-moderation-canon"`) ||
		!strings.Contains(body, `"input":"some text to classify"`) {
		t.Fatalf("upstream body %q", body)
	}
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.Endpoint != "moderations" || ev.TokensIn != 9 || ev.TokensOut != 0 {
		t.Fatalf("event endpoint/tokens: %+v", ev)
	}
	if ev.UsageSource != "provider" || ev.CostStatus != "unknown_price" {
		t.Fatalf("event usage source/cost status: %+v", ev)
	}
	if ev.EventType != "request.completed" || ev.ModelUsed != "omni-moderation-canon" {
		t.Fatalf("event type/model: %+v", ev)
	}
}

// TestModerations_InputForms: the string form and an at-cap array (256
// items) pass local validation; every invalid shape is refused locally with
// zero upstream calls.
func TestModerations_InputForms(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"mod","results":[]}`))
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})

	if rec := postR105(t, gw, "/v1/moderations", `{"model":"m","input":"plain string"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("string form status %d %s", rec.Code, rec.Body.String())
	}
	atCap := `{"model":"m","input":[` + strings.Repeat(`"t",`, moderationsMaxInputs-1) + `"t"]}`
	if rec := postR105(t, gw, "/v1/moderations", atCap, nil); rec.Code != http.StatusOK {
		t.Fatalf("array-at-cap status %d %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream called %d times", calls.Load())
	}

	cases := []struct {
		name        string
		body        string
		wantMessage string
	}{
		{"missing model", `{"input":"x"}`, "model is required"},
		{"missing input", `{"model":"m"}`, "input is required"},
		{"input null", `{"model":"m","input":null}`, "input is required"},
		{"input empty array", `{"model":"m","input":[]}`, "input must not be empty"},
		{"input number", `{"model":"m","input":7}`, "input must be a non-empty string or an array of items"},
		{"input empty string", `{"model":"m","input":""}`, "input must be a non-empty string or an array of items"},
		{"too many items", `{"model":"m","input":[` + strings.Repeat(`"t",`, moderationsMaxInputs) + `"t"]}`, "too many input items"},
		{"empty body", ``, "malformed JSON"},
		{"truncated json", `{"model":"m","input":"x"`, "malformed JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postR105(t, gw, "/v1/moderations", tc.body, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if errorType(t, rec) != "invalid_request_error" {
				t.Fatalf("envelope %s", rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantMessage) {
				t.Fatalf("message %q, want %q", rec.Body.String(), tc.wantMessage)
			}
		})
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream called %d times after invalid inputs", calls.Load())
	}
}

// TestModerations_UnsupportedProvider (D2 ratified openai-compat matrix).
func TestModerations_UnsupportedProvider(t *testing.T) {
	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "claude-3-5-sonnet", Provider: "anthropic", Enabled: true})
	rec := postR105(t, gw, "/v1/moderations", `{"model":"m","input":"x"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != "moderations_not_supported_for_provider" {
		t.Fatalf("code %q body %s", env.Error.Code, rec.Body.String())
	}
}

// TestModerations_MissingUsageNoUsage (D3): OpenAI moderations carry no
// usage block — the event reports zero tokens with usage_source none /
// cost_status no_usage, never a fabricated estimate or a silent zero-priced
// success.
func TestModerations_MissingUsageNoUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"mod-2","results":[{"flagged":false,"categories":{},"category_scores":{}}]}`))
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postR105(t, gw, "/v1/moderations", `{"model":"m","input":"x"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.UsageSource != "none" || ev.CostStatus != "no_usage" || ev.TokensIn != 0 {
		t.Fatalf("event usage accounting: %+v", ev)
	}
}

// TestModerations_ResidencyDeniedBeforeUpstream (contract example 3): a
// residency-denied model for a foreign org is refused 403 before any
// upstream call.
func TestModerations_ResidencyDeniedBeforeUpstream(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	gw.auth = NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-eu", nil))
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: false, Region: "EU", Reason: "model not resident"}}

	rec := postR105(t, gw, "/v1/moderations", `{"model":"m","input":"x"}`, map[string]string{"X-Org-Id": "org-eu"})
	if rec.Code != http.StatusForbidden || errorType(t, rec) != "residency_policy_violation" {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times after residency denial", calls.Load())
	}
}
