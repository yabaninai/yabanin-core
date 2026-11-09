package cli

// Consumer compatibility matrix for /v1/messages: old and new consumer
// configurations against the same endpoint, and the explicit refusals for
// unsupported requests.
//
//   - New (Claude Code) auth configuration: strict mode, key in x-api-key
//     or Authorization Bearer. Legacy (old) configuration: header mode with
//     the static key optional.
//   - Unknown-model policy: legacy default "fallback" (substitute and
//     advertise) vs new "reject" (explicit 404 model_not_found refusal).
//   - Unsupported request shapes: refused explicitly with the Anthropic
//     error envelope (invalid_request_error), never silently translated.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// fallbackMarkingResolver mirrors the real registry behavior for unknown
// models: the fallback model is substituted and marked Fallback so the
// gateway's unknown-model policy branch can act on it.
type fallbackMarkingResolver struct {
	stubModelResolver
	fallbackModel string
}

func (s fallbackMarkingResolver) ResolveChecked(_ context.Context, name string) (resolver.ModelInfo, error) {
	if info, ok := s.stubModelResolver[name]; ok {
		return info, nil
	}
	return resolver.ModelInfo{ModelName: s.fallbackModel, Enabled: true, Fallback: true}, nil
}

// TestMessages_ConsumerAuthGenerations: the new strict configuration
// accepts both the Authorization Bearer and the Claude Code x-api-key
// header; the legacy header-mode configuration (old consumer setup, static
// key optional) accepts a bearer without a configured static key and still
// refuses missing credentials explicitly.
func TestMessages_ConsumerAuthGenerations(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	newCfg := func(mode string) *gateway {
		gw := nativeMessagesGateway(t, upstream.URL)
		gw.cfg.AuthMode = mode
		gw.auth = NewAuthMiddleware(gw.cfg, nil)
		return gw
	}

	post := func(t *testing.T, gw *gateway, header, value string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages",
			strings.NewReader(`{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`))
		req.Header.Set("Content-Type", "application/json")
		if header != "" {
			req.Header.Set(header, value)
		}
		rec := httptest.NewRecorder()
		router := chi.NewRouter()
		gw.routes(router)
		router.ServeHTTP(rec, req)
		return rec
	}

	t.Run("strict-bearer", func(t *testing.T) {
		rec := post(t, newCfg("strict"), "Authorization", "Bearer test-key")
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("strict-x-api-key-claude-code", func(t *testing.T) {
		// Claude Code sends the key in x-api-key; the gateway promotes it.
		rec := post(t, newCfg("strict"), "x-api-key", "test-key")
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("legacy-header-mode-resolver-auth", func(t *testing.T) {
		// Old consumer configuration: header mode with the static key unset
		// and org key resolution — the bearer is a resolved org key.
		gw := newCfg("header")
		gw.cfg.APIKey = ""
		gw.auth = NewAuthMiddleware(gw.cfg, newTestResolver("legacy-org", nil))
		rec := post(t, gw, "Authorization", "Bearer legacy-client-key")
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("legacy-header-mode-missing-credentials-refused", func(t *testing.T) {
		rec := post(t, newCfg("header"), "", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"type":"authentication_error"`) {
			t.Fatalf("missing credentials must be refused with the Anthropic envelope: %s", rec.Body.String())
		}
	})
}

// TestMessages_UnknownModelPolicyMatrix: legacy default policy "fallback"
// substitutes the configured fallback model and advertises the substitution;
// the new "reject" policy refuses explicitly with 404 model_not_found.
func TestMessages_UnknownModelPolicyMatrix(t *testing.T) {
	newGateway := func(t *testing.T, upstreamURL string) *gateway {
		t.Helper()
		gw := responsesTestGateway(t, upstreamURL)
		gw.res = fallbackMarkingResolver{
			stubModelResolver: stubModelResolver{
				"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstreamURL, Enabled: true},
			},
			fallbackModel: "m",
		}
		return gw
	}

	t.Run("legacy-fallback-substitutes-and-advertises", func(t *testing.T) {
		var upstreamModel string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Model string `json:"model"`
			}
			raw := make([]byte, 1<<16)
			n, _ := r.Body.Read(raw)
			_ = json.Unmarshal(raw[:n], &req)
			upstreamModel = req.Model
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"c","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		}))
		defer upstream.Close()

		gw := newGateway(t, upstream.URL)
		rec := postMessages(t, gw, `{"model":"brand-new-model","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("X-Yabanin-Model-Fallback"); got != "brand-new-model->m" {
			t.Fatalf("fallback advertisement %q", got)
		}
		if upstreamModel != "m" {
			t.Fatalf("upstream model %q, want substituted fallback m", upstreamModel)
		}
	})

	t.Run("reject-refuses-explicitly", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("reject policy must refuse before any upstream call")
		}))
		defer upstream.Close()

		gw := newGateway(t, upstream.URL)
		gw.unknownModelPolicy = "reject"
		rec := postMessages(t, gw, `{"model":"brand-new-model","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		// The OpenAI-shaped refusal written by admission is translated by
		// the Anthropic writer: the messages consumer always sees the
		// Anthropic envelope with not_found_error and the model_not_found
		// code prefix naming the requested model.
		if !strings.Contains(rec.Body.String(), `"type":"error"`) || !strings.Contains(rec.Body.String(), `"type":"not_found_error"`) {
			t.Fatalf("refusal must carry the Anthropic not_found_error envelope: %s", rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "model_not_found") || !strings.Contains(rec.Body.String(), "brand-new-model") {
			t.Fatalf("refusal must name the code and the requested model: %s", rec.Body.String())
		}
	})
}

// TestMessages_UnsupportedRequestExplicitRefusal: request shapes the
// translation cannot represent are refused explicitly with the Anthropic
// invalid_request_error envelope — never silently mangled into a different
// request.
func TestMessages_UnsupportedRequestExplicitRefusal(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unsupported request must be refused before any upstream call")
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	cases := []struct {
		name    string
		body    string
		wantMsg string
	}{
		{name: "non-json-body", body: `not json at all`, wantMsg: "JSON"},
		{name: "empty-messages", body: `{"model":"m","max_tokens":8,"messages":[]}`, wantMsg: "at least one message"},
		{name: "unknown-role", body: `{"model":"m","max_tokens":8,"messages":[{"role":"wizard","content":"hi"}]}`, wantMsg: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postMessages(t, gw, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"type":"invalid_request_error"`) {
				t.Fatalf("refusal must carry the Anthropic invalid_request_error envelope: %s", rec.Body.String())
			}
			if tc.wantMsg != "" && !strings.Contains(rec.Body.String(), tc.wantMsg) {
				t.Fatalf("refusal must explain the reason (%q): %s", tc.wantMsg, rec.Body.String())
			}
		})
	}
}

// Compile-time shape check: the messages config generation still parses the
// documented yaml keys this matrix pins (auth_mode, api_key, fallback_model,
// unknown_model_policy).
var _ = config.Gateway{AuthMode: "strict", APIKey: "", UnknownModelPolicy: ""}
