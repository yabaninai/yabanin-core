package cli

// N07-P06-T06 — consumer consistency pins: DTO, rights and refusal-shape
// agreement across the packet's transport surfaces (rerank, moderations,
// realtime-SSE, chat JSON/SSE), so the packet criterion holds as one system
// contract rather than per-endpoint accidents:
//
//   - every packet refusal is a client-shaped 4xx in the
//     invalid_request_error family with a stable machine code (CONTRACT §1);
//     no fabricated 5xx anywhere in the family;
//   - the refusal family is identical across JSON and SSE for the same
//     trigger (SSE renders the structured terminal frame + [DONE]);
//   - the family is independent of caller rights/auth mode: no privilege or
//     auth variant makes an unsupported transport succeed, and admitted
//     callers get the same refusal semantics under strict and header auth;
//   - the WebSocket upgrade refusal is admission-front (JSON envelope, not
//     an SSE stream) with code unsupported_feature.
//
// Edition dimension: the gateway has no edition concept (single edition —
// grep evidence in the T06 record); there is nothing to pin.
//
// Live confirmation of the same rows on the real binary (docker pg16 stand)
// is recorded in N07-P06-T06-record-2026-10-31.md; this file is the
// executable regression pin, not a live claim.

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// t06Gateway builds the strict/header auth variant of the T02/T05 fixture
// shape: one bedrock model ("m" → b-canon) pointed at the stub upstream.
func t06Gateway(t *testing.T, upstreamURL, authMode string) *gateway {
	t.Helper()
	cfg := config.Gateway{AuthMode: authMode, APIKey: "test-key", Provider: upstreamURL}
	return &gateway{
		cfg:  cfg,
		log:  slog.New(slog.DiscardHandler),
		auth: NewAuthMiddleware(cfg, nil),
		res: stubModelResolver{
			"m": {ModelName: "b-canon", Provider: "bedrock", UpstreamURL: upstreamURL, Enabled: true},
		},
		pool: upstream.NewPool(upstream.Options{}),
	}
}

// t06CountingUpstream answers 200 to everything and counts hits — the
// refusal rows in this file must leave it at zero.
func t06CountingUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

// TestN07P6T06_RefusalFamilyConsistentAcrossTransports pins the packet
// refusal family as one system contract: the three non-chat transports
// refuse the bedrock adapter with the same status/type family and
// endpoint-stable codes; the chat capability refusal renders identically
// on JSON and SSE; the WS upgrade refusal is admission-front JSON. Zero
// upstream calls on every row.
func TestN07P6T06_RefusalFamilyConsistentAcrossTransports(t *testing.T) {
	server, calls := t06CountingUpstream(t)
	gw := t06Gateway(t, server.URL, "strict")

	// Non-chat transports × bedrock: 400 invalid_request_error with
	// endpoint-specific stable codes.
	for _, tc := range []struct {
		path, body, wantCode string
	}{
		{"/v1/rerank", `{"model":"m","query":"q","documents":["a"]}`, "rerank_not_supported_for_provider"},
		{"/v1/moderations", `{"model":"m","input":"hi"}`, "moderations_not_supported_for_provider"},
		{"/v1/realtime", `{"model":"m"}`, "realtime_not_supported_for_provider"},
	} {
		rec := postR105(t, gw, tc.path, tc.body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s on bedrock: status %d, want 400 (family: invalid_request_error); body=%s",
				tc.path, rec.Code, rec.Body.String())
		}
		if got := errorType(t, rec); got != "invalid_request_error" {
			t.Fatalf("%s on bedrock: error.type %q, want invalid_request_error (one family across transports)", tc.path, got)
		}
		if got := n07p6t02ErrorCode(t, rec); got != tc.wantCode {
			t.Fatalf("%s on bedrock: error.code %q, want %q (stable endpoint code)", tc.path, got, tc.wantCode)
		}
	}

	// Same trigger, JSON vs SSE: the chat capability refusal must carry the
	// same type+code on both transports (SSE renders the structured
	// terminal frame followed by [DONE]). Chat rows use the T04 chat
	// fixture (full retry/fallback wiring); the upstream stays silent —
	// the refusal precedes every dial.
	chatUpstream := newRT02Upstream(t)
	chatGW := rt02ChatGateway(t, chatUpstream, &rt02Access{})
	chatGW.res = stubModelResolver{
		"m": {ModelName: "b-canon", Provider: "bedrock", UpstreamURL: chatUpstream.srv.URL, Enabled: true},
	}
	toolsBody := `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{}}}}]}`
	jsonRec := rt02Post(t, chatGW, toolsBody, nil)
	if jsonRec.Code != http.StatusBadRequest || errorType(t, jsonRec) != "invalid_request_error" ||
		n07p6t02ErrorCode(t, jsonRec) != "capability_not_supported" {
		t.Fatalf("chat JSON tools-on-bedrock: status %d body %s — want 400 invalid_request_error/capability_not_supported",
			jsonRec.Code, jsonRec.Body.String())
	}
	sseRec := rt02Post(t, chatGW,
		strings.Replace(toolsBody, `"model":"m"`, `"model":"m","stream":true`, 1), nil)
	sseOut := sseRec.Body.String()
	if !strings.Contains(sseOut, `"type":"invalid_request_error"`) ||
		!strings.Contains(sseOut, `"code":"capability_not_supported"`) ||
		!strings.HasSuffix(sseOut, "data: [DONE]\n\n") {
		t.Fatalf("chat SSE tools-on-bedrock must render the structured terminal frame + [DONE], got %q", sseOut)
	}

	// WS upgrade on realtime: admission-front JSON refusal (not SSE),
	// stable code unsupported_feature.
	wsHeaders := map[string]string{
		"Connection":            "Upgrade",
		"Upgrade":               "websocket",
		"Sec-WebSocket-Version": "13",
		"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
	}
	wsRec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, wsHeaders)
	if wsRec.Code != http.StatusBadRequest || errorType(t, wsRec) != "invalid_request_error" ||
		n07p6t02ErrorCode(t, wsRec) != "unsupported_feature" {
		t.Fatalf("realtime WS upgrade: status %d body %s — want 400 invalid_request_error/unsupported_feature",
			wsRec.Code, wsRec.Body.String())
	}

	// Native Gemini-shaped routes stay outside the router (404 family,
	// T05 pins the rows) — one absent-family check here for consistency.
	rec := postR105(t, gw, "/v1/gemini/v1beta/models/gemini-2.0-flash:generateContent", `{}`, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("gemini route: status %d, want 404 (route family)", rec.Code)
	}

	if n := calls.Load(); n != 0 {
		t.Fatalf("refusal family touched the upstream %d times (must be zero)", n)
	}
	if c := chatUpstream.totalCalls(); c != 0 {
		t.Fatalf("chat refusal rows touched the chat upstream %d times (must be zero)", c)
	}
}

// TestN07P6T06_RefusalsIndependentOfRights pins the rights dimension: for
// an admitted caller the transport refusal is identical under strict and
// header auth (same status + code), and no auth variant makes the
// unsupported transport succeed. A missing/invalid key stays in front of
// the family (401 auth family — the boundary is not bypassed by weaker
// auth either).
func TestN07P6T06_RefusalsIndependentOfRights(t *testing.T) {
	server, calls := t06CountingUpstream(t)

	var refusalStatus int
	var refusalCode string
	for _, authMode := range []string{"strict", "header"} {
		gw := t06Gateway(t, server.URL, authMode)
		rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a"]}`, nil)
		if rec.Code != http.StatusBadRequest || n07p6t02ErrorCode(t, rec) != "rerank_not_supported_for_provider" {
			t.Fatalf("%s auth: rerank on bedrock status %d code %q — the transport refusal must be auth-invariant",
				authMode, rec.Code, n07p6t02ErrorCode(t, rec))
		}
		refusalStatus, refusalCode = rec.Code, n07p6t02ErrorCode(t, rec)
	}

	if refusalStatus != http.StatusBadRequest || refusalCode != "rerank_not_supported_for_provider" {
		t.Fatalf("inconsistent family state: %d/%s", refusalStatus, refusalCode)
	}

	// Unauthenticated strict caller: 401 auth family — weaker rights never
	// reach the transport boundary, and no variant 200s it.
	unauth := t06Gateway(t, server.URL, "strict")
	unauthReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/rerank",
		strings.NewReader(`{"model":"m","query":"q","documents":["a"]}`))
	unauthReq.Header.Set("Authorization", "Bearer wrong-key")
	unauthReq.Header.Set("Content-Type", "application/json")
	unauthRec := httptest.NewRecorder()
	unauthRouter := chi.NewRouter()
	unauth.routes(unauthRouter) // auth middleware mounted the same way the standard test harness mounts it
	unauthRouter.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("strict auth with wrong key: status %d, want 401 (auth family stays in front)", unauthRec.Code)
	}

	if n := calls.Load(); n != 0 {
		t.Fatalf("rights matrix touched the upstream %d times (must be zero)", n)
	}
}
