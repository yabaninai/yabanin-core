package cli

// failure states from the contract's negative scenario — policy block 400,
// upstream error passthrough shapes, mid-stream upstream error-event
// classification (D1 canon), malformed request bodies, and count_tokens
// failures. Test-only change: no production code is touched.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// postMessagesForOrg is postMessages with a resolver-backed auth middleware:
// the auth layer strips client-supplied X-Org-Id (anti-spoof) and re-stamps
// it from the authenticated principal's org, which org-scoped policy
// pipelines key on.
func postMessagesForOrg(t *testing.T, gw *gateway, body, orgID string) *httptest.ResponseRecorder {
	t.Helper()
	gw.auth = NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver(orgID, nil))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// TestMessagesNative_PolicyPreUpstreamBlock pins the messages policy failure
// stage: an enforce-mode org policy denies before any reservation or upstream
// call. The client gets the Anthropic 400 envelope carrying the
// content_policy_violation code, and the only analytics event is
// request.invalid with an empty payload (denied content must not enter the
// log stream); nothing is billed.
func TestMessagesNative_PolicyPreUpstreamBlock(t *testing.T) {
	upstreamHit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "deny-messages", OrgID: testOrg, Name: "deny-messages", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("deny-messages", "blocked-marker")},
		[]adminstore.PolicyAttachment{{ModelPattern: "*", Endpoint: "messages", Priority: 1}})
	gw.policyRuntime = newTestRuntime(t, store, nil, PolicyModeEnforce)

	var invalid, billed int
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		switch e.EventType {
		case "request.invalid":
			invalid++
		case "request.completed", "request.failed":
			billed++
		}
	})
	t.Cleanup(restore)

	rec := postMessagesForOrg(t, gw,
		`{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"blocked-marker"}]}`,
		testOrg)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("not an anthropic envelope: %v\n%s", err, rec.Body.String())
	}
	if doc.Type != "error" || doc.Error.Type != "invalid_request_error" {
		t.Fatalf("envelope %+v", doc)
	}
	if !strings.HasPrefix(doc.Error.Message, "["+policyDenyErrorCode+"]") {
		t.Fatalf("message %q", doc.Error.Message)
	}
	if invalid != 1 || billed != 0 {
		t.Fatalf("events invalid=%d billed=%d", invalid, billed)
	}
	if upstreamHit {
		t.Fatal("denied request reached the upstream")
	}
}

// TestMessagesNative_UpstreamErrorPassthroughShapes pins the non-200
// behavior on both branches of /v1/messages: an upstream body already shaped
// {"type":"error",...} passes through byte-for-byte with its original status,
// Content-Type and request-id retry header; a foreign-shape error body is
// normalized into the Anthropic error envelope by the endpoint's
// error-envelope middleware (status preserved). The stream branch must not
// fake an SSE envelope, and the finish event is request.failed carrying the
// upstream status.
func TestMessagesNative_UpstreamErrorPassthroughShapes(t *testing.T) {
	tests := []struct {
		name     string
		stream   bool
		status   int
		ct       string
		body     string
		wantBody string
		wantCT   string
	}{
		{
			name:     "stream branch json api_error",
			stream:   true,
			status:   http.StatusInternalServerError,
			ct:       "application/json",
			body:     `{"type":"error","error":{"type":"api_error","message":"Internal server error"}}`,
			wantBody: `{"type":"error","error":{"type":"api_error","message":"Internal server error"}}`,
			wantCT:   "application/json",
		},
		{
			name:     "stream branch overloaded",
			stream:   true,
			status:   http.StatusServiceUnavailable,
			ct:       "application/json",
			body:     `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`,
			wantBody: `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`,
			wantCT:   "application/json",
		},
		{
			name:   "non-stream non-json body normalized",
			stream: false,
			status: http.StatusBadGateway,
			ct:     "text/plain",
			body:   "upstream exploded",
			// The envelope middleware rewrites foreign error bodies into the
			// Anthropic shape; the unparseable text leaves message empty.
			wantBody: `{"type":"error","error":{"type":"api_error","message":""}}`,
			wantCT:   "application/json",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Request-Id", "req_upstream_1")
				w.Header().Set("Content-Type", tc.ct)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()

			gw := nativeMessagesGateway(t, server.URL)
			var ev *eventpub.Event
			restore := observeEvent(func(e *eventpub.Event) {
				if e.EventType == "request.failed" && e.Endpoint == "messages" {
					ev = e
				}
			})
			t.Cleanup(restore)

			body := `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`
			if tc.stream {
				body = strings.TrimSuffix(body, "}") + `,"stream":true}`
			}
			rec := postMessages(t, gw, body)

			if rec.Code != tc.status {
				t.Fatalf("status %d want %d body %s", rec.Code, tc.status, rec.Body.String())
			}
			if rec.Body.String() != tc.wantBody {
				t.Fatalf("body %q want %q", rec.Body.String(), tc.wantBody)
			}
			if got := rec.Header().Get("Content-Type"); got != tc.wantCT {
				t.Fatalf("content-type %q want %q", got, tc.wantCT)
			}
			if got := rec.Header().Get("Request-Id"); got != "req_upstream_1" {
				t.Fatalf("request-id %q", got)
			}
			if tc.stream && strings.Contains(rec.Body.String(), "event:") {
				t.Fatalf("stream branch must not fabricate SSE on non-200: %s", rec.Body.String())
			}
			if ev == nil {
				t.Fatal("missing request.failed")
			}
			if ev.StatusCode != int64(tc.status) || ev.Error != "upstream request failed" {
				t.Fatalf("event status=%d error=%q", ev.StatusCode, ev.Error)
			}
		})
	}
}

// TestMessagesNative_MidStreamErrorEvent pins the native classification of an
// explicit terminal `event: error` inside an otherwise healthy SSE relay: the
// event passes through byte-identically (no fabricated message_stop), the
// partial usage seen so far is billed, and per the D1 canon the finish stays
// request.completed — request.failed on a native mid-stream error would break
// the asymmetry contract pinned by TestMessagesNative_EventAsymmetry_CutStream.
func TestMessagesNative_MidStreamErrorEvent(t *testing.T) {
	const sse = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sse)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "messages" {
			ev = e
		}
	})
	t.Cleanup(restore)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if ev == nil {
		t.Fatalf("missing finish event\nbody:\n%s", rec.Body.String())
	}
	if ev.EventType != "request.completed" {
		t.Fatalf("native explicit error event must stay request.completed (D1 canon), got %s", ev.EventType)
	}
	if ev.TokensIn != 3 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
	if rec.Body.String() != sse {
		t.Fatalf("error event must pass through untouched\ngot %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "message_stop") {
		t.Fatal("no message_stop may be fabricated")
	}
}

// TestMessagesNative_MalformedRequestBodies pins the local 400s: a body the
// probe cannot route to the native branch falls to the adapted translator,
// whose FormatError is answered with the Anthropic envelope before admission
// — no upstream call, no analytics event, nothing billed.
func TestMessagesNative_MalformedRequestBodies(t *testing.T) {
	upstreamHit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	gw := responsesTestGateway(t, server.URL)
	var events int
	restore := observeEvent(func(*eventpub.Event) { events++ })
	t.Cleanup(restore)

	tests := []struct {
		name    string
		body    string
		message string
		code    string
	}{
		{name: "invalid json", body: `{{"model":`, message: "request body must be a JSON object", code: "invalid_json"},
		{name: "missing model", body: `{"max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`, message: "model: Field required"},
		{name: "missing messages", body: `{"model":"m","max_tokens":8}`, message: "messages: at least one message is required"},
		{name: "empty messages", body: `{"model":"m","max_tokens":8,"messages":[]}`, message: "messages: at least one message is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := postMessages(t, gw, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			var doc struct {
				Type  string `json:"type"`
				Error struct {
					Type    string `json:"type"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				t.Fatalf("not an anthropic envelope: %v\n%s", err, rec.Body.String())
			}
			if doc.Type != "error" || doc.Error.Type != "invalid_request_error" {
				t.Fatalf("envelope %+v", doc)
			}
			if !strings.Contains(doc.Error.Message, tc.message) {
				t.Fatalf("message %q want substring %q", doc.Error.Message, tc.message)
			}
			if tc.code != "" && !strings.Contains(doc.Error.Message, "["+tc.code+"]") {
				t.Fatalf("code %q missing from %q", tc.code, doc.Error.Message)
			}
		})
	}
	if upstreamHit {
		t.Fatal("malformed request reached the upstream")
	}
	if events != 0 {
		t.Fatalf("malformed requests published %d events", events)
	}
}

// TestMessagesNative_InvalidBodyForwardedToUpstream pins the passthrough
// posture of the native branch: bodies that resolve to an anthropic model are
// not re-validated locally — an anthropic-invalid body (no messages) reaches
// the upstream with the model override applied, and its 400 comes back as a
// byte-identical passthrough recorded as request.failed.
func TestMessagesNative_InvalidBodyForwardedToUpstream(t *testing.T) {
	const upstreamErr = `{"type":"error","error":{"type":"invalid_request_error","message":"messages: at least one message is required"}}`
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, upstreamErr)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var failed bool
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.failed" && e.Endpoint == "messages" {
			failed = true
		}
	})
	t.Cleanup(restore)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8}`)
	if rec.Code != http.StatusBadRequest || rec.Body.String() != upstreamErr {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(string(gotBody), `"model":"claude-upstream"`) {
		t.Fatalf("upstream body %s", gotBody)
	}
	if !failed {
		t.Fatal("missing request.failed")
	}
}

// TestMessagesNative_CountTokensFailures pins the count_tokens failure stage:
// a body without a usable model is a local 400 before admission, an upstream
// non-200 passes through untouched with its retry headers, and an unreachable
// upstream answers 502 in the Anthropic envelope — all without publishing an
// analytics event.
func TestMessagesNative_CountTokensFailures(t *testing.T) {
	t.Run("missing model", func(t *testing.T) {
		gw := nativeMessagesGateway(t, "http://127.0.0.1:1")
		rec := postCount(t, gw, `{"messages":[{"role":"user","content":"Hi"}]}`, false)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		var doc struct {
			Type  string `json:"type"`
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("not an anthropic envelope: %v\n%s", err, rec.Body.String())
		}
		if doc.Type != "error" || doc.Error.Type != "invalid_request_error" || doc.Error.Message != "model is required" {
			t.Fatalf("envelope %+v", doc)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		gw := nativeMessagesGateway(t, "http://127.0.0.1:1")
		rec := postCount(t, gw, `{{`, false)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"model is required"`) {
			t.Fatalf("body %s", rec.Body.String())
		}
	})

	t.Run("upstream non-200 passthrough", func(t *testing.T) {
		const errBody = `{"type":"error","error":{"type":"rate_limit_error","message":"slow"}}`
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "7")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, errBody)
		}))
		defer server.Close()

		gw := nativeMessagesGateway(t, server.URL)
		var events int
		restore := observeEvent(func(*eventpub.Event) { events++ })
		t.Cleanup(restore)

		rec := postCount(t, gw, `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"Hi"}]}`, true)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if rec.Body.String() != errBody {
			t.Fatalf("body %s", rec.Body.String())
		}
		if rec.Header().Get("Retry-After") != "7" {
			t.Fatalf("retry-after %q", rec.Header().Get("Retry-After"))
		}
		if events != 0 {
			t.Fatalf("count_tokens published %d events", events)
		}
	})

	t.Run("upstream unreachable", func(t *testing.T) {
		gw := nativeMessagesGateway(t, "http://127.0.0.1:1")
		rec := postCount(t, gw, `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"Hi"}]}`, true)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		var doc struct {
			Type  string `json:"type"`
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("not an anthropic envelope: %v\n%s", err, rec.Body.String())
		}
		if doc.Type != "error" || doc.Error.Type != "api_error" || doc.Error.Message != "upstream request failed" {
			t.Fatalf("envelope %+v", doc)
		}
		if rec.Header().Get("x-should-retry") != "true" {
			t.Fatalf("x-should-retry %q", rec.Header().Get("x-should-retry"))
		}
	})
}

// The native relay must close open content blocks before the terminal
// error — the native twin of the adapted writer's D2 closing in
// emitStreamErrorLocked, pinned by
// TestMessagesNative_EventAsymmetry_CutStream/"adapted failed". An upstream
// cut or an idle-watchdog abort used to leave the client with an
// unterminated content block and no terminal event, so clients like Claude
// Code wedged instead of rendering the partial text. These tests pin:
// still-open blocks close in ascending index order, then one terminal
// error frame in the shared adapted shape; message_stop is never
// fabricated; the D1 analytics canon (request.completed, partial usage
// billed once) is untouched.

const nativeCutTerminalError = `{"type":"error","error":{"type":"api_error","message":"stream interrupted"}}`

// TestMessagesNative_UpstreamCutClosesOpenBlocks: the upstream dies with an
// open text block. The client must receive the byte-identical passthrough
// prefix, then the synthesized content_block_stop, then the terminal error —
// exactly the D2 shape the adapted path already pins.
func TestMessagesNative_UpstreamCutClosesOpenBlocks(t *testing.T) {
	const passthrough = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"par\"}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, passthrough)
		flusher.Flush()
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var finishes int
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		if e.EventType == "request.completed" || e.EventType == "request.failed" {
			finishes++
			ev = e
		}
	})
	t.Cleanup(restore)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	body := rec.Body.String()
	if !strings.HasPrefix(body, passthrough) {
		t.Fatalf("passthrough prefix must stay byte-identical:\n%s", body)
	}
	if strings.Contains(body, "message_stop") {
		t.Fatalf("cut stream must not fabricate message_stop:\n%s", body)
	}
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	if last := events[len(events)-1]; last.Event != "error" || strings.TrimSpace(last.Data) != nativeCutTerminalError {
		t.Fatalf("terminal event %q data %s, want error %s\n%s", last.Event, last.Data, nativeCutTerminalError, body)
	}
	var stops []string
	for _, e := range events {
		if e.Event == "content_block_stop" {
			stops = append(stops, e.Data)
		}
	}
	if len(stops) != 1 || stops[0] != `{"type":"content_block_stop","index":0}` {
		t.Fatalf("synthesized stops %v, want exactly [index 0]:\n%s", stops, body)
	}
	if ev == nil || finishes != 1 {
		t.Fatalf("finish events %d, want exactly one", finishes)
	}
	if ev.EventType != "request.completed" {
		t.Fatalf("native cut must stay request.completed (D1 canon), got %s (%s)", ev.EventType, ev.Error)
	}
	if ev.TokensIn != 3 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d (no double billing)", ev.TokensIn, ev.TokensOut)
	}
}

// TestMessagesNative_UpstreamCutClosesMultipleOpenBlocks: the negative
// scenario's half tool JSON — a tool_use block open with a partial
// input_json_delta plus a second open text block. The synthesized stops run
// in ascending index order (2, then 1), the upstream-stopped index 0 is not
// stopped twice, and the terminal error follows. The validator accepts the
// half tool JSON: with a terminal error it skips completeness checks, so
// the SDK discards the partial call instead of hanging on it.
func TestMessagesNative_UpstreamCutClosesMultipleOpenBlocks(t *testing.T) {
	const passthrough = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"done\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\",\"input\":{}}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\"}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"text_delta\",\"text\":\"tail\"}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, passthrough)
		flusher.Flush()
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "messages" && e.EventType == "request.completed" {
			ev = e
		}
	})
	t.Cleanup(restore)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	body := rec.Body.String()
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	if last := events[len(events)-1]; last.Event != "error" || strings.TrimSpace(last.Data) != nativeCutTerminalError {
		t.Fatalf("terminal event %q data %s\n%s", last.Event, last.Data, body)
	}
	var stopIdx []int
	for _, e := range events {
		if e.Event != "content_block_stop" {
			continue
		}
		var doc struct {
			Index int `json:"index"`
		}
		if err := json.Unmarshal([]byte(e.Data), &doc); err != nil {
			t.Fatalf("stop frame %s: %v", e.Data, err)
		}
		stopIdx = append(stopIdx, doc.Index)
	}
	if len(stopIdx) != 3 || stopIdx[0] != 0 || stopIdx[1] != 1 || stopIdx[2] != 2 {
		t.Fatalf("stop order %v, want [0 1 2] — upstream stop first, then the open {1,2} in ascending order:\n%s", stopIdx, body)
	}
	if ev == nil {
		t.Fatal("missing request.completed (D1 canon)")
	}
	if ev.TokensIn != 2 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
}

// TestMessagesNative_IdleTimeoutClosesOpenBlocks: the wedge case this
// behavior exists for — the upstream stalls with an open block, the
// gateway's idle watchdog cancels the upstream read, and the
// still-connected client now gets a terminated stream (block stop + error)
// instead of a silent truncation it would hang on.
func TestMessagesNative_IdleTimeoutClosesOpenBlocks(t *testing.T) {
	const passthrough = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, passthrough)
		flusher.Flush()
		time.Sleep(1500 * time.Millisecond) // far past the idle watchdog
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.streamIdleTimeout = 80 * time.Millisecond
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "messages" && e.EventType == "request.completed" {
			ev = e
		}
	})
	t.Cleanup(restore)

	start := time.Now()
	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("idle watchdog did not cut the stalled upstream (took %v):\n%s", took, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "content_block_stop") {
		t.Fatalf("open block must close before the terminal error:\n%s", body)
	}
	if strings.Contains(body, "message_stop") {
		t.Fatalf("timed-out stream must not fabricate message_stop:\n%s", body)
	}
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	if last := events[len(events)-1]; last.Event != "error" || strings.TrimSpace(last.Data) != nativeCutTerminalError {
		t.Fatalf("terminal event %q data %s\n%s", last.Event, last.Data, body)
	}
	if ev == nil {
		t.Fatal("missing request.completed (D1 canon)")
	}
	if ev.TokensIn != 4 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
}

// TestMessagesNative_UpstreamCutBeforeBlockStart: the cut lands between
// message_start and the first content_block_start — nothing is open, so
// only the terminal error is synthesized; no content_block_stop may be
// fabricated for an index that never started.
func TestMessagesNative_UpstreamCutBeforeBlockStart(t *testing.T) {
	const passthrough = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, passthrough)
		flusher.Flush()
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "messages" && e.EventType == "request.completed" {
			ev = e
		}
	})
	t.Cleanup(restore)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	body := rec.Body.String()
	if !strings.HasPrefix(body, passthrough) {
		t.Fatalf("passthrough prefix must stay byte-identical:\n%s", body)
	}
	if strings.Contains(body, "content_block_stop") {
		t.Fatalf("no content_block_stop may be fabricated without a block start:\n%s", body)
	}
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	if last := events[len(events)-1]; last.Event != "error" || strings.TrimSpace(last.Data) != nativeCutTerminalError {
		t.Fatalf("terminal event %q data %s\n%s", last.Event, last.Data, body)
	}
	if ev == nil {
		t.Fatal("missing request.completed (D1 canon)")
	}
	if ev.TokensIn != 1 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
}
