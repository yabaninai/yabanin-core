package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test fixtures.
// ---------------------------------------------------------------------------

// stubBackend records calls and returns canned results.
type stubBackend struct {
	mu       sync.Mutex
	tools    []ToolDesc
	toolsErr error
	calls    []stubCall
	callRes  map[string]json.RawMessage
	callErr  map[string]error
}

type stubCall struct {
	principal Principal
	name      string
	args      json.RawMessage
}

func (s *stubBackend) Tools(context.Context, Principal) ([]ToolDesc, error) {
	return s.tools, s.toolsErr
}

func (s *stubBackend) Call(_ context.Context, p Principal, name string, args json.RawMessage) (json.RawMessage, error) {
	s.mu.Lock()
	s.calls = append(s.calls, stubCall{principal: p, name: name, args: args})
	res := s.callRes[name]
	cerr := s.callErr[name]
	s.mu.Unlock()
	if cerr != nil {
		return nil, cerr
	}
	return res, nil
}

func newStubBackend() *stubBackend {
	return &stubBackend{
		callRes: map[string]json.RawMessage{},
		callErr: map[string]error{},
	}
}

// newTestServer wires the handler the gateway way: a fake auth middleware
// strips client identity headers and resolves the Bearer token (yag_ =
// agent principal; ypk_ = non-agent key; anything else = 401), mirroring
// the contract the endpoint depends on.
func newTestServer(t *testing.T, cfg Config, backend Backend) http.Handler {
	t.Helper()
	srv := New(cfg, backend, nil, []byte("test-session-secret"))
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Del("X-Org-Id")
			r.Header.Del("X-Agent-Id")
			r.Header.Del("X-Team-Id")
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			switch token {
			case "yag_test":
				r.Header.Set("X-Org-Id", "org1")
				r.Header.Set("X-Agent-Id", "agent1")
				r.Header.Set("X-Team-Id", "team1")
			case "ypk_test":
				r.Header.Set("X-Org-Id", "org1")
			default:
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	return mw(srv)
}

// post is a raw POST helper returning the recorder (authenticated as the
// yag_ agent key unless the Authorization header is overridden).
func post(handler http.Handler, body, accept, session string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer yag_test")
	if accept == "" {
		accept = "application/json, text/event-stream"
	}
	req.Header.Set("Accept", accept)
	if session != "" {
		req.Header.Set(sessionHeader, session)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// rpcCall posts one request and decodes the JSON-RPC response.
func rpcCall(t *testing.T, handler http.Handler, body string) (int, map[string]any) {
	t.Helper()
	rec := post(handler, body, "", "")
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return rec.Code, out
}

const (
	agentAccept = "application/json, text/event-stream"
)

// ---------------------------------------------------------------------------
// initialize handshake + protocol version negotiation.
// ---------------------------------------------------------------------------

func TestInitializeHandshake(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	code, resp := rpcCall(t, handler, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"t","version":"0"}}}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Fatalf("jsonrpc = %v", resp["jsonrpc"])
	}
	res, _ := resp["result"].(map[string]any)
	if res == nil {
		t.Fatalf("no result: %v", resp)
	}
	if res["protocolVersion"] != protocolVersionLatest {
		t.Fatalf("protocolVersion = %v", res["protocolVersion"])
	}
	caps, _ := res["capabilities"].(map[string]any)
	if caps == nil || caps["tools"] == nil {
		t.Fatalf("capabilities missing tools: %v", caps)
	}
	info, _ := res["serverInfo"].(map[string]any)
	if info["name"] != "yabanin-mcp-gateway" {
		t.Fatalf("serverInfo = %v", info)
	}
}

func TestInitializeIssuesSession(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	rec := post(handler, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "")
	sid := rec.Header().Get(sessionHeader)
	if sid == "" {
		t.Fatal("no Mcp-Session-Id header on initialize response")
	}
	// A follow-up request presenting the session passes validation.
	rec = post(handler, `{"jsonrpc":"2.0","id":2,"method":"ping"}`, "", sid)
	if rec.Code != http.StatusOK {
		t.Fatalf("follow-up with session: status %d body %s", rec.Code, rec.Body.String())
	}
	// A forged session id is rejected with 404 (re-initialize signal).
	rec = post(handler, `{"jsonrpc":"2.0","id":3,"method":"ping"}`, "", sid+"tampered")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("forged session: status %d", rec.Code)
	}
}

func TestProtocolVersionNegotiation(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	for _, tc := range []struct{ requested, want string }{
		{protocolVersionPrevious, protocolVersionPrevious},
		{"1999-01-01", protocolVersionLatest}, // unsupported → server's latest
	} {
		_, resp := rpcCall(t, handler,
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+tc.requested+`"}}`)
		res := resp["result"].(map[string]any)
		if res["protocolVersion"] != tc.want {
			t.Fatalf("requested %q → %v, want %v", tc.requested, res["protocolVersion"], tc.want)
		}
	}
	// An unsupported MCP-Protocol-Version header on a follow-up is a 400.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", agentAccept)
	req.Header.Set("Authorization", "Bearer yag_test")
	req.Header.Set(protocolVersionHeader, "2000-01-01")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported protocol version header: status %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// tools/list: filtering (backend contract) + pagination (protocol layer).
// ---------------------------------------------------------------------------

func TestToolsListPagination(t *testing.T) {
	backend := newStubBackend()
	for _, n := range []string{"srv-a:alpha", "srv-a:beta", "srv-b:gamma"} {
		backend.tools = append(backend.tools, ToolDesc{Name: n})
	}
	handler := newTestServer(t, Config{PageSize: 2}, backend)

	_, resp := rpcCall(t, handler, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	res := resp["result"].(map[string]any)
	tools := res["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("page 1 tools = %d", len(tools))
	}
	cursor, _ := res["nextCursor"].(string)
	if cursor == "" {
		t.Fatal("page 1: missing nextCursor")
	}

	_, resp = rpcCall(t, handler, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"`+cursor+`"}}`)
	res = resp["result"].(map[string]any)
	tools = res["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("page 2 tools = %d", len(tools))
	}
	if _, has := res["nextCursor"]; has {
		t.Fatal("page 2 must not carry nextCursor")
	}

	// Malformed cursors are invalid params.
	_, resp = rpcCall(t, handler, `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":"%%%bad"}}`)
	if resp["error"] == nil {
		t.Fatal("malformed cursor must error")
	}
}

func TestToolsListPreservesBackendOrder(t *testing.T) {
	// The protocol layer does NOT reorder: stable pagination requires the
	// backend's order to be stable (the gateway adapter sorts by name —
	// pinned there).
	backend := newStubBackend()
	backend.tools = []ToolDesc{{Name: "b:x"}, {Name: "a:y"}}
	handler := newTestServer(t, Config{}, backend)
	_, resp := rpcCall(t, handler, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tools := resp["result"].(map[string]any)["tools"].([]any)
	if tools[0].(map[string]any)["name"] != "b:x" || tools[1].(map[string]any)["name"] != "a:y" {
		t.Fatalf("catalog order changed: %v", tools)
	}
}

// ---------------------------------------------------------------------------
// tools/call: happy, guard-blocked, creds-missing.
// ---------------------------------------------------------------------------

func TestToolsCallHappy(t *testing.T) {
	backend := newStubBackend()
	upstream := json.RawMessage(`{"content":[{"type":"text","text":"ok"}],"isError":false}`)
	backend.callRes["srv:search"] = upstream
	handler := newTestServer(t, Config{}, backend)

	_, resp := rpcCall(t, handler, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"srv:search","arguments":{"q":"x"}}}`)
	res := resp["result"].(map[string]any)
	if res["isError"] != false {
		t.Fatalf("result = %v", res)
	}
	content, _ := res["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["text"] != "ok" {
		t.Fatalf("content = %v", content)
	}
	// The call reached the backend with the principal and split name.
	if len(backend.calls) != 1 || backend.calls[0].name != "srv:search" {
		t.Fatalf("backend calls = %+v", backend.calls)
	}
	if backend.calls[0].principal.OrgID != "org1" || backend.calls[0].principal.AgentID != "agent1" {
		t.Fatalf("principal = %+v", backend.calls[0].principal)
	}
}

func TestToolsCallResultNormalized(t *testing.T) {
	backend := newStubBackend()
	backend.callRes["srv:raw"] = json.RawMessage(`"plain-text"`)
	handler := newTestServer(t, Config{}, backend)
	_, resp := rpcCall(t, handler, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"srv:raw"}}`)
	res := resp["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["text"] != `"plain-text"` {
		t.Fatalf("normalized result = %v", res)
	}
}

func TestToolsCallGuardBlockedIsJSONRPCError(t *testing.T) {
	backend := newStubBackend()
	backend.callErr["srv:blocked"] = &ToolCallError{Code: "mcp_tool_blocked", Message: "args rule deny_regex"}
	handler := newTestServer(t, Config{}, backend)

	code, resp := rpcCall(t, handler, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"srv:blocked","arguments":{}}}`)
	if code != http.StatusOK {
		t.Fatalf("JSON-RPC errors ride HTTP 200, got %d", code)
	}
	e, _ := resp["error"].(map[string]any)
	if e == nil {
		t.Fatalf("no error object: %v", resp)
	}
	if e["code"] != float64(serverErrorCode) || e["message"] != "mcp_tool_blocked" {
		t.Fatalf("error = %v", e)
	}
	data, _ := e["data"].(map[string]any)
	if data["code"] != "mcp_tool_blocked" {
		t.Fatalf("error.data = %v", data)
	}
}

func TestToolsCallAuthRequiredSurfacesKindAndURL(t *testing.T) {
	backend := newStubBackend()
	backend.callErr["srv:oauthed"] = &ToolCallError{
		Code: "mcp_auth_required", Message: "re-authorization is required",
		Kind: "oauth", URL: "/api/mcp/auth/srv/begin",
	}
	handler := newTestServer(t, Config{}, backend)

	_, resp := rpcCall(t, handler, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"srv:oauthed"}}`)
	e := resp["error"].(map[string]any)
	data := e["data"].(map[string]any)
	if data["code"] != "mcp_auth_required" || data["kind"] != "oauth" || data["url"] != "/api/mcp/auth/srv/begin" {
		t.Fatalf("mcp_auth_required must surface kind+url, got %v", data)
	}
}

func TestToolsCallUnknownTool(t *testing.T) {
	backend := newStubBackend()
	backend.callErr["srv:missing"] = &ToolCallError{Code: "not_found", Message: `tool "missing" is not allowed on mcp server "srv"`}
	handler := newTestServer(t, Config{}, backend)

	_, resp := rpcCall(t, handler, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"srv:missing"}}`)
	if e := resp["error"].(map[string]any); e["data"].(map[string]any)["code"] != "not_found" {
		t.Fatalf("not_found must surface, got %v", e)
	}

	// The name passes through verbatim; flat-name splitting is the
	// backend's contract (pinned in the gateway adapter tests).
	if len(backend.calls) != 1 || backend.calls[0].name != "srv:missing" {
		t.Fatalf("backend calls = %+v", backend.calls)
	}

	// Missing name → invalid params.
	_, resp = rpcCall(t, handler, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}`)
	e := resp["error"].(map[string]any)
	if e["code"] != float64(codeInvalidParams) {
		t.Fatalf("missing name: %v", e)
	}
}

// ---------------------------------------------------------------------------
// JSON-RPC error handling per spec.
// ---------------------------------------------------------------------------

func TestParseAndInvalidRequestErrors(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	for _, tc := range []struct {
		name, body string
		wantCode   float64
	}{
		{"parse error", `{not json`, -32700},
		{"batch array", `["{"]`, -32600},
		{"wrong jsonrpc", `{"jsonrpc":"1.0","id":1,"method":"ping"}`, -32600},
		{"null id", `{"jsonrpc":"2.0","id":null,"method":"ping"}`, -32600},
		{"unknown method", `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, -32601},
		{"depth bomb", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"a":` + strings.Repeat("[", 80) + strings.Repeat("]", 80) + `}}`, -32600},
	} {
		_, resp := rpcCall(t, handler, tc.body)
		e, ok := resp["error"].(map[string]any)
		if !ok {
			t.Fatalf("%s: no error object in %v", tc.name, resp)
		}
		if e["code"] != tc.wantCode {
			t.Fatalf("%s: code = %v, want %v", tc.name, e["code"], tc.wantCode)
		}
	}
}

func TestNotificationsAcceptedWithNoBody(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	for _, body := range []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/unknown-thing"}`,
		`{"jsonrpc":"2.0","id":9,"result":{}}`, // a client→server response
	} {
		rec := post(handler, body, "", "")
		if rec.Code != http.StatusAccepted {
			t.Fatalf("%s: status %d", body, rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("%s: body = %q", body, rec.Body.String())
		}
	}
}

func TestPing(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	_, resp := rpcCall(t, handler, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if _, ok := resp["result"]; !ok {
		t.Fatalf("ping: %v", resp)
	}
}

// ---------------------------------------------------------------------------
// Transport-level guards: auth, content type, accept, size, methods.
// ---------------------------------------------------------------------------

func TestAuthGate(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	// No key → 401 (middleware).
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key: %d", rec.Code)
	}
	// Non-agent key (ypk_) → 403 agent_only, same shape as invoke.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ypk_test")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-agent key: %d", rec.Code)
	}
	var body struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error["code"] != "agent_only" {
		t.Fatalf("agent_only body: %s", rec.Body.String())
	}
}

func TestContentTypeAndAcceptGuards(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept", agentAccept)
	req.Header.Set("Authorization", "Bearer yag_test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content-type: %d", rec.Code)
	}

	// An Accept naming neither JSON nor SSE → 406.
	rec = post(handler, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "text/html", "")
	if rec.Code != http.StatusNotAcceptable {
		t.Fatalf("accept: %d", rec.Code)
	}
}

func TestBodySizeLimit(t *testing.T) {
	handler := newTestServer(t, Config{MaxBodyBytes: 64}, newStubBackend())
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a:b","arguments":{"x":"` + strings.Repeat("y", 500) + `"}}}`
	rec := post(handler, big, "", "")
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", rec.Code)
	}
}

func TestMethods(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer yag_test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /mcp must be 405 (no server-initiated SSE), got %d", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "POST, DELETE" {
		t.Fatalf("Allow = %q", allow)
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer yag_test")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /mcp: %d", rec.Code)
	}

	// DELETE acknowledges (204); a bad session is 404.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer yag_test")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /mcp: %d", rec.Code)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer yag_test")
	req.Header.Set(sessionHeader, "bogus.bogus.bogus")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE /mcp with bad session: %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Streamable HTTP: SSE response mode.
// ---------------------------------------------------------------------------

func TestSSEResponseMode(t *testing.T) {
	backend := newStubBackend()
	backend.tools = []ToolDesc{{Name: "srv:only"}}
	handler := newTestServer(t, Config{}, backend)

	rec := post(handler, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "text/event-stream", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "event: message\ndata: ") {
		t.Fatalf("sse body = %q", body)
	}
	line := strings.TrimPrefix(strings.Split(body, "data: ")[1], "")
	line = strings.TrimRight(line, "\n")
	var resp rpcResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("sse frame is not a JSON-RPC response: %v (%s)", err, line)
	}
	if resp.ID == nil || resp.Result == nil {
		t.Fatalf("sse frame = %+v", resp)
	}
}

// ---------------------------------------------------------------------------
// Backend failure surfaces as internal error.
// ---------------------------------------------------------------------------

func TestBackendFailure(t *testing.T) {
	backend := newStubBackend()
	backend.toolsErr = errors.New("db down")
	handler := newTestServer(t, Config{}, backend)
	_, resp := rpcCall(t, handler, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	e := resp["error"].(map[string]any)
	if e["code"] != float64(codeInternal) {
		t.Fatalf("internal error: %v", e)
	}
}

// ---------------------------------------------------------------------------
// Session signer.
// ---------------------------------------------------------------------------

func TestSessionSigner(t *testing.T) {
	s := newSessionSigner([]byte("k"), time.Hour)
	sid := s.issue()
	if err := s.validate(sid); err != nil {
		t.Fatalf("fresh session rejected: %v", err)
	}
	if err := s.validate(sid + "x"); err == nil {
		t.Fatal("tampered session accepted")
	}
	if err := newSessionSigner([]byte("other"), time.Hour).validate(sid); err == nil {
		t.Fatal("cross-key session accepted")
	}
	// An expired session is rejected (the clock is advanced past the TTL).
	base := time.Now()
	s.now = func() time.Time { return base }
	expired := newSessionSigner([]byte("k"), time.Hour)
	expired.now = func() time.Time { return base }
	sid = expired.issue()
	expired.now = func() time.Time { return base.Add(2 * time.Hour) }
	if err := expired.validate(sid); err == nil {
		t.Fatal("expired session accepted")
	}
}

// TestSessionSigner_RejectsNonCanonicalMac pins the signer against the
// AUTHFLAKESEC1 malleability class: Go's lenient base64 decoding ignores the
// two discarded bits of the final base64 character, so a session id whose MAC
// segment ends in "XU" (about 1/1024 of ids; 'U'=010100 re-spelled 'X'=010111
// keeps the four data bits and differs only in the discarded bits) decodes to
// the exact same HMAC bytes and used to validate as a second, malleable
// spelling of the same session. A session id must verify only in its exact
// issued, canonical form. (AUTHSTR2, mirror of AUTHFLAKESEC1.)
func TestSessionSigner_RejectsNonCanonicalMac(t *testing.T) {
	s := newSessionSigner([]byte("k"), time.Hour)
	var sid string
	for i := 0; i < 200000; i++ {
		candidate := s.issue()
		if candidate[len(candidate)-2:] == "XU" {
			sid = candidate
			break
		}
	}
	if sid == "" {
		t.Fatal("no XU-suffix session id found in 200000 tries (expected ~1/1024)")
	}

	if err := s.validate(sid); err != nil {
		t.Fatalf("canonical session id rejected: %v", err)
	}

	// The historical re-spelling transform: last two characters -> "XX".
	tampered := sid[:len(sid)-2] + "XX"
	if tampered == sid {
		t.Fatal("test bug: tampered value equals the original")
	}
	if err := s.validate(tampered); err == nil {
		t.Fatal("non-canonical MAC spelling of a valid session id was accepted")
	}
}

// ---------------------------------------------------------------------------
// Depth scanner.
// ---------------------------------------------------------------------------

func TestJSONMaxDepth(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{`{}`, 1},
		{`[]`, 1},
		{`{"a":[1,{"b":"}["}]}`, 3},
		{`"{"`, 0}, // a bare JSON string is a valid document: depth 0
		{`{"a":`, -1},
		{`{"a":"escaped \" string"}`, 1},
		{`{"a":"\\\\", "b":{}}`, 2},
	} {
		if got := jsonMaxDepth([]byte(tc.in)); got != tc.want {
			t.Fatalf("jsonMaxDepth(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Metrics: counters advance with protocol traffic.
// ---------------------------------------------------------------------------

func TestMetricsCounters(t *testing.T) {
	// Global promauto counters are shared across tests: assert deltas, not
	// absolute values.
	beforeInit := counterVec(t, mcpRequestsTotal, "initialize", "ok")
	beforeList := counterVec(t, mcpRequestsTotal, "tools/list", "ok")
	beforeParse := counterVec(t, mcpRequestsTotal, "parse_error", "protocol_error")
	beforeSess := counterVec(t, mcpSessionsTotal, "created")

	backend := newStubBackend()
	handler := newTestServer(t, Config{}, backend)
	post(handler, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "")
	post(handler, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, "", "")
	post(handler, `{bad`, "", "")

	if got := counterVec(t, mcpRequestsTotal, "initialize", "ok") - beforeInit; got != 1 {
		t.Fatalf("initialize delta = %v", got)
	}
	if got := counterVec(t, mcpRequestsTotal, "tools/list", "ok") - beforeList; got != 1 {
		t.Fatalf("tools/list delta = %v", got)
	}
	if got := counterVec(t, mcpRequestsTotal, "parse_error", "protocol_error") - beforeParse; got != 1 {
		t.Fatalf("parse_error delta = %v", got)
	}
	if got := counterVec(t, mcpSessionsTotal, "created") - beforeSess; got != 1 {
		t.Fatalf("sessions delta = %v", got)
	}
}
