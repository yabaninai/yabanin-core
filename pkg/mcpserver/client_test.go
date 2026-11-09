package mcpserver

// Compatibility smoke: a minimal MCP client speaking the Streamable HTTP
// transport end to end — initialize (session capture + version echo),
// notifications/initialized, tools/list (cursor pagination), tools/call —
// the same message flow Claude Desktop / Cursor drive. The client is
// deliberately naive (no SDK): plain POSTs with the spec's Accept header,
// the Mcp-Session-Id header, and both JSON and SSE response decoding, so a
// regression in the wire surface shows up as a client-side decode failure.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mcpClient is the minimal client under test.
type mcpClient struct {
	base    string
	http    *http.Client
	session string
}

// post sends one JSON-RPC message and returns (status, body). SSE
// responses are collapsed to the payload of their message event.
func (c *mcpClient) post(t *testing.T, msg string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.base+"/mcp", strings.NewReader(msg))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	// The identity headers the gateway auth middleware sets from the
	// resolved yag_ principal (this raw server has no middleware, so the
	// client supplies what production ingress would).
	req.Header.Set("X-Org-Id", "org1")
	req.Header.Set("X-Agent-Id", "agent1")
	if c.session != "" {
		req.Header.Set(sessionHeader, c.session)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if sid := resp.Header.Get(sessionHeader); sid != "" {
		c.session = sid
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		body = sseMessagePayload(t, body)
	}
	return resp.StatusCode, body
}

// sseMessagePayload extracts the data of the first `event: message` frame.
func sseMessagePayload(t *testing.T, body []byte) []byte {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if payload, ok := strings.CutPrefix(line, "data:"); ok {
			return []byte(strings.TrimSpace(payload))
		}
	}
	t.Fatalf("no data frame in sse body: %q", body)
	return nil
}

// request sends a JSON-RPC request and decodes the response envelope.
func (c *mcpClient) request(t *testing.T, id int, method, params string) (map[string]any, error) {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q`, id, method)
	if params != "" {
		body += `,"params":` + params
	}
	body += `}`
	status, raw := c.post(t, body)
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  map[string]any  `json:"result"`
		Error   *struct {
			Code    int            `json:"code"`
			Message string         `json:"message"`
			Data    map[string]any `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("status %d: not a JSON-RPC response: %q", status, raw)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("json-rpc error %d (%s) data=%v", resp.Error.Code, resp.Error.Message, resp.Error.Data)
	}
	return resp.Result, nil
}

// TestMinimalMCPClientFullCycle is the wire-compat smoke: the exact message
// flow an MCP client drives against the gateway endpoint.
func TestMinimalMCPClientFullCycle(t *testing.T) {
	backend := newStubBackend()
	backend.tools = []ToolDesc{
		{Name: "knowledge:search", Description: "search docs", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "knowledge:fetch", Description: "fetch doc"},
	}
	backend.callRes["knowledge:search"] = json.RawMessage(`{"content":[{"type":"text","text":"42"}],"isError":false}`)
	srv := New(Config{PageSize: 1}, backend, nil, []byte("smoke-secret"))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	client := &mcpClient{base: ts.URL, http: ts.Client()}

	// 1. initialize — the version echo and session come back.
	status, raw := client.post(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}`)
	if status != http.StatusOK {
		t.Fatalf("initialize status %d", status)
	}
	var init struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &init); err != nil {
		t.Fatalf("initialize decode: %v", err)
	}
	if init.Result.ProtocolVersion != protocolVersionLatest || init.Result.ServerInfo.Name == "" {
		t.Fatalf("initialize result: %+v", init.Result)
	}
	if client.session == "" {
		t.Fatal("initialize did not issue a session")
	}

	// 2. notifications/initialized — 202, empty body.
	if status, raw = client.post(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); status != http.StatusAccepted || len(raw) != 0 {
		t.Fatalf("initialized: status %d body %q", status, raw)
	}

	// 3. tools/list — paginated catalog (PageSize 1 → two pages).
	page1, err := client.request(t, 2, "tools/list", "")
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	tools := page1["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("page 1 tools = %v", tools)
	}
	cursor, _ := page1["nextCursor"].(string)
	if cursor == "" {
		t.Fatal("page 1 nextCursor missing")
	}
	page2, err := client.request(t, 3, "tools/list", fmt.Sprintf(`{"cursor":%q}`, cursor))
	if err != nil {
		t.Fatalf("tools/list page 2: %v", err)
	}
	if tools = page2["tools"].([]any); len(tools) != 1 {
		t.Fatalf("page 2 tools = %v", tools)
	}
	if _, has := page2["nextCursor"]; has {
		t.Fatal("page 2 must be the last")
	}

	// 4. tools/call — happy path through the guard chain.
	res, err := client.request(t, 4, "tools/call", `{"name":"knowledge:search","arguments":{"q":"meaning"}}`)
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	content := res["content"].([]any)
	if content[0].(map[string]any)["text"] != "42" {
		t.Fatalf("tools/call result: %v", res)
	}

	// 5. tools/call with a present-but-tampered session → 404 (the
	// re-initialize signal), then a valid session still works.
	good := client.session
	client.session = good + "x"
	if status, _ = client.post(t, `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`); status != http.StatusNotFound {
		t.Fatalf("tampered session: status %d", status)
	}
	client.session = good
	if _, err = client.request(t, 6, "ping", ""); err != nil {
		t.Fatalf("ping with valid session: %v", err)
	}
}

// TestMinimalMCPClientSSEOnlyMode: a client that accepts ONLY SSE still
// gets every response as a message event.
func TestMinimalMCPClientSSEOnlyMode(t *testing.T) {
	backend := newStubBackend()
	backend.tools = []ToolDesc{{Name: "s:t"}}
	srv := New(Config{}, backend, nil, []byte("smoke-secret"))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("X-Org-Id", "org1")
	req.Header.Set("X-Agent-Id", "agent1")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	payload := sseMessagePayload(t, body)
	var frame struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(payload, &frame); err != nil || frame.Result == nil {
		t.Fatalf("sse frame: %v (%s)", err, payload)
	}
}

// TestMinimalMCPClientBackendErrors: guard-blocked and creds-missing calls
// surface as JSON-RPC errors the client can branch on.
func TestMinimalMCPClientBackendErrors(t *testing.T) {
	backend := newStubBackend()
	backend.callErr["s:blocked"] = &ToolCallError{Code: "mcp_tool_blocked", Message: "deny"}
	backend.callErr["s:locked"] = &ToolCallError{Code: "mcp_auth_required", Message: "authorize",
		Kind: "headers", URL: "/api/mcp/credentials/s"}
	srv := New(Config{}, backend, nil, []byte("smoke-secret"))
	ts := httptest.NewServer(srv)
	defer ts.Close()
	client := &mcpClient{base: ts.URL, http: ts.Client()}

	if _, err := client.request(t, 1, "tools/call", `{"name":"s:blocked"}`); err == nil ||
		!strings.Contains(err.Error(), "mcp_tool_blocked") {
		t.Fatalf("blocked call: %v", err)
	}
	_, err := client.request(t, 2, "tools/call", `{"name":"s:locked"}`)
	if err == nil || !strings.Contains(err.Error(), "mcp_auth_required") || !strings.Contains(err.Error(), "headers") {
		t.Fatalf("auth-required call: %v", err)
	}
}
