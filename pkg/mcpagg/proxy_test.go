package mcpagg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// ---------------------------------------------------------------------------
// Store: mockDB (same pattern as pkg/adminstore/error_propagation_test.go).
// The SQL is integration-covered (pkg/migrate + the 0004 structural test);
// here the Store's row-binding and error mapping are the subject.
// ---------------------------------------------------------------------------

type mcpMockDB struct {
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
	queryFn    func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	execFn     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (m *mcpMockDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return m.queryRowFn(ctx, sql, args...)
}
func (m *mcpMockDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return m.queryFn(ctx, sql, args...)
}
func (m *mcpMockDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return m.execFn(ctx, sql, args...)
}

// serverRow is a pgx.Row backed by one Server (or a scan error).
type serverRow struct {
	srv *Server
	err error
}

func (r *serverRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if r.srv == nil {
		return pgx.ErrNoRows
	}
	return bindServer(r.srv, dest...)
}

// serverRows is a pgx.Rows over a slice of Servers.
type serverRows struct {
	rows []*Server
	pos  int
}

func (r *serverRows) Next() bool { r.pos++; return r.pos <= len(r.rows) }
func (r *serverRows) Err() error { return nil }
func (r *serverRows) Close()     {}
func (r *serverRows) Scan(dest ...any) error {
	if r.pos < 1 || r.pos > len(r.rows) {
		return errors.New("serverRows: out of range")
	}
	return bindServer(r.rows[r.pos-1], dest...)
}
func (r *serverRows) CommandTag() pgconn.CommandTag { return pgconn.NewCommandTag("") }
func (r *serverRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}
func (r *serverRows) Conn() *pgx.Conn     { return nil }
func (r *serverRows) RawValues() [][]byte { return nil }
func (r *serverRows) Values() ([]any, error) {
	return nil, nil
}

// bindServer copies a Server into the scanArgs address order.
func bindServer(srv *Server, dest ...any) error {
	if len(dest) != 12 {
		return fmt.Errorf("bindServer: expected 12 dests, got %d", len(dest))
	}
	var toolsJSON []byte
	if len(srv.AllowedTools) > 0 {
		b, err := json.Marshal(srv.AllowedTools)
		if err != nil {
			return err
		}
		toolsJSON = b
	}
	mode := srv.CredentialMode
	if mode == "" {
		mode = CredModeAuto
	}
	version := srv.ConfigVersion
	if version == 0 {
		version = 1
	}
	*(dest[0].(*string)) = srv.ID
	*(dest[1].(*string)) = srv.OrgID
	*(dest[2].(*string)) = srv.Name
	*(dest[3].(**string)) = srv.DisplayName
	*(dest[4].(*string)) = srv.URL
	*(dest[5].(*string)) = srv.Transport
	*(dest[6].(*[]byte)) = toolsJSON
	*(dest[7].(*bool)) = srv.Enabled
	*(dest[8].(*string)) = mode
	*(dest[9].(*int64)) = version
	*(dest[10].(*time.Time)) = srv.CreatedAt
	*(dest[11].(*time.Time)) = srv.UpdatedAt
	return nil
}

func testServer(url string, tools ...string) *Server {
	if tools == nil {
		tools = []string{}
	}
	return &Server{
		ID:           "id-1",
		OrgID:        "org-1",
		Name:         "knowledge",
		URL:          url,
		Transport:    TransportHTTP,
		AllowedTools: tools,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

// grantRow is a pgx.Row backed by one Grant (or a scan error / no-rows).
type grantRow struct {
	g   *Grant
	err error
}

func (r *grantRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if r.g == nil {
		return pgx.ErrNoRows
	}
	return bindGrant(r.g, dest...)
}

// bindGrant copies a Grant into the grantScanArgs address order (9 dests
// since migration 0020 added allowed_actions between allowed_tools and
// enabled).
func bindGrant(g *Grant, dest ...any) error {
	if len(dest) != 9 {
		return fmt.Errorf("bindGrant: expected 9 dests, got %d", len(dest))
	}
	var toolsJSON []byte
	if len(g.AllowedTools) > 0 {
		b, err := json.Marshal(g.AllowedTools)
		if err != nil {
			return err
		}
		toolsJSON = b
	}
	var actionsJSON []byte
	if len(g.AllowedActions) > 0 {
		b, err := json.Marshal(g.AllowedActions)
		if err != nil {
			return err
		}
		actionsJSON = b
	}
	*(dest[0].(*string)) = g.ID
	*(dest[1].(*string)) = g.OrgID
	*(dest[2].(*string)) = g.AgentID
	*(dest[3].(*string)) = g.ServerName
	*(dest[4].(*[]byte)) = toolsJSON
	*(dest[5].(*[]byte)) = actionsJSON
	*(dest[6].(*bool)) = g.Enabled
	*(dest[7].(*time.Time)) = g.CreatedAt
	*(dest[8].(*time.Time)) = g.UpdatedAt
	return nil
}

// defaultActions is migration 0020's column default — what a grant row
// created before (or without) an explicit action list carries.
func defaultActions() []string {
	return []string{GrantActionInvoke, GrantActionList}
}

func testGrant(agentID string, tools ...string) *Grant {
	if tools == nil {
		tools = []string{}
	}
	return &Grant{
		ID:             "gr-1",
		OrgID:          "org-1",
		AgentID:        agentID,
		ServerName:     "knowledge",
		AllowedTools:   tools,
		AllowedActions: defaultActions(),
		Enabled:        true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
}

// isGrantQuery reports whether the SQL targets the grants table (used by the
// mock DB to dispatch QueryRow between the server and grant lookups).
func isGrantQuery(sql string) bool {
	return strings.Contains(sql, "mcp_server_grants")
}

// storeForUpstreamWithGrant returns a Store whose QueryRow serves BOTH the
// server lookup (pointing at url, enabled, the given server tools) and the
// grant lookup (the given grant). MCP-03 requires a valid agent grant, so the
// proxy tests use this instead of the grant-less storeForUpstream.
func storeForUpstreamWithGrant(url string, serverTools []string, grant *Grant) *Store {
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				return chainRowFor(grant)
			}
			if isGrantQuery(sql) {
				return &grantRow{g: grant}
			}
			return &serverRow{srv: testServer(url, serverTools...)}
		},
	}
	return NewStore(db)
}

func TestStoreGetEnabled_NotFound(t *testing.T) {
	db := &mcpMockDB{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return &serverRow{srv: nil}
		},
	}
	st := NewStore(db)
	_, err := st.GetEnabled(context.Background(), "org-1", "knowledge")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestStoreGetEnabled_NilDB(t *testing.T) {
	st := NewStore(nil)
	if _, err := st.GetEnabled(context.Background(), "org-1", "x"); err == nil {
		t.Fatal("nil db must error")
	}
}

func TestStoreCreate_BindsArgs(t *testing.T) {
	var gotArgs []any
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, _ string, args ...any) pgx.Row {
			gotArgs = args
			return &serverRow{srv: testServer("https://mcp.example.com/mcp")}
		},
	}
	st := NewStore(db)
	tools := []string{"search"}
	srv, err := st.Create(context.Background(), CreateParams{
		OrgID: "org-1", Name: "knowledge", URL: "https://mcp.example.com/mcp",
		AllowedTools: tools, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if srv.Name != "knowledge" || !srv.Enabled {
		t.Fatalf("bad row: %+v", srv)
	}
	// Positional args: org, name, display, url, transport, tools(json), enabled.
	if gotArgs[0] != "org-1" || gotArgs[1] != "knowledge" {
		t.Fatalf("bad args: %v", gotArgs)
	}
	toolsJSON, _ := gotArgs[5].([]byte)
	var decoded []string
	_ = json.Unmarshal(toolsJSON, &decoded)
	if len(decoded) != 1 || decoded[0] != "search" {
		t.Fatalf("allowed_tools not bound as json: %s", toolsJSON)
	}
	if gotArgs[6] != true {
		t.Fatalf("enabled not bound: %v", gotArgs[6])
	}
}

func TestStoreList_ScansRows(t *testing.T) {
	db := &mcpMockDB{
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) {
			return &serverRows{rows: []*Server{testServer("https://a.example.com"), testServer("https://b.example.com")}}, nil
		},
	}
	st := NewStore(db)
	out, err := st.List(context.Background(), "org-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 rows, got %d", len(out))
	}
}

func TestStoreDelete_NotFound(t *testing.T) {
	db := &mcpMockDB{
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("DELETE 0"), nil
		},
	}
	st := NewStore(db)
	if err := st.Delete(context.Background(), "org-1", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Proxy: the upstream is a real httptest server; the store is the mock above.
// The SSRF allow-list admits loopback so the test upstream is reachable —
// the SSRF guard itself is pinned in validate_test.go.
// ---------------------------------------------------------------------------

// newUpstreamMCP starts an MCP test upstream. mode: json|sse|redirect|slow.
func newUpstreamMCP(t *testing.T, mode, target string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if mode == "redirect" {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		if mode == "slow" {
			time.Sleep(2 * time.Second)
		}
		var req struct {
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		result := map[string]any{
			"content": []map[string]any{{
				"type": "text",
				// MCP-04: echo the three verified identity headers back so a
				// test can assert the proxy forwarded each of them upstream.
				"text": fmt.Sprintf("result:%s:agent=%s:agentname=%s:team=%s",
					req.Params.Name,
					r.Header.Get("X-Yabanin-Agent-Id"),
					r.Header.Get("X-Yabanin-Agent-Name"),
					r.Header.Get("X-Yabanin-Team-Id")),
			}},
		}
		if mode == "sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", body)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func loopbackAllow(t *testing.T) ssrf.AllowList {
	t.Helper()
	al, err := ssrf.NewAllowList([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("loopbackAllow: %v", err)
	}
	return al
}

// testConfig returns a proxy Config for httptest (http://) upstreams. The
// https-only rule is a production SSRF guard pinned in validate_test.go;
// the proxy-logic tests here need plain-http loopback upstreams, so they
// use a test-only bypass flag that the production Config never sets.
func testConfig() Config {
	cfg := NewDefaultConfig()
	cfg.ConnectTimeout = 500 * time.Millisecond
	cfg.ReadTimeout = 2 * time.Second
	cfg.testAllowHTTP = true
	return cfg
}

func TestProxy_Invoke_JSONUpstream(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil)
	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1", TeamID: "tm-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	s := string(res)
	if !strings.Contains(s, "result:search") || !strings.Contains(s, "agent=ag-1") || !strings.Contains(s, "team=tm-1") {
		t.Fatalf("identity headers / tool not in result: %s", s)
	}
}

func TestProxy_Invoke_SSEUpstream(t *testing.T) {
	up := newUpstreamMCP(t, "sse", "")
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-2")), testConfig(), loopbackAllow(t), nil, nil)
	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-2"},
		InvokeRequest{Server: "knowledge", Tool: "fetch", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("invoke sse: %v", err)
	}
	if !strings.Contains(string(res), "result:fetch") {
		t.Fatalf("sse result missing tool: %s", res)
	}
}

func TestProxy_Invoke_ToolNotAllowed(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				// Grant allows all tools; the SERVER allow-list (only-this) is
				// the ceiling, so "other" is still not_found.
				return chainRowFor(testGrant("ag-1"))
			}
			if isGrantQuery(sql) {
				return &grantRow{g: testGrant("ag-1")}
			}
			return &serverRow{srv: testServer(up.URL, "only-this")}
		},
	}
	var auditEvents []AuditEvent
	audit := &recordingAudit{events: &auditEvents}
	p := NewProxy(NewStore(db), testConfig(), loopbackAllow(t), nil, audit)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "other", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeNotFound {
		t.Fatalf("want not_found, got %v", err)
	}
	if len(auditEvents) != 1 || auditEvents[0].Outcome != OutcomeNotFound {
		t.Fatalf("audit should record not_found: %+v", auditEvents)
	}
}

func TestProxy_Invoke_ServerNotFound(t *testing.T) {
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				return chainRowFor(testGrant("ag-1"))
			}
			if isGrantQuery(sql) {
				return &grantRow{g: testGrant("ag-1")}
			}
			return &serverRow{srv: nil}
		},
	}
	p := NewProxy(NewStore(db), testConfig(), loopbackAllow(t), nil, nil)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "missing", Tool: "x", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeNotFound {
		t.Fatalf("want not_found, got %v", err)
	}
}

func TestProxy_Invoke_HookDeny(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	hook := &staticHook{deny: "secret detected in params"}
	var auditEvents []AuditEvent
	audit := &recordingAudit{events: &auditEvents}
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), hook, audit)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"sk-abc"}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("want denied, got %v", err)
	}
	if len(auditEvents) != 1 || auditEvents[0].Outcome != OutcomeDenied {
		t.Fatalf("audit should record denied: %+v", auditEvents)
	}
}

func TestProxy_Invoke_HookRedact(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	hook := &staticHook{redacted: []byte(`{"q":"***"}`)}
	var auditEvents []AuditEvent
	audit := &recordingAudit{events: &auditEvents}
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), hook, audit)
	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"sk-abc"}`)})
	if err != nil {
		t.Fatalf("invoke with redact: %v", err)
	}
	_ = res
	// The audit must carry the REDACTED params, not the originals.
	if len(auditEvents) != 1 || !strings.Contains(string(auditEvents[0].ParamsRedacted), "***") {
		t.Fatalf("audit must carry redacted params: %+v", auditEvents)
	}
	if strings.Contains(string(auditEvents[0].ParamsRedacted), "sk-abc") {
		t.Fatalf("audit must NOT carry the original secret: %+v", auditEvents)
	}
}

func TestProxy_Invoke_UpstreamError(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"err":"boom"}`))
	}))
	t.Cleanup(up.Close)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "x", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatalf("want upstream, got %v", err)
	}
}

func TestProxy_Invoke_UpstreamFailureMessageIsSanitized(t *testing.T) {
	const marker = "synthetic-upstream-secret-marker"
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        string
	}{
		{
			name:   "http status body",
			status: http.StatusBadGateway,
			body:   `{"error":"` + marker + `","diagnostics":"private detail"}`,
			want:   "upstream status 502",
		},
		{
			name:        "json rpc message and data",
			status:      http.StatusOK,
			contentType: "application/json",
			body:        `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"` + marker + `","data":"` + marker + `"}}`,
			want:        "upstream json-rpc error -32000",
		},
		{
			name:        "sse json rpc message and data",
			status:      http.StatusOK,
			contentType: "text/event-stream",
			body:        "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"" + marker + "\",\"data\":\"" + marker + "\"}}\n\n",
			want:        "upstream json-rpc error -32000",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(up.Close)

			var auditEvents []AuditEvent
			audit := &recordingAudit{events: &auditEvents}
			p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, audit)
			_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
				InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
			var iErr *InvokeError
			if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
				t.Fatal("expected a typed upstream error")
			}
			if !strings.Contains(iErr.Message, tc.want) {
				t.Error("safe message should retain the upstream failure category")
			}
			if strings.Contains(iErr.Message, marker) || strings.Contains(iErr.Message, "private detail") {
				t.Error("caller-facing error exposed upstream content")
			}
			if len(auditEvents) != 1 || auditEvents[0].UpstreamStatus != tc.status {
				t.Error("audit should retain the upstream HTTP status")
			}
		})
	}
}

type proxyRoundTripFunc func(*http.Request) (*http.Response, error)

func (f proxyRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestProxy_Invoke_TransportErrorMessageIsSanitized(t *testing.T) {
	const marker = "synthetic-transport-url-secret"
	cfg := testConfig()
	cfg.HTTP = &http.Client{Transport: proxyRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial failed for https://upstream.invalid/path?token=%s", marker)
	})}
	p := NewProxy(storeForUpstreamWithGrant("https://upstream.invalid/path?token="+marker, nil, testGrant("ag-1")), cfg, loopbackAllow(t), nil, nil)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatal("expected a typed upstream error")
	}
	if !strings.Contains(iErr.Message, "upstream unreachable") {
		t.Error("safe message should retain the transport failure category")
	}
	if strings.Contains(iErr.Message, marker) || strings.Contains(iErr.Message, "upstream.invalid") {
		t.Error("caller-facing transport error exposed request details")
	}
}

type proxyErrorReader struct{ err error }

func (r proxyErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestProxy_Invoke_ReadErrorMessageIsSanitized(t *testing.T) {
	const marker = "synthetic-read-error-secret"
	cfg := testConfig()
	cfg.HTTP = &http.Client{Transport: proxyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     make(http.Header),
			Body:       io.NopCloser(proxyErrorReader{err: fmt.Errorf("response body contains %s", marker)}),
			Request:    req,
		}, nil
	})}
	var auditEvents []AuditEvent
	audit := &recordingAudit{events: &auditEvents}
	p := NewProxy(storeForUpstreamWithGrant("http://upstream.invalid/mcp", nil, testGrant("ag-1")), cfg, loopbackAllow(t), nil, audit)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatal("expected a typed upstream error")
	}
	if !strings.Contains(iErr.Message, "read upstream response failed") {
		t.Error("read failure should use a stable safe category")
	}
	if strings.Contains(iErr.Message, marker) {
		t.Error("caller-facing read error exposed response details")
	}
	if len(auditEvents) != 1 || auditEvents[0].UpstreamStatus != http.StatusBadGateway {
		t.Error("audit should retain the upstream HTTP status")
	}
}

func TestProxy_Invoke_Timeout(t *testing.T) {
	up := newUpstreamMCP(t, "slow", "")
	cfg := testConfig()
	cfg.ReadTimeout = 200 * time.Millisecond
	cfg.ConnectTimeout = 200 * time.Millisecond
	var auditEvents []AuditEvent
	audit := &recordingAudit{events: &auditEvents}
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), cfg, loopbackAllow(t), nil, audit)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "x", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeTimeout {
		t.Fatalf("want timeout, got %v", err)
	}
	if !strings.Contains(iErr.Message, "upstream timeout") || strings.Contains(iErr.Message, "127.0.0.1") {
		t.Error("timeout error should retain its category without exposing transport details")
	}
	if len(auditEvents) != 1 || auditEvents[0].Outcome != OutcomeTimeout {
		t.Fatalf("audit should record timeout: %+v", auditEvents)
	}
}

func TestProxy_Invoke_IdentityHeadersFromVerifiedPrincipal(t *testing.T) {
	// The proxy sets identity headers from the verified Identity struct, not
	// from the request — there is no request here, so a client cannot inject
	// them: the only source is the Identity passed to Invoke (R6, MCP-03).
	// MCP-04: all three identity headers (agent id, agent name, team id) are
	// forwarded to the upstream MCP server.
	up := newUpstreamMCP(t, "json", "")
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-9")), testConfig(), loopbackAllow(t), nil, nil)
	res, err := p.Invoke(context.Background(), "org-1",
		Identity{AgentID: "ag-9", AgentName: "research-agent", TeamID: "tm-9"},
		InvokeRequest{Server: "knowledge", Tool: "x", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	// The upstream must see all three verified-principal headers.
	if !strings.Contains(string(res), "agent=ag-9:agentname=research-agent:team=tm-9") {
		t.Fatalf("identity headers must come from the verified principal: %s", res)
	}
}

// TestProxy_Invoke_IdentityNameOmittedWhenUnknown: MCP-04 — an empty AgentName
// (the gateway omits it when the name lookup fails / there is no DB) results in
// the X-Yabanin-Agent-Name header NOT being sent, while agent id + team still
// ride. The name is an attribution aid, not an auth input.
func TestProxy_Invoke_IdentityNameOmittedWhenUnknown(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-9")), testConfig(), loopbackAllow(t), nil, nil)
	res, err := p.Invoke(context.Background(), "org-1",
		Identity{AgentID: "ag-9", AgentName: "", TeamID: "tm-9"},
		InvokeRequest{Server: "knowledge", Tool: "x", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	// The name field is empty → the header is omitted (agentname= with no value
	// between it and the team marker).
	if !strings.Contains(string(res), "agent=ag-9:agentname=:team=tm-9") {
		t.Fatalf("empty agent name must omit the header, not send blank: %s", res)
	}
}

// TestProxy_Invoke_NonAgentKeyRejected: MCP-03 — a regular api_key (empty
// AgentID) cannot invoke tools; the proxy returns agent_only (→ 403) before
// any server lookup and audits the denial.
func TestProxy_Invoke_NonAgentKeyRejected(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	var auditEvents []AuditEvent
	audit := &recordingAudit{events: &auditEvents}
	// Even a fully-registered server + grant must not matter: no agent ID.
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, audit)
	_, err := p.Invoke(context.Background(), "org-1", Identity{}, // regular key
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeAgentOnly {
		t.Fatalf("want agent_only, got %v", err)
	}
	if len(auditEvents) != 1 || auditEvents[0].Outcome != OutcomeDenied {
		t.Fatalf("audit should record the agent_only denial: %+v", auditEvents)
	}
}

// TestProxy_Invoke_NoGrantRejected: MCP-03 — an agent with NO enabled grant on
// the server is rejected (not_found, indistinguishable from a missing server).
func TestProxy_Invoke_NoGrantRejected(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	var auditEvents []AuditEvent
	audit := &recordingAudit{events: &auditEvents}
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, nil /* no grant */), testConfig(), loopbackAllow(t), nil, audit)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeNotFound {
		t.Fatalf("want not_found (no grant), got %v", err)
	}
	if len(auditEvents) != 1 || auditEvents[0].Outcome != OutcomeNotFound {
		t.Fatalf("audit should record not_found: %+v", auditEvents)
	}
}

// TestProxy_Invoke_AuditCarriesRequestContext: MCP-03 — the audit event the
// proxy emits must carry the per-request context (request id, task tag,
// upstream URL) so loggerd can join the tool call to its request_logs row and
// tag spend by task/agent.
func TestProxy_Invoke_AuditCarriesRequestContext(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	var auditEvents []AuditEvent
	audit := &recordingAudit{events: &auditEvents}
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, audit)
	_, err := p.Invoke(context.Background(), "org-1",
		Identity{AgentID: "ag-1", TeamID: "tm-1", RequestID: "req-42", TaskID: "task-9"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if len(auditEvents) != 1 {
		t.Fatalf("expected exactly one audit event, got %d", len(auditEvents))
	}
	e := auditEvents[0]
	if e.RequestID != "req-42" {
		t.Errorf("audit request id = %q, want req-42", e.RequestID)
	}
	if e.TaskID != "task-9" {
		t.Errorf("audit task id = %q, want task-9", e.TaskID)
	}
	if e.TeamID != "tm-1" {
		t.Errorf("audit team id = %q, want tm-1", e.TeamID)
	}
	if e.UpstreamURL != up.URL {
		t.Errorf("audit upstream url = %q, want %q", e.UpstreamURL, up.URL)
	}
	if e.Outcome != OutcomeOK {
		t.Errorf("audit outcome = %q, want ok", e.Outcome)
	}
}

// TestProxy_Invoke_GrantToolCeiling: MCP-03 — the effective tool set is the
// intersection of the server allow-list and the agent grant allow-list. A tool
// the server allows but the grant does NOT is rejected.
func TestProxy_Invoke_GrantToolCeiling(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	// Server allows all tools (nil); the grant allows only "search". Calling
	// "fetch" (server-OK, grant-blocked) must be not_found.
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				return chainRowFor(testGrant("ag-1", "search"))
			}
			if isGrantQuery(sql) {
				return &grantRow{g: testGrant("ag-1", "search")}
			}
			return &serverRow{srv: testServer(up.URL)} // all tools
		},
	}
	p := NewProxy(NewStore(db), testConfig(), loopbackAllow(t), nil, nil)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "fetch", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeNotFound {
		t.Fatalf("want not_found (grant ceiling), got %v", err)
	}
	// And the allowed tool ("search") goes through.
	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("allowed tool must succeed: %v", err)
	}
	if !strings.Contains(string(res), "result:search") {
		t.Fatalf("expected search result, got %s", res)
	}
}

func TestToolAllowed(t *testing.T) {
	if !toolAllowed(nil, "anything") {
		t.Fatal("empty allow-list must allow all tools")
	}
	if !toolAllowed([]string{"a", "b"}, "b") {
		t.Fatal("listed tool must be allowed")
	}
	if toolAllowed([]string{"a", "b"}, "c") {
		t.Fatal("unlisted tool must be denied")
	}
}

// --- fakes for Hook / AuditLogger ------------------------------------------

type staticHook struct {
	deny     string
	redacted []byte
}

func (h *staticHook) Scan(_ context.Context, params []byte) ([]byte, string, string) {
	if h.deny != "" {
		return params, h.deny, "deny"
	}
	if h.redacted != nil {
		return h.redacted, "", "redact"
	}
	return params, "", "off"
}

type recordingAudit struct {
	mu     sync.Mutex
	events *[]AuditEvent
}

func (a *recordingAudit) Log(_ context.Context, e AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	*a.events = append(*a.events, e)
	return nil
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *serverRows) TypeMap() *pgtype.Map { return nil }
