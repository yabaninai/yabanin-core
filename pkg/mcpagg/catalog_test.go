package mcpagg

// endpoint's catalog reads through. Same fixture style as proxy_test.go /
// creds_test.go (mock DB + httptest loopback upstreams via testAllowHTTP).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// methodRecorder is a tiny string cell (atomic.String is not in the stdlib).
type methodRecorder struct {
	mu sync.Mutex
	v  string
}

func (m *methodRecorder) store(s string) {
	m.mu.Lock()
	m.v = s
	m.mu.Unlock()
}

func (m *methodRecorder) load() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.v
}

// newToolsListUpstream serves the MCP tools/list JSON-RPC method (and
// records which method was requested); status controls the HTTP verdict.
func newToolsListUpstream(t *testing.T, status int) (*httptest.Server, *methodRecorder) {
	t.Helper()
	var lastMethod methodRecorder
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		lastMethod.store(req.Method)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = fmt.Fprintln(w, "unauthorized")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"tools": []map[string]any{
					{"name": "search", "description": "search docs",
						"inputSchema": map[string]any{"type": "object"}},
					{"name": "fetch", "description": "fetch a doc"},
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &lastMethod
}

// toolsListStore returns a Store whose server+grant rows carry a DISTINCT
// server name ("catalogsrv") so the shared gateway_mcp_creds_total /
// gateway_mcp_calls_total series asserted by the existing invoke tests are
// not polluted by these tests (global promauto counters).
func toolsListStore(upURL string) *Store {
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				return chainRowFor(&Grant{
					ID: "gr-c1", OrgID: "org-1", AgentID: "ag-1",
					ServerName: "catalogsrv", AllowedActions: defaultActions(), Enabled: true,
				})
			}
			if isGrantQuery(sql) {
				return &grantRow{g: &Grant{
					ID: "gr-c1", OrgID: "org-1", AgentID: "ag-1",
					ServerName: "catalogsrv", AllowedActions: defaultActions(), Enabled: true,
				}}
			}
			return &serverRow{srv: func() *Server {
				s := testServer(upURL)
				s.Name = "catalogsrv"
				return s
			}()}
		},
	}
	return NewStore(db)
}

func toolsListProxy(t *testing.T, upURL string, cs CredSource) *Proxy {
	t.Helper()
	p := NewProxy(toolsListStore(upURL), testConfig(), loopbackAllow(t), nil, nil)
	if cs != nil {
		p = p.WithCredsSource(cs)
	}
	return p
}

func TestProxy_ListServerTools_Happy(t *testing.T) {
	up, lastMethod := newToolsListUpstream(t, http.StatusOK)
	p := toolsListProxy(t, up.URL, nil)

	tools, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "catalogsrv")
	if err != nil {
		t.Fatalf("ListServerTools: %v", err)
	}
	if lastMethod.load() != "tools/list" {
		t.Fatalf("upstream method = %q", lastMethod.load())
	}
	if len(tools) != 2 || tools[0].Name != "search" || tools[0].Description != "search docs" {
		t.Fatalf("tools = %+v", tools)
	}
	if string(tools[0].InputSchema) != `{"type":"object"}` {
		t.Fatalf("inputSchema = %s", tools[0].InputSchema)
	}
}

func TestProxy_ListServerTools_AgentOnly(t *testing.T) {
	up, _ := newToolsListUpstream(t, http.StatusOK)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil)

	_, err := p.ListServerTools(context.Background(), "org-1", Identity{}, "knowledge")
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeAgentOnly {
		t.Fatalf("want agent_only, got %v", err)
	}
}

func TestProxy_ListServerTools_ServerNotFound(t *testing.T) {
	// No server row at all: ErrNotFound before any credential/metric work.
	st := NewStore(&mcpMockDB{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return &serverRow{srv: nil}
		},
	})
	p := NewProxy(st, testConfig(), loopbackAllow(t), nil, nil)
	_, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "missing")
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeNotFound {
		t.Fatalf("want not_found, got %v", err)
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Fatalf("not_found must not reveal disabled-vs-missing: %v", err)
	}
}

func TestProxy_ListServerTools_NoGrant(t *testing.T) {
	up, _ := newToolsListUpstream(t, http.StatusOK)
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				return chainRowFor(nil) // grant missing/disabled
			}
			if isGrantQuery(sql) {
				return &grantRow{g: nil} // grant missing/disabled
			}
			return &serverRow{srv: testServer(up.URL)}
		},
	}
	p := NewProxy(NewStore(db), testConfig(), loopbackAllow(t), nil, nil)
	_, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "knowledge") //nolint:goconst // distinct fixture: no grant found before any metric fires
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeNotFound {
		t.Fatalf("want not_found, got %v", err)
	}
}

func TestProxy_ListServerTools_UpstreamError(t *testing.T) {
	up, _ := newToolsListUpstream(t, http.StatusBadGateway)
	p := toolsListProxy(t, up.URL, nil)
	_, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "catalogsrv")
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatalf("want upstream, got %v", err)
	}
}

func TestProxy_ListServerTools_AuthRequiredNoCreds(t *testing.T) {
	up, _ := newToolsListUpstream(t, http.StatusUnauthorized)
	// The org holds NO credential: the lazy-authorization error names the
	// headers flow (the actionable default).
	cs := &fakeCredSource{kind: CredKindNone}
	p := toolsListProxy(t, up.URL, cs)

	_, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "catalogsrv")
	var authErr *AuthRequiredError
	if !errors.As(err, &authErr) {
		t.Fatalf("want mcp_auth_required, got %v", err)
	}
	if authErr.Kind != CredKindHeaders || !strings.Contains(authErr.URL, "/api/mcp/credentials/catalogsrv") {
		t.Fatalf("auth error = %+v", authErr)
	}
}

func TestProxy_ListServerTools_CredsApplied(t *testing.T) {
	var gotAuth methodRecorder
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotAuth.store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"tools": []map[string]any{{"name": "search"}}},
		})
	})
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)

	cs := &fakeCredSource{headers: map[string][]string{"Authorization": {"Bearer tok"}}, kind: CredKindHeaders}
	p := toolsListProxy(t, up.URL, cs)
	tools, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "catalogsrv")
	if err != nil {
		t.Fatalf("ListServerTools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "search" {
		t.Fatalf("tools = %+v", tools)
	}
	if gotAuth.load() != "Bearer tok" {
		t.Fatalf("credential not applied upstream: %q", gotAuth.load())
	}
}

func TestProxy_ListServerTools_MalformedResult(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":"not-a-list"}}`))
	})
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)

	p := toolsListProxy(t, up.URL, nil)
	_, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "catalogsrv")
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatalf("want upstream (malformed), got %v", err)
	}
}
