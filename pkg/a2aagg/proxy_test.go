package a2aagg

// Proxy tests over a stubbed registry DB and httptest upstreams: the happy
// path, the authz/registry failure matrix, the guard hook contract and
// timeout handling. The testAllowHTTP seam keeps the upstream http://
// (the https-only and reserved-IP guards are pinned in validate_test.go).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// ---- stub DB: answers the GetEnabled query shape --------------------------

type stubDB struct{ agents map[string]*Agent } // key: orgID/name

func (m *stubDB) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	if len(args) == 2 {
		key := fmt.Sprintf("%v/%v", args[0], args[1])
		if a, ok := m.agents[key]; ok && a.Enabled {
			return &stubRow{agent: a}
		}
	}
	return &stubRow{err: pgx.ErrNoRows}
}
func (m *stubDB) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return nil, errors.New("unused")
}
func (m *stubDB) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unused")
}

type stubRow struct {
	agent *Agent
	err   error
}

func (r *stubRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	a := r.agent
	now := time.Now()
	// Column order: id, org_id, name, display_name, url, enabled, created_at, updated_at
	for i, d := range dest {
		switch i {
		case 0:
			if p, ok := d.(*string); ok {
				if a.ID == "" {
					a.ID = "a-1"
				}
				*p = a.ID
			}
		case 1:
			if p, ok := d.(*string); ok {
				*p = a.OrgID
			}
		case 2:
			if p, ok := d.(*string); ok {
				*p = a.Name
			}
		case 3:
			switch p := d.(type) {
			case **string:
				*p = a.DisplayName
			case *string:
				if a.DisplayName != nil {
					*p = *a.DisplayName
				}
			}
		case 4:
			if p, ok := d.(*string); ok {
				*p = a.URL
			}
		case 5:
			if p, ok := d.(*bool); ok {
				*p = a.Enabled
			}
		case 6, 7:
			if p, ok := d.(*time.Time); ok {
				*p = now
			}
		}
	}
	return nil
}

func (r *stubRow) Close()                                       {}
func (r *stubRow) Err() error                                   { return r.err }
func (r *stubRow) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *stubRow) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *stubRow) Values() ([]any, error)                       { return nil, r.err }
func (r *stubRow) RawScan(_ []any) error                        { return r.err }

// ---- fixtures --------------------------------------------------------------

type recordingAudit struct{ events []AuditEvent }

func (a *recordingAudit) Log(_ context.Context, e AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}

type denyHook struct{ reason string }

func (h denyHook) Scan(_ context.Context, params []byte) ([]byte, string, string) {
	if h.reason != "" {
		return params, h.reason, "deny"
	}
	return params, "", "log"
}

// a2aUpstream is an httptest A2A agent answering message/send.
func a2aUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("upstream got %s, want POST", r.Method)
		}
		var env struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&env)
		if env.Method != "message/send" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"message":"method not supported"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"kind":"message","messageId":"m-1"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testProxy builds a Proxy whose registry resolves org-1/helper to url,
// with the http-test seam enabled.
func testProxy(t *testing.T, url string, hook Hook, audit AuditLogger) *Proxy {
	t.Helper()
	cfg := NewDefaultConfig()
	cfg.testAllowHTTP = true
	allow, err := ssrf.NewAllowList([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	db := &stubDB{agents: map[string]*Agent{
		"org-1/helper": {ID: "a-1", OrgID: "org-1", Name: "helper", URL: url, Enabled: true},
	}}
	return NewProxy(NewStore(db), cfg, allow, hook, audit)
}

// ---- tests -----------------------------------------------------------------

func TestSend_HappyPath(t *testing.T) {
	var audit recordingAudit
	upstream := a2aUpstream(t)
	p := testProxy(t, upstream.URL, nil, &audit)

	result, err := p.Send(context.Background(), "org-1",
		Identity{AgentID: "agent-9", RequestID: "req-1", TaskID: "task-7"},
		SendRequest{Agent: "helper", Params: json.RawMessage(`{"message":{"messageId":"x","parts":[]}}`)})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !json.Valid(result) {
		t.Fatalf("result not valid JSON: %s", result)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events: %d, want 1", len(audit.events))
	}
	e := audit.events[0]
	if e.Outcome != OutcomeOK || e.AgentID != "agent-9" || e.TaskID != "task-7" || e.TargetName != "helper" {
		t.Fatalf("audit event mismatch: %+v", e)
	}
}

func TestSend_AgentKeyOnly(t *testing.T) {
	p := testProxy(t, "https://unused.test", nil, nil)
	_, err := p.Send(context.Background(), "org-1", Identity{}, SendRequest{Agent: "helper"})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeAgentOnly {
		t.Fatalf("empty identity: got %v, want agent_only", err)
	}
}

func TestSend_UnknownOrDisabledAgent_NotFound(t *testing.T) {
	p := testProxy(t, "https://unused.test", nil, nil)
	// "nope" is not in the registry → not_found.
	_, err := p.Send(context.Background(), "org-1", Identity{AgentID: "a"}, SendRequest{Agent: "nope"})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeNotFound {
		t.Fatalf("unknown agent: got %v, want not_found", err)
	}
}

func TestSend_GuardDeny(t *testing.T) {
	var audit recordingAudit
	p := testProxy(t, "https://x.test", denyHook{reason: "secrets in message"}, &audit)

	_, err := p.Send(context.Background(), "org-1", Identity{AgentID: "a"},
		SendRequest{Agent: "helper", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("guard deny: got %v, want denied", err)
	}
	if len(audit.events) != 1 || audit.events[0].Outcome != OutcomeDenied {
		t.Fatalf("denied audit: %+v", audit.events)
	}
}

func TestSend_UpstreamJSONRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"agent failed"}}`))
	}))
	t.Cleanup(srv.Close)

	p := testProxy(t, srv.URL, nil, nil)
	_, err := p.Send(context.Background(), "org-1", Identity{AgentID: "a"}, SendRequest{Agent: "helper"})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatalf("upstream rpc error: got %v, want upstream", err)
	}
	if !strings.Contains(iErr.Message, "agent failed") {
		t.Fatalf("error should carry the upstream message: %v", iErr.Message)
	}
}

func TestSend_UpstreamTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(srv.Close)

	cfg := NewDefaultConfig()
	cfg.testAllowHTTP = true
	cfg.ReadTimeout = 50 * time.Millisecond
	allow, _ := ssrf.NewAllowList([]string{"127.0.0.1"})
	db := &stubDB{agents: map[string]*Agent{
		"org-1/helper": {OrgID: "org-1", Name: "helper", URL: srv.URL, Enabled: true},
	}}
	p := NewProxy(NewStore(db), cfg, allow, nil, nil)

	_, err := p.Send(context.Background(), "org-1", Identity{AgentID: "a"}, SendRequest{Agent: "helper"})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeTimeout {
		t.Fatalf("timeout: got %v, want timeout", err)
	}
}

func TestSend_SSRFBlockedInProductionMode(t *testing.T) {
	// testAllowHTTP=false: an http:// upstream must be rejected by the
	// per-send SSRF guard even though the row exists and is enabled.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be called")
	}))
	t.Cleanup(srv.Close)

	cfg := NewDefaultConfig() // testAllowHTTP stays false
	allow, _ := ssrf.NewAllowList([]string{"127.0.0.1"})
	db := &stubDB{agents: map[string]*Agent{
		"org-1/helper": {OrgID: "org-1", Name: "helper", URL: srv.URL, Enabled: true},
	}}
	p := NewProxy(NewStore(db), cfg, allow, nil, nil)

	_, err := p.Send(context.Background(), "org-1", Identity{AgentID: "a"}, SendRequest{Agent: "helper"})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeSSRF {
		t.Fatalf("http upstream: got %v, want ssrf_blocked", err)
	}
}
