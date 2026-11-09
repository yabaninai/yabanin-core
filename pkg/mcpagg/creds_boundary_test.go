package mcpagg

// Failure/boundary tests for the MC-2 invoke path: when an upstream
// answers with an error body that echoes the very credential the proxy just
// applied (a hostile or misconfigured MCP server), neither the caller-facing
// error nor the audit trail may carry the material. Also pinned here: the
// fail-closed copy of credential headers (a store bypass carrying CR/LF
// never reaches the wire) and the cancel/interrupt posture (an interrupted
// invoke is an error, never a partial success).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
)

// boundaryServerName keeps these tests off the shared prometheus label set
// the older exact-count assertions in creds_test.go pin ("knowledge").
const boundaryServerName = "boundary-srv"

// boundaryStoreFor builds a mock Store serving a server+grant pair under
// boundaryServerName (same mock mechanics as storeForUpstreamWithGrant).
func boundaryStoreFor(upURL string) *Store {
	srv := testServer(upURL)
	srv.Name = boundaryServerName
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				g := testGrant("ag-1")
				g.ServerName = boundaryServerName
				return chainRowFor(g)
			}
			if isGrantQuery(sql) {
				g := testGrant("ag-1")
				g.ServerName = boundaryServerName
				return &grantRow{g: g}
			}
			return &serverRow{srv: srv}
		},
	}
	return NewStore(db)
}

// echoingUpstream builds an upstream that reflects the Authorization header
// it received back into the response body (the leak vector: a hostile server
// bouncing the credential) with the given status and content type.
func echoingUpstream(t *testing.T, status int, contentType string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		//nolint:gosec // G705: the mock upstream deliberately echoes the credential it received — the test proves the proxy redacts it
		_, _ = w.Write([]byte(`{"error":"rejected credential: ` + r.Header.Get("Authorization") + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestProxy_Invoke_UpstreamEchoCredential_AuthRequiredRedacted: a 401 whose
// body echoes the applied credential must surface as mcp_auth_required with
// zero credential material in the error, its JSON shape, or the audit event.
func TestProxy_Invoke_UpstreamEchoCredential_AuthRequiredRedacted(t *testing.T) {
	const credential = "sk-mcpagg-echo-oauth-9a7b3c2f" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	up, _ := echoingUpstream(t, http.StatusUnauthorized, "")
	cs := &fakeCredSource{
		headers: map[string][]string{"Authorization": {"Bearer " + credential}},
		kind:    CredKindOAuth, // terminal rejection: no refresh configured → no retry
	}
	var auditEvents []AuditEvent
	p := NewProxy(boundaryStoreFor(up.URL), testConfig(), loopbackAllow(t), nil,
		&recordingAudit{events: &auditEvents}).WithCredsSource(cs)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: boundaryServerName, Tool: "search", Params: json.RawMessage(`{}`)})
	var authErr *AuthRequiredError
	if !errors.As(err, &authErr) {
		t.Fatalf("want mcp_auth_required, got %v", err)
	}
	if strings.Contains(err.Error(), credential) {
		t.Errorf("lazy-auth error carried the credential: %v", err)
	}
	shape, mErr := json.Marshal(authErr)
	if mErr != nil {
		t.Fatalf("marshal AuthRequiredError: %v", mErr)
	}
	if strings.Contains(string(shape), credential) {
		t.Errorf("structured 401 body carried the credential: %s", shape)
	}
	if len(auditEvents) != 1 {
		t.Fatalf("expected exactly one audit event, got %d", len(auditEvents))
	}
	if auditEvents[0].Outcome != OutcomeAuthRequired {
		t.Errorf("audit outcome = %q, want %q", auditEvents[0].Outcome, OutcomeAuthRequired)
	}
	for _, leak := range auditMaterialCandidates(auditEvents[0]) {
		if strings.Contains(leak, credential) {
			t.Error("audit event carried the echoed credential")
		}
	}
}

// TestProxy_Invoke_UpstreamEchoCredential_UpstreamErrorRedacted: the same
// echo on a plain upstream failure stays "upstream status %d" everywhere.
func TestProxy_Invoke_UpstreamEchoCredential_UpstreamErrorRedacted(t *testing.T) {
	const credential = "sk-mcpagg-echo-headers-4d8e1f60" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	up, _ := echoingUpstream(t, http.StatusInternalServerError, "application/json")
	cs := &fakeCredSource{
		headers: map[string][]string{"Authorization": {"Bearer " + credential}},
		kind:    CredKindHeaders,
	}
	var auditEvents []AuditEvent
	p := NewProxy(boundaryStoreFor(up.URL), testConfig(), loopbackAllow(t), nil,
		&recordingAudit{events: &auditEvents}).WithCredsSource(cs)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: boundaryServerName, Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatalf("want typed upstream error, got %v", err)
	}
	if !strings.Contains(iErr.Message, "upstream status 500") {
		t.Errorf("error should stay the status-only category, got %q", iErr.Message)
	}
	if strings.Contains(err.Error(), credential) {
		t.Errorf("upstream error carried the echoed credential: %v", err)
	}
	for _, ev := range auditEvents {
		for _, leak := range auditMaterialCandidates(ev) {
			if strings.Contains(leak, credential) {
				t.Error("audit event carried the echoed credential")
			}
		}
	}
}

// auditMaterialCandidates flattens every free-text field of an AuditEvent
// that could carry material (error message + redacted params).
func auditMaterialCandidates(e AuditEvent) []string {
	return []string{e.ErrorMessage, string(e.ParamsRedacted)}
}

// TestProxy_Invoke_CredHeaderInjectionFailsClosed simulates a store bypass
// handing the proxy a CR/LF-bearing credential header: the request must fail
// closed (the upstream is never dialed) and the injected payload must not
// surface in the error.
func TestProxy_Invoke_CredHeaderInjectionFailsClosed(t *testing.T) {
	const injected = "injected-credential-7c2f"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("an upstream must never see an injectable credential header")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)

	tests := []struct {
		name    string
		headers map[string][]string
	}{
		{"crlf in value", map[string][]string{"Authorization": {"Bearer x\r\nX-Evil: " + injected}}},
		{"crlf in name", map[string][]string{"X-Bad\r\nX-Evil": {injected}}},
		{"nul in value", map[string][]string{"Authorization": {"Bearer " + injected + "\x00"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := &fakeCredSource{headers: tc.headers, kind: CredKindHeaders}
			p := NewProxy(boundaryStoreFor(up.URL), testConfig(), loopbackAllow(t), nil, nil).
				WithCredsSource(cs)
			_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
				InvokeRequest{Server: boundaryServerName, Tool: "search", Params: json.RawMessage(`{}`)})
			if err == nil {
				t.Fatal("an injectable credential header must fail the invoke (fail closed)")
			}
			if strings.Contains(err.Error(), injected) {
				t.Errorf("error echoed the injected payload: %v", err)
			}
		})
	}
}

// TestProxy_Invoke_CancelledContext_NeverPartialSuccess: an interrupted
// invoke is a typed error with zero upstream calls — never a partial result.
func TestProxy_Invoke_CancelledContext_NeverPartialSuccess(t *testing.T) {
	up, calls := echoingUpstream(t, http.StatusOK, "application/json")
	cs := &fakeCredSource{
		headers: map[string][]string{"Authorization": {"Bearer tok"}},
		kind:    CredKindHeaders,
	}
	p := NewProxy(boundaryStoreFor(up.URL), testConfig(), loopbackAllow(t), nil, nil).
		WithCredsSource(cs)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := p.Invoke(ctx, "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: boundaryServerName, Tool: "search", Params: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("a cancelled invoke must not succeed")
	}
	if res != nil {
		t.Errorf("a cancelled invoke must not return a partial result: %s", res)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("the cancelled invoke dialed the upstream %d times, want 0", n)
	}
	var iErr *InvokeError
	if !errors.As(err, &iErr) {
		t.Fatalf("want a typed InvokeError, got %v", err)
	}
	if iErr.Message == "" {
		t.Error("the failure must stay diagnosable (non-empty message)")
	}
}
