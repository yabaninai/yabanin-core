package mcpagg

// MC-2 proxy tests: credential resolution on the invoke path — header
// application, the single refresh+retry round after an upstream 401, the
// mcp_auth_required lazy-authorization error, fail-closed source errors, and
// the invariant that a credential NEVER extends the egress allow-list.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// fakeCredSource is the CredSource double: canned headers, a configurable
// refresh outcome, and probe accounting for the egress-invariant test.
type fakeCredSource struct {
	headers      map[string][]string
	kind         string
	authCalls    atomic.Int64
	unauthCalls  atomic.Int64
	refreshed    map[string][]string
	retry        bool
	refreshErr   error
	resolveErr   error
	unauthorized func(kind string)
}

func (f *fakeCredSource) AuthHeaders(context.Context, string, string, string) (map[string][]string, string, error) {
	f.authCalls.Add(1)
	if f.resolveErr != nil {
		return nil, f.kind, f.resolveErr
	}
	if f.headers == nil {
		return nil, f.kind, nil
	}
	return f.headers, f.kind, nil
}

func (f *fakeCredSource) OnUpstreamUnauthorized(_ context.Context, _, _, _, kind string) (map[string][]string, bool, error) {
	f.unauthCalls.Add(1)
	if f.unauthorized != nil {
		f.unauthorized(kind)
	}
	if f.refreshErr != nil {
		return nil, false, f.refreshErr
	}
	if f.retry {
		return f.refreshed, true, nil
	}
	return nil, false, nil
}

// bearerUpstream is a mock MCP server that checks the Authorization header:
// wantToken "" accepts anything; otherwise it demands exactly that bearer
// token and answers 401 otherwise. calls counts the JSON-RPC attempts.
type bearerUpstream struct {
	srv       *httptest.Server
	calls     atomic.Int64
	lastAuth  atomic.Value // string
	wantToken string
}

func newBearerUpstream(t *testing.T, wantToken string) *bearerUpstream {
	t.Helper()
	b := &bearerUpstream{wantToken: wantToken}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.calls.Add(1)
		auth := r.Header.Get("Authorization")
		b.lastAuth.Store(auth)
		if b.wantToken != "" && auth != "Bearer "+b.wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	t.Cleanup(b.srv.Close)
	return b
}

// credProxy builds a proxy over an upstream with the given cred source.
func credProxy(t *testing.T, upURL string, cs CredSource) *Proxy {
	t.Helper()
	return NewProxy(storeForUpstreamWithGrant(upURL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithCredsSource(cs)
}

func TestProxy_Invoke_CredHeadersApplied(t *testing.T) {
	up := newBearerUpstream(t, "tok-good")
	cs := &fakeCredSource{headers: map[string][]string{"Authorization": {"Bearer tok-good"}}, kind: CredKindHeaders}
	p := credProxy(t, up.srv.URL, cs)
	beforeHit := testutil.ToFloat64(metrics.MCPCredsTotal.WithLabelValues("knowledge", CredKindHeaders, CredOutcomeHit))

	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("invoke with credential: %v", err)
	}
	if !strings.Contains(string(res), "ok") {
		t.Fatalf("unexpected result: %s", res)
	}
	if up.calls.Load() != 1 || up.lastAuth.Load().(string) != "Bearer tok-good" {
		t.Fatalf("upstream must receive the credential header (calls=%d auth=%v)", up.calls.Load(), up.lastAuth.Load())
	}
	if n := testutil.ToFloat64(metrics.MCPCredsTotal.WithLabelValues("knowledge", CredKindHeaders, CredOutcomeHit)) - beforeHit; n != 1 {
		t.Fatalf("hit metric delta = %v, want 1", n)
	}
}

func TestProxy_Invoke_NoCredUpstream401_AuthRequired(t *testing.T) {
	up := newBearerUpstream(t, "tok-any") // always 401s: nobody has the token
	cs := &fakeCredSource{kind: CredKindNone}
	p := credProxy(t, up.srv.URL, cs)
	beforeMiss := testutil.ToFloat64(metrics.MCPCredsTotal.WithLabelValues("knowledge", CredKindNone, CredOutcomeMiss))

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var authErr *AuthRequiredError
	if !errors.As(err, &authErr) {
		t.Fatalf("want mcp_auth_required, got %v", err)
	}
	if authErr.Kind != CredKindHeaders {
		t.Fatalf("default kind must be headers (submit endpoint), got %q", authErr.Kind)
	}
	if authErr.URL != "/api/mcp/credentials/knowledge" {
		t.Fatalf("url = %q", authErr.URL)
	}
	if n := testutil.ToFloat64(metrics.MCPCredsTotal.WithLabelValues("knowledge", CredKindNone, CredOutcomeMiss)) - beforeMiss; n != 1 {
		t.Fatalf("miss metric delta = %v, want 1", n)
	}
}

func TestProxy_Invoke_RefreshRetryOn401(t *testing.T) {
	up := newBearerUpstream(t, "tok-new")
	cs := &fakeCredSource{
		headers:   map[string][]string{"Authorization": {"Bearer tok-expired"}},
		kind:      CredKindOAuth,
		refreshed: map[string][]string{"Authorization": {"Bearer tok-new"}},
		retry:     true,
	}
	p := credProxy(t, up.srv.URL, cs)
	beforeRefresh := testutil.ToFloat64(metrics.MCPCredsTotal.WithLabelValues("knowledge", CredKindOAuth, CredOutcomeRefresh))

	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("invoke with refresh: %v", err)
	}
	_ = res
	if up.calls.Load() != 2 {
		t.Fatalf("upstream must see exactly 2 calls (expired + refreshed), got %d", up.calls.Load())
	}
	if up.lastAuth.Load().(string) != "Bearer tok-new" {
		t.Fatalf("retry must carry the refreshed token, got %v", up.lastAuth.Load())
	}
	if cs.unauthCalls.Load() != 1 {
		t.Fatalf("exactly one refresh round, got %d", cs.unauthCalls.Load())
	}
	if n := testutil.ToFloat64(metrics.MCPCredsTotal.WithLabelValues("knowledge", CredKindOAuth, CredOutcomeRefresh)) - beforeRefresh; n != 1 {
		t.Fatalf("refresh metric delta = %v, want 1", n)
	}
}

func TestProxy_Invoke_TerminalRejection_NeedsReauthError(t *testing.T) {
	up := newBearerUpstream(t, "tok-any")
	cs := &fakeCredSource{headers: map[string][]string{"Authorization": {"Bearer tok-dead"}}, kind: CredKindOAuth}
	p := credProxy(t, up.srv.URL, cs)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var authErr *AuthRequiredError
	if !errors.As(err, &authErr) {
		t.Fatalf("want mcp_auth_required after terminal rejection, got %v", err)
	}
	if authErr.Kind != CredKindOAuth || authErr.URL != "/api/mcp/auth/knowledge/begin" {
		t.Fatalf("oauth rejection must point at the begin flow: %+v", authErr)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("no retry without a refresh, got %d calls", up.calls.Load())
	}
}

func TestProxy_Invoke_SourceError_FailClosed(t *testing.T) {
	up := newBearerUpstream(t, "")
	cs := &fakeCredSource{resolveErr: errors.New("db down")}
	p := credProxy(t, up.srv.URL, cs)
	beforeError := testutil.ToFloat64(metrics.MCPCredsTotal.WithLabelValues("knowledge", CredKindNone, CredOutcomeError))

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("a credential resolution failure must fail the call (fail closed)")
	}
	if up.calls.Load() != 0 {
		t.Fatalf("the upstream must not be dialed without a resolved credential, got %d calls", up.calls.Load())
	}
	if n := testutil.ToFloat64(metrics.MCPCredsTotal.WithLabelValues("knowledge", CredKindNone, CredOutcomeError)) - beforeError; n != 1 {
		t.Fatalf("error metric delta = %v, want 1", n)
	}
}

func TestProxy_Invoke_CredDoesNotExtendEgressAllowList(t *testing.T) {
	// The host is OUTSIDE the allow-list. With a perfectly good credential
	// attached the call must STILL be ssrf_blocked, and the credential source
	// must never even be consulted (the guard runs before resolution).
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("the disallowed upstream must never be dialed")
	}))
	t.Cleanup(up.Close)

	allow, err := ssrf.NewAllowList([]string{"127.0.0.1", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	srv := testServer("https://disallowed-host.example.com") // not in the list
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				return chainRowFor(testGrant("ag-1"))
			}
			if isGrantQuery(sql) {
				return &grantRow{g: testGrant("ag-1")}
			}
			return &serverRow{srv: srv}
		},
	}
	cs := &fakeCredSource{headers: map[string][]string{"Authorization": {"Bearer tok"}}, kind: CredKindHeaders}
	p := NewProxy(NewStore(db), NewDefaultConfig(), allow, nil, nil).WithCredsSource(cs)

	_, err = p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeSSRF {
		t.Fatalf("want ssrf_blocked with a credential attached, got %v", err)
	}
	if cs.authCalls.Load() != 0 {
		t.Fatalf("the credential source must not be consulted for a disallowed host, got %d calls", cs.authCalls.Load())
	}
}

func TestApplyCredHeaders(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://mcp.example.test", nil)
	if err := applyCredHeaders(req, map[string][]string{
		"Authorization": {"Bearer a", "Bearer b"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Values("Authorization"); len(got) != 2 {
		t.Fatalf("multi-value header must be preserved: %v", got)
	}
	oversized := make(map[string][]string, maxCredHeaderCount+1)
	for i := 0; i < maxCredHeaderCount+1; i++ {
		oversized[fmt.Sprintf("X-H-%d", i)] = []string{"v"}
	}
	if err := applyCredHeaders(req, oversized); err == nil {
		t.Fatal("an oversized header set must be refused")
	}
}

func TestNewAuthRequiredError_URLs(t *testing.T) {
	h := newAuthRequiredError(CredKindHeaders, "knowledge", "m")
	if h.URL != "/api/mcp/credentials/knowledge" {
		t.Fatalf("headers URL = %q", h.URL)
	}
	o := newAuthRequiredError(CredKindOAuth, "knowledge", "m")
	if o.URL != "/api/mcp/auth/knowledge/begin" {
		t.Fatalf("oauth URL = %q", o.URL)
	}
}
