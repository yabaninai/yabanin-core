package mcpagg

// Characterization suite for Proxy.Invoke: pins the observable invoke
// contract (stage ordering, egress values, error translation, cancellation,
// audit labels) before the Invoke decomposition. Independent of the other
// proxy suites: each test names the behavior it freezes on the unmodified
// base, with negative controls where a plausible refactor could flip it.

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
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// charEchoUpstream answers a JSON-RPC tools/call result that echoes the raw
// arguments bytes back into the result text, capturing what actually
// egressed. Returns the capture snapshot and the server.
func charEchoUpstream(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var args []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		args = append(args, string(req.Params.Arguments))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), args...)
	}
}

// The OP-6 args guard (stage 2c) runs BEFORE the MCP-06 hook scan (stage 4):
// when both would deny, the caller sees mcp_tool_blocked, not denied. (The
// hook-only outcome is frozen by TestInvokeChar_HookDenySurfacesWhenNoGuard.)
func TestInvokeChar_GuardArgsDenyOutranksHookDeny(t *testing.T) {
	up, sawArgs := charEchoUpstream(t)
	g := &fakeGuard{args: toolpolicy.ArgsReport{Denied: true, Reason: "policy cap"}}
	hook := &staticHook{deny: "secret detected"}
	var auditEvents []AuditEvent
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), hook,
		&recordingAudit{events: &auditEvents}).WithToolGuard(g)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
		t.Fatalf("guard deny must win the ordering, got %v", err)
	}
	if iErr.Message != "policy cap" {
		t.Fatalf("message must be the guard reason, got %q", iErr.Message)
	}
	if got := sawArgs(); len(got) != 0 {
		t.Fatalf("denied call must not egress, saw %v", got)
	}
	if len(auditEvents) != 1 || auditEvents[0].Outcome != OutcomeToolBlocked {
		t.Fatalf("audit must record one tool_blocked event: %+v", auditEvents)
	}
}

// Negative control for the ordering pin above: the same hook denial, but
// with no toolpolicy guard installed, surfaces as denied (OutcomeDenied).
func TestInvokeChar_HookDenySurfacesWhenNoGuard(t *testing.T) {
	up, sawArgs := charEchoUpstream(t)
	hook := &staticHook{deny: "secret detected"}
	var ctlEvents []AuditEvent
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), hook,
		&recordingAudit{events: &ctlEvents})
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("hook-only deny must surface denied, got %v", err)
	}
	if len(ctlEvents) != 1 || ctlEvents[0].Outcome != OutcomeDenied {
		t.Fatalf("control audit must record denied: %+v", ctlEvents)
	}
	if got := sawArgs(); len(got) != 0 {
		t.Fatalf("denied call must not egress, saw %v", got)
	}
}

// What the hook returns is what egresses (and what the audit records): the
// redacted params, never the originals.
func TestInvokeChar_HookRedactedParamsAreWhatEgress(t *testing.T) {
	up, sawArgs := charEchoUpstream(t)
	hook := &staticHook{redacted: []byte(`{"q":"***"}`)}
	var auditEvents []AuditEvent
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), hook,
		&recordingAudit{events: &auditEvents})

	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"sk-orig"}`)}); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	got := sawArgs()
	if len(got) != 1 || got[0] != `{"q":"***"}` {
		t.Fatalf("upstream must see exactly the redacted params, saw %v", got)
	}
	if len(auditEvents) != 1 || string(auditEvents[0].ParamsRedacted) != `{"q":"***"}` {
		t.Fatalf("audit must carry the same redacted params: %+v", auditEvents)
	}
}

// Nil params default to the empty JSON object before egress (never null or
// an absent arguments member).
func TestInvokeChar_NilParamsEgressAsEmptyObject(t *testing.T) {
	up, sawArgs := charEchoUpstream(t)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil)

	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search"}); err != nil {
		t.Fatalf("invoke with nil params: %v", err)
	}
	got := sawArgs()
	if len(got) != 1 || got[0] != `{}` {
		t.Fatalf("nil params must egress as {}, saw %v", got)
	}
}

// An HTTP 200 whose body is a JSON-RPC error member is an upstream error
// (message category only), audited as upstream_error with the 200 status.
func TestInvokeChar_JSONRPCErrorMemberOnHTTP200(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"tool failed"}}`))
	}))
	t.Cleanup(up.Close)
	var auditEvents []AuditEvent
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil,
		&recordingAudit{events: &auditEvents})

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatalf("want upstream, got %v", err)
	}
	if !strings.Contains(iErr.Message, "upstream json-rpc error -32000") {
		t.Fatalf("message must carry the json-rpc error category, got %q", iErr.Message)
	}
	// Base behavior: a failed call's audit outcome carries the InvokeError
	// CODE string ("upstream"), not the OutcomeUpstreamError constant.
	if len(auditEvents) != 1 || auditEvents[0].Outcome != ErrCodeUpstream ||
		auditEvents[0].UpstreamStatus != http.StatusOK {
		t.Fatalf("audit must record outcome=upstream at status 200: %+v", auditEvents)
	}
}

// SSE framing: comment keep-alives, non-JSON data payloads and notification
// frames (no result/error member) are skipped; the first result frame wins.
// A stream with no result frame at all is an upstream error.
func TestInvokeChar_SSEFrameSelection(t *testing.T) {
	body := ": keep-alive\n" +
		"event: message\n" +
		"data: ping\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"picked\"}]}}\n\n"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(up.Close)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil)

	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("sse frame selection: %v", err)
	}
	if !strings.Contains(string(res), "picked") {
		t.Fatalf("the result frame must be selected, got %s", res)
	}

	noResult := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"))
	}))
	t.Cleanup(noResult.Close)
	p2 := NewProxy(storeForUpstreamWithGrant(noResult.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil)
	_, err = p2.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatalf("stream without a result frame must be an upstream error, got %v", err)
	}
}

// Cancelling the caller context while the upstream call is in flight fails
// the invoke (context.Canceled is not a deadline: it maps to the generic
// upstream code) and audits it; it never reads as success. The negative
// control runs the same upstream without cancellation.
func TestInvokeChar_ContextCancelMidFlight(t *testing.T) {
	arrived := make(chan struct{}, 4)
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r // hold the response open until the test releases the handler
		arrived <- struct{}{}
		<-release
	}))
	t.Cleanup(func() { close(release); up.Close() })
	var auditEvents []AuditEvent
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil,
		&recordingAudit{events: &auditEvents})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-arrived
		cancel()
	}()
	_, err := p.Invoke(ctx, "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	cancel()
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatalf("mid-flight cancel must fail as an upstream error, got %v", err)
	}
	// Base behavior: the audit outcome carries the InvokeError code and the
	// call never even got a status back (0).
	if len(auditEvents) != 1 || auditEvents[0].Outcome != ErrCodeUpstream || auditEvents[0].UpstreamStatus != 0 {
		t.Fatalf("audit must record outcome=upstream at status 0: %+v", auditEvents)
	}

	// Negative control: the same upstream, no cancellation → success. The
	// handler returns when this test server closes (r.Context done) but the
	// response has already been written by then only if we do not hang: use
	// a fresh upstream that answers immediately.
	okUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	t.Cleanup(okUp.Close)
	p2 := NewProxy(storeForUpstreamWithGrant(okUp.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil)
	if _, err := p2.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("control invoke must succeed: %v", err)
	}
}

// A store infrastructure failure (not ErrNotFound) is a plain wrapped error,
// never an InvokeError, and produces NO audit event.
func TestInvokeChar_StoreErrorIsPlainErrorNoAudit(t *testing.T) {
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isGrantQuery(sql) {
				return &grantRow{g: testGrant("ag-1")}
			}
			return &serverRow{err: errors.New("db is down")}
		},
	}
	var auditEvents []AuditEvent
	p := NewProxy(NewStore(db), testConfig(), loopbackAllow(t), nil, &recordingAudit{events: &auditEvents})

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if errors.As(err, &iErr) {
		t.Fatalf("store failure must stay a plain error, got %v", err)
	}
	if !strings.Contains(err.Error(), "lookup server") {
		t.Fatalf("error must name the failing lookup, got %v", err)
	}
	if len(auditEvents) != 0 {
		t.Fatalf("infrastructure failure must not audit: %+v", auditEvents)
	}
}

// A delegation-chain lookup infrastructure failure is likewise a plain
// wrapped error with no audit event.
func TestInvokeChar_ChainLookupErrorIsPlainErrorNoAudit(t *testing.T) {
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				return &chainAggregateRow{err: errors.New("chain query exploded")}
			}
			if isGrantQuery(sql) {
				return &grantRow{g: testGrant("ag-1")}
			}
			return &serverRow{srv: testServer("http://upstream.invalid/mcp")}
		},
	}
	var auditEvents []AuditEvent
	p := NewProxy(NewStore(db), testConfig(), loopbackAllow(t), nil, &recordingAudit{events: &auditEvents})

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if errors.As(err, &iErr) {
		t.Fatalf("chain failure must stay a plain error, got %v", err)
	}
	if !strings.Contains(err.Error(), "lookup delegation chain allowance") {
		t.Fatalf("error must name the chain lookup, got %v", err)
	}
	if len(auditEvents) != 0 {
		t.Fatalf("infrastructure failure must not audit: %+v", auditEvents)
	}
}

// A successful call audits outcome=ok with the upstream HTTP status, an
// empty error message and a non-negative latency.
func TestInvokeChar_SuccessAuditLabels(t *testing.T) {
	up, _ := charEchoUpstream(t)
	var auditEvents []AuditEvent
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil,
		&recordingAudit{events: &auditEvents})

	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)}); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if len(auditEvents) != 1 {
		t.Fatalf("want exactly one audit event, got %d", len(auditEvents))
	}
	e := auditEvents[0]
	if e.Outcome != OutcomeOK || e.UpstreamStatus != http.StatusOK || e.ErrorMessage != "" {
		t.Fatalf("success audit labels wrong: %+v", e)
	}
	if e.LatencyMS < 0 {
		t.Fatalf("latency must be non-negative, got %d", e.LatencyMS)
	}
	if e.ServerName != "knowledge" || e.Tool != "search" || e.UpstreamURL != up.URL {
		t.Fatalf("audit coordinates wrong: %+v", e)
	}
}

// charFailingCredSource models an infrastructure failure of the credential
// resolver on the legacy (unconstrained) path.
type charFailingCredSource struct{ calls int }

func (s *charFailingCredSource) AuthHeaders(context.Context, string, string, string) (map[string][]string, string, error) {
	s.calls++
	return nil, "", errors.New("credential store unavailable")
}

func (s *charFailingCredSource) OnUpstreamUnauthorized(context.Context, string, string, string, string) (map[string][]string, bool, error) {
	return nil, false, nil
}

// A credential-resolution failure fails closed BEFORE egress: a plain
// wrapped error (not an InvokeError, not auth_required), audited as
// upstream_error at status 0.
func TestInvokeChar_CredResolveErrorAuditedAsUpstreamError(t *testing.T) {
	up, sawArgs := charEchoUpstream(t)
	src := &charFailingCredSource{}
	var auditEvents []AuditEvent
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil,
		&recordingAudit{events: &auditEvents}).WithCredsSource(src)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	var authErr *AuthRequiredError
	if errors.As(err, &iErr) || errors.As(err, &authErr) {
		t.Fatalf("resolver failure must be a plain error, got %v", err)
	}
	if !strings.Contains(err.Error(), "resolve credential") {
		t.Fatalf("error must name the resolve step, got %v", err)
	}
	if got := sawArgs(); len(got) != 0 {
		t.Fatalf("resolver failure must not egress, saw %v", got)
	}
	if len(auditEvents) != 1 || auditEvents[0].Outcome != OutcomeUpstreamError || auditEvents[0].UpstreamStatus != 0 {
		t.Fatalf("audit must record upstream_error at status 0: %+v", auditEvents)
	}
	if src.calls != 1 {
		t.Fatalf("exactly one resolve attempt, got %d", src.calls)
	}
}
