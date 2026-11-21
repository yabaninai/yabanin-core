package cli

// Fuzz seeds for the A2A handler and audit adapter (task
// gateway-fuzz-seeds). Case IDs and expected outcomes are frozen in
// FROZEN-CASE-TABLE.md (A2A-*). Upstreams are TLS loopback servers with a
// pinned 127.0.0.1 allow-list; DB rows come from fuzzA2ADB.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/reireirei/yabanin/pkg/a2aagg"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// fuzzA2AGateway builds a gateway with the given proxy and static pieces.
func fuzzA2AGateway(proxy *a2aagg.Proxy, engineOn bool) *gateway {
	gw := &gateway{log: fuzzDiscardLogger()}
	if engineOn {
		gw.toolPolicies = fuzzToolEngine()
	}
	// A typed nil *a2aagg.Proxy must not enter the interface seam as a
	// non-nil interface value: that would bypass a2aSend's feature-off 404
	// and panic inside Send. Keep the field the nil interface instead.
	if proxy != nil {
		gw.a2aProxy = proxy
	}
	return gw
}

// fuzzA2AProxy wires a Proxy over the canned DB row/err.
func fuzzA2AProxy(t *testing.T, db fuzzA2ADB, cfg a2aagg.Config, hook a2aagg.Hook, audit a2aagg.AuditLogger) *a2aagg.Proxy {
	t.Helper()
	allow, err := ssrf.NewAllowListTrustingExactPins([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("pin list: %v", err)
	}
	return a2aagg.NewProxy(a2aagg.NewStore(db), cfg, allow, hook, audit)
}

func fuzzA2ARequest(t *testing.T, org, agent, body string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/a2a/send", strings.NewReader(body))
	if org != "" {
		r.Header.Set("X-Org-Id", org)
	}
	if agent != "" {
		r.Header.Set("X-Agent-Id", agent)
	}
	r.Header.Set("X-Session-Id", "s1")
	return httptest.NewRecorder(), r
}

func FuzzA2ASend(f *testing.F) {
	for id := 1; id <= 16; id++ {
		f.Add([]byte{byte(id)}) // frozen regression corpus
	}
	// Generated-request seeds: policy-denied agent send, and an unknown agent.
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add([]byte{0x40, 0x00, 0x02})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 0 && data[0] >= 1 && data[0] <= 16 {
			fuzzA2ACases[int(data[0])](t)
			return
		}
		a2aGenerated(t, data)
	})
}

// a2aGenExpect derives the independently expected outcome from the
// generated request parts: empty org ⇒ 401, empty agent principal ⇒ 403
// agent_only, org-a2a sending to agent "alpha" ⇒ 403 policy denial BEFORE
// the proxy, and any other agent under an empty registry ⇒ 404 not_found.
// A policy leak would surface as 404 (proxy lookup) instead of 403.
func a2aGenExpect(org, agent, target string) int {
	switch {
	case org == "":
		return http.StatusUnauthorized
	case agent == "":
		return http.StatusForbidden // agent_only pre-gate
	case org == "org-a2a" && target == "alpha":
		return http.StatusForbidden // policy: a2a:alpha denied before proxy
	default:
		return http.StatusNotFound // empty agent registry in the proxy store
	}
}

// fuzzA2AGenerated drives the real a2aSend handler with generated
// org/agent/target combinations and asserts the authorization outcome
// above; the empty registry makes any policy bypass observable.
func a2aGenerated(t *testing.T, data []byte) {
	t.Helper()
	p := data
	if len(p) > 0 && p[0] < 16 {
		p = p[1:]
	}
	if len(p) < 3 {
		p = append(p, 0, 1, 2)
	}
	orgs := []string{"org1", "org-a2a", ""}
	agents := []string{"yag_1", "yag_2", ""}
	targets := []string{"alpha", "beta"}
	org := orgs[int(p[0])%len(orgs)]
	agent := agents[int(p[1])%len(agents)]
	target := targets[int(p[2])%len(targets)]
	body := fmt.Sprintf(`{"agent":%q,"message":"hi"}`, target)

	proxy := fuzzA2AProxy(t, fuzzA2ADB{err: pgx.ErrNoRows}, a2aagg.NewDefaultConfig(), nil, nil)
	w, r := fuzzA2ARequest(t, org, agent, body)
	fuzzA2AGateway(proxy, true).a2aSend(w, r) // engine on: policy path live

	if want := a2aGenExpect(org, agent, target); w.Code != want {
		t.Fatalf("a2a gen: org=%q agent=%q target=%q: want %d got %d %q",
			org, agent, target, want, w.Code, w.Body.String())
	}
	if w.Code >= 400 && !json.Valid(w.Body.Bytes()) && w.Body.Len() > 0 {
		t.Fatalf("a2a gen: non-JSON error envelope: %q", w.Body.String())
	}
}

var fuzzA2ACases = map[int]func(*testing.T){
	1:  fuzzA2A01,
	2:  fuzzA2A02,
	3:  fuzzA2A03,
	4:  fuzzA2A04,
	5:  fuzzA2A05,
	6:  fuzzA2A06,
	7:  fuzzA2A07,
	8:  fuzzA2A08,
	9:  fuzzA2A09,
	10: fuzzA2A10,
	11: fuzzA2A11,
	12: fuzzA2A12,
	13: fuzzA2A13,
	14: fuzzA2A14,
	15: fuzzA2A15,
	16: a2aAgentOnlyMappingCase,
}

// // A2A-01 nil proxy → 404, no body
// fuzzTLSClient trusts only the given loopback test server's certificate.
func fuzzTLSClient(srv *httptest.Server, timeout time.Duration) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
}

func fuzzA2A01(t *testing.T) {
	t.Helper()

	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{}`)
	fuzzA2AGateway(nil, false).a2aSend(w, r)
	if w.Code != http.StatusNotFound || w.Body.Len() != 0 {
		t.Fatalf("A2A-01: want 404 empty, got %d %q", w.Code, w.Body.String())
	}
}

// // A2A-02 missing org → 401 authentication
func fuzzA2A02(t *testing.T) {
	t.Helper()

	w, r := fuzzA2ARequest(t, "", "yag_1", `{}`)
	fuzzA2AGateway(fuzzA2AProxy(t, fuzzA2ADB{}, a2aagg.NewDefaultConfig(), nil, nil), false).a2aSend(w, r)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), apierrors.ErrorCodeAuthentication) {
		t.Fatalf("A2A-02: %d %s", w.Code, w.Body.String())
	}
}

// // A2A-03 missing agent principal → 403 agent_only
func fuzzA2A03(t *testing.T) {
	t.Helper()

	w, r := fuzzA2ARequest(t, "org1", "", `{}`)
	fuzzA2AGateway(fuzzA2AProxy(t, fuzzA2ADB{}, a2aagg.NewDefaultConfig(), nil, nil), false).a2aSend(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "agent_only") {
		t.Fatalf("A2A-03: %d %s", w.Code, w.Body.String())
	}
}

// // A2A-04 malformed body → 400 invalid_request_error
func fuzzA2A04(t *testing.T) {
	t.Helper()

	w, r := fuzzA2ARequest(t, "org1", "yag_1", "not-json")
	fuzzA2AGateway(fuzzA2AProxy(t, fuzzA2ADB{}, a2aagg.NewDefaultConfig(), nil, nil), false).a2aSend(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), apierrors.ErrorCodeInvalidRequest) {
		t.Fatalf("A2A-04: %d %s", w.Code, w.Body.String())
	}
}

// // A2A-05 policy denies a2a:alpha → 403 policy_denied
func fuzzA2A05(t *testing.T) {
	t.Helper()

	w, r := fuzzA2ARequest(t, "org-a2a", "yag_1", `{"agent":"alpha"}`)
	fuzzA2AGateway(fuzzA2AProxy(t, fuzzA2ADB{}, a2aagg.NewDefaultConfig(), nil, nil), true).a2aSend(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "policy_denied") {
		t.Fatalf("A2A-05: %d %s", w.Code, w.Body.String())
	}
}

// // A2A-06 agent missing → 404 not_found
func fuzzA2A06(t *testing.T) {
	t.Helper()

	db := fuzzA2ADB{err: pgx.ErrNoRows}
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	fuzzA2AGateway(fuzzA2AProxy(t, db, a2aagg.NewDefaultConfig(), nil, nil), false).a2aSend(w, r)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), a2aagg.ErrCodeNotFound) {
		t.Fatalf("A2A-06: %d %s", w.Code, w.Body.String())
	}
}

// // A2A-07 DB failure → 500 internal
func fuzzA2A07(t *testing.T) {
	t.Helper()

	db := fuzzA2ADB{err: errors.New("db down")}
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	fuzzA2AGateway(fuzzA2AProxy(t, db, a2aagg.NewDefaultConfig(), nil, nil), false).a2aSend(w, r)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "internal") {
		t.Fatalf("A2A-07: %d %s", w.Code, w.Body.String())
	}
}

// // A2A-08 http:// URL fails https-only at send → 400 ssrf_blocked
func fuzzA2A08(t *testing.T) {
	t.Helper()

	db := fuzzA2ADB{agent: &a2aagg.Agent{ID: "ag1", OrgID: "org1", Name: "alpha",
		URL: "http://127.0.0.1:1/x", Enabled: true}}
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	fuzzA2AGateway(fuzzA2AProxy(t, db, a2aagg.NewDefaultConfig(), nil, nil), false).a2aSend(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), a2aagg.ErrCodeSSRF) {
		t.Fatalf("A2A-08: %d %s", w.Code, w.Body.String())
	}
}

// // A2A-09 guard hook deny → 409 denied
func fuzzA2A09(t *testing.T) {
	t.Helper()

	db := fuzzA2ADB{agent: &a2aagg.Agent{ID: "ag1", OrgID: "org1", Name: "alpha",
		URL: "https://127.0.0.1:1/x", Enabled: true}}
	hook := fuzzA2AHook{deny: "params contain secrets"}
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha","params":{"q":"x"}}`)
	fuzzA2AGateway(fuzzA2AProxy(t, db, a2aagg.NewDefaultConfig(), hook, nil), false).a2aSend(w, r)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), a2aagg.ErrCodeDenied) {
		t.Fatalf("A2A-09: %d %s", w.Code, w.Body.String())
	}
}

// // A2A-10 upstream 500 → 502 upstream
func fuzzA2A10(t *testing.T) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	db := fuzzA2ADB{agent: &a2aagg.Agent{ID: "ag1", OrgID: "org1", Name: "alpha",
		URL: srv.URL, Enabled: true}}
	cfg := a2aagg.NewDefaultConfig()
	cfg.HTTP = fuzzTLSClient(srv, 2*time.Second)
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	fuzzA2AGateway(fuzzA2AProxy(t, db, cfg, nil, nil), false).a2aSend(w, r)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), a2aagg.ErrCodeUpstream) {
		t.Fatalf("A2A-10: %d %s", w.Code, w.Body.String())
	}
}

// // A2A-11 slow upstream + 30ms client timeout → 504 timeout
func fuzzA2A11(t *testing.T) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(srv.Close)
	db := fuzzA2ADB{agent: &a2aagg.Agent{ID: "ag1", OrgID: "org1", Name: "alpha",
		URL: srv.URL, Enabled: true}}
	cfg := a2aagg.NewDefaultConfig()
	cfg.HTTP = fuzzTLSClient(srv, 30*time.Millisecond)
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	fuzzA2AGateway(fuzzA2AProxy(t, db, cfg, nil, nil), false).a2aSend(w, r)
	if w.Code != http.StatusGatewayTimeout || !strings.Contains(w.Body.String(), a2aagg.ErrCodeTimeout) {
		t.Fatalf("A2A-11: %d %s", w.Code, w.Body.String())
	}
}

// // A2A-12 success: result passthrough + identity header
func fuzzA2A12(t *testing.T) {
	t.Helper()

	var gotAgentName string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgentName = r.Header.Get("X-Yabanin-Agent-Name")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":1}}`))
	}))
	t.Cleanup(srv.Close)
	db := fuzzA2ADB{agent: &a2aagg.Agent{ID: "ag1", OrgID: "org1", Name: "alpha",
		URL: srv.URL, Enabled: true}}
	cfg := a2aagg.NewDefaultConfig()
	cfg.HTTP = fuzzTLSClient(srv, 2*time.Second)
	gw := fuzzA2AGateway(fuzzA2AProxy(t, db, cfg, nil, nil), false)
	gw.mcpAgentName = func(context.Context, string) string { return "Alpha Agent" }
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	gw.a2aSend(w, r)
	if w.Code != http.StatusOK || w.Body.String() != `{"ok":1}` {
		t.Fatalf("A2A-12: %d %q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("A2A-12: content type %q", ct)
	}
	if gotAgentName != "Alpha Agent" {
		t.Fatalf("A2A-12: agent name header missing: %q", gotAgentName)
	}
}

// // A2A-13 success against a failing writer → no panic, warn logged
func fuzzA2A13(t *testing.T) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":1}}`))
	}))
	t.Cleanup(srv.Close)
	db := fuzzA2ADB{agent: &a2aagg.Agent{ID: "ag1", OrgID: "org1", Name: "alpha",
		URL: srv.URL, Enabled: true}}
	cfg := a2aagg.NewDefaultConfig()
	cfg.HTTP = fuzzTLSClient(srv, 2*time.Second)
	gw := fuzzA2AGateway(fuzzA2AProxy(t, db, cfg, nil, nil), false)
	fw := &fuzzRecorder{ResponseRecorder: httptest.NewRecorder(), failWrite: true}
	_, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	gw.a2aSend(fw, r)
	if fw.Code != http.StatusOK {
		t.Fatalf("A2A-13: status attempt %d", fw.Code)
	}
}

// // A2A-14 audit adapter: nil publisher + event mapping arms
func fuzzA2A14(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	nilPub := &a2aAuditLogger{publisher: nil, log: fuzzDiscardLogger()}
	if err := nilPub.Log(ctx, a2aagg.AuditEvent{Outcome: a2aagg.OutcomeOK}); err != nil {
		t.Fatalf("A2A-14: nil publisher must be nil error: %v", err)
	}
	ev := a2aAuditEvent(a2aagg.AuditEvent{Outcome: a2aagg.OutcomeOK, TargetName: "alpha",
		UpstreamStatus: 200, RequestID: "r1", OrgID: "o1", LatencyMS: 5, ParamsRedacted: []byte(`{"q":"hi"}`)})
	if ev.EventType != "request.completed" || ev.ModelUsed != "a2a:alpha" || ev.Payload != `{"q":"hi"}` {
		t.Fatalf("A2A-14: ok event wrong: %+v", ev)
	}
	ev = a2aAuditEvent(a2aagg.AuditEvent{Outcome: a2aagg.OutcomeDenied})
	if ev.EventType != "request.failed" || ev.Error != "a2a:denied" {
		t.Fatalf("A2A-14: denied(0) event wrong: %+v", ev)
	}
	ev = a2aAuditEvent(a2aagg.AuditEvent{Outcome: a2aagg.OutcomeUpstreamError, UpstreamStatus: 503})
	if ev.EventType != "request.failed" || ev.Error != "a2a:upstream_error (upstream 503)" {
		t.Fatalf("A2A-14: failed(status) event wrong: %+v", ev)
	}
}

// // A2A-15 Log with unreachable publisher → nil error, no panic
func fuzzA2A15(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	l := &a2aAuditLogger{publisher: fuzzDeadRedis(t), log: fuzzDiscardLogger()}
	if err := l.Log(ctx, a2aagg.AuditEvent{Outcome: a2aagg.OutcomeOK, TargetName: "alpha"}); err != nil {
		t.Fatalf("A2A-15: publish failure must be non-fatal: %v", err)
	}
}
