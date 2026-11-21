package cli

// N1-A2A-EFFECTS: upstream-effect oracles for the reviewer-required
// zero-egress contracts. The frozen status cases (A2A-03 agent_only,
// A2A-07 store error → 500 internal) pin the response contracts; these
// prove the same paths send ZERO upstream bytes, measured by an
// independent hit counter on a live loopback TLS upstream with a valid
// agent row — never inferred from a closed port. Each test runs an
// allowed control leg first through the identical stack (row, URL, proxy,
// client) proving the upstream is reachable and the counter observes
// hits when the operation is permitted.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/a2aagg"
)

// a2aEffectsUpstream starts a counted TLS loopback upstream returning a
// valid JSON-RPC result. The counter is the independent effect oracle.
func a2aEffectsUpstream(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":1}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// a2aEffectsRow is the valid enabled agent row for the live upstream.
func a2aEffectsRow(srv *httptest.Server) *a2aagg.Agent {
	return &a2aagg.Agent{ID: "ag1", OrgID: "org1", Name: "alpha",
		URL: srv.URL, Enabled: true}
}

// a2aEffectsGateway builds the real a2aSend handler over the real
// a2aagg.Proxy pointed at the counted upstream.
func a2aEffectsGateway(t *testing.T, db fuzzA2ADB, srv *httptest.Server) *gateway {
	t.Helper()
	cfg := a2aagg.NewDefaultConfig()
	cfg.HTTP = fuzzTLSClient(srv, 2*time.Second)
	return fuzzA2AGateway(fuzzA2AProxy(t, db, cfg, nil, nil), false)
}

// TestA2AEffectsDBErrorZeroUpstreamHits: a store failure must surface as
// 500 internal and must not send a single byte upstream. The control leg
// proves the same row/URL/proxy/client stack does hit the live upstream
// when the store is healthy, so the zero in the error leg is attributable
// to the store-error boundary, not to an unreachable server.
func TestA2AEffectsDBErrorZeroUpstreamHits(t *testing.T) {
	srv, hits := a2aEffectsUpstream(t)

	// Control: healthy store, identical stack → success and one observed hit.
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	a2aEffectsGateway(t, fuzzA2ADB{agent: a2aEffectsRow(srv)}, srv).a2aSend(w, r)
	if w.Code != http.StatusOK || w.Body.String() != `{"ok":1}` {
		t.Fatalf("a2a effects control: want 200 {\"ok\":1}, got %d %q", w.Code, w.Body.String())
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("a2a effects control: upstream hits = %d, want 1 (reachability proof)", n)
	}

	// Store error against the same live upstream with the SAME valid row:
	// err stays non-nil so production discards the row at scanAgent and
	// returns 500 with zero egress — while the isolated error-suppression
	// variant sees a usable row/URL through the identical stack and can
	// demonstrate the forbidden hit instead of failing on missing-agent
	// setup.
	dbErr := fuzzA2ADB{agent: a2aEffectsRow(srv), err: errors.New("effects: db down")}
	w, r = fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	a2aEffectsGateway(t, dbErr, srv).a2aSend(w, r)
	// Errorf (not Fatalf) on both facts: a suppressed store error must show
	// BOTH the status regression and the observed forbidden hit in the log.
	if n := hits.Load(); n != 1 {
		t.Errorf("a2a effects db-error: upstream hits = %d, want still 1 (zero egress on store error)", n)
	}
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "internal") {
		t.Errorf("a2a effects db-error: want 500 internal, got %d %q", w.Code, w.Body.String())
	}
}

// TestA2AEffectsAgentOnlyZeroUpstreamHits: a missing agent principal
// must surface as 403 agent_only and must not send a single byte
// upstream. The control leg proves reachability and counter sensitivity
// with the identical stack before the gated leg measures zero.
func TestA2AEffectsAgentOnlyZeroUpstreamHits(t *testing.T) {
	srv, hits := a2aEffectsUpstream(t)
	gw := a2aEffectsGateway(t, fuzzA2ADB{agent: a2aEffectsRow(srv)}, srv)

	// Control: agent principal present → success and one observed hit.
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	gw.a2aSend(w, r)
	if w.Code != http.StatusOK || w.Body.String() != `{"ok":1}` {
		t.Fatalf("a2a effects control: want 200 {\"ok\":1}, got %d %q", w.Code, w.Body.String())
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("a2a effects control: upstream hits = %d, want 1 (reachability proof)", n)
	}

	// Gated leg: empty X-Agent-Id against the same live upstream.
	w, r = fuzzA2ARequest(t, "org1", "", `{"agent":"alpha"}`)
	gw.a2aSend(w, r)
	// Errorf on both facts so a suppressed gate shows BOTH the status
	// regression and the observed forbidden hit in the log.
	if n := hits.Load(); n != 1 {
		t.Errorf("a2a effects agent-only: upstream hits = %d, want still 1 (zero egress without agent principal)", n)
	}
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "agent_only") {
		t.Errorf("a2a effects agent-only: want 403 agent_only, got %d %q", w.Code, w.Body.String())
	}
}
