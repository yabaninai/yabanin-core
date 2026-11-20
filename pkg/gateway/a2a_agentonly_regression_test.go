package cli

// A2A-08 dependency-boundary regression (critical-go seed-cover
// correction): the a2aSend InvokeError switch's ErrCodeAgentOnly arm is
// defensive — the real a2aagg.Proxy answers agent-only only for an empty
// agent identity, which the handler's own agent-principal check rejects
// before the proxy is called, so no real-proxy request reaches the arm.
// The mapping stays (boundary defense for proxy-side triggers) and this
// regression pins it at the seam: the stub answers Send with the proxy's
// own InvokeError shape and the handler must map it to 403 agent_only
// with exactly one boundary call. No zero-egress claim is made for the
// stub legs — the stub replaces the handler's only outbound path, so
// egress there is structural; the real-stack zero-egress contracts live
// in a2a_effects_test.go. Frozen FuzzA2ASend corpus case 16 replays the
// boundary leg so the seed profile covers every a2aSend block.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/a2aagg"
)

// a2aAgentOnlyStub is the dependency-boundary stand-in: it answers Send
// with the proxy's own agent-only InvokeError and never opens a socket.
type a2aAgentOnlyStub struct {
	calls int
}

func (s *a2aAgentOnlyStub) Send(_ context.Context, _ string, _ a2aagg.Identity, _ a2aagg.SendRequest) (json.RawMessage, error) {
	s.calls++
	return nil, &a2aagg.InvokeError{
		Code:    a2aagg.ErrCodeAgentOnly,
		Message: "a2a send requires an agent principal",
	}
}

// TestA2AProxyAgentOnlyMappingForbidden: a boundary-level agent-only
// refusal must map to 403 agent_only with exactly one boundary call. The
// control leg runs first through the identical real stack (row, URL,
// proxy, client), proving that stack still succeeds — the seam only
// widens the testable boundary, it must not disturb the real path.
func TestA2AProxyAgentOnlyMappingForbidden(t *testing.T) {
	srv, hits := a2aEffectsUpstream(t)

	// Control: the real stack is permitted; the counter observes the hit.
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	a2aEffectsGateway(t, fuzzA2ADB{agent: a2aEffectsRow(srv)}, srv).a2aSend(w, r)
	if w.Code != http.StatusOK || w.Body.String() != `{"ok":1}` {
		t.Fatalf("a2a agent-only mapping control: want 200 {\"ok\":1}, got %d %q", w.Code, w.Body.String())
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("a2a agent-only mapping control: upstream hits = %d, want 1 (reachability proof)", n)
	}

	// Gated: the seam stub answers with the proxy's own agent-only
	// InvokeError; the handler must map it to 403 agent_only. Egress in
	// this leg is structural (the stub replaces the only outbound path),
	// so no counter assertion is claimed here. Errorf keeps both facts in
	// the log when the mapping regresses.
	stub := &a2aAgentOnlyStub{}
	gw := &gateway{log: fuzzDiscardLogger()}
	gw.a2aProxy = stub
	w, r = fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	gw.a2aSend(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "agent_only") {
		t.Errorf("a2a agent-only mapping: want 403 agent_only, got %d %q", w.Code, w.Body.String())
	}
	if stub.calls != 1 {
		t.Errorf("a2a agent-only mapping: boundary calls = %d, want 1", stub.calls)
	}
}

// a2aAgentOnlyMappingCase is frozen FuzzA2ASend corpus case 16: the same
// dependency-boundary leg through the seed replay, covering the a2a.go
// ErrCodeAgentOnly arm in the seed coverage profile.
func a2aAgentOnlyMappingCase(t *testing.T) {
	stub := &a2aAgentOnlyStub{}
	gw := &gateway{log: fuzzDiscardLogger()}
	gw.a2aProxy = stub
	w, r := fuzzA2ARequest(t, "org1", "yag_1", `{"agent":"alpha"}`)
	gw.a2aSend(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "agent_only") {
		t.Fatalf("a2a agent-only case 16: want 403 agent_only, got %d %q", w.Code, w.Body.String())
	}
	if stub.calls != 1 {
		t.Fatalf("a2a agent-only case 16: boundary calls = %d, want 1", stub.calls)
	}
}
