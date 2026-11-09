package mcpagg

// (store → resolve → rotate → revoke on the real stack) and isolated proxy
// postures; what was missing is the consume-side contract: the proxy must
// re-resolve the credential on EVERY invoke (rotation is visible on the next
// call, an old version is never re-sent after rotation), a revocation must
// flip the very next invoke to the lazy-authorization error (never a stale
// replay, never a silent success against an auth-demanding upstream), the
// oauth single-refresh round rotates for subsequent invokes too, a 403 is
// terminal exactly like a 401, and no step leaks material into errors, the
// structured 401 shape, or the audit trail. Server name stays on
// boundaryServerName (decoupled from the exact-count prometheus assertions
// the older creds_test.go pins); these tests make NO metric assertions.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// lifecycleCredSource is a stateful CredSource double modelling the
// store-authoritative resolution semantics: every AuthHeaders call returns
// the CURRENT credential (nil after revoke), mirroring the real source's
// per-request store read. onUnauthorized models the refresh round outcome.
type lifecycleCredSource struct {
	mu             sync.Mutex
	headers        map[string][]string
	kind           string
	onUnauthorized func(kind string) (map[string][]string, bool, error)
	unauthRounds   int
}

func (s *lifecycleCredSource) serveHeaders(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headers = map[string][]string{"Authorization": {"Bearer " + token}}
	s.kind = CredKindHeaders
}

func (s *lifecycleCredSource) serveOAuth(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headers = map[string][]string{"Authorization": {"Bearer " + token}}
	s.kind = CredKindOAuth
}

func (s *lifecycleCredSource) revoke() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headers = nil
	s.kind = CredKindNone
}

func (s *lifecycleCredSource) AuthHeaders(context.Context, string, string, string) (map[string][]string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headers, s.kind, nil
}

func (s *lifecycleCredSource) OnUpstreamUnauthorized(_ context.Context, _, _, _ string, kind string) (map[string][]string, bool, error) {
	s.mu.Lock()
	s.unauthRounds++
	f := s.onUnauthorized
	s.mu.Unlock()
	if f == nil {
		return nil, false, nil // terminal: no refresh configured
	}
	return f(kind)
}

func (s *lifecycleCredSource) refreshRounds() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unauthRounds
}

// lifecycleUpstream builds an upstream that records every Authorization
// value it saw and answers like a bearer-protected MCP server: 200 with the
// seen value echoed into the tool result, or wantStatus with an echo body
// (the hostile bounce-back leak vector) otherwise.
func lifecycleUpstream(t *testing.T, acceptToken string, wantStatus int) (*httptest.Server, func() map[string]int) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		mu.Lock()
		seen[auth]++
		mu.Unlock()
		if auth == "" || (acceptToken != "" && auth != "Bearer "+acceptToken) {
			w.WriteHeader(wantStatus)
			//nolint:gosec // G705: the mock upstream deliberately echoes the credential it received — the test proves the proxy redacts it
			_, _ = w.Write([]byte(`{"error":"rejected credential: ` + auth + `"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G705: the mock upstream deliberately echoes the credential it received — the test proves the proxy redacts it
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"saw ` + auth + `"}]}}`))
	}))
	t.Cleanup(srv.Close)
	snapshot := func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[string]int, len(seen))
		for k, v := range seen {
			out[k] = v
		}
		return out
	}
	return srv, snapshot
}

func lifecycleProxy(t *testing.T, upURL string, src *lifecycleCredSource, audit *[]AuditEvent) *Proxy {
	t.Helper()
	return NewProxy(boundaryStoreFor(upURL), testConfig(), loopbackAllow(t), nil,
		&recordingAudit{events: audit}).WithCredsSource(src)
}

func lifecycleInvoke(p *Proxy) (json.RawMessage, error) {
	return p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: boundaryServerName, Tool: "search", Params: json.RawMessage(`{}`)})
}

// assertNoMaterial fails the test when any credential token surfaces in err
// or in any audit event free-text field.
func assertNoMaterial(t *testing.T, tokens []string, err error, events []AuditEvent) {
	t.Helper()
	if err != nil {
		if strings.Contains(err.Error(), "rejected credential") {
			t.Errorf("error carried the upstream echo body: %v", err)
		}
		for _, tok := range tokens {
			if strings.Contains(err.Error(), tok) {
				t.Errorf("error carried credential material %q: %v", tok, err)
			}
		}
	}
	for _, ev := range events {
		for _, leak := range []string{ev.ErrorMessage, string(ev.ParamsRedacted), ev.UpstreamURL, ev.ServerName} {
			for _, tok := range tokens {
				if strings.Contains(leak, tok) {
					t.Errorf("audit event carried credential material %q: %+v", tok, ev)
				}
			}
		}
	}
}

// assertAuthRequiredShape pins the structured 401 body: exactly the
// kind+url+message keys, the expected kind, the flow URL for the server, a
// non-empty diagnosable message, and no token material.
func assertAuthRequiredShape(t *testing.T, err error, wantKind string) {
	t.Helper()
	var authErr *AuthRequiredError
	if !errors.As(err, &authErr) {
		t.Fatalf("want mcp_auth_required, got %v", err)
	}
	if authErr.Kind != wantKind {
		t.Errorf("auth-required kind = %q, want %q", authErr.Kind, wantKind)
	}
	wantURL := "/api/mcp/credentials/" + boundaryServerName
	if wantKind == CredKindOAuth {
		wantURL = "/api/mcp/auth/" + boundaryServerName + "/begin"
	}
	if authErr.URL != wantURL {
		t.Errorf("auth-required url = %q, want %q", authErr.URL, wantURL)
	}
	if authErr.Message == "" {
		t.Error("the auth-required error must stay diagnosable (non-empty message)")
	}
	shape, mErr := json.Marshal(authErr)
	if mErr != nil {
		t.Fatalf("marshal AuthRequiredError: %v", mErr)
	}
	var decoded map[string]any
	if uErr := json.Unmarshal(shape, &decoded); uErr != nil {
		t.Fatalf("unmarshal structured 401 body %s: %v", shape, uErr)
	}
	if len(decoded) != 3 {
		t.Errorf("the structured 401 body must carry kind+url+message only, got %s", shape)
	}
	for _, tok := range []string{"Bearer ", "sk-"} {
		if strings.Contains(string(shape), tok) {
			t.Errorf("the structured 401 body carried credential material: %s", shape)
		}
	}
}

// TestProxy_Invoke_CredentialLifecycle_RotateRevokeFailsClosed: create →
// resolve → rotate (old version never re-sent) → revoke (the very next
// invoke fails closed as mcp_auth_required, repeatedly, with zero material
// in the error, its JSON shape, or the audit trail).
func TestProxy_Invoke_CredentialLifecycle_RotateRevokeFailsClosed(t *testing.T) {
	const (
		tokenV1 = "sk-lifecycle-v1-aaaa" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
		tokenV2 = "sk-lifecycle-v2-bbbb" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	)
	up, seenAuth := lifecycleUpstream(t, "", http.StatusUnauthorized)
	src := &lifecycleCredSource{}
	src.serveHeaders(tokenV1)
	var auditEvents []AuditEvent
	p := lifecycleProxy(t, up.URL, src, &auditEvents)

	// Create + resolve: the credential reaches the upstream as the outbound
	// header and nowhere else.
	res, err := lifecycleInvoke(p)
	if err != nil {
		t.Fatalf("invoke with v1: %v", err)
	}
	if !strings.Contains(string(res), "saw Bearer "+tokenV1) {
		t.Fatalf("upstream must see the created credential, got %s", res)
	}

	// Rotate: the very next invoke serves v2; v1 is never re-sent.
	src.serveHeaders(tokenV2)
	res, err = lifecycleInvoke(p)
	if err != nil {
		t.Fatalf("invoke after rotation: %v", err)
	}
	if !strings.Contains(string(res), "saw Bearer "+tokenV2) {
		t.Fatalf("the rotated credential must be served on the next invoke, got %s", res)
	}
	if strings.Contains(string(res), tokenV1) {
		t.Fatalf("the old version leaked into the result: %s", res)
	}
	if got := seenAuth()["Bearer "+tokenV1]; got != 1 {
		t.Fatalf("the old version must not be re-sent after rotation, saw %d times", got)
	}

	// Revoke: the next invoke proceeds unauthenticated, the upstream rejects,
	// and the proxy surfaces the lazy-authorization error — no stale replay
	// of either version.
	src.revoke()
	_, err = lifecycleInvoke(p)
	assertAuthRequiredShape(t, err, CredKindHeaders)
	if n := seenAuth()[""]; n != 1 {
		t.Errorf("the revoked invoke must go out unauthenticated exactly once, saw %d", n)
	}
	for _, tok := range []string{tokenV1, tokenV2} {
		if got := seenAuth()["Bearer "+tok]; got != 1 {
			t.Errorf("the revoked posture must never replay %q, saw %d times", tok, got)
		}
	}

	// The failure is stable: a second invoke fails closed the same way (no
	// cache resurrects the revoked credential).
	_, err = lifecycleInvoke(p)
	assertAuthRequiredShape(t, err, CredKindHeaders)
	if n := seenAuth()[""]; n != 2 {
		t.Errorf("the repeat invoke must also go out unauthenticated, saw %d", n)
	}

	// No material anywhere in the audit trail; the outcome trail reads
	// ok, ok, auth_required, auth_required.
	assertNoMaterial(t, []string{tokenV1, tokenV2}, err, auditEvents)
	wantOutcomes := []string{OutcomeOK, OutcomeOK, OutcomeAuthRequired, OutcomeAuthRequired}
	if len(auditEvents) != len(wantOutcomes) {
		t.Fatalf("audit events = %d, want %d", len(auditEvents), len(wantOutcomes))
	}
	for i, want := range wantOutcomes {
		if auditEvents[i].Outcome != want {
			t.Errorf("audit[%d].Outcome = %q, want %q", i, auditEvents[i].Outcome, want)
		}
	}
}

// TestProxy_Invoke_OAuthLifecycle_SingleRefreshRotatesForSubsequentCalls:
// an upstream 401 on oauth gets exactly ONE refresh round; the retry carries
// the refreshed token, the rotation persists for the NEXT invoke without a
// second refresh round, and neither the expired nor the refreshed token nor
// the upstream echo body ever reaches the caller-facing surface.
func TestProxy_Invoke_OAuthLifecycle_SingleRefreshRotatesForSubsequentCalls(t *testing.T) {
	const (
		expiredTok   = "sk-oauth-lifecycle-expired-1a2b"
		refreshedTok = "sk-oauth-lifecycle-refreshed-3c4d"
	)
	up, seenAuth := lifecycleUpstream(t, refreshedTok, http.StatusUnauthorized)
	src := &lifecycleCredSource{}
	src.serveOAuth(expiredTok)
	src.onUnauthorized = func(kind string) (map[string][]string, bool, error) {
		if kind != CredKindOAuth {
			t.Errorf("refresh round got kind %q, want %q", kind, CredKindOAuth)
		}
		// The rotation lands (the real source rewrites the row); the retry
		// uses the refreshed headers.
		src.serveOAuth(refreshedTok)
		return map[string][]string{"Authorization": {"Bearer " + refreshedTok}}, true, nil
	}
	var auditEvents []AuditEvent
	p := lifecycleProxy(t, up.URL, src, &auditEvents)

	// Invoke 1: expired token rejected → exactly one refresh round → the
	// retry carries the refreshed token and succeeds.
	res, err := lifecycleInvoke(p)
	if err != nil {
		t.Fatalf("invoke with refresh: %v", err)
	}
	if !strings.Contains(string(res), "saw Bearer "+refreshedTok) {
		t.Fatalf("the retry must carry the refreshed token, got %s", res)
	}
	if n := seenAuth()["Bearer "+expiredTok]; n != 1 {
		t.Fatalf("the expired token must be attempted exactly once, saw %d", n)
	}
	if got := src.refreshRounds(); got != 1 {
		t.Fatalf("exactly one refresh round, got %d", got)
	}

	// Invoke 2: the rotation persisted — the next invoke serves the rotated
	// token directly, WITHOUT another refresh round.
	res, err = lifecycleInvoke(p)
	if err != nil {
		t.Fatalf("invoke after refresh rotation: %v", err)
	}
	if !strings.Contains(string(res), "saw Bearer "+refreshedTok) {
		t.Fatalf("the rotated token must serve subsequent invokes, got %s", res)
	}
	if got := src.refreshRounds(); got != 1 {
		t.Fatalf("the rotation must persist (no second refresh round), got %d rounds", got)
	}
	if n := seenAuth()["Bearer "+expiredTok]; n != 1 {
		t.Fatalf("the expired token must never be retried, saw %d", n)
	}

	// Non-visibility: the 401 echo body and both tokens stay off the audit
	// trail across the whole flow.
	assertNoMaterial(t, []string{expiredTok, refreshedTok}, nil, auditEvents)
	if len(auditEvents) != 2 {
		t.Fatalf("audit events = %d, want 2", len(auditEvents))
	}
	for i, ev := range auditEvents {
		if ev.Outcome != OutcomeOK {
			t.Errorf("audit[%d].Outcome = %q, want %q", i, ev.Outcome, OutcomeOK)
		}
	}
}

// TestProxy_Invoke_Upstream403_TerminalAuthRequiredNoRetry: a 403 with a
// credential applied is terminal exactly like a 401 — one upstream call, the
// oauth begin-flow error, and neither the credential nor the upstream echo
// body surfaces anywhere.
func TestProxy_Invoke_Upstream403_TerminalAuthRequiredNoRetry(t *testing.T) {
	const deadTok = "sk-oauth-lifecycle-forbidden-5e6f"
	// The never-matching accept token makes the upstream 403 every
	// credential-bearing call (the always-rejected posture) while still
	// echoing the credential it received into the body.
	up, seenAuth := lifecycleUpstream(t, "\x00-never-matches", http.StatusForbidden)
	src := &lifecycleCredSource{}
	src.serveOAuth(deadTok) // onUnauthorized nil: refresh impossible → terminal
	var auditEvents []AuditEvent
	p := lifecycleProxy(t, up.URL, src, &auditEvents)

	_, err := lifecycleInvoke(p)
	assertAuthRequiredShape(t, err, CredKindOAuth)
	if got := src.refreshRounds(); got != 1 {
		t.Errorf("the single recovery round must run for a 403 too, got %d", got)
	}
	if n := len(seenAuth()); n != 1 {
		t.Errorf("a 403 is terminal: the upstream must see exactly one call (no retry), saw %d", n)
	}
	assertNoMaterial(t, []string{deadTok}, err, auditEvents)
	if len(auditEvents) != 1 || auditEvents[0].Outcome != OutcomeAuthRequired {
		t.Fatalf("audit = %+v, want exactly one auth_required event", auditEvents)
	}
}
