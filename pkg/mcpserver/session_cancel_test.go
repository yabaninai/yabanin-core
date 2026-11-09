package mcpserver

// Wire-level pins for client-initiated session cancel and the reconnect
// cycle it forces on the native Streamable HTTP endpoint.
//
// Cells pinned here:
//   - DELETE of a live session terminates it server-side: 204 now, and
//     every later request carrying the id is 404 with no downstream
//     processing (fail-closed);
//   - the reconnect cycle is reproducible end to end: cancel → 404 →
//     fresh initialize → new session fully operational;
//   - a cancelled session is indistinguishable from an unknown one on the
//     wire (no oracle);
//   - termination requires presenting a currently-valid session id;
//   - the revocation registry is bounded, prunes expired entries, and
//     refuses (500) rather than falsely acknowledges a cancel it cannot
//     record;
//   - concurrent cancel/use traffic is race-clean.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// deleteSession is a raw DELETE with an optional Mcp-Session-Id.
func deleteSession(handler http.Handler, session string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer yag_test")
	if session != "" {
		req.Header.Set(sessionHeader, session)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestSessionCancelForcesReconnectCycle is the acceptance cell: a cancelled
// session dies server-side and the prescribed recovery (fresh initialize)
// fully restores operation. The dead id is 404 at every later use, and a
// cancelled id never reaches a downstream tool backend again.
func TestSessionCancelForcesReconnectCycle(t *testing.T) {
	backend := newStubBackend()
	backend.tools = []ToolDesc{{Name: "srv:search"}}
	backend.callRes["srv:search"] = json.RawMessage(`{"content":[{"type":"text","text":"ok"}],"isError":false}`)
	handler := newTestServer(t, Config{}, backend)
	// Global promauto counters are shared across tests: assert deltas.
	beforeCancelled := counterVec(t, mcpSessionsTotal, "cancelled")

	// 1. Handshake issues session A; a tool call through it works.
	rec := post(handler, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, "", "")
	sidA := rec.Header().Get(sessionHeader)
	if sidA == "" {
		t.Fatal("initialize issued no session")
	}
	rec = post(handler, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"srv:search"}}`, "", sidA)
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-cancel tools/call: status %d body %s", rec.Code, rec.Body.String())
	}
	backend.mu.Lock()
	callsBefore := len(backend.calls)
	backend.mu.Unlock()
	if callsBefore != 1 {
		t.Fatalf("pre-cancel backend calls = %d", callsBefore)
	}

	// 2. Client cancels the session: 204 No Content.
	if rec = deleteSession(handler, sidA); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE live session: status %d body %s", rec.Code, rec.Body.String())
	}
	if got := counterVec(t, mcpSessionsTotal, "cancelled") - beforeCancelled; got != 1 {
		t.Fatalf("cancelled metric delta = %v, want 1", got)
	}

	// 3. Every later use of the cancelled id is the 404 re-initialize
	// signal — and the request is dropped before any backend work.
	rec = post(handler, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"srv:search"}}`, "", sidA)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("tools/call with cancelled session: status %d, want 404", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("cancelled-session rejection must be bodyless (same as unknown), got %q", rec.Body.String())
	}
	backend.mu.Lock()
	callsAfter := len(backend.calls)
	backend.mu.Unlock()
	if callsAfter != callsBefore {
		t.Fatalf("cancelled session reached the backend (%d → %d calls)", callsBefore, callsAfter)
	}

	// 4. Cancelling again is not a second success: the id is already
	// unknown (terminated sessions are not special).
	if rec = deleteSession(handler, sidA); rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE cancelled session: status %d, want 404", rec.Code)
	}

	// 5. Reconnect: fresh initialize issues a new session, which is fully
	// operational — the old id stays dead.
	rec = post(handler, `{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, "", "")
	sidB := rec.Header().Get(sessionHeader)
	if sidB == "" || sidB == sidA {
		t.Fatalf("re-initialize issued no fresh session (same=%t)", sidB == sidA)
	}
	rec = post(handler, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"srv:search"}}`, "", sidB)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-reconnect tools/call: status %d body %s", rec.Code, rec.Body.String())
	}
	backend.mu.Lock()
	callsReconnected := len(backend.calls)
	backend.mu.Unlock()
	if callsReconnected != callsBefore+1 {
		t.Fatalf("post-reconnect backend calls = %d, want %d", callsReconnected, callsBefore+1)
	}
	// Session A remains dead after the reconnect (cancel is permanent for
	// the id's lifetime; it is not resurrected by later traffic).
	if rec = post(handler, `{"jsonrpc":"2.0","id":6,"method":"ping"}`, "", sidA); rec.Code != http.StatusNotFound {
		t.Fatalf("cancelled id resurrected: status %d, want 404", rec.Code)
	}
}

// TestCancelledSessionIsUnknownNotSpecial pins the no-oracle property: the
// wire rejection of a cancelled session (status, empty body) is byte-shape
// identical to that of a forged session, so an observer cannot tell
// revocation from an unknown id — matching the expired-session parity pin
// and keeping the 404 recovery path uniform.
func TestCancelledSessionIsUnknownNotSpecial(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	rec := post(handler, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "")
	sid := rec.Header().Get(sessionHeader)

	if rec = deleteSession(handler, sid); rec.Code != http.StatusNoContent {
		t.Fatalf("cancel: status %d", rec.Code)
	}
	cancelled := post(handler, `{"jsonrpc":"2.0","id":2,"method":"ping"}`, "", sid)
	forged := post(handler, `{"jsonrpc":"2.0","id":3,"method":"ping"}`, "", sid+"tampered")

	if cancelled.Code != http.StatusNotFound || forged.Code != http.StatusNotFound {
		t.Fatalf("statuses: cancelled %d forged %d", cancelled.Code, forged.Code)
	}
	if cancelled.Body.String() != forged.Body.String() {
		t.Fatalf("rejection shapes differ: cancelled %q forged %q", cancelled.Body.String(), forged.Body.String())
	}
}

// TestCancelRequiresPresentableSession pins the termination authority: a
// DELETE without a session header is a no-op ack (stateless clients hold
// nothing to terminate), and a forged id is rejected — it never enters the
// revocation registry (validate-then-record ordering), so cancelling can
// not become a poisoning primitive.
func TestCancelRequiresPresentableSession(t *testing.T) {
	srv := New(Config{}, newStubBackend(), nil, []byte("cancel-secret"))

	if rec := deleteSession(http.HandlerFunc(srv.ServeHTTP), ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE without session: status %d, want 204", rec.Code)
	}

	forged := "bogus.bogus.bogus"
	if rec := deleteSession(http.HandlerFunc(srv.ServeHTTP), forged); rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE forged session: status %d, want 404", rec.Code)
	}
	if err := srv.session.revoke(forged); err == nil {
		t.Fatal("forged id accepted for revocation")
	}
	srv.session.mu.Lock()
	size := len(srv.session.revoked)
	srv.session.mu.Unlock()
	if size != 0 {
		t.Fatalf("revocation registry grew from rejected ids: %d entries", size)
	}

	// A live id revokes and the registry holds exactly that entry.
	live := srv.session.issue()
	if err := srv.session.revoke(live); err != nil {
		t.Fatalf("live revoke: %v", err)
	}
	srv.session.mu.Lock()
	size = len(srv.session.revoked)
	srv.session.mu.Unlock()
	if size != 1 {
		t.Fatalf("registry size = %d, want 1", size)
	}
}

// TestRevocationRegistryBoundedAndFailClosed pins the registry's memory and
// honesty bounds: at capacity, revocations that cannot be recorded are
// refused (the signer reports exhaustion instead of silently dropping the
// cancel, and the affected session stays valid — the client was told the
// truth); after the recorded sessions expire, pruning frees capacity and
// terminations work again.
func TestRevocationRegistryBoundedAndFailClosed(t *testing.T) {
	s := newSessionSigner([]byte("cap-secret"), time.Hour)
	base := time.Now()
	s.now = func() time.Time { return base }
	s.revocationCap = 4

	live := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		live = append(live, s.issue())
	}
	// Cancel the first four: each succeeds and is enforced.
	for i := 0; i < 4; i++ {
		if err := s.revoke(live[i]); err != nil {
			t.Fatalf("revoke %d: %v", i, err)
		}
		if err := s.validate(live[i]); err == nil {
			t.Fatalf("revoked session %d still valid", i)
		}
	}
	// The fifth termination cannot be recorded: refused with exhaustion,
	// and the session stays valid (the refusal was honest).
	if err := s.revoke(live[4]); err != errRevocationExhausted {
		t.Fatalf("revoke at capacity: %v, want errRevocationExhausted", err)
	}
	if err := s.validate(live[4]); err != nil {
		t.Fatalf("session whose cancel was refused must stay valid: %v", err)
	}

	// Advance past the recorded sessions' expiry: their registry entries
	// are dead weight (verify rejects such ids without the registry), and
	// the next termination pressure prunes them — capacity is freed and
	// the refused cancel now succeeds.
	s.now = func() time.Time { return base.Add(2 * time.Hour) }
	if err := s.validate(live[4]); err == nil {
		t.Fatal("setup: session did not expire alongside the registry entries")
	}
	fresh := s.issue() // issue-path prune runs at capacity and sheds the expired records
	if err := s.revoke(fresh); err != nil {
		t.Fatalf("revoke after prune: %v", err)
	}
	if err := s.validate(fresh); err == nil {
		t.Fatal("post-prune revocation not enforced")
	}
	s.mu.Lock()
	size := len(s.revoked)
	s.mu.Unlock()
	if size != 1 {
		t.Fatalf("registry after prune+revoke = %d entries, want 1", size)
	}
}

// TestServeDeleteRefusedWhenExhausted pins the transport honesty cell: when
// the registry is exhausted, DELETE reports a server failure (500) instead
// of acknowledging a termination that did not happen, and the session keeps
// working (the client was told the cancel failed).
func TestServeDeleteRefusedWhenExhausted(t *testing.T) {
	backend := newStubBackend()
	srv := New(Config{}, backend, nil, []byte("exhaust-secret"))
	srv.session.revocationCap = 1

	first := srv.session.issue()
	second := srv.session.issue()

	if rec := deleteSession(srv, first); rec.Code != http.StatusNoContent {
		t.Fatalf("first cancel: status %d", rec.Code)
	}
	rec := deleteSession(srv, second)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("cancel at capacity: status %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "session termination") {
		t.Fatalf("refusal body: %q", rec.Body.String())
	}
	if err := srv.session.validate(second); err != nil {
		t.Fatalf("refused-cancel session must stay valid: %v", err)
	}
}

// TestConcurrentCancelAndUse is the race pin: parallel traffic mixing
// issue, validate and revoke stays race-clean and semantically exact. The
// id sets are disjoint by phase so every assertion is deterministic: live
// ids are validated only while provably unrevoked, and a cancelled id must
// fail validation from its revoke's return onward (the registry insert is
// ordered before the revoke returns and every later validate takes the same
// lock). The race detector exercises the read/write lock interleave.
func TestConcurrentCancelAndUse(t *testing.T) {
	s := newSessionSigner([]byte("race-secret"), time.Hour)
	const workers, rounds, capSessions = 8, 40, 20
	s.revocationCap = capSessions

	ids := make([]string, capSessions)
	for i := range ids {
		ids[i] = s.issue()
	}
	cancelTarget := capSessions / 2

	var wg sync.WaitGroup
	fail := func(format string, args ...any) {
		t.Errorf(format, args...) // Errorf is race-safe (t.Fatal is not, off the test goroutine)
	}
	// Validators: live ids must never reject, at any point (their set is
	// disjoint from the revocation set, so the assertion is deterministic
	// under any interleave).
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				for _, sid := range ids[cancelTarget:] {
					if err := s.validate(sid); err != nil {
						fail("live session rejected mid-traffic: %v", err)
					}
				}
			}
		}()
	}
	// A canceller revokes the first half while validators and the issuer
	// run: the race detector sees revoke's write lock interleaved with
	// validate's read lock on the same registry (disjoint id sets).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < cancelTarget; i++ {
			if err := s.revoke(ids[i]); err != nil {
				fail("revoke %d: %v", i, err)
			}
		}
	}()
	// A concurrent issuer exercises the issue-path lock interleave
	// (registry capacity checks under the write lock).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			sid := s.issue()
			if err := s.validate(sid); err != nil {
				fail("freshly issued session rejected: %v", err)
			}
		}
	}()
	wg.Wait()

	// Quiesced phase: the exactness pin over every id.
	var wg2 sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			for r := 0; r < rounds; r++ {
				for i := 0; i < capSessions; i++ {
					err := s.validate(ids[i])
					cancelled := i < cancelTarget
					if cancelled && err == nil {
						fail("cancelled session %d validated", i)
					}
					if !cancelled && err != nil {
						fail("live session %d rejected: %v", i, err)
					}
				}
			}
		}()
	}
	wg2.Wait()

	s.mu.Lock()
	size := len(s.revoked)
	s.mu.Unlock()
	if size != cancelTarget {
		t.Fatalf("registry size = %d, want %d", size, cancelTarget)
	}
}
