package mcpserver

// Wire-level reproducibility pins for protocol-version negotiation and
// transport recovery on the native Streamable HTTP endpoint (matrix source:
// version.go).
//
// Acceptance cells pinned here:
//   - negotiation matrix reproducible over the wire (initialize echo +
//     explicit latest fallback + follow-up header acceptance);
//   - NEGATIVE cell "unknown version is rejected without silent downgrade"
//     at both decision points (initialize response, follow-up header);
//   - a client speaking only a newer spec revision (2025-11-25, the
//     SDK-side latest) is pinned end to end;
//   - transport recovery reproducible: an invalid/expired session yields
//     404 (the spec's re-initialize signal) and a fresh initialize fully
//     restores the session without server-side state.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// initVersion drives one initialize handshake and returns the negotiated
// protocolVersion from the response result.
func initVersion(t *testing.T, handler http.Handler, requested string) string {
	t.Helper()
	_, resp := rpcCall(t, handler,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+requested+`"}}`)
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("initialize(%q): no result object: %v", requested, resp)
	}
	got, _ := res["protocolVersion"].(string)
	return got
}

// postWithVersionHeader is a raw POST carrying MCP-Protocol-Version.
func postWithVersionHeader(handler http.Handler, body, version string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", agentAccept)
	req.Header.Set("Authorization", "Bearer yag_test")
	if version != "" {
		req.Header.Set(protocolVersionHeader, version)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestNegotiationMatrixWire drives the full supported matrix through the
// endpoint: every offered version is echoed exactly, and a follow-up that
// names the negotiated version in MCP-Protocol-Version is accepted.
func TestNegotiationMatrixWire(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	for _, want := range protocolMatrix {
		if got := initVersion(t, handler, want); got != want {
			t.Fatalf("initialize(%q) → %q, want exact echo", want, got)
		}
		// The negotiated version is a valid follow-up header value.
		rec := postWithVersionHeader(handler, `{"jsonrpc":"2.0","id":2,"method":"ping"}`, want)
		if rec.Code != http.StatusOK {
			t.Fatalf("follow-up header %q: status %d body %s", want, rec.Code, rec.Body.String())
		}
	}
}

// TestUnknownVersionRejectedWithoutSilentDowngrade is the card's negative
// cell, pinned at BOTH protocol-version decision points:
//
//  1. initialize with an unknown version: the response names the server's
//     latest (a matrix member) — it never echoes the unknown value and
//     never claims an unimplemented revision (no silent downgrade).
//  2. follow-up with an unknown MCP-Protocol-Version header: HTTP 400 with
//     the exact reason, and the request is NOT processed — the rejection is
//     terminal, not a downgrade-and-continue.
func TestUnknownVersionRejectedWithoutSilentDowngrade(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())

	// Point 1: unknown initialize requests get an explicit matrix member.
	for _, requested := range []string{"1999-01-01", "2025-11-25", "2024-11-05", "garbage", ""} {
		got := initVersion(t, handler, requested)
		if got != protocolVersionLatest {
			t.Fatalf("unknown %q negotiated to %q, want explicit latest %q", requested, got, protocolVersionLatest)
		}
	}

	// Point 2: unknown follow-up header → 400, exact reason, no processing.
	backend := newStubBackend()
	backend.callRes["srv:mustnotcall"] = json.RawMessage(`{"content":[],"isError":false}`)
	strict := newTestServer(t, Config{}, backend)
	for _, v := range []string{"2000-01-01", "2025-11-25", "2024-11-05", "garbage"} {
		rec := postWithVersionHeader(strict, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"srv:mustnotcall"}}`, v)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unknown header %q: status %d, want 400", v, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "unsupported MCP-Protocol-Version") {
			t.Fatalf("unknown header %q: reason missing, body %q", v, rec.Body.String())
		}
		if len(backend.calls) != 0 {
			t.Fatalf("request with unknown header %q reached the backend (silent downgrade)", v)
		}
	}
	// Absent header stays allowed (stateless clients).
	if rec := postWithVersionHeader(strict, `{"jsonrpc":"2.0","id":4,"method":"ping"}`, ""); rec.Code != http.StatusOK {
		t.Fatalf("absent header: status %d", rec.Code)
	}
}

// TestNewerRevisionOnlyClient pins the newer-revision-only client cell end
// to end: a client speaking only the newer SDK revision (2025-11-25) negotiates down
// EXPLICITLY (it is told 2025-06-18), then either adopts the negotiated
// version (works) or keeps sending its own (400 — rejected, not downgraded
// silently). Interop stays safe because the negotiated value is inside the
// SDK's ValidProtocolVersions.
func TestNewerRevisionOnlyClient(t *testing.T) {
	handler := newTestServer(t, Config{}, newStubBackend())
	const sdkLatest = "2025-11-25"

	// Handshake: the client asks for 2025-11-25 and is told the truth.
	got := initVersion(t, handler, sdkLatest)
	if got != protocolVersionLatest || got == sdkLatest {
		t.Fatalf("2025-11-25-only client got %q, want explicit %q", got, protocolVersionLatest)
	}

	// The client adopts the negotiated version → follow-ups pass.
	rec := postWithVersionHeader(handler, `{"jsonrpc":"2.0","id":2,"method":"ping"}`, got)
	if rec.Code != http.StatusOK {
		t.Fatalf("negotiated-version follow-up: status %d", rec.Code)
	}

	// The client insists on 2025-11-25 → rejected, exact reason.
	rec = postWithVersionHeader(handler, `{"jsonrpc":"2.0","id":3,"method":"ping"}`, sdkLatest)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unsupported MCP-Protocol-Version") {
		t.Fatalf("insisting client: status %d body %s", rec.Code, rec.Body.String())
	}
}

// TestTransportRecoveryReinitialize pins the transport-recovery cell: an
// invalid session is 404 (the spec's re-initialize signal) and a fresh
// initialize restores full operation with a NEW session — reproducible with
// zero server-side state (stateless signed sessions).
func TestTransportRecoveryReinitialize(t *testing.T) {
	backend := newStubBackend()
	backend.tools = []ToolDesc{{Name: "srv:search"}}
	backend.callRes["srv:search"] = json.RawMessage(`{"content":[{"type":"text","text":"ok"}],"isError":false}`)
	handler := newTestServer(t, Config{}, backend)

	// 1. First handshake issues session A.
	rec := post(handler, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, "", "")
	sidA := rec.Header().Get(sessionHeader)
	if sidA == "" {
		t.Fatal("first initialize issued no session")
	}

	// 2. Session corruption (lost replica key / expired / forged) → 404.
	rec = post(handler, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, "", sidA+"tampered")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("invalid session: status %d, want 404 re-initialize signal", rec.Code)
	}

	// 3. Recovery: the client DROPS the dead session id and re-initializes
	// (the prescribed remedy for 404). Re-initialize issues a fresh session.
	rec = post(handler, `{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("re-initialize: status %d", rec.Code)
	}
	sidB := rec.Header().Get(sessionHeader)
	if sidB == "" || sidB == sidA {
		t.Fatalf("re-initialize issued no fresh session (A=%t)", sidB == sidA)
	}
	// Fail-closed posture: presenting the DEAD session with initialize is
	// still a 404 — recovery requires clearing the old id first.
	rec = post(handler, `{"jsonrpc":"2.0","id":5,"method":"initialize"}`, "", sidA+"tampered")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("initialize carrying a dead session: status %d, want 404", rec.Code)
	}

	// 4. Session B is fully operational (negotiated 2025-03-26 this time).
	rec = post(handler, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"srv:search"}}`, "", sidB)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-recovery tools/call: status %d body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Result == nil {
		t.Fatalf("post-recovery result: %v (%s)", err, rec.Body.String())
	}
}

// TestExpiredSessionIsUnknownNotSpecial pins the recovery SHAPE for expiry:
// a well-signed but expired session id produces exactly the same wire
// rejection as an unknown one (404, no body) — a client cannot distinguish
// expiry from a replica-key rotation and always recovers the same prescribed
// way (re-initialize). The expired id is minted with the server's own
// secret and a back-dated signer clock, so the 404 proves expiry handling,
// not a signature rejection.
func TestExpiredSessionIsUnknownNotSpecial(t *testing.T) {
	srv := New(Config{}, newStubBackend(), nil, []byte("test-session-secret"))

	// Mint a session with a back-dated clock, so its embedded expiry sits
	// in the past relative to the server's real clock (an id issued "2h
	// ago" with a 1h TTL).
	minter := newSessionSigner([]byte("test-session-secret"), time.Hour)
	base := time.Now()
	minter.now = func() time.Time { return base.Add(-2 * time.Hour) }
	expired := minter.issue()
	minter.now = time.Now
	if err := minter.validate(expired); err == nil {
		t.Fatal("setup: session did not expire")
	}

	// The server (same secret, real clock) rejects it exactly like unknown.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", agentAccept)
	req.Header.Set("Authorization", "Bearer yag_test")
	// The raw server has no middleware: supply the identity headers the
	// gateway auth middleware resolves from the yag_ principal.
	req.Header.Set("X-Org-Id", "org1")
	req.Header.Set("X-Agent-Id", "agent1")
	req.Header.Set(sessionHeader, expired)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
		t.Fatalf("expired session: status %d body %q, want 404 empty (same as unknown)", rec.Code, rec.Body.String())
	}
}
