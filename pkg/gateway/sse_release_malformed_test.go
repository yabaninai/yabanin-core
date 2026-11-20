package cli

// N1-SSE-RELEASE-MALFORMED: the release-path contract for an unparseable
// HELD frame. SSE-04 pins the immediate path (malformed input while not
// holding); writeFrame never buffers malformed frames, so the defensive
// branch in release() is pinned here at unit level with the real writer,
// real recorder and real engine: the malformed frame is emitted
// byte-identically, in arrival order relative to the other held frames;
// holding/heldFrames are cleared; declName/declArgs are reset; and the
// F5 sticky-deny state (verdict, seenChoice/keptChoice) is preserved —
// release must not clear security state indiscriminately.

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// releaseFixture builds an active gate writer over a real recorder with
// three held frames — an allowed safe_tool name fragment, a malformed
// frame, and an arguments fragment — plus the declaration/verdict state
// the hold accumulated. The returned booleans mirror the sticky state the
// writer must still hold after release.
func releaseFixture(allowed bool) (g *sseToolGateWriter, body *bytes.Buffer, fragName, malformed, fragArgs []byte) {
	w := httptest.NewRecorder()
	g = newSSEToolGateWriter(context.Background(), w, fuzzToolEngine(), "org-deny", "*", true)
	name := "safe_tool"
	if !allowed {
		name = "secret_tool"
	}
	fragName = []byte("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"" + name + "\",\"arguments\":\"\"}}]}}]}\n\n")
	malformed = []byte("data: {bad held json\n\n")
	fragArgs = []byte("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"a\\\":1}\"}}]}}]}\n\n")
	key := callKeyFor(0, 0)
	g.holding = true
	g.heldFrames = [][]byte{fragName, malformed, fragArgs}
	g.declName = map[callKey]string{key: name}
	g.declArgs = map[callKey]*bytes.Buffer{key: bytes.NewBufferString(`{"a":1}`)}
	g.verdict = map[callKey]bool{key: allowed}
	g.seenChoice = map[int]bool{0: true}
	g.keptChoice = map[int]bool{0: allowed}
	return g, w.Body, fragName, malformed, fragArgs
}

// assertReleaseStateCleared pins the reset contract: hold buffer and
// per-call declaration maps must be empty after release.
func assertReleaseStateCleared(t *testing.T, g *sseToolGateWriter) {
	t.Helper()
	if g.holding {
		t.Fatalf("release-malformed: holding still set after release")
	}
	if len(g.heldFrames) != 0 {
		t.Fatalf("release-malformed: heldFrames not cleared: %d frames", len(g.heldFrames))
	}
	if len(g.declName) != 0 || len(g.declArgs) != 0 {
		t.Fatalf("release-malformed: declaration state not reset: declName=%v declArgs=%d",
			g.declName, len(g.declArgs))
	}
}

// TestSSEReleaseMalformedHeldFrameAllowed: with the held call allowed,
// every held frame — the malformed one included — is written
// byte-identically in arrival order, and the reset/sticky contracts hold.
func TestSSEReleaseMalformedHeldFrameAllowed(t *testing.T) {
	g, body, fragName, malformed, fragArgs := releaseFixture(true)

	g.release() // no panic is part of the contract

	out := body.Bytes()
	if !bytes.Contains(out, malformed) {
		t.Fatalf("release-malformed allowed: malformed frame not byte-identical in output: %q", body.String())
	}
	iName, iBad, iArgs := bytes.Index(out, fragName), bytes.Index(out, malformed), bytes.Index(out, fragArgs)
	if iName < 0 || iBad < 0 || iArgs < 0 || iName >= iBad || iBad >= iArgs {
		t.Fatalf("release-malformed allowed: arrival order not preserved (name=%d bad=%d args=%d): %q",
			iName, iBad, iArgs, body.String())
	}
	assertReleaseStateCleared(t, g)
	if v := g.verdict[callKeyFor(0, 0)]; !v {
		t.Fatalf("release-malformed allowed: verdict not preserved: %v", g.verdict)
	}
	if !g.seenChoice[0] || !g.keptChoice[0] {
		t.Fatalf("release-malformed allowed: choice state not preserved: seen=%v kept=%v",
			g.seenChoice, g.keptChoice)
	}
}

// TestSSEReleaseMalformedHeldFrameDenied: with the held call name-denied
// (F5 sticky contract), the denied fragments are suppressed while the
// malformed frame still passes byte-identically and the verdict survives
// the release — security state is not cleared indiscriminately.
func TestSSEReleaseMalformedHeldFrameDenied(t *testing.T) {
	g, body, _, malformed, _ := releaseFixture(false)

	g.release()

	out := body.String()
	if strings.Contains(out, "secret_tool") {
		t.Fatalf("release-malformed denied: denied fragment leaked: %q", out)
	}
	if !strings.Contains(out, string(malformed)) {
		t.Fatalf("release-malformed denied: malformed frame not emitted byte-identically: %q", out)
	}
	assertReleaseStateCleared(t, g)
	if v, ok := g.verdict[callKeyFor(0, 0)]; !ok || v {
		t.Fatalf("release-malformed denied: sticky verdict not preserved: %v", g.verdict)
	}
	if !g.seenChoice[0] || g.keptChoice[0] {
		t.Fatalf("release-malformed denied: choice state wrong after release: seen=%v kept=%v",
			g.seenChoice, g.keptChoice)
	}
}

// TestSSEReleaseValidHeldFramesControl: no malformed input — the valid
// held frames pass through byte-identically in order with the same
// reset/sticky contracts (control for the malformed legs above).
func TestSSEReleaseValidHeldFramesControl(t *testing.T) {
	g, body, fragName, _, fragArgs := releaseFixture(true)
	g.heldFrames = [][]byte{fragName, fragArgs}

	g.release()

	out := body.Bytes()
	if !bytes.Equal(out, append(append([]byte{}, fragName...), fragArgs...)) {
		t.Fatalf("release control: valid held frames must pass byte-identically in order: %q", body.String())
	}
	assertReleaseStateCleared(t, g)
	if v := g.verdict[callKeyFor(0, 0)]; !v {
		t.Fatalf("release control: verdict not preserved: %v", g.verdict)
	}
}
