package cli

// Fuzz seeds for the SSE tool-call gate surface (task gateway-fuzz-seeds).
// Case IDs and expected outcomes are frozen in FROZEN-CASE-TABLE.md
// (SSE-*). Frames are driven through Write in the same split-write pattern
// the providers produce.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fuzzFlushRecorder struct {
	*httptest.ResponseRecorder
	flushed int
	noFlush bool
}

func (r *fuzzFlushRecorder) Flush() {
	r.flushed++
	if r.noFlush {
		return
	}
	r.ResponseRecorder.Flush()
}

func FuzzSSEToolGate(f *testing.F) {
	for id := 1; id <= 24; id++ {
		f.Add([]byte{byte(id)}) // frozen regression corpus
	}
	// Generated-stream seeds: active gate with denied fragment mid-hold, and
	// an inactive passthrough stream (see fuzzSSEGenerated).
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x80, 0x01, 0x02, 0x03, 0x81})
	// Critical-go seed extensions (arm table in sseGenFrames): identity
	// conflict, hold/discard lifecycles, ambiguous identities, nameless and
	// object-argument calls, plus inactive-stream payloads that fail JSON
	// decoding at different stages. Byte shapes follow the arm table: bit 0
	// picks the name (0x80 set for values ≥ 0x80), 0x04/0x08/0x10/0x20 are the
	// call-shape arms, 0x40 on the FIRST byte selects the inactive org, and
	// c[3] carries the frame-shape arms.
	f.Add([]byte{129, 0, 0, 0, 130, 0, 0, 0})                        // decideName conflict on one call key
	f.Add([]byte{129, 1, 0, 0, 128, 0, 0, 0x04})                     // held call, then malformed payload → discard
	f.Add([]byte{129, 0, 0, 0, 129, 1, 0, 0, 129, 0, 0, 0x10, 0x80}) // two held choices, terminal #0, ambiguous index-less finish
	f.Add([]byte{129, 0, 0, 0, 129, 0, 0, 0x20})                     // held call, then a null choice member
	f.Add([]byte{128, 0, 0, 0, 128, 0, 0, 1})                        // same denied call key twice → sticky deny
	f.Add([]byte{145, 0, 0, 0})                                      // fractional choice index → ambiguous drop
	f.Add([]byte{161, 0, 0, 0})                                      // duplicated choice index → both ambiguous
	f.Add([]byte{133, 0, 0, 0})                                      // nameless call with arguments → release guard
	f.Add([]byte{137, 0, 0, 0})                                      // object arguments → identity refused
	f.Add([]byte{193, 0, 0, 0x0C, 193, 0, 0, 0x40})                  // inactive: scalar then invalid-first-token payloads
	// Critical-go wave-2 frozen pins (SSE-19..SSE-24): the passthrough tail
	// tracker, the stream identity shim, the SSE error frame, held-frame
	// passthrough for unparseable payloads, and the streaming-policy state /
	// writer delegation cluster. These are direct unit pins — no SSE frames
	// are driven.
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 0 && data[0] >= 1 && data[0] <= 24 {
			fuzzSSECases[int(data[0])](t)
			return
		}
		fuzzSSEGenerated(t, data)
	})
}

// sseGenName maps a stream byte to a tool-call name. 0 is the policy-denied
// name under org-deny, 1 the allowed one, anything else a generated name the
// policy does not know (implicit allow).
func sseGenName(b byte) string {
	switch b & 3 {
	case 0:
		return "secret_tool"
	case 1:
		return "safe_tool"
	default:
		return fmt.Sprintf("gen_tool_%02x", b)
	}
}

// sseGenFrames derives an SSE frame stream from the fuzzed bytes. Frame
// shape comes from the 4-byte groups: c[0] carries the tool name (low two
// bits) plus the call-shape arms 0x04 nameless / 0x08 object arguments /
// 0x10 fractional choice index / 0x20 duplicated choice; c[1] is the choice
// index, c[2] the call index, and c[3] the frame-shape arms 0x04 malformed
// payload / 0x08 scalar payload / 0x10 indexed terminal frame / 0x20 null
// choice member / 0x40 invalid-first-token payload. Bit 0x80 on c[0] and
// the trailing byte feed the historical name/finish derivation. The pre-extension seeds keep c[3] ∈ {0, 3} and
// c[0] ∈ {0x00, 0x80}, so every new arm is clear for them and their emitted
// stream is byte-identical to the pre-extension generator.
func sseGenFrames(p []byte) (frames []string, sawDenied bool) {
	for i := 0; i+3 < len(p); i += 4 {
		c := p[i : i+4]
		if c[0]&3 == 3 { // non-data line: keepalive/comment passthrough
			frames = append(frames, sseGenKeepAlive(c))
			continue
		}
		if frame, special := sseGenSpecialFrame(c); special {
			frames = append(frames, frame)
			continue
		}
		frame, denied, resolvable := sseGenCallFrame(c, sseGenName(c[0]))
		frames = append(frames, frame)
		// sawDenied means "the gate must have counted a dropped denial".
		// Ambiguous identities (fractional index, in-frame duplicate) are
		// skipped by absorb before any name decision, so the gate suppresses
		// their bytes without a counted denial; only resolvable denied calls
		// carry the count expectation (TestSSEGenDeniedCountContract).
		sawDenied = sawDenied || (denied && resolvable)
	}
	if sseGenHasTerminalFrame(p) {
		frames = append(frames, `data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n")
	}
	return frames, sawDenied
}

// sseGenKeepAlive renders the non-data passthrough line (name arm 3): a
// comment frame the gate must forward untouched.
func sseGenKeepAlive(c []byte) string {
	return ": keepalive " + fmt.Sprintf("%02x", c[1]) + "\n\n"
}

// sseGenSpecialFrame renders the payload-shape arms that bypass the
// tool-call construction (frame-shape bits on c[3]), in arm priority
// order: invalid-first-token, malformed, scalar, indexed terminal.
// ok=false leaves the group to the ordinary call-frame path.
func sseGenSpecialFrame(c []byte) (frame string, ok bool) {
	switch {
	case c[3]&0x40 != 0:
		return "data: }\n\n", true // first JSON token itself invalid
	case c[3]&0x04 != 0 && c[3]&0x08 == 0:
		return "data: {bad\n\n", true // malformed JSON payload
	case c[3]&0x04 != 0:
		return "data: 5\n\n", true // scalar JSON payload
	case c[3]&0x10 != 0:
		return fmt.Sprintf(`data: {"choices":[{"index":%d,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n", c[1]%2), true
	}
	return "", false
}

// sseGenCallFrame renders one tool-call data frame from a 4-byte group:
// name/arguments payload plus the duplicate-choice (c[0]&0x20) and
// null-choice-member (c[3]&0x20) arms. denied reports a declared denied
// name — only a named call frame can carry (and leak) one; nameless frames
// omit the name key, so no denial is declared either. resolvable reports
// whether the choice identity survives resolution: a fractional index
// (0x10) and an in-frame duplicate (0x20) are ambiguous by construction
// (toolgate resolveChoiceIdentity marks both occurrences ambiguous), so
// absorb skips them before decideName and their suppressed bytes never
// produce a counted denial.
func sseGenCallFrame(c []byte, name string) (frame string, denied bool, resolvable bool) {
	nameless := c[0]&0x04 != 0
	denied = name == "secret_tool" && !nameless
	resolvable = c[0]&0x10 == 0 && c[0]&0x20 == 0
	argsBytes, _ := json.Marshal(string(c[1:])) // infallible for strings; valid JSON fragment
	if c[0]&0x08 != 0 {                         // non-string argument form: refused fail-closed
		argsBytes = []byte(`{"fuzz":true}`)
	}
	fn := fmt.Sprintf(`"arguments":%s`, string(argsBytes))
	if !nameless {
		// The arguments fragment is DATA, never part of the format string:
		// percent bytes in fuzzed arguments previously flowed through
		// Sprintf as verbs (corpus 1b76d105e1136cb4), malformed the frame,
		// and the gate hit its unparseable-passthrough arm, releasing the
		// denied name. Concatenate the rendered parts instead.
		fn = fmt.Sprintf(`"name":%q,`, name) + fn
	}
	choice := fmt.Sprintf(`{"index":%s,"delta":{"tool_calls":[{"index":%d,"function":{%s}}]}}`,
		choiceIndex(c), c[2]%3, fn)
	if c[0]&0x20 != 0 { // duplicate choice: the same wire index twice in one frame
		choice += "," + choice
	}
	choices := choice
	if c[3]&0x20 != 0 { // null choice member inside an indexed frame
		choices = "null," + choices
	}
	return fmt.Sprintf(`data: {"choices":[%s]}`+"\n\n", choices), denied, resolvable
}

// sseGenHasTerminalFrame reports the historical finish derivation: a
// stream whose final byte has bit 0x80 set appends an index-less terminal
// frame after the per-group frames.
func sseGenHasTerminalFrame(p []byte) bool {
	return len(p) > 0 && p[len(p)-1]&0x80 != 0
}

// choiceIndex renders the SSE choice index: a whole number unless the
// fractional-index arm is set (an unresolvable positional identity).
func choiceIndex(c []byte) string {
	if c[0]&0x10 != 0 {
		return fmt.Sprintf("%d.5", c[1]%2)
	}
	return fmt.Sprintf("%d", c[1]%2)
}

// sseGenStreamOracle holds the independent invariants for generated streams:
// the active gate must never release denied-tool bytes under ANY framing or
// chunk split, and it must have counted the drop for every denied call the
// oracle declares countable (identity-resolvable named calls; ambiguous
// fractional/duplicate choices legitimately accumulate nowhere while their
// bytes stay suppressed). Every released data line stays valid JSON except
// the generator's two genuinely non-JSON passthrough payloads, and the
// inactive writer is a strict byte-identical passthrough.
func sseGenStreamOracle(t *testing.T, out string, active, sawDenied bool, deniedCount int) {
	t.Helper()
	if active {
		if strings.Contains(out, "secret_tool") {
			t.Fatalf("sse gen: denied tool bytes released under generated framing: %q", out)
		}
		if sawDenied && deniedCount < 1 {
			t.Fatal("sse gen: denied fragment was held but never counted as dropped")
		}
	}
	sseAssertReleasedLinesValid(t, out)
}

// sseAssertReleasedLinesValid checks the released-stream JSON invariant: every
// non-empty "data: " line must parse as JSON, with the two generator
// passthrough payloads exempted.
func sseAssertReleasedLinesValid(t *testing.T, out string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		d, ok := strings.CutPrefix(line, "data: ")
		if !ok || d == "" {
			continue
		}
		if d == "{bad" || d == "}" {
			// Exactly the generator's two non-JSON payloads are exempt
			// from this parse check: "{bad" (malformed body) and "}"
			// (invalid first JSON token) exercise the fail-open and
			// first-token passthrough arms. The scalar "5" arm is valid
			// JSON and must pass json.Valid below like any released line.
			continue
		}
		if !json.Valid([]byte(d)) {
			t.Fatalf("sse gen: released data line is not valid JSON: %q (out %q)", d, out)
		}
	}
}

// fuzzSSEGenerated drives the real sseToolGateWriter with a generated frame
// stream delivered in fuzz-sized chunk splits (and optional mid-stream
// Flush), then applies the leak/framing oracle.
func fuzzSSEGenerated(t *testing.T, data []byte) {
	t.Helper()
	p := data
	if len(p) > 0 && p[0] < 19 { // first byte collides with seed range: use the rest
		p = p[1:]
	}
	frames, sawDenied := sseGenFrames(p)
	active := len(p) == 0 || p[0]&0x40 == 0
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	// SSE-REV-01: the inactive variant models an org WITHOUT deny rows —
	// applicability refresh finds none and the stream stays untouched.
	// (A false snapshot over an org that HAS denies is the corrected
	// transient state, pinned by fuzzSSE01's second half.)
	org := "org-deny"
	if !active {
		org = "org-none"
	}
	g := newSSEToolGateWriter(context.Background(), w, engine, org, "*", active)

	stream := strings.Join(frames, "")
	sseGenWriteChunks(t, g, stream, p)
	sseGenStreamOracle(t, w.Body.String(), active, sawDenied, g.DeniedCount())
	if !active && w.Body.String() != stream {
		t.Fatalf("sse gen: inactive writer altered the stream: %q != %q", w.Body.String(), stream)
	}
	// Critical-go pin: a choice that is not an object can never carry a
	// terminal finish reason, whatever the surrounding payload shape.
	if frameTerminal(map[string]any{"choices": []any{nil}}) {
		t.Fatal("sse gen: nil choice must not count as a terminal frame")
	}
}

// sseGenWriteChunks delivers the stream in fuzz-sized chunk splits with an
// optional mid-stream Flush (release-while-streaming) and forces the final
// release of anything still held.
func sseGenWriteChunks(t *testing.T, g *sseToolGateWriter, stream string, p []byte) {
	t.Helper()
	chunk := 1 + len(p)%7
	for off := 0; off < len(stream); off += chunk {
		end := min(off+chunk, len(stream))
		if _, err := g.Write([]byte(stream[off:end])); err != nil {
			t.Fatalf("sse gen: write: %v", err)
		}
		if len(p) > 1 && p[1]&0x20 != 0 && off+chunk < len(stream) {
			g.Flush() // release-while-streaming: held denies must still drop
		}
	}
	g.Flush() // force final release of anything still held
}

var fuzzSSECases = map[int]func(*testing.T){
	1:  fuzzSSE01,
	2:  fuzzSSE02,
	3:  fuzzSSE03,
	4:  fuzzSSE04,
	5:  fuzzSSE05,
	6:  fuzzSSE06,
	7:  fuzzSSE07,
	8:  fuzzSSE08,
	9:  fuzzSSE09,
	10: fuzzSSE10,
	11: fuzzSSE11,
	12: fuzzSSE12,
	13: fuzzSSE13,
	14: fuzzSSE14,
	15: fuzzSSE15,
	16: fuzzSSE16,
	17: fuzzSSE17,
	18: fuzzSSE18,
	19: fuzzSSE19,
	20: fuzzSSE20,
	21: fuzzSSE21,
	22: fuzzSSE22,
	23: fuzzSSE23,
	24: fuzzSSE24,
}

// // SSE-01 inactive writer passes frames through untouched
func fuzzSSE01(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	frame := []byte("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"secret_tool\"}}]}}]}\n\n")

	// An org without deny rows: the open-time snapshot is false and live
	// tool-bearing output refreshes applicability only to find none —
	// frames pass through untouched. SSE-REV-01 preserves this contract.
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-none", "*", false)
	if _, err := g.Write(frame); err != nil {
		t.Fatalf("SSE-01: write: %v", err)
	}
	if w.Body.String() != string(frame) {
		t.Fatalf("SSE-01: inactive writer must not alter frames: %q", w.Body.String())
	}

	// Corrected invariant (SSE-REV-01, intentional frozen-invariant
	// correction): a false open-time snapshot for an org that HAS deny
	// rows is transient — the first tool-bearing frame re-consults the
	// engine, activates the gate, and the denied name is filtered. The
	// former pin asserted the stale snapshot persists for the whole
	// stream; that persistence was the revocation gap.
	w2 := httptest.NewRecorder()
	g2 := newSSEToolGateWriter(ctx, w2, engine, "org-deny", "*", false)
	if _, err := g2.Write(frame); err != nil {
		t.Fatalf("SSE-01: write: %v", err)
	}
	if strings.Contains(w2.Body.String(), "secret_tool") {
		t.Fatalf("SSE-01: stale inactive snapshot released a denied tool: %q", w2.Body.String())
	}
}

// // SSE-02 non-data frame passthrough
func fuzzSSE02(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-deny", "*", true)
	if _, err := g.Write([]byte(": keepalive\n\n")); err != nil {
		t.Fatalf("SSE-02: write: %v", err)
	}
	if w.Body.String() != ": keepalive\n\n" {
		t.Fatalf("SSE-02: comment frame must pass: %q", w.Body.String())
	}
}

// // SSE-03 [DONE] releases and passes
func fuzzSSE03(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-deny", "*", true)
	if _, err := g.Write([]byte("data: [DONE]\n\n")); err != nil {
		t.Fatalf("SSE-03: write: %v", err)
	}
	if !strings.Contains(w.Body.String(), "[DONE]") {
		t.Fatalf("SSE-03: DONE must pass: %q", w.Body.String())
	}
}

// // SSE-04 unparseable data frame passes
func fuzzSSE04(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-deny", "*", true)
	if _, err := g.Write([]byte("data: {bad json\n\n")); err != nil {
		t.Fatalf("SSE-04: write: %v", err)
	}
	if !strings.Contains(w.Body.String(), "{bad json") {
		t.Fatalf("SSE-04: unparseable must pass: %q", w.Body.String())
	}
}

// // SSE-05 name-denied call dropped, finish rewritten
func fuzzSSE05(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-deny", "*", true)
	_, _ = g.Write([]byte("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"secret_tool\",\"arguments\":\"\"}}]}}]}\n\n"))
	_, _ = g.Write([]byte("data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n"))
	out := w.Body.String()
	if strings.Contains(out, "secret_tool") {
		t.Fatalf("SSE-05: denied fragment leaked: %q", out)
	}
	if !strings.Contains(out, `"finish_reason":"stop"`) {
		t.Fatalf("SSE-05: finish must rewrite to stop: %q", out)
	}
	if g.DeniedCount() != 1 {
		t.Fatalf("SSE-05: denied count %d", g.DeniedCount())
	}
}

// // SSE-06 allowed call held then released on terminal frame
func fuzzSSE06(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-args", "*", true)
	_, _ = g.Write([]byte(`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":"{\"q\":\"ok\"}"}}]}}]}` + "\n\n"))
	_, _ = g.Write([]byte(`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n"))
	out := w.Body.String()
	if !strings.Contains(out, "safe_tool") || !strings.Contains(out, `"finish_reason":"tool_calls"`) {
		t.Fatalf("SSE-06: allowed call must pass unmodified: %q", out)
	}
	if g.DeniedCount() != 0 {
		t.Fatalf("SSE-06: nothing denied, got %d", g.DeniedCount())
	}
}

// // SSE-07 args-denied call dropped whole at release
func fuzzSSE07(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-args", "*", true)
	_, _ = g.Write([]byte("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"safe_tool\",\"arguments\":\"forbidden\"}}]}}]}\n\n"))
	_, _ = g.Write([]byte("data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n"))
	out := w.Body.String()
	if strings.Contains(out, "safe_tool") {
		t.Fatalf("SSE-07: args-denied call leaked: %q", out)
	}
	if !strings.Contains(out, `"finish_reason":"stop"`) {
		t.Fatalf("SSE-07: finish must rewrite: %q", out)
	}
	if g.DeniedCount() != 1 {
		t.Fatalf("SSE-07: denied count %d", g.DeniedCount())
	}
}

// // SSE-08 canceled context fails open (D-15)
func fuzzSSE08(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(cctx, w, engine, "org-args", "*", true)
	frame := []byte("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"safe_tool\",\"arguments\":\"forbidden\"}}]}}]}\n\n")
	_, _ = g.Write(frame)
	if w.Body.String() != string(frame) {
		t.Fatalf("SSE-08: fail-open must pass frames untouched: %q", w.Body.String())
	}
}

// // SSE-09 frame split across writes is buffered then forwarded
func fuzzSSE09(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-deny", "*", false)
	_, _ = g.Write([]byte("data: {\"x\":"))
	if w.Body.Len() != 0 {
		t.Fatalf("SSE-09: partial write must buffer, got %q", w.Body.String())
	}
	_, _ = g.Write([]byte("1}\n\n"))
	if !strings.Contains(w.Body.String(), `"x":1`) {
		t.Fatalf("SSE-09: completed frame must forward: %q", w.Body.String())
	}
}

// // SSE-10 trailing partial bytes flushed on final
func fuzzSSE10(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-deny", "*", false)
	_, _ = g.Write([]byte("data: {\"a\":1}\n\ndata: {\"tr"))
	if w.Body.Len() == 0 {
		t.Fatal("SSE-10: complete frame must forward eagerly")
	}
	g.flushFrames(true)
	if !strings.Contains(w.Body.String(), "{\"tr") {
		t.Fatalf("SSE-10: trailing bytes must flush: %q", w.Body.String())
	}
	if len(g.buf) != 0 {
		t.Fatalf("SSE-10: buffer must empty after final flush: %q", g.buf)
	}
}

// // SSE-11 Flush with and without an http.Flusher
func fuzzSSE11(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	fw := &fuzzFlushRecorder{ResponseRecorder: httptest.NewRecorder()}
	g := newSSEToolGateWriter(ctx, fw, engine, "org-deny", "*", false)
	g.Flush()
	if fw.flushed != 1 {
		t.Fatalf("SSE-11: flusher arm not taken: %d", fw.flushed)
	}
	nf := &fuzzPlainWriter{hdr: http.Header{}}
	g2 := newSSEToolGateWriter(ctx, nf, engine, "org-deny", "*", false)
	g2.Flush()                     // must not panic when the underlying writer lacks Flush
	g2.Header().Set("X-Fuzz", "1") // delegate: ResponseWriter.Header
	g2.WriteHeader(200)            // delegate: ResponseWriter.WriteHeader
	if nf.hdr.Get("X-Fuzz") != "1" {
		t.Fatal("SSE-11: Header must delegate")
	}
}

// // SSE-12 pure helpers
func fuzzSSE12(t *testing.T) {
	t.Helper()

	if callIndex(map[string]any{}) != 0 {
		t.Fatal("SSE-12: missing index must default to 0")
	}
	if callIndex(map[string]any{"index": float64(3)}) != 3 {
		t.Fatal("SSE-12: float index must convert")
	}
	if !bytes.Equal(framePayload([]byte("data: {\"a\":1}\n")), []byte(`{"a":1}`)) {
		t.Fatalf("SSE-12: framePayload wrong: %q", framePayload([]byte("data: {\"a\":1}\n")))
	}
	if frameTerminal(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop"}}}) != true {
		t.Fatal("SSE-12: finish frame must be terminal")
	}
	if frameTerminal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{}}}}) != false {
		t.Fatal("SSE-12: delta frame must not be terminal")
	}
	var nilDoc map[string]any
	_ = json.Unmarshal([]byte(`{}`), &nilDoc)
	if frameTerminal(nilDoc) {
		t.Fatal("SSE-12: empty doc must not be terminal")
	}
}

// // SSE-13 single fragment+finish frame: hold and terminal release
func fuzzSSE13(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-args", "*", true)
	_, _ = g.Write([]byte(`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":"forbidden"}}]},"finish_reason":"tool_calls"}]}` + "\n\n"))
	if strings.Contains(w.Body.String(), "forbidden") {
		t.Fatalf("SSE-13: denied args must not leak: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"delta":{}`) {
		t.Fatalf("SSE-13: args-denied call must be deleted: %q", w.Body.String())
	}
	_, _ = g.Write([]byte("data: [DONE]\n\n")) // release with nothing held
	if !strings.Contains(w.Body.String(), "[DONE]") {
		t.Fatalf("SSE-13: DONE must pass: %q", w.Body.String())
	}
}

// // SSE-14 malformed choices entries survive the gate
func fuzzSSE14(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-deny", "*", true)
	_, _ = g.Write([]byte(`data: {"choices":[null]}` + "\n\n"))
	_, _ = g.Write([]byte(`data: {"choices":[{"finish_reason":"stop"}]}` + "\n\n"))
	_, _ = g.Write([]byte(`data: {"choices":[{"delta":{"tool_calls":[{"index":0}]}}]}` + "\n\n"))
	_, _ = g.Write([]byte("data: [DONE]\n\n"))
	if !strings.Contains(w.Body.String(), `[null]`) {
		t.Fatalf("SSE-14: null choice frame must pass: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"finish_reason":"stop"`) {
		t.Fatalf("SSE-14: bare finish must pass: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"index":0`) {
		t.Fatalf("SSE-14: functionless call must survive hold: %q", w.Body.String())
	}
}

// // SSE-15 one args-denied + one kept call in a held frame rewrites the call list
func fuzzSSE15(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-args", "*", true)
	_, _ = g.Write([]byte(`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":"forbidden"}},{"index":1,"function":{"name":"safe_tool","arguments":"ok"}}]}}]}` + "\n\n"))
	_, _ = g.Write([]byte(`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n"))
	body := w.Body.String()
	if strings.Contains(body, "forbidden") {
		t.Fatalf("SSE-15: args-denied call must drop at release: %q", body)
	}
	if !strings.Contains(body, `"ok"`) {
		t.Fatalf("SSE-15: kept call must survive rewrite: %q", body)
	}
}

// // SSE-16 same-index rename allowed→denied drops the whole held call
func fuzzSSE16(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(ctx, w, engine, "org-deny", "*", true)
	_, _ = g.Write([]byte(`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool"}}]}}]}` + "\n\n"))
	_, _ = g.Write([]byte(`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"secret_tool","arguments":"x"}}]}}]}` + "\n\n"))
	_, _ = g.Write([]byte(`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n"))
	body := w.Body.String()
	if strings.Contains(body, "secret_tool") {
		t.Fatalf("SSE-16: renamed denied call must drop: %q", body)
	}
	if strings.Contains(body, "safe_tool") {
		t.Fatalf("SSE-16: dropped call must vanish entirely: %q", body)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) {
		t.Fatalf("SSE-16: dead choice finish must rewrite: %q", body)
	}
}

// fuzzPlainWriter implements http.ResponseWriter without Flush.
type fuzzPlainWriter struct {
	hdr http.Header
	buf bytes.Buffer
}

func (w *fuzzPlainWriter) Header() http.Header         { return w.hdr }
func (w *fuzzPlainWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *fuzzPlainWriter) WriteHeader(int)             {}

// // SSE-17 filterFrame marshal guard: a doc that mutates (a call is
// // dropped) but cannot re-marshal — NaN cannot arrive through
// // json.Unmarshal, so production callers never pass such a doc — must pass
// // the ORIGINAL frame through unchanged: never fail the stream over a
// // filter bug. Pins the guard contract at the function's own entry.
func fuzzSSE17(t *testing.T) {
	t.Helper()

	frame := []byte("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0}]}}]}\n\n")
	doc := map[string]any{
		"choices": []any{map[string]any{
			"delta": map[string]any{
				"tool_calls": []any{map[string]any{"index": float64(0)}},
				"poison":     math.NaN(),
			},
		}},
	}
	g := &sseToolGateWriter{seenChoice: map[int]bool{}, keptChoice: map[int]bool{}}
	res := frameRes{ids: []int{0}, ambiguous: []bool{false}} // single unindexed choice
	out, changed := g.filterFrame(frame, doc, res, func(_, _ int) bool { return true })
	if changed || !bytes.Equal(out, frame) {
		t.Fatalf("SSE-17: guard must pass the original frame through: changed=%v out=%q", changed, out)
	}
}

// // SSE-18 release with a nil policy engine: an active deny-capable writer
// (activation is hasDeny, not engine presence) still holds declaring calls
// and must release them untouched — the engine-less arm of the drop loop.
func fuzzSSE18(t *testing.T) {
	t.Helper()

	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), w, nil, "org-deny", "*", true)
	frames := []string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool"}}]}}]}` + "\n\n",
		`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n",
	}
	for _, f := range frames {
		if _, err := g.Write([]byte(f)); err != nil {
			t.Fatalf("SSE-18: write: %v", err)
		}
	}
	body := w.Body.String()
	if !strings.Contains(body, "safe_tool") || !strings.Contains(body, `"finish_reason":"tool_calls"`) {
		t.Fatalf("SSE-18: engine-less release must pass frames through: %q", body)
	}
}

// // SSE-19 passthrough tail tracker: header/status delegation, byte-exact
// write passthrough, and the torn-tail predicate in both polarities
// (critical-go wave 2: stream.go ssePassthroughTail.Header, WriteHeader,
// torn).
func fuzzSSE19(t *testing.T) {
	t.Helper()

	rec := httptest.NewRecorder()
	tail := &ssePassthroughTail{w: rec}
	fuzzSSE19HeaderStatus(t, tail, rec)
	fuzzSSE19TornLifecycle(t, tail)
	if got := rec.Body.String(); got != "data: x\n\n" {
		t.Fatalf("SSE-19: passthrough must stay byte-identical, got %q", got)
	}
}

// fuzzSSE19HeaderStatus pins the ssePassthroughTail header/status
// delegation: Header returns the wrapped writer's header map and
// WriteHeader forwards the status code unchanged (stream.go
// ssePassthroughTail.Header, WriteHeader).
func fuzzSSE19HeaderStatus(t *testing.T, tail *ssePassthroughTail, rec *httptest.ResponseRecorder) {
	t.Helper()

	tail.Header().Set("X-Tail-Probe", "1")
	if got := rec.Header().Get("X-Tail-Probe"); got != "1" {
		t.Fatalf("SSE-19: Header must delegate to the wrapped writer, got %q", got)
	}
	tail.WriteHeader(http.StatusTeapot)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("SSE-19: WriteHeader must delegate, got %d", rec.Code)
	}
}

// fuzzSSE19TornLifecycle pins the ssePassthroughTail torn-tail predicate in
// both polarities around the byte-exact write passthrough: an empty tail is
// not torn, a written data line without its blank separator is, and the
// completed frame clears it again (stream.go ssePassthroughTail.torn, Write).
func fuzzSSE19TornLifecycle(t *testing.T, tail *ssePassthroughTail) {
	t.Helper()

	if tail.torn() {
		t.Fatal("SSE-19: nothing written must not be torn")
	}
	if n, err := tail.Write([]byte("data: x\n")); err != nil || n != 8 {
		t.Fatalf("SSE-19: data write: n=%d err=%v", n, err)
	}
	if !tail.torn() {
		t.Fatal("SSE-19: a written data line without its blank separator must be torn")
	}
	if n, err := tail.Write([]byte("\n")); err != nil || n != 1 {
		t.Fatalf("SSE-19: separator write: n=%d err=%v", n, err)
	}
	if tail.torn() {
		t.Fatal("SSE-19: a completed frame must not be torn")
	}
}

// // SSE-20 stream identity shim: the stream stage stamps the same resolved
// team and key identities the middleware would set on the JSON path
// (critical-go wave 2: stream.go streamIdentityRequest).
func fuzzSSE20(t *testing.T) {
	t.Helper()

	ctx := withPrincipal(context.Background(), principal{APIKeyID: "key-fz20"})
	req := streamIdentityRequest(&streamRun{teamID: "team-fz20", ctx: ctx})
	if got := req.Header.Get("X-Team-Id"); got != "team-fz20" {
		t.Fatalf("SSE-20: X-Team-Id = %q, want team-fz20", got)
	}
	if got := req.Header.Get("X-API-Key-Id"); got != "key-fz20" {
		t.Fatalf("SSE-20: X-API-Key-Id = %q, want key-fz20", got)
	}
}

// // SSE-21 code-less SSE error frame: type and message render, the [DONE]
// terminator follows, the flush reaches the client, and a failing writer
// must not panic (critical-go wave 2: stream.go writeSSEError).
func fuzzSSE21(t *testing.T) {
	t.Helper()

	rec := httptest.NewRecorder()
	writeSSEError(rec, "upstream_error", "boom")
	body := rec.Body.String()
	if !strings.Contains(body, `"type":"upstream_error"`) || !strings.Contains(body, "boom") {
		t.Fatalf("SSE-21: error frame missing type/message: %q", body)
	}
	if !strings.HasSuffix(body, "data: [DONE]\n\n") {
		t.Fatalf("SSE-21: frame must end with the [DONE] terminator: %q", body)
	}
	if !rec.Flushed {
		t.Fatal("SSE-21: the error frame must flush")
	}
	dead := &fuzzRecorder{ResponseRecorder: httptest.NewRecorder(), failWrite: true}
	writeSSEError(dead, "upstream_error", "client gone") // must not panic
}

// // SSE-22 held-frame passthrough and payload stripping: a held frame whose
// payload no longer parses passes byte-identically (never fail the stream
// over a filter bug), and a non-data frame strips to its trimmed line
// (critical-go wave 2: toolgate.go writeHeld, framePayload).
func fuzzSSE22(t *testing.T) {
	t.Helper()

	if got := string(framePayload([]byte("  : keepalive\t"))); got != ": keepalive" {
		t.Fatalf("SSE-22: non-data payload must trim to the raw line, got %q", got)
	}
	rec := httptest.NewRecorder()
	g := &sseToolGateWriter{w: rec}
	frame := []byte(": keepalive\n\n")
	g.writeHeld(heldFrame{frame: frame}, map[callKey]bool{}, map[int]bool{})
	if rec.Body.String() != string(frame) {
		t.Fatalf("SSE-22: unparseable held frame must pass byte-identically, got %q", rec.Body.String())
	}
}

// // SSE-23 streaming-policy state: markAborted records the terminal denial,
// aborted and payloadJSON expose it, and an empty state reports nothing
// (critical-go wave 2: stream_policy.go streamPolicyState).
func fuzzSSE23(t *testing.T) {
	t.Helper()

	st := &streamPolicyState{}
	if aborted, msg := st.aborted(); aborted || msg != "" {
		t.Fatalf("SSE-23: fresh state must not be aborted, got (%v,%q)", aborted, msg)
	}
	if got := st.payloadJSON(); got != "" {
		t.Fatalf("SSE-23: empty state must render an empty policy payload, got %q", got)
	}
	st.markAborted("blocked by stream policy")
	aborted, msg := st.aborted()
	if !aborted || msg != "blocked by stream policy" {
		t.Fatalf("SSE-23: markAborted must record the denial, got (%v,%q)", aborted, msg)
	}
}

// // SSE-24 policy-seam writer delegation: header/status passthrough, the
// [DONE] terminator predicate, and the abort accessors riding the shared
// state (critical-go wave 2: stream_policy.go sseStreamPolicyWriter).
func fuzzSSE24(t *testing.T) {
	t.Helper()

	rec := httptest.NewRecorder()
	pw := &sseStreamPolicyWriter{w: rec, state: &streamPolicyState{}}
	pw.Header().Set("X-Policy-Probe", "1")
	if got := rec.Header().Get("X-Policy-Probe"); got != "1" {
		t.Fatalf("SSE-24: Header must delegate to the wrapped writer, got %q", got)
	}
	pw.WriteHeader(http.StatusInsufficientStorage)
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("SSE-24: WriteHeader must delegate, got %d", rec.Code)
	}
	if !pw.isDone([]byte("data: [DONE]\n")) || pw.isDone([]byte("data: x\n")) {
		t.Fatal("SSE-24: isDone must accept only the trimmed [DONE] terminator")
	}
	if pw.policyAborted() || pw.abortMessage() != "" {
		t.Fatalf("SSE-24: fresh writer must not be aborted, got (%v,%q)",
			pw.policyAborted(), pw.abortMessage())
	}
	pw.state.markAborted("prefix deny")
	if !pw.policyAborted() || pw.abortMessage() != "prefix deny" {
		t.Fatalf("SSE-24: writer must surface the state denial, got (%v,%q)",
			pw.policyAborted(), pw.abortMessage())
	}
	if got := pw.payloadJSON(); got != "" {
		t.Fatalf("SSE-24: writer payload must render the empty state, got %q", got)
	}
}

// TestSSEGenDeniedCountContract pins the deny-accounting contract the
// generated-stream oracle relies on, deterministically and in both
// directions: an identity-ambiguous denied call (fractional index plus
// in-frame duplicate — the exact 71b1b831e6189cae corpus shape, driven
// byte-wise with mid-stream flushes) must keep its bytes suppressed WITHOUT
// a counted denial, while an unambiguous denied call must both stay
// suppressed and be counted.
// sseGenDrive renders the generated stream for p and drives the active
// gate with the fuzz chunking; the deterministic contract controls use it.
func sseGenDrive(t *testing.T, p []byte) (stream, out string, count int, sawDenied bool) {
	t.Helper()
	frames, sawDenied := sseGenFrames(p)
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), w, fuzzToolEngine(), "org-deny", "*", true)
	stream = strings.Join(frames, "")
	sseGenWriteChunks(t, g, stream, p)
	return stream, w.Body.String(), g.DeniedCount(), sawDenied
}

func TestSSEGenDeniedCountContract(t *testing.T) {
	// Ambiguous denied call (fractional + duplicated choice): bytes
	// suppressed, count zero. The guard rejects a vacuous control: the
	// generated stream must actually declare the denied name while sawDenied
	// stays unset.
	stream, out, count, sawDenied := sseGenDrive(t, []byte("000 000"))
	if !strings.Contains(stream, "secret_tool") {
		t.Fatal("contract control: ambiguous stream did not declare the denied name")
	}
	if sawDenied {
		t.Fatal("contract control: ambiguous denied call was declared countable")
	}
	if strings.Contains(out, "secret_tool") {
		t.Fatalf("ambiguous denied bytes leaked: %q", out)
	}
	if count != 0 {
		t.Fatalf("ambiguous denied call was counted: %d", count)
	}

	// Unambiguous denied call: bytes suppressed AND counted.
	_, out, count, sawDenied = sseGenDrive(t, []byte{0x00, 0x00, 0x00, 0x00})
	if !sawDenied {
		t.Fatal("contract control: unambiguous denied call was not declared countable")
	}
	if strings.Contains(out, "secret_tool") {
		t.Fatalf("denied bytes leaked: %q", out)
	}
	if count != 1 {
		t.Fatalf("denied call not counted exactly once: %d", count)
	}
}

// TestSSEGenJSONValidAndDeniedFilter pins the generator contract restored by
// the Sprintf format-string fix (corpus 1b76d105e1136cb4): percent payloads
// in fuzzed arguments stay DATA — every generated frame remains valid JSON
// with the denied name and exact argument payload intact — and the gate
// must still filter that denied call (bytes suppressed, exactly one counted
// denial) instead of falling through its unparseable-passthrough arm.
// sseGenJSONDoc mirrors the tool-call frame shape the generator emits.
type sseGenJSONDoc struct {
	Choices []struct {
		Delta struct {
			ToolCalls []map[string]any `json:"tool_calls"`
		} `json:"delta"`
	} `json:"choices"`
}

// sseGenFrameCase is one percent-payload table entry: args is the raw
// denied payload tail, wantArgs the exact arguments string the generator
// must carry through JSON, and nullChoice marks the entry that also
// activates the null-choice-member arm via 0x20 at c[3].
type sseGenFrameCase struct {
	args       string
	wantArgs   string
	nullChoice bool
}

// sseGenPercentPayload builds the denied, named, resolvable control input
// for one table case: the 0x80 lead byte, then args, zero-padded to
// exactly one 4-byte group so the round-trip maps frame-to-payload.
// Trailing zero bytes avoid the c[3] frame-shape arms; a nullChoice entry
// must end at c[3]=0x20 to activate the null-choice-member arm.
func sseGenPercentPayload(t *testing.T, tc sseGenFrameCase) []byte {
	payload := append([]byte{0x80}, []byte(tc.args)...) // denied, named, resolvable
	for len(payload) < 4 {                              // sseGenFrames emits whole 4-byte groups only
		payload = append(payload, 0x00)
	}
	if len(payload) != 4 {
		t.Fatalf("args %q: control payload exceeds one frame group", tc.args)
	}
	if tc.nullChoice && payload[3] != 0x20 {
		t.Fatalf("args %q: null-choice case must set 0x20 at c[3]", tc.args)
	}
	return payload
}

// assertSSEGenFramePayload decodes one generated SSE frame: it must be
// valid JSON whose tool call carries the denied name with exactly the
// table's wanted arguments (JSON round-trip control).
func assertSSEGenFramePayload(t *testing.T, fr, wantArgs string) {
	t.Helper()
	line := strings.TrimSuffix(strings.TrimPrefix(fr, "data: "), "\n\n")
	if !json.Valid([]byte(line)) {
		t.Fatalf("generated frame is not valid JSON: %q", fr)
	}
	var doc sseGenJSONDoc
	if err := json.Unmarshal([]byte(line), &doc); err != nil {
		t.Fatalf("frame does not decode: %v", err)
	}
	var call map[string]any
	for _, ch := range doc.Choices {
		if len(ch.Delta.ToolCalls) > 0 {
			call = ch.Delta.ToolCalls[0]
		}
	}
	if call == nil {
		t.Fatalf("frame carries no tool call: %q", fr)
	}
	fn, _ := call["function"].(map[string]any)
	if fn == nil || fn["name"] != "secret_tool" {
		t.Fatalf("denied name lost or mangled: %v", fn)
	}
	if fn["arguments"] != wantArgs {
		t.Fatalf("arguments mangled: %q != %q", fn["arguments"], wantArgs)
	}
}

// assertSSEGenDeniedFrames runs the JSON round-trip control across every
// generated frame of one table case.
func assertSSEGenDeniedFrames(t *testing.T, tc sseGenFrameCase, frames []string) {
	t.Helper()
	if len(frames) == 0 {
		t.Fatalf("args %q: no generated frames to validate", tc.args)
	}
	for _, fr := range frames {
		assertSSEGenFramePayload(t, fr, tc.wantArgs)
	}
}

// assertSSEGenDeniedCall drives the real gate over the built payload: the
// denied bytes must never leak and the denied call must count exactly once.
func assertSSEGenDeniedCall(t *testing.T, payload []byte) {
	t.Helper()
	_, out, count, _ := sseGenDrive(t, payload)
	if strings.Contains(out, "secret_tool") {
		t.Fatalf("denied bytes leaked: %q", out)
	}
	if count != 1 {
		t.Fatalf("denied call not counted exactly once: %d", count)
	}
}

// TestSSEGenJSONValidAndDeniedFilter drives one 4-byte percent payload per
// table case through the generator: every frame must round-trip as valid
// JSON with the denied name and arguments intact, denied bytes must never
// leak, and the denied call must count exactly once.
func TestSSEGenJSONValidAndDeniedFilter(t *testing.T) {
	for _, tc := range []sseGenFrameCase{
		{args: "% ", wantArgs: "% \x00"},
		{args: "%s", wantArgs: "%s\x00"},
		{args: "%!", wantArgs: "%!\x00"},
		{args: "%w", wantArgs: "%w\x00"},
		{args: "0%\x03", wantArgs: "0%\x03"},
		{args: "% \x20", wantArgs: "% \x20", nullChoice: true},
	} {
		t.Run(tc.args, func(t *testing.T) {
			payload := sseGenPercentPayload(t, tc)
			frames, sawDenied := sseGenFrames(payload)
			if !sawDenied {
				t.Fatalf("args %q: denied call was not declared countable", tc.args)
			}
			assertSSEGenDeniedFrames(t, tc, frames)
			assertSSEGenDeniedCall(t, payload)
		})
	}
}
