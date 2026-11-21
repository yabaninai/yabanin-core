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
	for id := 1; id <= 18; id++ {
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
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 0 && data[0] >= 1 && data[0] <= 18 {
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
		frame, denied := sseGenCallFrame(c, sseGenName(c[0]))
		frames = append(frames, frame)
		sawDenied = sawDenied || denied
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
// null-choice-member (c[3]&0x20) arms. The bool reports a declared denied
// name — only a named call frame can carry (and leak) one; nameless frames
// omit the name key, so no denial is declared either.
func sseGenCallFrame(c []byte, name string) (string, bool) {
	nameless := c[0]&0x04 != 0
	denied := name == "secret_tool" && !nameless
	argsBytes, _ := json.Marshal(string(c[1:])) // infallible for strings; valid JSON fragment
	if c[0]&0x08 != 0 {                         // non-string argument form: refused fail-closed
		argsBytes = []byte(`{"fuzz":true}`)
	}
	fn := fmt.Sprintf(`"arguments":%s`, string(argsBytes))
	if !nameless {
		fn = fmt.Sprintf(`"name":%q,`+fn, name)
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
	return fmt.Sprintf(`data: {"choices":[%s]}`+"\n\n", choices), denied
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
// chunk split (and must have counted the drop when one was declared), every
// released data line stays valid JSON except the generator's two genuinely
// non-JSON passthrough payloads, and the inactive writer is a strict
// byte-identical passthrough.
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
