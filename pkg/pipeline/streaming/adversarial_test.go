package streaming

// N03-P03-T02 adversarial corpus (packet facet 1: «Проверить PrefixGate и
// window buffering»). The acceptance is executable: a set of adversarial
// chunks must not reveal forbidden spans across the prefix→carry chain, and
// the negative is codified as a test: the prefix stage makes no promise about
// tokens it has not received yet — after a release the gate never re-checks,
// and a post-issuance final deny can only flag (delivered bytes cannot be
// recalled; the released-bytes boundary itself is card T04's scope).
//
// The chain mirrors the production wiring in pkg/gateway/stream_policy.go
// (finishPrefix/emitFrame): the held prefix frames are re-emitted through the
// FrameProcessor derived from the prefix mutation's replacement map, then the
// stream turns to passthrough through the same processor. The gateway-level
// glue (deriveReplacements, writer order, cache parity) keeps its own
// regressions in pkg/gateway/stream_policy_test.go; this corpus exercises the
// primitives those tests stand on.

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// advStream is the observed result of one adversarial chain run.
type advStream struct {
	wire    []byte // exact bytes the client would receive
	mutated bool   // the prefix policies changed the buffer
	aborted bool   // the prefix policies denied the buffer
}

// advMultiMaskStep is a mutator fixture replacing a fixed set of
// (original → replacement) pairs in the payload body. The pairs must not
// overlap (corpus guarantee): sequential replacement equals the batch
// leftmost-longest replace only then, which is what refReplace models.
type advMultiMaskStep struct {
	pipeline.MutatorBase
	pairs [][2]string // longest original first
}

// Name returns the fixture step name.
func (advMultiMaskStep) Name() string { return "test/mask-many" }

// Run rewrites the payload body, replacing every pair's original.
func (s advMultiMaskStep) Run(_ context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if in == nil || len(in.Body) == 0 {
		return nil
	}
	body := in.Body
	for _, pair := range s.pairs {
		body = bytes.ReplaceAll(body, []byte(pair[0]), []byte(pair[1]))
	}
	if !bytes.Equal(body, in.Body) {
		in.Body = body
		out.Findings = append(out.Findings, pipeline.Finding{
			Step: p.StepID(), Category: "secret", Severity: "high", Action: pipeline.ActionMask,
		})
	}
	return nil
}

// advMultiMaskRunner builds a Runner whose mask policy replaces exactly the
// given pairs over the stream_prefix hook — the production shape of a
// multi-pattern pseudonymize prefix mutation (the chunk carry map is the
// diff of that mutation).
func advMultiMaskRunner(t *testing.T, pairs [][2]string) Runner {
	t.Helper()
	sorted := make([][2]string, len(pairs))
	copy(sorted, pairs)
	slices.SortStableFunc(sorted, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
	eng := pipeline.NewEngine()
	step := advMultiMaskStep{pairs: sorted}
	eng.Steps().MustRegister("test/mask-many", func(map[string]any) (pipeline.Step, error) {
		return step, nil
	})
	pol := mustCompile(t, eng, `
apiVersion: ypp/v1
kind: Policy
name: adv-mask-many
mode: enforce
hooks: [stream_prefix]
steps:
  - id: mask
    mutator: test/mask-many
`)
	return EngineRunner(eng, []pipeline.Compiled{pol})
}

// advDenyRunner builds a Runner over the package deny policy (the detector
// denies when testInjectionTrigger appears in the buffered prefix).
func advDenyRunner(t *testing.T) Runner {
	t.Helper()
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, prefixDenyPolicy)
	return EngineRunner(eng, []pipeline.Compiled{pol})
}

// advChunkFrame renders one OpenAI-compatible SSE content-delta frame.
func advChunkFrame(content string) []byte {
	chunk := map[string]any{
		"id":      "adv-1",
		"object":  "chat.completion.chunk",
		"created": 1700000000,
		"model":   "adv-model",
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{"content": content},
			"finish_reason": nil,
		}},
	}
	line, err := json.Marshal(chunk)
	if err != nil {
		panic(err) // fixture rendering of a plain map cannot fail
	}
	return []byte("data: " + string(line) + "\n\n")
}

// advReplMap renders the replacement pairs as the map shape the production
// deriveReplacements hands to NewChunkProcessor.
func advReplMap(pairs [][2]string) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		m[p[0]] = p[1]
	}
	return m
}

// advRunStream replays the production prefix→carry chain over one stream:
// prefixChunks fill the gate (buffered, policy-checked once), then the held
// frames are re-emitted through the FrameProcessor derived from the prefix
// mutation (finishPrefix parity) and the rest of the stream passes through
// the same processor, terminated by the synthetic tail frame and [DONE].
// The pairs drive both the prefix mutator and the carry map — the corpus
// keeps them non-overlapping, so the buffer diff yields exactly these pairs.
func advRunStream(t *testing.T, pairs [][2]string, prefixChunks, restChunks []string) advStream {
	t.Helper()
	g := NewPrefixGate(PrefixConfig{Runner: advMultiMaskRunner(t, pairs)})
	var prefix strings.Builder
	for _, c := range prefixChunks {
		g.Ingest(c)
		prefix.WriteString(c)
	}
	out := g.Flush(context.Background())
	st := advStream{}
	if out.Decision == PrefixAbort {
		st.aborted = true
		return st
	}
	if out.Decision != PrefixRelease {
		t.Fatalf("prefix decision = %q, want release", out.Decision)
	}
	st.mutated = out.Text != prefix.String()

	var fp *FrameProcessor
	if st.mutated {
		cp, err := NewChunkProcessor(advReplMap(pairs))
		if err != nil {
			t.Fatalf("carry map: %v", err)
		}
		fp = NewFrameProcessor(cp)
	}
	emit := func(content string) {
		frame := advChunkFrame(content)
		if fp != nil {
			frame = fp.ProcessFrame(frame)
		}
		st.wire = append(st.wire, frame...)
	}
	for _, c := range prefixChunks { // the held frames, released through fp
		emit(c)
	}
	for _, c := range restChunks { // passthrough
		emit(c)
	}
	if fp != nil {
		if tail := fp.FlushFrame("adv-1", "adv-model"); tail != nil {
			st.wire = append(st.wire, tail...)
		}
	}
	st.wire = append(st.wire, []byte("data: [DONE]\n\n")...)
	return st
}

// advDecodedStream concatenates the delta.content of every data frame on the
// wire — exactly what a client's content assembly sees.
func advDecodedStream(t *testing.T, wire []byte) string {
	t.Helper()
	var sb strings.Builder
	rest := wire
	for len(rest) > 0 {
		idx := bytes.Index(rest, []byte("\n\n"))
		if idx < 0 {
			t.Fatal("unterminated SSE frame on the wire")
		}
		frame := rest[:idx+2]
		rest = rest[idx+2:]
		payload := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(frame), []byte("data: ")))
		if bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		var top struct {
			Choices []struct {
				Delta struct {
					Content json.RawMessage `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(payload, &top); err != nil {
			t.Fatalf("client frame is not valid JSON: %v (%q)", err, payload)
		}
		if len(top.Choices) == 0 || len(top.Choices[0].Delta.Content) == 0 {
			continue
		}
		var s string
		if err := json.Unmarshal(top.Choices[0].Delta.Content, &s); err != nil {
			t.Fatalf("content delta is not a string: %v", err)
		}
		sb.WriteString(s)
	}
	return sb.String()
}

// TestAdversarial_CarryCorpusSplitsForbiddenSpans: for every chunk boundary
// of the post-prefix stream, the forbidden originals never reach the client
// and the decoded content equals the batch leftmost-longest replace of the
// whole text (the carry contract of ChunkProcessor, end-to-end through the
// gate mutation and SSE re-encoding).
//
// Splits iterate rune boundaries: an SSE frame's content is a JSON string,
// so a valid provider stream cannot cut inside a UTF-8 rune at a frame
// boundary (encoding/json would fail or mangle it). Byte-level split
// coverage of the decoded carry itself lives in chunkcarry_test.go.
func TestAdversarial_CarryCorpusSplitsForbiddenSpans(t *testing.T) {
	// Per-row pairs: the carry map must mirror exactly what the prefix
	// mutation changed, so each row's head contains every pair's original
	// in full (production deriveReplacements works off the buffer diff).
	secret := [2]string{testSecretTrigger, testSecretMask}
	rows := []struct {
		name  string
		pairs [][2]string
		head  string // buffered prefix, contains every pair original in full
		rest  string // released through passthrough/carry
		extra []string
	}{
		{
			name:  "secret at boundary",
			pairs: [][2]string{secret},
			head:  "value is " + testSecretTrigger,
			rest:  " and done",
			extra: []string{"filler " + testSecretTrigger + " again"},
		},
		{
			name:  "secret twice",
			pairs: [][2]string{secret},
			head:  testSecretTrigger,
			rest:  " then " + testSecretTrigger + " end",
		},
		{
			name:  "adjacent matches",
			pairs: [][2]string{secret, {"abc", "X"}},
			head:  "start " + testSecretTrigger + " abc",
			rest:  "abcabcabc",
		},
		{
			name:  "cyrillic alias at boundary",
			pairs: [][2]string{{"Иванов Иван", "ORG_1"}, secret},
			head:  "Дорогой Иванов Иван, код " + testSecretTrigger,
			rest:  ", привет! А это Иванов Иван снова",
		},
		{
			name:  "utf8 around the split",
			pairs: [][2]string{secret},
			head:  "итог: " + testSecretTrigger,
			rest:  "ЙЙЙ и ещё " + testSecretTrigger,
		},
		{
			name:  "whole stream is the prefix",
			pairs: [][2]string{secret},
			head:  testSecretTrigger,
			rest:  "",
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			full := row.head + row.rest
			for _, ex := range row.extra {
				full += ex
			}
			repl := advReplMap(row.pairs)
			want := refReplace(full, repl)

			// The rest is fed split at EVERY rune offset (adversarial
			// chunker), each split a fresh stream.
			runes := []rune(row.rest)
			for i := 0; i <= len(runes); i++ {
				chunks := []string{string(runes[:i]), string(runes[i:])}
				chunks = append(chunks, row.extra...)
				st := advRunStream(t, row.pairs, []string{row.head}, chunks)
				if st.aborted {
					t.Fatalf("split %d: unexpected prefix abort", i)
				}
				if !st.mutated {
					t.Fatalf("split %d: prefix mutation missing (carry map would not be derived)", i)
				}
				got := advDecodedStream(t, st.wire)
				if got != want {
					t.Fatalf("split %d: decoded stream = %q, want %q", i, got, want)
				}
				for pat := range repl {
					if strings.Contains(got, pat) {
						t.Fatalf("split %d: forbidden span %q leaked to the client", i, pat)
					}
					if bytes.Contains(st.wire, []byte(pat)) {
						t.Fatalf("split %d: forbidden span %q present in raw wire bytes", i, pat)
					}
				}
				if !bytes.HasSuffix(st.wire, []byte("data: [DONE]\n\n")) {
					t.Fatalf("split %d: wire does not terminate with [DONE]", i)
				}
			}
		})
	}
}

// TestAdversarial_SecretAcrossJSONEscapeBoundary: a forbidden span split
// across two SSE frames where the earlier frame's content carries a JSON
// escape right before the held-back match head. The masking operates on the
// DECODED text while the wire must stay a valid escaped JSON string — the
// re-encoded frames must carry both the escape and the substitution.
func TestAdversarial_SecretAcrossJSONEscapeBoundary(t *testing.T) {
	pairs := [][2]string{{testSecretTrigger, testSecretMask}}
	prefix := []string{"start " + testSecretTrigger + " mid "} // mutation → carry map exists
	// Wire-level the first rest chunk carries the escape `\"` right before
	// the incomplete match head `super-secret-val` (2 bytes held back).
	rest := []string{`q\" ` + testSecretTrigger[:len(testSecretTrigger)-2], testSecretTrigger[len(testSecretTrigger)-2:] + ` tail`}

	st := advRunStream(t, pairs, prefix, rest)
	if st.aborted || !st.mutated {
		t.Fatalf("chain state: aborted=%v mutated=%v", st.aborted, st.mutated)
	}
	got := advDecodedStream(t, st.wire)
	want := refReplace("start "+testSecretTrigger+" mid "+`q\" `+testSecretTrigger+" tail", advReplMap(pairs))
	if got != want {
		t.Fatalf("decoded stream = %q, want %q", got, want)
	}
	if strings.Contains(got, testSecretTrigger) {
		t.Fatal("forbidden span leaked across the escape boundary")
	}
	// The escape survives re-encoding: the wire must carry the JSON string
	// form `q\\\" ` (backslash doubled, quote escaped) of the decoded `q\" `.
	if !bytes.Contains(st.wire, []byte(`q\\\" `)) {
		t.Fatalf("JSON escape lost in re-encoding: %q", st.wire)
	}
	if bytes.Contains(st.wire, []byte(testSecretTrigger)) {
		t.Fatal("forbidden span present in raw wire bytes")
	}
}

// TestAdversarial_PrefixDeny_SplitTriggerNeverReveals: the injection trigger
// split at EVERY byte offset still aborts, and neither the buffered halves
// nor the canonical AbortFrame ever carry a fragment of the forbidden span.
func TestAdversarial_PrefixDeny_SplitTriggerNeverReveals(t *testing.T) {
	for i := 0; i <= len(testInjectionTrigger); i++ {
		head, tail := testInjectionTrigger[:i], testInjectionTrigger[i:]
		g := NewPrefixGate(PrefixConfig{Runner: advDenyRunner(t)})
		g.Ingest("please, ")
		g.Ingest(head)
		g.Ingest(tail)
		g.Ingest(" — thanks")
		out := g.Flush(context.Background())
		if out.Decision != PrefixAbort {
			t.Fatalf("split %d: decision = %q, want abort", i, out.Decision)
		}
		if out.Text != "" {
			t.Fatalf("split %d: aborted buffer leaked %q", i, out.Text)
		}
		frame := AbortFrame("request blocked by organization policy")
		// The abort frame quotes no buffered content. Short windows cannot
		// be asserted collision-free against the fixed message's own letters
		// (e.g. "i" of "organization"), so the check uses 8-byte windows —
		// textually distinctive for this corpus; the exact full-trigger
		// behavior is already covered in prefixgate_test.go.
		const fragMin = 8
		for name, frag := range map[string]string{"head": head, "tail": tail} {
			if len(frag) >= fragMin && bytes.Contains(frame, []byte(frag)) {
				t.Fatalf("split %d: abort frame carries the %s fragment %q", i, name, frag)
			}
		}
		if !bytes.HasSuffix(frame, []byte("data: [DONE]\n\n")) {
			t.Fatalf("split %d: abort frame misses the [DONE] terminator", i)
		}
	}
}

// TestAdversarial_PostRelease_NoFutureTokenPromise codifies the card's
// negative: the prefix stage cannot promise checking future tokens before
// they arrive. Once the gate has released, late deltas are neither retained
// nor re-inspected (the decision stays fixed), and the only backstop for a
// forbidden span issued afterwards is the final flag — the delivered bytes
// are not rewritten and the effective action is flag, not deny.
func TestAdversarial_PostRelease_NoFutureTokenPromise(t *testing.T) {
	// Phase 1 — the gate releases a clean prefix and never looks again.
	g := NewPrefixGate(PrefixConfig{Runner: advDenyRunner(t)})
	g.Ingest("clean prefix: ")
	first := g.Flush(context.Background())
	if first.Decision != PrefixRelease {
		t.Fatalf("clean prefix = %+v, want release", first)
	}
	g.Ingest(testInjectionTrigger) // a forbidden span arriving after release
	if !g.Flushed() {
		t.Fatal("late ingest resurrected the gate")
	}
	if buf, _ := g.Buffered(); buf != "" {
		t.Fatalf("late delta was retained after release: %q", buf)
	}
	second := g.Flush(context.Background())
	if second.Decision != PrefixRelease || second.Text != first.Text {
		t.Fatalf("late delta changed the fixed decision: %+v vs %+v", second, first)
	}
	if strings.Contains(second.Text, testInjectionTrigger) {
		t.Fatal("the cached outcome absorbed post-release content")
	}

	// Phase 2 — the final backstop can only flag what already shipped.
	agg := NewFinalAggregate()
	agg.AddFrame(advChunkFrame("clean prefix: " + testInjectionTrigger))
	out := FinalCheck(context.Background(), advDenyRunnerFinal(t), agg, nil, "chat")
	if out.Effective != pipeline.ActionFlag {
		t.Fatalf("effective action = %q, want flag (delivered bytes cannot be recalled)", out.Effective)
	}
	if out.Result == nil || out.Result.Verdict != pipeline.ActionDeny {
		t.Fatalf("true verdict must stay visible in the result: %+v", out.Result)
	}
	if !bytes.Contains(out.Document, []byte(testInjectionTrigger)) {
		t.Fatal("the audited document is not the client-received aggregate")
	}
}

// advDenyRunnerFinal builds a Runner running the deny policy on the
// stream_final hook (the final aggregate payload carries the text as Body).
func advDenyRunnerFinal(t *testing.T) Runner {
	t.Helper()
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, finalDenyPolicy)
	return EngineRunner(eng, []pipeline.Compiled{pol})
}
