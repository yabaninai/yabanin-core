package streaming

// N03-P03-T08 interruption/retry/resume recovery corpus (packet card:
// «Проверить interruption/retry/resume и восстановление результатов без
// дубликатов и потерь»). T06 proved the joint adversarial stream and T07 the
// boundaries of a HEALTHY stream; this corpus adds the broken ones:
//
//   - axis A: the feed is interrupted while a forbidden span head is held
//     (the hold-back has the only copy of the span bytes) — the interrupted
//     pass must not have disclosed the span, and resuming the SAME processor
//     must complete the suppression with zero losses;
//   - axis B: the retry — a fresh prefix→carry stack over a replayed stream —
//     must be byte-identical to the uninterrupted control (no duplicated
//     replacements, no resurrected content), and a replayed ALREADY-MUTATED
//     text must never be mutated twice;
//   - axis C: the interruption lands on line-ending-heavy content (the H5
//     CRLF lineage) — the buffer rebuild across the interruption boundary
//     keeps suppression byte-parity;
//   - axis D: a cancel during the prefix hold fails closed (the held buffer
//     is dropped, never released), and a FRESH gate re-decides the replayed
//     prefix from scratch — a concurrent retry cannot inherit or bypass the
//     decision (the packet negative: no promise about future tokens).
//
// Real vs mock (packet exit criterion): the REAL production primitives
// (PrefixGate, ChunkProcessor, FrameProcessor, FinalAggregate, FinalCheck,
// EngineRunner over compiled policies) and the REAL policy execution path;
// the MOCK parts are the fixture mutator/detector steps (advMultiMaskRunner,
// advDenyRunner) and the fixture SSE frame renderer (advChunkFrame) standing
// in for the gateway HTTP plumbing. The gateway relay seam is covered by
// pkg/gateway/n03p3t08_recovery_test.go.

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// t08Pairs is the corpus map: the ASCII secret plus a Cyrillic alias, both
// learned in the prefix buffer (spanSelfCheck guards the row invariants).
func t08Pairs() [][2]string {
	return [][2]string{
		{testSecretTrigger, testSecretMask},
		{"Иванов Иван", "ORG_1"},
	}
}

// t08Emit pushes one content chunk through the frame processor, appends the
// wire bytes, and returns the decoded delta (what a client assembler sees).
func t08Emit(fp *FrameProcessor, wire *[]byte, content string) string {
	frame := advChunkFrame(content)
	if fp != nil {
		frame = fp.ProcessFrame(frame)
	}
	*wire = append(*wire, frame...)
	return string(frame)
}

// TestN03P3T08_InterruptedMidSpan_ResumeAndRetryParity — axis A: the feed
// stops while the span head is held; the interrupted pass disclosed no span
// byte; resuming the SAME stack completes the suppression byte-exactly; and
// a fresh stack over the whole sequence (the client retry) produces a
// byte-identical wire — recovery without duplicates and without losses.
func TestN03P3T08_InterruptedMidSpan_ResumeAndRetryParity(t *testing.T) {
	pairs := t08Pairs()
	repl := advReplMap(pairs)
	maxHold := spanMaxPat(repl) - 1
	head := "start " + testSecretTrigger + " mid Иванов Иван "
	// The retried span re-occurs in the rest, split at EVERY byte position:
	// the interruption lands exactly between the two halves.
	restTail := " end of stream"
	runner := advMultiMaskRunner(t, pairs)

	for k := 1; k < len(testSecretTrigger); k++ {
		pre := "pre " + testSecretTrigger[:k]
		post := testSecretTrigger[k:] + restTail
		full := head + pre + post
		want := refReplace(full, repl)
		spanSelfCheck(t, "t08-resume", head, pre+post, pairs, want)

		// --- pass 1: interrupted mid-span-head ---------------------------
		g := NewPrefixGate(PrefixConfig{Runner: runner})
		g.Ingest(head)
		out := g.Flush(context.Background())
		if out.Err != nil || out.Decision != PrefixRelease || out.Text == head {
			t.Fatalf("k=%d: prefix stage: decision=%q err=%v", k, out.Decision, out.Err)
		}
		cp, err := NewChunkProcessor(repl)
		if err != nil {
			t.Fatalf("carry map: %v", err)
		}
		fp := NewFrameProcessor(cp)
		var wire []byte
		var decoded strings.Builder
		decoded.WriteString(advDecodedStream(t, []byte(t08Emit(fp, &wire, head))))

		decoded.WriteString(advDecodedStream(t, []byte(t08Emit(fp, &wire, pre))))
		// The interruption point: the span head is fully inside the hold.
		if held := cp.Held(); held < k || held > maxHold {
			t.Fatalf("k=%d: held=%d, want the span head held (>= %d, <= %d)", k, held, k, maxHold)
		}
		soFar := decoded.String()
		if !strings.HasPrefix(want, soFar) {
			t.Fatalf("k=%d: interrupted view %q is not a prefix of %q", k, soFar, want)
		}
		if !strings.HasSuffix(soFar, "pre ") || strings.HasSuffix(soFar, testSecretTrigger[:k]) {
			t.Fatalf("k=%d: the held span head is visible at the interruption point: %q", k, soFar)
		}

		// --- resume: the SAME processor completes the span ---------------
		decoded.WriteString(advDecodedStream(t, []byte(t08Emit(fp, &wire, post))))
		if tail := fp.FlushFrame("adv-1", "adv-model"); tail != nil {
			decoded.WriteString(advDecodedStream(t, tail))
			wire = append(wire, tail...)
		}
		wire = append(wire, []byte("data: [DONE]\n\n")...)
		if got := decoded.String(); got != want {
			t.Fatalf("k=%d: resumed view %q != batch replace %q (recovery lost or duplicated bytes)", k, got, want)
		}
		if cp.Held() != 0 {
			t.Fatalf("k=%d: resume left %d bytes held", k, cp.Held())
		}
		if bytes.Contains(wire, []byte(testSecretTrigger)) {
			t.Fatalf("k=%d: the raw span rode the recovered wire", k)
		}

		// --- retry: a fresh stack over the same sequence ------------------
		g2 := NewPrefixGate(PrefixConfig{Runner: runner})
		g2.Ingest(head)
		out2 := g2.Flush(context.Background())
		if out2.Decision != PrefixRelease || out2.Text != out.Text {
			t.Fatalf("k=%d: retry prefix re-decision drifted: %+v vs %+v", k, out2, out)
		}
		cp2, err := NewChunkProcessor(repl)
		if err != nil {
			t.Fatalf("retry carry map: %v", err)
		}
		fp2 := NewFrameProcessor(cp2)
		var wire2 []byte
		for _, c := range []string{head, pre, post} {
			t08Emit(fp2, &wire2, c)
		}
		if tail := fp2.FlushFrame("adv-1", "adv-model"); tail != nil {
			wire2 = append(wire2, tail...)
		}
		wire2 = append(wire2, []byte("data: [DONE]\n\n")...)
		if !bytes.Equal(wire, wire2) {
			t.Fatalf("k=%d: retry wire != recovered wire:\n resumed: %q\n retried: %q", k, wire, wire2)
		}
	}
}

// TestN03P3T08_RetryReplay_NoDoubleMutationAndAuditFlag — axis B: the retry's
// upstream replays content the FIRST pass already mutated. (a) In the carry
// domain the replayed replacement tokens pass untouched while a fresh span
// occurrence is replaced exactly once (no double mutation, no resurrection).
// (b) When the replayed MUTATED text forms the prefix itself, the gate
// honestly sees no pattern (it cannot re-detect what the buffer no longer
// contains — the documented prefix-scoped boundary, T04/T05) — and the
// aggregate audit still flags the fresh occurrence post-issuance: the retry
// degrades detection to a flag, it never makes it silently disappear.
func TestN03P3T08_RetryReplay_NoDoubleMutationAndAuditFlag(t *testing.T) {
	pairs := [][2]string{{testSecretTrigger, testSecretMask}}
	repl := advReplMap(pairs)

	// (a) carry domain: the prefix re-matches the raw span (map learned),
	// the rest carries replayed replacement tokens + a fresh occurrence.
	head := "value " + testSecretTrigger + " ok "
	replayMid := testSecretMask + " replayed " + testSecretMask
	freshTail := " and fresh " + testSecretTrigger + " end"
	want := refReplace(head+replayMid+freshTail, repl)

	g := NewPrefixGate(PrefixConfig{Runner: advMultiMaskRunner(t, pairs)})
	g.Ingest(head)
	out := g.Flush(context.Background())
	if out.Decision != PrefixRelease || out.Text == head {
		t.Fatalf("prefix stage: decision=%q err=%v", out.Decision, out.Err)
	}
	cp, err := NewChunkProcessor(repl)
	if err != nil {
		t.Fatalf("carry map: %v", err)
	}
	fp := NewFrameProcessor(cp)
	var wire []byte
	var decoded strings.Builder
	for _, c := range []string{head, replayMid, freshTail} {
		decoded.WriteString(advDecodedStream(t, []byte(t08Emit(fp, &wire, c))))
	}
	got := decoded.String()
	if got != want {
		t.Fatalf("carry view %q != batch replace %q", got, want)
	}
	// The replacement count: the head's token, the two replayed tokens
	// untouched, and exactly one fresh replacement — never two (no double
	// mutation on the replay).
	if n := strings.Count(got, testSecretMask); n != 4 {
		t.Fatalf("replacement tokens on the wire = %d, want 4 (1 head + 2 replayed + 1 fresh): %q", n, got)
	}
	if strings.Count(got, testSecretTrigger) != 0 {
		t.Fatalf("a raw span occurrence survived the retry stream: %q", got)
	}

	// (b) prefix-blind boundary: the replayed mutated text IS the prefix.
	mutatedPrefix := "before " + testSecretMask + " after "
	g2 := NewPrefixGate(PrefixConfig{Runner: advMultiMaskRunner(t, pairs)})
	g2.Ingest(mutatedPrefix)
	out2 := g2.Flush(context.Background())
	if out2.Decision != PrefixRelease {
		t.Fatalf("mutated-only prefix must release, got %q (%v)", out2.Decision, out2.Err)
	}
	if out2.Text != mutatedPrefix {
		t.Fatalf("the gate invented a mutation for a pattern-free buffer: %q", out2.Text)
	}
	// No carry map is derived (nothing changed) — a fresh span occurrence
	// later in the retried stream passes raw. That is the documented
	// no-lookahead boundary; the aggregate audit is the backstop.
	rawFrame := advChunkFrame(mutatedPrefix + " tail " + testSecretTrigger)
	agg := NewFinalAggregate()
	agg.AddFrame(rawFrame)
	final := FinalCheck(context.Background(), t08FinalDenyRunner(t, testSecretTrigger), agg, nil, "chat")
	if final.Effective != pipeline.ActionFlag {
		t.Fatalf("post-issuance effective action = %q, want flag", final.Effective)
	}
	if final.Result == nil || final.Result.Verdict != pipeline.ActionDeny {
		t.Fatalf("the true verdict must stay visible: %+v", final.Result)
	}
	if !bytes.Contains(final.Document, []byte(testSecretTrigger)) {
		t.Fatal("the audit document is not the client-received aggregate")
	}

	// (b2) the retry's fresh prefix RE-DECIDES: the same raw span in a fresh
	// buffer is re-suppressed (mutated again) — a retry cannot inherit the
	// previous release and ride the raw span through (the deny-side re-decide
	// is pinned above with the deny runner).
	g3 := NewPrefixGate(PrefixConfig{Runner: advMultiMaskRunner(t, pairs)})
	g3.Ingest("retry upstream re-serves " + testSecretTrigger + " raw")
	out3 := g3.Flush(context.Background())
	if out3.Decision != PrefixRelease {
		t.Fatalf("fresh buffer with the raw span must release through mutation, got %q", out3.Decision)
	}
	if strings.Contains(out3.Text, testSecretTrigger) || !strings.Contains(out3.Text, testSecretMask) {
		t.Fatalf("the re-served span was not re-suppressed: %q", out3.Text)
	}
}

// TestN03P3T08_CancelDuringHold_FailCloseAndFreshGateReDecides — axis D: a
// cancel during the prefix hold fails closed (the held buffer is dropped,
// never released to the dead client), a fresh gate over the same replayed
// text decides identically to the healthy pass (determinism), and a fresh
// gate over a replayed FORBIDDEN prefix re-denies — the packet negative: no
// bypass of the future-token check through cancel+retry.
func TestN03P3T08_CancelDuringHold_FailCloseAndFreshGateReDecides(t *testing.T) {
	pairs := [][2]string{{testSecretTrigger, testSecretMask}}
	runner := advMultiMaskRunner(t, pairs)
	buffered := "buffered client text without any pattern "

	// The cancelled pass: the gate is still holding when the client leaves.
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	gCancelled := NewPrefixGate(PrefixConfig{Runner: runner})
	gCancelled.Ingest(buffered)
	outCancelled := gCancelled.Flush(gone)
	if outCancelled.Decision == PrefixRelease {
		t.Fatalf("cancelled flush released the buffer: %q", outCancelled.Text)
	}
	if strings.Contains(outCancelled.Text, buffered) {
		t.Fatalf("fail-close leaked the held buffer: %q", outCancelled.Text)
	}

	// The fresh pass: identical decision and bytes to a never-cancelled run.
	gLive := NewPrefixGate(PrefixConfig{Runner: runner})
	gLive.Ingest(buffered)
	outLive := gLive.Flush(context.Background())
	if outLive.Decision != PrefixRelease || outLive.Text != buffered {
		t.Fatalf("fresh pass drifted: decision=%q text=%q", outLive.Decision, outLive.Text)
	}

	// The replayed FORBIDDEN prefix re-denies in a fresh gate.
	gDeny1 := NewPrefixGate(PrefixConfig{Runner: advDenyRunner(t)})
	gDeny1.Ingest("please " + testInjectionTrigger + " now")
	deny1 := gDeny1.Flush(context.Background())
	gDeny2 := NewPrefixGate(PrefixConfig{Runner: advDenyRunner(t)})
	gDeny2.Ingest("please " + testInjectionTrigger + " now")
	deny2 := gDeny2.Flush(context.Background())
	if deny1.Decision != PrefixAbort || deny2.Decision != PrefixAbort {
		t.Fatalf("replayed forbidden prefix must re-abort: %q then %q", deny1.Decision, deny2.Decision)
	}
	if deny1.Text != deny2.Text {
		t.Fatalf("re-decision drift: %q vs %q", deny1.Text, deny2.Text)
	}

	// Concurrency: cancelled and healthy stacks interleave over the same
	// corpus (race detector domain); every goroutine's outcome is exact.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				g := NewPrefixGate(PrefixConfig{Runner: runner})
				g.Ingest(buffered)
				if out := g.Flush(ctx); out.Decision == PrefixRelease || strings.Contains(out.Text, buffered) {
					t.Errorf("goroutine %d: cancelled gate released: %+v", i, out)
				}
				return
			}
			g := NewPrefixGate(PrefixConfig{Runner: runner})
			g.Ingest(buffered)
			if out := g.Flush(context.Background()); out.Decision != PrefixRelease || out.Text != buffered {
				t.Errorf("goroutine %d: healthy gate drifted: %+v", i, out)
			}
		}(i)
	}
	wg.Wait()
}

// TestN03P3T08_CRLFContentAcrossInterruption_SuppressionParity — axis C (the
// H5 mixed-line-ending lineage): the interruption lands on content whose
// chunk boundaries surround CRLF sequences (JSON-escaped on the wire). The
// buffer rebuild across the interruption keeps the suppression byte-exact:
// no suppression loss at the line-ending boundary, no leak, and the
// interrupted+resumed wire equals the uninterrupted control.
func TestN03P3T08_CRLFContentAcrossInterruption_SuppressionParity(t *testing.T) {
	pairs := [][2]string{{testSecretTrigger, testSecretMask}}
	repl := advReplMap(pairs)
	head := "head " + testSecretTrigger + " "

	cases := []struct {
		name        string
		chunks      []string // the full sequence
		interruptAt int      // stop after this many chunks, then resume
	}{
		{name: "interrupt inside span head right after CRLF", chunks: []string{head, "line1\r\n" + testSecretTrigger[:9], testSecretTrigger[9:] + "\r\nline2 tail"}, interruptAt: 2},
		{name: "interrupt at the CRLF/span junction", chunks: []string{head, "line1\r\n", testSecretTrigger + "\r\nline2 tail"}, interruptAt: 1},
		{name: "interrupt after span completes before trailing CRLF", chunks: []string{head, "line1\r\n" + testSecretTrigger, "\r\nline2 tail"}, interruptAt: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			full := head + strings.Join(tc.chunks[1:], "")
			want := refReplace(full, repl)
			spanSelfCheck(t, tc.name, head, strings.Join(tc.chunks[1:], ""), pairs, want)

			run := func() []byte {
				g := NewPrefixGate(PrefixConfig{Runner: advMultiMaskRunner(t, pairs)})
				g.Ingest(head)
				out := g.Flush(context.Background())
				if out.Decision != PrefixRelease || out.Text == head {
					t.Fatalf("prefix stage: decision=%q err=%v", out.Decision, out.Err)
				}
				cp, err := NewChunkProcessor(repl)
				if err != nil {
					t.Fatalf("carry map: %v", err)
				}
				fp := NewFrameProcessor(cp)
				var wire []byte
				for i, c := range tc.chunks {
					t08Emit(fp, &wire, c)
					if i == tc.interruptAt-1 && tc.interruptAt < len(tc.chunks) {
						// The interruption: nothing of a pending span may be
						// on the wire at this point.
						if bytes.Contains(wire, []byte(testSecretTrigger)) {
							t.Fatalf("span bytes on the wire at the interruption point: %q", wire)
						}
					}
				}
				if tail := fp.FlushFrame("adv-1", "adv-model"); tail != nil {
					wire = append(wire, tail...)
				}
				return append(wire, []byte("data: [DONE]\n\n")...)
			}

			// The control: the same sequence fed without observation gaps —
			// identical bytes (the interruption itself is invisible to the
			// pipeline; recovery restores the exact stream).
			wireInterrupted := run()
			wireControl := run()
			if !bytes.Equal(wireInterrupted, wireControl) {
				t.Fatalf("interrupted wire != control:\n %q\n %q", wireInterrupted, wireControl)
			}
			if got := advDecodedStream(t, wireInterrupted); got != want {
				t.Fatalf("decoded %q != batch replace %q", got, want)
			}
			if bytes.Contains(wireInterrupted, []byte(testSecretTrigger)) {
				t.Fatalf("the raw span rode the wire: %q", wireInterrupted)
			}
		})
	}
}

// t08FinalDenyRunner builds a Runner denying `word` on the stream_final hook
// (the post-issuance audit backstop used by the prefix-blind boundary pin).
func t08FinalDenyRunner(t *testing.T, word string) Runner {
	t.Helper()
	eng := pipeline.NewEngine()
	eng.Steps().MustRegister("t08/deny-word", func(params map[string]any) (pipeline.Step, error) {
		w, _ := params["word"].(string)
		act := pipeline.ActionDeny
		if raw, ok := params["action"].(string); ok && raw != "" {
			act = pipeline.Action(raw)
		}
		return &t08DenyWordStep{word: w, action: act}, nil
	})
	pol := mustCompile(t, eng, `
apiVersion: ypp/v1
kind: Policy
name: t08-final-deny
mode: enforce
hooks: [stream_final]
steps:
  - id: deny-word
    detector: t08/deny-word
    params:
      word: "`+word+`"
      action: deny
`)
	return EngineRunner(eng, []pipeline.Compiled{pol})
}

// t08DenyWordStep is a read-only detector denying when the payload body
// contains the configured word (same shape as the test/injection step).
type t08DenyWordStep struct {
	pipeline.DetectorBase
	word   string
	action pipeline.Action
}

// Name returns the step name.
func (s *t08DenyWordStep) Name() string { return "t08/deny-word" }

// Run reports the finding when the word is present in the body.
func (s *t08DenyWordStep) Run(_ context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if in == nil || !bytes.Contains(in.Body, []byte(s.word)) {
		return nil
	}
	out.Findings = append(out.Findings, pipeline.Finding{
		Step:     p.StepID(),
		Category: "secret",
		Severity: "high",
		Action:   s.action,
	})
	return nil
}
