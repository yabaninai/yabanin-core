package streaming

// Consumer-compatibility corpus for the safe streaming mutation: what the
// move from the no-policy passthrough configuration to the mutation seam
// (prefix gate → derived carry map → FrameProcessor → final audit) means
// for every supported consumer of a provider stream.
//
// The contracts pinned here, per consumer:
//
//   - the no-policy configuration is byte-identical passthrough — and, pinned
//     honestly, the raw forbidden span IS on its wire and in its decoded
//     view. The seam exists because the old configuration does not protect;
//   - the client SSE decoder: the decoded delta.content view of the new
//     configuration equals the batch leftmost-longest replace of the old
//     view — enabling the seam changes EXACTLY the defined replacements on
//     the client view, nothing else;
//   - the final aggregate audit: policies audit what the client received.
//     Fed the same mutated frames, the audit document equals the client view
//     and carries no forbidden span, and a span detector stays silent (allow);
//     fed the raw old-configuration wire, the same detector denies — degraded
//     to flag after issuance (the audit never silently blesses an unmutated
//     stream, and never recalls delivered bytes);
//   - the SSE framing: the mutation domain is the delta content only. Framing
//     bytes never enter the carry, so even a replacement map whose patterns
//     ARE scaffolding text replaces in-content occurrences while the framing
//     stays intact and exactly one standalone [DONE] event terminates the
//     stream.
//
// The negative (no promise about future tokens) is pinned at the consumer
// boundary: a stream that ends mid-span releases the incomplete head
// verbatim, the audit document carries exactly that verbatim head, and a
// contiguous-span detector does NOT fire on it — the pipeline never claims
// the head will be re-checked, masked, or completed later.
//
// Existing coverage cited instead of duplicated: exhaustive split space and
// hold-bound proofs (chunkspans corpus), the joint adversarial stream
// (n03p3t06 helpers reused here), the release-boundary corpus (n03p3t07),
// interruption/retry/resume (n03p1t08, n03p3t08), frame structural
// boundaries (frame_test), and the constructor/parameter refusal surfaces
// (chunkcarry_test, cachewrite_test, prefixgate_test).
//
// Stable IDs: n03p3t09-*.

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// n03p3t09Frame is one emitted SSE event with the delta text it carried.
type n03p3t09Frame struct {
	raw     []byte
	decoded string
}

// n03p3t09NewRun drives the NEW configuration (prefix mutation → derived
// carry map → FrameProcessor → flush → [DONE]) over head+rest and returns
// every emitted frame with its decoded text. Per step it asserts the running
// invariants shared with the joint corpus: the decoded view stays a prefix
// of the expected batch replace (never withhold-then-flood) and the carry
// hold-back never exceeds maxLen-1.
func n03p3t09NewRun(t *testing.T, runner Runner, repl map[string]string, head string, rest []string, want string) ([]n03p3t09Frame, string) {
	t.Helper()
	g := NewPrefixGate(PrefixConfig{Runner: runner})
	g.Ingest(head)
	out := g.Flush(context.Background())
	if out.Err != nil {
		t.Fatalf("prefix stage: %v", out.Err)
	}
	if out.Decision != PrefixRelease {
		t.Fatalf("prefix decision = %q, want release", out.Decision)
	}
	if out.Text == head {
		t.Fatal("prefix mutation missing — the carry map would not be derived")
	}
	cp, err := NewChunkProcessor(repl)
	if err != nil {
		t.Fatalf("carry map: %v", err)
	}
	fp := NewFrameProcessor(cp)
	maxHold := spanMaxPat(repl) - 1
	var decoded strings.Builder
	var frames []n03p3t09Frame
	emit := func(content string) {
		raw := fp.ProcessFrame(advChunkFrame(content))
		text, err := n03p3t06Decode(raw)
		if err != nil {
			t.Fatalf("chunk %q: %v", content, err)
		}
		decoded.WriteString(text)
		if !strings.HasPrefix(want, decoded.String()) {
			t.Fatalf("decoded %q is not a prefix of the expected %q (withhold-then-flood)", decoded.String(), want)
		}
		if cp.Held() > maxHold {
			t.Fatalf("after chunk %q: Held()=%d exceeds maxLen-1=%d", content, cp.Held(), maxHold)
		}
		frames = append(frames, n03p3t09Frame{raw: raw, decoded: text})
	}
	emit(head)
	for _, c := range rest {
		emit(c)
	}
	if tail := fp.FlushFrame("n03p3t09", "n03p3t09-model"); tail != nil {
		text, err := n03p3t06Decode(tail)
		if err != nil {
			t.Fatalf("flush tail: %v", err)
		}
		decoded.WriteString(text)
		if !strings.HasPrefix(want, decoded.String()) {
			t.Fatalf("flushed tail broke the prefix invariant: %q vs %q", decoded.String(), want)
		}
		if cp.Held() != 0 {
			t.Fatalf("flush left %d bytes held", cp.Held())
		}
		frames = append(frames, n03p3t09Frame{raw: tail, decoded: text})
	}
	frames = append(frames, n03p3t09Frame{raw: []byte("data: [DONE]\n\n")})
	return frames, decoded.String()
}

// n03p3t09OldRun replays the same stream through the OLD configuration: no
// policies attached, the FrameProcessor is nil and every frame passes
// through byte-identical (the documented kill-switch path).
func n03p3t09OldRun(t *testing.T, head string, rest []string) ([]n03p3t09Frame, string) {
	t.Helper()
	var decoded strings.Builder
	var frames []n03p3t09Frame
	emit := func(content string) {
		raw := advChunkFrame(content) // fp == nil: byte-identical passthrough
		text, err := n03p3t06Decode(raw)
		if err != nil {
			t.Fatalf("old configuration frame is not decodable: %v", err)
		}
		decoded.WriteString(text)
		frames = append(frames, n03p3t09Frame{raw: raw, decoded: text})
	}
	emit(head)
	for _, c := range rest {
		emit(c)
	}
	frames = append(frames, n03p3t09Frame{raw: []byte("data: [DONE]\n\n")})
	return frames, decoded.String()
}

// n03p3t09Wire concatenates the raw bytes of the emitted frames.
func n03p3t09Wire(frames []n03p3t09Frame) []byte {
	var wire []byte
	for _, f := range frames {
		wire = append(wire, f.raw...)
	}
	return wire
}

// n03p3t09Audit feeds every frame the client received into the final
// aggregate (the middleware contract: the same mutated frames the wire
// carried) and returns the aggregate, the audit document's primary-choice
// content and the document itself.
func n03p3t09Audit(t *testing.T, frames []n03p3t09Frame) (*FinalAggregate, string, []byte) {
	t.Helper()
	agg := NewFinalAggregate()
	for _, f := range frames {
		agg.AddFrame(f.raw)
	}
	doc := agg.Document()
	if doc == nil {
		t.Fatal("audit document is nil")
	}
	var got struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(doc, &got); err != nil {
		t.Fatalf("audit document is not valid JSON: %v (%s)", err, doc)
	}
	if len(got.Choices) != 1 {
		t.Fatalf("audit document choices = %+v", got.Choices)
	}
	return agg, got.Choices[0].Message.Content, doc
}

// n03p3t09AssertSingleTerminator pins the client-consumer framing contract:
// exactly one standalone [DONE] event, at the end of the wire.
func n03p3t09AssertSingleTerminator(t *testing.T, wire []byte) {
	t.Helper()
	const done = "data: [DONE]\n\n"
	if n := bytes.Count(wire, []byte(done)); n != 1 {
		t.Fatalf("wire carries %d standalone %q events, want exactly 1", n, done)
	}
	if !bytes.HasSuffix(wire, []byte(done)) {
		t.Fatal("wire does not terminate with the [DONE] event")
	}
}

// TestN03P3T09_Redact_OldVsNewConfig_AdversarialSplits pins the upgrade
// contract over an adversarial chunk corpus. For every row the SAME chunks
// run through both configurations:
//
//   - the old configuration is identity — and the raw forbidden span IS
//     present on its wire and in its decoded view (the honest reason the
//     seam exists);
//   - the new configuration delivers the batch replace with zero reveal,
//     bounded hold-back, and exactly one standalone terminator;
//   - the upgrade changes EXACTLY the defined replacements: new decoded view
//     == batch replace of the old decoded view.
func TestN03P3T09_Redact_OldVsNewConfig_AdversarialSplits(t *testing.T) {
	pairs := [][2]string{{testSecretTrigger, testSecretMask}, {"Иванов Иван", "ORG_1"}}
	repl := advReplMap(pairs)
	runner := advMultiMaskRunner(t, pairs)

	rows := []struct {
		name string
		head string
		rest []string
	}{
		{"control-no-split", "код: " + testSecretTrigger + " и Иванов Иван.", []string{" ров без секретов."}},
		{"half-split-secret-and-alias", "код: " + testSecretTrigger + " и Иванов Иван.", []string{
			" Ответ: super-secret-", "value и Иванов Ив", "ан уехал.",
		}},
		{"byte-trickle", "код: " + testSecretTrigger + " / Иванов Иван", []string{
			" ", "s", "u", "p", "e", "r", "-", "s", "e", "c", "r", "e", "t", "-", "v", "a", "l", "u", "e", " конец",
		}},
		{"interleaved-two-secrets", "антон: " + testSecretTrigger + " + Иванов Иван", []string{
			" Раз: super-secret-valu", "е. Два: Иванов Ив", "ан. Снова: super-", "secret-value. Конец",
		}},
		{"span-completes-in-final-chunk", "код: " + testSecretTrigger + " и Иванов Иван", []string{
			" Пауза. ", " Пауза. ", " финал: super-secret-valu", "e.",
		}},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			rest := strings.Join(row.rest, "")
			full := row.head + rest
			want := refReplace(full, repl)
			spanSelfCheck(t, row.name, row.head, rest, pairs, want)

			oldFrames, oldDecoded := n03p3t09OldRun(t, row.head, row.rest)
			if oldDecoded != full {
				t.Fatalf("old configuration is not identity: %q, want %q", oldDecoded, full)
			}
			oldWire := n03p3t09Wire(oldFrames)
			if !bytes.Contains(oldWire, []byte(testSecretTrigger)) || !strings.Contains(oldDecoded, testSecretTrigger) {
				t.Fatal("corpus broken: the raw span must be present in the unprotected stream")
			}

			newFrames, newDecoded := n03p3t09NewRun(t, runner, repl, row.head, row.rest, want)
			if newDecoded != want {
				t.Fatalf("new decoded = %q, want %q", newDecoded, want)
			}
			newWire := n03p3t09Wire(newFrames)
			for pat := range repl {
				if strings.Contains(newDecoded, pat) || bytes.Contains(newWire, []byte(pat)) {
					t.Fatalf("forbidden span %q survived the new configuration", pat)
				}
			}
			n03p3t09AssertSingleTerminator(t, newWire)

			if newDecoded != refReplace(oldDecoded, repl) {
				t.Fatalf("upgrade drift: new view %q, want batch replace of the old view %q",
					newDecoded, refReplace(oldDecoded, repl))
			}
		})
	}
}

// TestN03P3T09_Redact_AuditConsumerParity_SpanSplitWire pins the audit
// consumer contract over an adversarially split wire: the final aggregate is
// fed the same frames the client received, so the audit document equals the
// client view. The mutated stream audits clean (the mutation removed the
// span); the raw old-configuration stream is honestly reported — the
// detector denies and the verdict degrades to flag after issuance. The
// negative closes the file at the consumer boundary: an incomplete span head
// released verbatim at end-of-stream is NOT claimed as "will be checked
// later" — the contiguous-span detector does not fire on it.
func TestN03P3T09_Redact_AuditConsumerParity_SpanSplitWire(t *testing.T) {
	pairs := [][2]string{{testSecretTrigger, testSecretMask}, {"Иванов Иван", "ORG_1"}}
	repl := advReplMap(pairs)
	runner := advMultiMaskRunner(t, pairs)
	denySecret := t08FinalDenyRunner(t, testSecretTrigger)

	head := "код: " + testSecretTrigger + " и Иванов Иван."
	rest := []string{" Ответ: super-secret-", "value и Иванов Ив", "ан уехал."}
	full := head + strings.Join(rest, "")
	want := refReplace(full, repl)
	spanSelfCheck(t, "audit", head, strings.Join(rest, ""), pairs, want)

	t.Run("mutated wire: the audit sees exactly the client view", func(t *testing.T) {
		newFrames, newDecoded := n03p3t09NewRun(t, runner, repl, head, rest, want)
		agg, content, doc := n03p3t09Audit(t, newFrames)
		if content != newDecoded {
			t.Fatalf("audit content %q != client view %q — the audit must see what shipped", content, newDecoded)
		}
		if strings.Contains(content, testSecretTrigger) || bytes.Contains(doc, []byte(testSecretTrigger)) {
			t.Fatal("audit document carries the forbidden span")
		}
		out := FinalCheck(context.Background(), denySecret, agg, nil, "chat")
		if out.Err != nil {
			t.Fatalf("final check error: %v", out.Err)
		}
		if out.Result == nil || out.Result.Verdict != pipeline.ActionAllow {
			t.Fatalf("the mutated stream must audit clean: %+v", out.Result)
		}
		if out.Effective != pipeline.ActionAllow {
			t.Fatalf("effective = %q, want allow", out.Effective)
		}
	})

	t.Run("raw wire: the audit honestly reports the exposure", func(t *testing.T) {
		oldFrames, _ := n03p3t09OldRun(t, head, rest)
		agg, content, doc := n03p3t09Audit(t, oldFrames)
		if !strings.Contains(content, testSecretTrigger) || !bytes.Contains(doc, []byte(testSecretTrigger)) {
			t.Fatal("corpus broken: the unmutated document must carry the span")
		}
		out := FinalCheck(context.Background(), denySecret, agg, nil, "chat")
		if out.Err != nil {
			t.Fatalf("final check error: %v", out.Err)
		}
		if out.Result == nil || out.Result.Verdict != pipeline.ActionDeny {
			t.Fatalf("the exposed stream must deny: %+v", out.Result)
		}
		if out.Effective != pipeline.ActionFlag {
			t.Fatalf("effective = %q, want flag — deny after issuance degrades to flag, never recall", out.Effective)
		}
	})

	t.Run("no redact-ahead at the consumer boundary", func(t *testing.T) {
		// The stream ENDS mid-span: the carry releases the incomplete head
		// verbatim (masking without a match would corrupt text), the audit
		// document carries exactly that head, and a contiguous-span detector
		// does not fire on it — the incomplete prefix is not the forbidden
		// value, and the pipeline promises nothing about tokens it never
		// received.
		restTail := "super-secret-valu" // incomplete head of a second occurrence
		rowHead := "код: " + testSecretTrigger
		rowRest := []string{" хвост: ", restTail}
		incomplete := rowHead + strings.Join(rowRest, "")
		wantTail := refReplace(incomplete, repl)

		newFrames, newDecoded := n03p3t09NewRun(t, runner, repl, rowHead, rowRest, wantTail)
		if !strings.HasSuffix(newDecoded, restTail) {
			t.Fatalf("the incomplete head must reach the client verbatim, got %q", newDecoded)
		}
		if strings.Contains(newDecoded, testSecretTrigger) {
			t.Fatal("the complete span must not exist in a stream that ended mid-span")
		}
		agg, content, _ := n03p3t09Audit(t, newFrames)
		if content != newDecoded {
			t.Fatalf("audit content %q != client view %q", content, newDecoded)
		}
		out := FinalCheck(context.Background(), denySecret, agg, nil, "chat")
		if out.Err != nil {
			t.Fatalf("final check error: %v", out.Err)
		}
		if out.Result == nil || out.Result.Verdict != pipeline.ActionAllow {
			t.Fatalf("a contiguous-span detector must not fire on the verbatim head: %+v", out.Result)
		}
	})
}

// TestN03P3T09_Redact_ScaffoldingNeverMatchingFuel pins the mutation-domain
// boundary: the carry sees decoded delta CONTENT only — framing bytes never
// enter it. A replacement map whose patterns ARE scaffolding text therefore
// replaces every in-content occurrence (even one split across chunks) while
// the wire framing stays intact, and exactly one standalone [DONE] event
// terminates the stream — an in-content mention can neither survive nor fake
// the terminator.
func TestN03P3T09_Redact_ScaffoldingNeverMatchingFuel(t *testing.T) {
	pairs := [][2]string{{"data:", "MD_"}, {"[DONE]", "STOP"}}
	repl := advReplMap(pairs)
	runner := advMultiMaskRunner(t, pairs)

	head := "формат: data: [DONE] — служебный"
	rest := []string{"формат: data", ": [DONE] и снова data: [DONE]"}
	full := head + strings.Join(rest, "")
	want := refReplace(full, repl)
	spanSelfCheck(t, "scaffold", head, strings.Join(rest, ""), pairs, want)

	_, oldDecoded := n03p3t09OldRun(t, head, rest)
	if oldDecoded != full {
		t.Fatalf("old configuration is not identity: %q, want %q", oldDecoded, full)
	}

	newFrames, newDecoded := n03p3t09NewRun(t, runner, repl, head, rest, want)
	if newDecoded != want {
		t.Fatalf("decoded = %q, want %q", newDecoded, want)
	}
	if newDecoded != refReplace(oldDecoded, repl) {
		t.Fatal("upgrade drift on the scaffolding corpus")
	}
	if strings.Contains(newDecoded, "data:") || strings.Contains(newDecoded, "[DONE]") {
		t.Fatalf("in-content scaffolding mentions must be replaced, got %q", newDecoded)
	}

	n03p3t09AssertSingleTerminator(t, n03p3t09Wire(newFrames))
}
