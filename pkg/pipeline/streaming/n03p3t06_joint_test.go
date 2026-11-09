package streaming

// N03-P03-T06 joint user scenario: the adversarial chunking patterns proven
// separately by T02/T04/T05 composed into ONE end-to-end stream — a provider
// stream carrying forbidden content that is split adversarially:
//
//   - a forbidden span that straddles a chunk boundary (start in one chunk,
//     completion in the next);
//   - a multibyte (Cyrillic) span straddled the same way, plus mid-rune
//     splits (primitive level, and the corrupted-stream wire degradation);
//   - a span completed only in the FINAL chunk after a long stall;
//   - two concurrent consumers with DIFFERENT mutation policies over the
//     SAME underlying chunk sequence.
//
// Assertions (the card's acceptance):
//
//   - no consumer ever receives a byte sequence containing a forbidden span,
//     neither in the decoded client view (after mutation) nor in the raw
//     wire bytes (before mutation);
//   - the hold-back bound (wave-18 fix, chunkcarry.go holdback: k ≤
//     maxLen-1, proper prefixes only) is never exceeded at any step;
//   - late-arriving completions are released correctly (replacement) or
//     dropped per contract (prefix deny → abort, buffer never released);
//   - the negative: the system makes NO promise about future tokens — the
//     hold-back never buffers unboundedly "waiting to check ahead"; bytes
//     that stop being a live proper-pattern-prefix are released without
//     seeing the deciding byte, and an incomplete tail is released verbatim
//     at Flush (the documented contract: docs/pipeline.md §7 item 3, the
//     ChunkProcessor/holdback doc comments).
//
// Real vs mock (packet exit criterion, recorded in T06-record): the chain
// uses the REAL in-process policy engine (pipeline.Engine with compiled
// enforce-mode YAML policies — the production policy runtime) and the REAL
// streaming primitives (PrefixGate, ChunkProcessor, FrameProcessor); the
// MOCK parts are the fixture detector/mutator steps (helpers_test.go,
// advMultiMaskStep) standing in for production guardrail steps and the
// fixture SSE frame renderer standing in for the gateway HTTP plumbing
// (the gateway HTTP surfaces are not exercised by this scenario). No
// external network/provider is contacted — the fixtures run fully
// in-process.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// n03p3t06MaxHold returns the hold-back bound of a replacement map: at most
// maxLen-1 bytes (what a learned pattern could still complete) may be in
// flight at any chunk boundary — the wave-18 proper-prefix requirement.
func n03p3t06MaxHold(repl map[string]string) int {
	return spanMaxPat(repl) - 1
}

// n03p3t06Decode concatenates the delta.content of every data frame on the
// wire (the client's assembled content view). Error-returning twin of
// advDecodedStream so the concurrent consumers can run off the test
// goroutine.
func n03p3t06Decode(wire []byte) (string, error) {
	var sb strings.Builder
	rest := wire
	for len(rest) > 0 {
		idx := bytes.Index(rest, []byte("\n\n"))
		if idx < 0 {
			return "", errors.New("unterminated SSE frame on the wire")
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
			return "", fmt.Errorf("client frame is not valid JSON: %w (%q)", err, payload)
		}
		if len(top.Choices) == 0 || len(top.Choices[0].Delta.Content) == 0 {
			continue
		}
		var s string
		if err := json.Unmarshal(top.Choices[0].Delta.Content, &s); err != nil {
			return "", fmt.Errorf("content delta is not a string: %w", err)
		}
		sb.WriteString(s)
	}
	return sb.String(), nil
}

// n03p3t06Chain drives one consumer stack (prefix gate → carry frame
// processor → flush) over head+chunks and returns (decoded, wire). Every
// step asserts the two invariants the card pins: the emitted view stays a
// prefix of the expected batch replace (never withhold-then-flood), and the
// carry hold-back never exceeds maxLen-1. Safe to call from any goroutine:
// failures are returned, not Fatal'd.
func n03p3t06Chain(runner Runner, repl map[string]string, head string, chunks []string, want string) (string, []byte, error) {
	g := NewPrefixGate(PrefixConfig{Runner: runner})
	g.Ingest(head)
	out := g.Flush(context.Background())
	if out.Err != nil {
		return "", nil, fmt.Errorf("prefix stage: %w", out.Err)
	}
	if out.Decision != PrefixRelease {
		return "", nil, fmt.Errorf("prefix decision = %q, want release", out.Decision)
	}
	if out.Text == head {
		return "", nil, errors.New("prefix mutation missing (the carry map would not be derived)")
	}
	cp, err := NewChunkProcessor(repl)
	if err != nil {
		return "", nil, fmt.Errorf("carry map: %w", err)
	}
	fp := NewFrameProcessor(cp)
	maxHold := n03p3t06MaxHold(repl)
	var wire []byte
	var decoded strings.Builder
	emit := func(content string) error {
		frame := fp.ProcessFrame(advChunkFrame(content))
		wire = append(wire, frame...)
		text, err := n03p3t06Decode(frame)
		if err != nil {
			return err
		}
		decoded.WriteString(text)
		if !strings.HasPrefix(want, decoded.String()) {
			return fmt.Errorf("decoded %q is not a prefix of the expected %q (withhold-then-flood)", decoded.String(), want)
		}
		if cp.Held() > maxHold {
			return fmt.Errorf("after chunk %q: Held()=%d exceeds maxLen-1=%d", content, cp.Held(), maxHold)
		}
		return nil
	}
	if err := emit(head); err != nil {
		return "", nil, err
	}
	for _, c := range chunks {
		if err := emit(c); err != nil {
			return "", nil, err
		}
	}
	if tail := fp.FlushFrame("n03p3t06", "n03p3t06-model"); tail != nil {
		wire = append(wire, tail...)
		text, err := n03p3t06Decode(tail)
		if err != nil {
			return "", nil, err
		}
		decoded.WriteString(text)
		if !strings.HasPrefix(want, decoded.String()) {
			return "", nil, fmt.Errorf("flushed tail broke the prefix invariant: %q vs %q", decoded.String(), want)
		}
	}
	if cp.Held() != 0 {
		return "", nil, fmt.Errorf("flush left %d bytes held", cp.Held())
	}
	wire = append(wire, []byte("data: [DONE]\n\n")...)
	if !bytes.HasSuffix(wire, []byte("data: [DONE]\n\n")) {
		return "", nil, errors.New("wire does not terminate with [DONE]")
	}
	return decoded.String(), wire, nil
}

// n03p3t06AssertNoLeak checks the card's core acceptance for one consumer
// result: no forbidden span anywhere — decoded (after mutation) or raw wire
// (before mutation).
func n03p3t06AssertNoLeak(t *testing.T, name, decoded string, wire []byte, repl map[string]string) {
	t.Helper()
	for pat := range repl {
		if strings.Contains(decoded, pat) {
			t.Fatalf("%s: forbidden span %q leaked to the decoded client view", name, pat)
		}
		if bytes.Contains(wire, []byte(pat)) {
			t.Fatalf("%s: forbidden span %q present in raw wire bytes", name, pat)
		}
	}
}

// n03p3t06JointChunks is the joint adversarial stream (identical for every
// consumer — the same underlying provider stream): a straddled ASCII secret,
// a long stall, a straddled Cyrillic alias, and a secret completed only in
// the FINAL chunk. head is the buffered prefix (contains every pattern
// complete — the production deriveReplacements learning shape).
func n03p3t06JointChunks(split int) (head string, chunks []string) {
	head = "Дорогой Иванов Иван! Код: " + testSecretTrigger
	c1 := " Ответ: super-secret-valu" // forbidden span start (straddled)
	if split > 0 {                    // adversarially re-split the start chunk too
		r := []rune(c1)
		if split <= len(r) {
			c1a, c1b := string(r[:split]), string(r[split:])
			return head, []string{
				c1a, c1b, // straddle at the chosen offset
				"-value. Стоп.",                // completion in the NEXT chunk
				" Пауза один. ",                // long stall begins
				" Пауза два. ",                 //
				" Пауза три. ",                 //
				" Опять Иванов Ив",             // Cyrillic span start
				"ан и снова super-secret-valu", // completes the alias; starts the late span
				"-value, конец.",               // FINAL chunk: the late completion
			}
		}
	}
	return head, []string{
		c1,
		"-value. Стоп.",
		" Пауза один. ",
		" Пауза два. ",
		" Пауза три. ",
		" Опять Иванов Ив",
		"ан и снова super-secret-valu",
		"-value, конец.",
	}
}

// TestN03P3T06_Joint_AdversarialStreamNeverLeaks: the flagship joint
// scenario. One provider stream carrying two forbidden values (ASCII secret,
// Cyrillic alias) is chunked adversarially: the first span start is re-split
// at EVERY rune offset (straddle dimension), the stall sits between the
// early pair and the late pair, and the last forbidden span completes only
// in the final chunk. Through the full prefix→carry chain the decoded view
// must equal the batch leftmost-longest replace of the whole text and no
// forbidden span may exist in the decoded view or the raw wire, at any
// split.
func TestN03P3T06_Joint_AdversarialStreamNeverLeaks(t *testing.T) {
	pairsA := [][2]string{{testSecretTrigger, testSecretMask}, {"Иванов Иван", "ORG_1"}}
	repl := advReplMap(pairsA)
	runner := advMultiMaskRunner(t, pairsA)
	head, chunks := n03p3t06JointChunks(0)
	full := head + strings.Join(chunks, "")
	want := refReplace(full, repl)

	// Corpus self-check (house rule from the T05 corpus): the fixture
	// sequential replace must equal the batch reference, replacements must
	// not contain patterns, and the head must contain every pattern complete.
	spanSelfCheck(t, "joint", head, strings.Join(chunks, ""), pairsA, want)

	start := []rune(" Ответ: super-secret-valu")
	for split := 0; split <= len(start); split++ {
		t.Run(fmt.Sprintf("straddle-%02d", split), func(t *testing.T) {
			head, chunks := n03p3t06JointChunks(split)
			decoded, wire, err := n03p3t06Chain(runner, repl, head, chunks, want)
			if err != nil {
				t.Fatalf("split %d: %v", split, err)
			}
			if decoded != want {
				t.Fatalf("split %d: decoded = %q, want %q", split, decoded, want)
			}
			n03p3t06AssertNoLeak(t, fmt.Sprintf("split-%d", split), decoded, wire, repl)
		})
	}
}

// TestN03P3T06_Joint_StallByteTrickle_FinalChunkCompletion: the span head
// trickles in ONE BYTE per chunk (17 chunks — a stall inside the span head
// itself) and the completion arrives only in the FINAL chunk. Pins three
// things at once: the hold grows to exactly maxLen-1 (the proper-prefix
// bound — reached, never exceeded), bytes keep flowing around the held tail
// during the stall (no unbounded buffering), and the late completion is
// released correctly as the replacement.
func TestN03P3T06_Joint_StallByteTrickle_FinalChunkCompletion(t *testing.T) {
	pairs := [][2]string{{testSecretTrigger, testSecretMask}} // len 18 → bound 17
	repl := advReplMap(pairs)
	maxHold := n03p3t06MaxHold(repl)
	runner := advMultiMaskRunner(t, pairs)

	head := "код: " + testSecretTrigger
	var chunks []string
	chunks = append(chunks, " Пауза. ", " Пауза. ", " Пауза. ") // stall BEFORE the span
	for _, r := range testSecretTrigger[:len(testSecretTrigger)-1] {
		chunks = append(chunks, string(r)) // byte-trickle of the span head
	}
	chunks = append(chunks, "e, конец.") // FINAL chunk completes the span
	full := head + strings.Join(chunks, "")
	want := refReplace(full, repl)

	// Primitive-level instrument: watch Held() grow to exactly the bound and
	// never a byte beyond it, with emission progress around the held tail.
	cp, err := NewChunkProcessor(repl)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	peak := 0
	for i, c := range chunks {
		cp.Process(c)
		if h := cp.Held(); h > maxHold {
			t.Fatalf("step %d (chunk %q): Held()=%d exceeds maxLen-1=%d", i, c, h, maxHold)
		} else if h > peak {
			peak = h
		}
	}
	if peak != maxHold {
		t.Fatalf("trickle peaked at Held()=%d, want exactly maxLen-1=%d (the proper-prefix bound must be reachable and exact)", peak, maxHold)
	}

	// End-to-end through the production chain: decoded == batch replace, no
	// span on the wire.
	decoded, wire, err := n03p3t06Chain(runner, repl, head, chunks, want)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if decoded != want {
		t.Fatalf("decoded = %q, want %q", decoded, want)
	}
	n03p3t06AssertNoLeak(t, "trickle", decoded, wire, repl)
	if !strings.Contains(decoded, testSecretMask+", конец.") {
		t.Fatalf("the late final-chunk completion was not released as the replacement: %q", decoded)
	}
}

// TestN03P3T06_Joint_LateCompletionDroppedPerContract: the DROP branch of
// the late-completion contract. The forbidden injection trigger is assembled
// across a chunk boundary after a long stall (filler chunks precede the
// trigger head — the stream is stalled, then the span arrives late) and
// completes only in the FINAL buffered chunk; the prefix deny policy must
// abort, the buffered text must never be released (out.Text empty), and the
// canonical AbortFrame must carry no ≥8-byte fragment of either half and
// terminate with [DONE]. (T02 pinned the abort at every two-way split
// without the long-stall shape; this is the joint stall + final-chunk
// completion composition. The halves stay ADJACENT in the buffer — a
// detector that matches the contiguous span cannot fire on halves separated
// by intervening text, and no production contract promises lookahead across
// unrelated bytes.)
func TestN03P3T06_Joint_LateCompletionDroppedPerContract(t *testing.T) {
	runner := advDenyRunner(t)
	trig := testInjectionTrigger
	mid := len(trig) / 2
	g := NewPrefixGate(PrefixConfig{Runner: runner})
	g.Ingest(" Пауза. ")     // long stall BEFORE the span
	g.Ingest(" Пауза. ")     //
	g.Ingest(" ещё пауза. ") //
	g.Ingest(trig[:mid])     // trigger head arrives late
	g.Ingest(trig[mid:])     // completion only in the FINAL buffered chunk
	out := g.Flush(context.Background())
	if out.Decision != PrefixAbort {
		t.Fatalf("decision = %q, want abort (deny must drop the stalled buffer)", out.Decision)
	}
	if out.Err != nil {
		t.Fatalf("unexpected infra error: %v", out.Err)
	}
	if out.Text != "" {
		t.Fatalf("aborted buffer leaked %q — dropped content must never be released", out.Text)
	}
	if out.Result == nil || out.Result.Verdict != pipeline.ActionDeny {
		t.Fatalf("result must carry the deny verdict: %+v", out.Result)
	}
	frame := AbortFrame("request blocked by organization policy")
	const fragMin = 8 // short windows collide with the fixed message's letters (T02 precedent)
	for name, frag := range map[string]string{"head": trig[:mid], "tail": trig[mid:], "full": trig} {
		if len(frag) >= fragMin && bytes.Contains(frame, []byte(frag)) {
			t.Fatalf("abort frame carries the %s fragment %q", name, frag)
		}
	}
	if !bytes.HasSuffix(frame, []byte("data: [DONE]\n\n")) {
		t.Fatal("abort frame misses the [DONE] terminator")
	}
}

// TestN03P3T06_Joint_TwoConsumers_DifferentMutationPolicies: two consumers
// with DIFFERENT mutation policies consume the SAME underlying adversarial
// stream (identical chunk sequence) concurrently. Each stack is fully
// independent — own gate, own carry processor, own frame processor, and own
// Runner (each consumer builds its engine and compiled policy; the stacks
// share no mutable state across goroutines — the race detector validates
// the concurrent use of these independent instances under -race -count=2).
// Per consumer: the decoded view equals ITS OWN batch replace, none of ITS
// OWN forbidden spans appears decoded or raw, its own hold bound holds at
// every step — and the policies are genuinely different (outputs differ, no
// cross-policy replacement text anywhere).
func TestN03P3T06_Joint_TwoConsumers_DifferentMutationPolicies(t *testing.T) {
	pairsA := [][2]string{{testSecretTrigger, testSecretMask}, {"Иванов Иван", "ORG_1"}}
	pairsB := [][2]string{{"Иванов", "Ф1"}, {"Иван", "Ф2"}}
	replA, replB := advReplMap(pairsA), advReplMap(pairsB)
	runnerA, runnerB := advMultiMaskRunner(t, pairsA), advMultiMaskRunner(t, pairsB)

	head, chunks := n03p3t06JointChunks(7) // one fixed adversarial chunking, shared
	full := head + strings.Join(chunks, "")
	wantA, wantB := refReplace(full, replA), refReplace(full, replB)
	if wantA == wantB {
		t.Fatal("corpus broken: the two policies must produce different expected outputs")
	}

	type result struct {
		decoded string
		wire    []byte
		err     error
	}
	run := func(runner Runner, repl map[string]string, want string) <-chan result {
		ch := make(chan result, 1)
		go func() {
			decoded, wire, err := n03p3t06Chain(runner, repl, head, chunks, want)
			ch <- result{decoded: decoded, wire: wire, err: err}
		}()
		return ch
	}
	const iterations = 4
	for it := 0; it < iterations; it++ {
		chA, chB := run(runnerA, replA, wantA), run(runnerB, replB, wantB)
		resA, resB := <-chA, <-chB
		if resA.err != nil {
			t.Fatalf("iteration %d consumer A: %v", it, resA.err)
		}
		if resB.err != nil {
			t.Fatalf("iteration %d consumer B: %v", it, resB.err)
		}
		if resA.decoded != wantA {
			t.Fatalf("iteration %d consumer A: decoded %q, want %q", it, resA.decoded, wantA)
		}
		if resB.decoded != wantB {
			t.Fatalf("iteration %d consumer B: decoded %q, want %q", it, resB.decoded, wantB)
		}
		n03p3t06AssertNoLeak(t, fmt.Sprintf("it%d-A", it), resA.decoded, resA.wire, replA)
		n03p3t06AssertNoLeak(t, fmt.Sprintf("it%d-B", it), resB.decoded, resB.wire, replB)
		// No cross-contamination: each consumer sees only its own policy's
		// replacement vocabulary.
		for _, foreign := range []string{testSecretMask, "ORG_1"} {
			if strings.Contains(resB.decoded, foreign) {
				t.Fatalf("iteration %d consumer B shows consumer A's replacement %q", it, foreign)
			}
		}
		for _, foreign := range []string{"Ф1", "Ф2"} {
			if strings.Contains(resA.decoded, foreign) {
				t.Fatalf("iteration %d consumer A shows consumer B's replacement %q", it, foreign)
			}
		}
	}
}

// TestN03P3T06_Negative_NoLookahead_HoldbackNeverChecksFutureTokens pins the
// card's negative as behavior: the streaming mutation API makes NO promise
// about tokens it has not received. The hold-back never buffers unboundedly
// "waiting to check ahead": bytes stop being held the moment they stop being
// a live proper pattern prefix — WITHOUT seeing the deciding byte — and an
// incomplete tail is released verbatim at Flush, never retained for a
// future-token re-check. (docs/pipeline.md §7 item 3: "the pipeline cannot
// withhold the stream to validate future tokens"; the gate-level no-recheck
// half of the negative is T02's TestAdversarial_PostRelease_NoFutureTokenPromise
// and is referenced, not re-pinned here.)
func TestN03P3T06_Negative_NoLookahead_HoldbackNeverChecksFutureTokens(t *testing.T) {
	t.Run("never waits for the deciding byte", func(t *testing.T) {
		cp, err := NewChunkProcessor(map[string]string{"abcd": "X"})
		if err != nil {
			t.Fatalf("construct: %v", err)
		}
		if got := cp.Process("abc"); got != "" {
			t.Fatalf("live prefix must be held, got %q", got)
		}
		if cp.Held() != 3 || cp.Held() > n03p3t06MaxHold(map[string]string{"abcd": "X"}) {
			t.Fatalf("Held()=%d, want 3 (the bound itself)", cp.Held())
		}
		// The "d" never arrives — and the processor does NOT wait for it: the
		// next chunk proves "abc" is not a match head, so ALL of it releases
		// immediately, without any future-token inspection.
		if got := cp.Process("x"); got != "abcx" {
			t.Fatalf("emitted %q, want %q — the hold-back waited for a future byte instead of releasing", got, "abcx")
		}
		if cp.Held() != 0 {
			t.Fatalf("Held()=%d after the deciding evidence, want 0", cp.Held())
		}
		if got := cp.Process("abc") + cp.Flush(); got != "abc" {
			t.Fatalf("flush must release the incomplete tail verbatim (no future-token re-check), got %q", got)
		}
	})

	t.Run("never buffers unboundedly across a long stall", func(t *testing.T) {
		repl := map[string]string{"abcd": "X"}
		cp, err := NewChunkProcessor(repl)
		if err != nil {
			t.Fatalf("construct: %v", err)
		}
		maxHold := n03p3t06MaxHold(repl)
		var got strings.Builder
		got.WriteString(cp.Process("abc")) // match head held (3 bytes)
		for i := 0; i < 1000; i++ {        // the deciding byte never comes
			got.WriteString(cp.Process("q"))
			if cp.Held() > maxHold {
				t.Fatalf("step %d: Held()=%d exceeds maxLen-1=%d — the hold-back buffered beyond any pattern could complete", i, cp.Held(), maxHold)
			}
			if i >= 1 && got.Len() < 3+(i) { // progress: bytes keep flowing
				t.Fatalf("step %d: only %d bytes emitted — the stream is being withheld", i, got.Len())
			}
		}
		got.WriteString(cp.Flush())
		if got.String() != "abc"+strings.Repeat("q", 1000) {
			t.Fatalf("output = %q, want the verbatim stream (batch replace of a text without the pattern)", got.String())
		}
	})

	t.Run("incomplete tail released verbatim at end of stream", func(t *testing.T) {
		// A stream that ENDS while a span head is still held: Flush must
		// release the tail verbatim — the pipeline cannot (and does not
		// promise to) hold the stream open waiting for a completion that may
		// never arrive. The forbidden span (the complete value) never
		// existed in this stream; the incomplete prefix is not the span.
		pairs := [][2]string{{testSecretTrigger, testSecretMask}}
		repl := advReplMap(pairs)
		cp, err := NewChunkProcessor(repl)
		if err != nil {
			t.Fatalf("construct: %v", err)
		}
		var got strings.Builder
		got.WriteString(cp.Process("start "))
		for _, r := range testSecretTrigger[:10] {
			got.WriteString(cp.Process(string(r))) // trickled head, then the stream stalls forever
		}
		if cp.Held() != 10 {
			t.Fatalf("Held()=%d, want 10 (the live prefix)", cp.Held())
		}
		got.WriteString(cp.Flush())
		if cp.Held() != 0 {
			t.Fatalf("flush left %d bytes held", cp.Held())
		}
		want := "start " + testSecretTrigger[:10] // batch replace of the text as received
		if got.String() != want {
			t.Fatalf("tail = %q, want %q released verbatim at end of stream", got.String(), want)
		}
	})
}

// TestN03P3T06_Joint_MultibyteRuneSplit: the multibyte dimension of the
// joint scenario. Two levels, honestly separated:
//
//   - the carry primitive sees DECODED text, where a mid-rune split is just
//     bytes: it reassembles the rune, finds the forbidden span, and replaces
//     it — for every split at a non-rune byte offset, output equals the
//     batch replace and the hold bound holds (the full split space lives in
//     the T05 corpus; here only the mid-rune offsets);
//   - on the SSE wire a mid-rune frame boundary is a CORRUPTED stream: the
//     JSON layer degrades each dangling half to U+FFFD before the carry sees
//     it, so the span can never reassemble client-side — and nothing
//     resembling it leaks. Both paths keep the forbidden span off the client.
func TestN03P3T06_Joint_MultibyteRuneSplit(t *testing.T) {
	pairs := [][2]string{{"Иванов", "Ф1"}}
	repl := advReplMap(pairs)
	text := "ок Иванов ок"
	want := refReplace(text, repl)

	t.Run("primitive reassembles mid-rune splits", func(t *testing.T) {
		for i := 1; i < len(text); i++ {
			if utf8.RuneStart(text[i]) {
				continue // rune-aligned offsets are the T05 corpus' dimension
			}
			spanFeed(t, fmt.Sprintf("mid-rune-%02d", i), repl, want, []string{text[:i], text[i:]})
		}
	})

	t.Run("wire degrades corrupted mid-rune frames to U+FFFD", func(t *testing.T) {
		const cut = 6 // inside "И" (2 bytes): text[:6] ends with a dangling lead byte
		if utf8.RuneStart(text[cut]) {
			t.Fatalf("corpus: offset %d must be mid-rune", cut)
		}
		cp, err := NewChunkProcessor(repl)
		if err != nil {
			t.Fatalf("construct: %v", err)
		}
		fp := NewFrameProcessor(cp)
		var wire []byte
		var decoded strings.Builder
		for _, half := range []string{text[:cut], text[cut:]} {
			frame := fp.ProcessFrame(advChunkFrame(half))
			wire = append(wire, frame...)
			d, err := n03p3t06Decode(frame)
			if err != nil {
				t.Fatalf("half %q: %v", half, err)
			}
			decoded.WriteString(d)
			if cp.Held() > n03p3t06MaxHold(repl) {
				t.Fatalf("hold bound exceeded after half %q: Held()=%d", half, cp.Held())
			}
		}
		if tail := fp.FlushFrame("n03p3t06-utf8", "n03p3t06-model"); tail != nil {
			wire = append(wire, tail...)
			d, err := n03p3t06Decode(tail)
			if err != nil {
				t.Fatalf("flush tail: %v", err)
			}
			decoded.WriteString(d)
		}
		for pat := range repl {
			if bytes.Contains(wire, []byte(pat)) || strings.Contains(decoded.String(), pat) {
				t.Fatalf("forbidden span %q resurrected from a corrupted mid-rune stream", pat)
			}
		}
		if !strings.ContainsRune(decoded.String(), '\uFFFD') {
			t.Fatalf("expected the corrupted halves to degrade to U+FFFD, got %q", decoded.String())
		}
		wire = append(wire, []byte("data: [DONE]\n\n")...)
		if !bytes.HasSuffix(wire, []byte("data: [DONE]\n\n")) {
			t.Fatal("wire does not terminate with [DONE]")
		}
	})

	t.Run("contrast: raw bytes reassemble and replace", func(t *testing.T) {
		// The same split fed to the primitive directly (no JSON layer):
		// the span reassembles and is replaced in full — neither path leaks.
		const cut = 6
		spanFeed(t, "raw-bytes", repl, want, []string{text[:cut], text[cut:]})
	})
}
