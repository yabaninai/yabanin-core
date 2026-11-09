package streaming

// N03-P03-T07 boundary corpus — hold-boundary and released-bytes aspects.
// The card demands a boundary corpus over three aspects with observable
// errors and prior behavior pinned. This file owns the aspects that live at
// the streaming primitives:
//
//  1. the prefix hold boundary itself: thresholds fire exactly at their
//     boundary (never one token/delay early), zero config selects the
//     package defaults (a policy parameter can never disable a threshold —
//     the hold stays bounded by design), and disabling needs negative raw
//     config that policy params cannot produce;
//  2. the released-bytes boundary across the release split at EVERY rune
//     offset (the T04 pin generalized to a corpus): emitted bytes are never
//     revised after release, an unlearned value assembles in the client
//     view while never riding one wire frame, and learned spans never leak;
//  3. production-shaped carry maps (pseudonym tokens, [REDACTED], pure
//     deletions, minimal 4-byte patterns) over adversarial byte splits with
//     the hold bound and emit-prefix invariants of pipeline.md §7 item 3.
//
// The gateway-glue aspects (streamPrefixParams priority/error fallback,
// deriveReplacements diff boundary, client↔cache parity for the derived
// map) live in pkg/gateway/n03p3t07_boundary_test.go.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// twoWayByteSplits yields every two-chunk byte split of text.
func twoWayByteSplits(text string) [][]string {
	splits := make([][]string, 0, len(text)-1)
	for i := 1; i < len(text); i++ {
		splits = append(splits, []string{text[:i], text[i:]})
	}
	return splits
}

// fixedStrideSplits chunks text into fixed-size pieces (last one short).
func fixedStrideSplits(text string, stride int) []string {
	var chunks []string
	for i := 0; i < len(text); i += stride {
		end := min(i+stride, len(text))
		chunks = append(chunks, text[i:end])
	}
	return chunks
}

// TestN03P3T07_HoldThresholds_BoundaryExactness pins the hold boundary of
// the prefix gate (the TTFB cost is exactly the documented bound, never one
// unit more):
//
//   - the token threshold fires at >= MaxTokens and holds at MaxTokens-1;
//   - the delay threshold fires at >= first+MaxDelay and holds 1ns before;
//   - zero config selects the package defaults — this is what the gateway
//     params wiring relies on: ParsePrefixParams validates >= 0, so a
//     policy can NEVER produce a negative threshold; an explicit
//     prefix_tokens: 0 / prefix_delay_ms: 0 collapses to the default bound
//     (64 tokens / 500 ms), never to an unbounded hold. Disabling a
//     threshold is a raw-config-only shape (negative), unreachable from
//     policy parameters by construction.
func TestN03P3T07_HoldThresholds_BoundaryExactness(t *testing.T) {
	now := time.Now()

	// Token boundary: MaxTokens-1 holds, MaxTokens fires.
	g := NewPrefixGate(PrefixConfig{MaxTokens: 4, MaxDelay: time.Hour, TokenCounter: counter()})
	for i := 0; i < 3; i++ {
		g.Ingest("x")
	}
	if g.ShouldFlush(now) {
		t.Fatal("token threshold fired at MaxTokens-1 (one delta early)")
	}
	g.Ingest("x")
	if !g.ShouldFlush(now) {
		t.Fatal("token threshold did not fire at exactly MaxTokens")
	}

	// Delay boundary: 1ns before the deadline holds, at the deadline fires.
	g = NewPrefixGate(PrefixConfig{MaxTokens: -1, MaxDelay: 40 * time.Millisecond, TokenCounter: counter()})
	g.Ingest("x") // arms first at time.Now()
	deadline, ok := g.Deadline()
	if !ok {
		t.Fatal("deadline not armed")
	}
	if g.ShouldFlush(deadline.Add(-time.Nanosecond)) {
		t.Fatal("delay threshold fired 1ns before the deadline")
	}
	if !g.ShouldFlush(deadline) {
		t.Fatal("delay threshold did not fire at the deadline")
	}

	// Zero tokens → default 64 (delay disabled via raw negative): the
	// explicit prefix_tokens: 0 policy param lands here.
	g = NewPrefixGate(PrefixConfig{MaxDelay: -1, TokenCounter: counter()})
	for i := 0; i < DefaultPrefixTokens-1; i++ {
		g.Ingest("x")
	}
	if g.ShouldFlush(now) {
		t.Fatalf("flushed at %d tokens; zero config must select the %d-token default", DefaultPrefixTokens-1, DefaultPrefixTokens)
	}
	g.Ingest("x")
	if !g.ShouldFlush(now) {
		t.Fatal("default token bound did not fire at DefaultPrefixTokens")
	}

	// Zero delay → default 500ms armed (tokens disabled via raw negative):
	// the explicit prefix_delay_ms: 0 policy param lands here.
	g = NewPrefixGate(PrefixConfig{MaxTokens: -1, TokenCounter: counter()})
	g.Ingest("x")
	deadline, ok = g.Deadline()
	if !ok {
		t.Fatal("zero MaxDelay must arm the default delay, not disable it")
	}
	want := DefaultPrefixDelay
	if d := time.Until(deadline); d > want || d < want-time.Second {
		t.Fatalf("zero MaxDelay armed a ~%v deadline, want ~%v", d, want)
	}

	// Negative raw config disables both thresholds — the only unbounded
	// shape, unreachable from policy params (ParsePrefixParams rejects
	// negatives). Pinned so a wiring change cannot silently re-enable it.
	g = NewPrefixGate(PrefixConfig{MaxTokens: -1, MaxDelay: -1, TokenCounter: counter()})
	for i := 0; i < DefaultPrefixTokens+10; i++ {
		g.Ingest("x")
	}
	if g.ShouldFlush(time.Now().Add(time.Hour)) {
		t.Fatal("disabled thresholds fired (negative raw config must pass through)")
	}
	if _, ok := g.Deadline(); ok {
		t.Fatal("deadline armed with both thresholds disabled")
	}
}

// TestN03P3T07_PrefixStage_FailClosedAndIdempotent pins the observable
// errors of the prefix stage that no other test covers: a nil Runner and a
// runner returning no result both fail CLOSED (abort, Err set, no text), a
// stage error always carries the abort decision (the Err-implies-abort
// implication the middleware branches on), and Flush is idempotent — the
// second call returns the cached outcome without a second policy run.
func TestN03P3T07_PrefixStage_FailClosedAndIdempotent(t *testing.T) {
	ctx := context.Background()

	// Nil runner: the engine never ran, so nothing is verified — no byte
	// may leave.
	g := NewPrefixGate(PrefixConfig{TokenCounter: counter()})
	g.Ingest("unverified prefix text")
	out := g.Flush(ctx)
	if out.Decision != PrefixAbort || out.Err == nil || out.Text != "" {
		t.Fatalf("nil runner: outcome = %+v, want abort with Err set and empty text", out)
	}

	// Runner returns no result: same fail-closed shape.
	g = NewPrefixGate(PrefixConfig{Runner: RunnerFunc(func(context.Context, *pipeline.Payload) *pipeline.Result { return nil }), TokenCounter: counter()})
	g.Ingest("unverified prefix text")
	out = g.Flush(ctx)
	if out.Decision != PrefixAbort || out.Err == nil || out.Text != "" {
		t.Fatalf("nil result: outcome = %+v, want abort with Err set and empty text", out)
	}

	// Idempotent Flush: one policy run, cached outcome (the middleware
	// calls Flush both from the timer loop and from finishStream).
	runs := 0
	g = NewPrefixGate(PrefixConfig{
		Runner: RunnerFunc(func(_ context.Context, p *pipeline.Payload) *pipeline.Result {
			runs++
			return &pipeline.Result{Verdict: pipeline.ActionAllow}
		}),
		TokenCounter: counter(),
	})
	g.Ingest("x")
	first := g.Flush(ctx)
	second := g.Flush(ctx)
	if runs != 1 {
		t.Fatalf("policy ran %d times, want exactly 1 (Flush must be idempotent)", runs)
	}
	if first.Decision != PrefixRelease || second.Decision != PrefixRelease {
		t.Fatalf("decisions = %q then %q, want release both times", first.Decision, second.Decision)
	}
	// The cached outcome is the same value, not a re-run artifact.
	if first.Text != second.Text {
		t.Fatalf("cached text %q != first text %q", second.Text, first.Text)
	}
}

// TestN03P3T07_UnlearnedHeadPriorBehavior_EveryReleaseSplit generalizes the
// T04 release-boundary pin to a corpus: the release boundary cuts an
// unlearned multi-byte value at EVERY rune offset. Prior behavior, pinned
// per split:
//
//   - the emitted region (mutated snapshot + the verbatim partial head) is
//     never revised after release — the negative contract ("no promise of
//     checking future tokens") in its positive form;
//   - the unlearned value assembles complete in the CLIENT view while never
//     riding a single wire frame (for cuts strictly inside the value);
//   - the learned span never appears anywhere, raw or decoded;
//   - the stream terminates with the [DONE] terminator.
func TestN03P3T07_UnlearnedHeadPriorBehavior_EveryReleaseSplit(t *testing.T) {
	pairs := [][2]string{{"alias-one", "ONE"}}
	value := "ключ-Иванов-12345678" // multi-byte; rune offsets ≠ byte offsets
	prefixHead := "x alias-one y "

	runes := []rune(value)
	for k := 0; k <= len(runes); k++ {
		head := string(runes[:k])
		tail := string(runes[k:])
		name := "split-" + head
		t.Run(name, func(t *testing.T) {
			prefix := []string{prefixHead + head}
			rest := []string{tail + " конец"}
			full := prefixHead + value + " конец"

			st := advRunStream(t, pairs, prefix, rest)
			if st.aborted {
				t.Fatal("unexpected prefix abort")
			}
			if !st.mutated {
				t.Fatal("prefix mutation missing (the learned span must transform before release)")
			}
			got := advDecodedStream(t, st.wire)
			if want := refReplace(full, advReplMap(pairs)); got != want {
				t.Fatalf("decoded stream = %q, want %q", got, want)
			}
			// The emitted region is final: mutated snapshot + verbatim head.
			if !strings.HasPrefix(got, "x ONE y "+head) {
				t.Fatalf("emitted region revised after release: %q", got)
			}
			// The unlearned value assembles client-side.
			if !strings.Contains(got, value) {
				t.Fatalf("unlearned value must assemble in the client view, got %q", got)
			}
			// Learned span never leaks (raw wire or decoded view).
			if strings.Contains(got, "alias-one") {
				t.Fatal("learned span present in the decoded view")
			}
			if t07WireContains(st.wire, "alias-one") {
				t.Fatal("learned span present in raw wire bytes")
			}
			// Straddled cuts: the full value never rides one wire frame.
			if k > 0 && k < len(runes) && t07WireContains(st.wire, value) {
				t.Fatal("the full unlearned value rode a single wire frame across the release boundary")
			}
			if !t07WireHasSuffix(st.wire, "data: [DONE]\n\n") {
				t.Fatal("stream misses the [DONE] terminator")
			}
		})
	}
}

// t07WireContains/t07WireHasSuffix are string-shorthand wrappers for the
// wire assertions above (the wire is one []byte).
func t07WireContains(b []byte, s string) bool  { return strings.Contains(string(b), s) }
func t07WireHasSuffix(b []byte, s string) bool { return strings.HasSuffix(string(b), s) }

// TestN03P3T07_ProductionMapShapes_AdversarialSplits runs production-shaped
// carry maps — the shapes deriveReplacements actually emits at the gateway
// (pseudonym tokens, [REDACTED], pure deletions with an empty replacement,
// minimal 4-byte patterns) — over every two-way byte split plus a 3-byte
// stride family. Per split, spanFeed asserts the hold bound (≤ maxLen-1),
// the emit-prefix invariant, and the exact batch-replace total; the corpus
// includes decoys (pattern minus last byte, pattern with extra suffix) to
// pin that matching is exact, never fuzzy: a one-byte-short decoy is NOT
// rewritten and rides the wire as-is.
func TestN03P3T07_ProductionMapShapes_AdversarialSplits(t *testing.T) {
	rows := []struct {
		name  string
		pairs [][2]string
		corps string
	}{
		{
			name:  "pseudonym-tokens",
			pairs: [][2]string{{"super-secret-value", "{{YPP_1}}"}, {"Иванов Иван", "ORG_1"}},
			corps: "ключ super-secret-value, Иванов Иван; снова super-secret-valu (decoy) и Иванов Иван!",
		},
		{
			name:  "redact",
			pairs: [][2]string{{"super-secret-value", "[REDACTED]"}},
			corps: "a super-secret-value b super-secret-valuec c super-secret-valu d",
		},
		{
			name:  "pure-deletion-empty-replacement",
			pairs: [][2]string{{"super-secret-value", ""}},
			corps: "keep super-secret-value drop, keep super-secret-valuee, keep super-secret-valu end",
		},
		{
			name:  "minimal-4-byte-pattern",
			pairs: [][2]string{{"Key ", "{{YPP_1}}"}},
			corps: "Key A Key BKey C KeyKey D Ke E",
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			repl := advReplMap(row.pairs)
			spanSelfCheck(t, row.name, row.corps, "", row.pairs, refReplace(row.corps, repl))
			want := refReplace(row.corps, repl)
			splits := twoWayByteSplits(row.corps)
			splits = append(splits, fixedStrideSplits(row.corps, 3))
			for i, chunks := range splits {
				if got := spanFeed(t, row.name, repl, want, chunks); got != want {
					t.Fatalf("%s split %d: decoded %q, want %q", row.name, i, got, want)
				}
			}
		})
	}
}
