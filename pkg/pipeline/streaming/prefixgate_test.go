package streaming

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// counter returns a TokenCounter that counts one token per non-empty delta
// (deterministic; independent of the clock).
func counter() func(string) int {
	return func(s string) int {
		if s == "" {
			return 0
		}
		return 1
	}
}

func TestPrefixGate_HoldsUntilTokenThreshold(t *testing.T) {
	g := NewPrefixGate(PrefixConfig{MaxTokens: 3, MaxDelay: time.Hour, TokenCounter: counter()})
	g.Ingest("a")
	g.Ingest("b")
	if g.ShouldFlush(time.Now()) {
		t.Fatal("flushed before the token budget was reached")
	}
	g.Ingest("c")
	if !g.ShouldFlush(time.Now()) {
		t.Fatal("token threshold did not fire")
	}
	buf, tokens := g.Buffered()
	if buf != "abc" || tokens != 3 {
		t.Fatalf("buffered %q tokens=%d, want abc/3", buf, tokens)
	}
}

func TestPrefixGate_DelayFlushOnSlowStream(t *testing.T) {
	// A slow stream: only a small delta arrives, well under the token
	// budget; the 20ms hold timeout is what must fire the flush.
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, prefixFlagPolicy)
	g := NewPrefixGate(PrefixConfig{
		MaxTokens: 1000, MaxDelay: 20 * time.Millisecond, TokenCounter: counter(),
		Runner: EngineRunner(eng, []pipeline.Compiled{pol}),
	})
	g.Ingest("tiny")
	if g.ShouldFlush(time.Now()) {
		t.Fatal("flushed immediately after the first delta")
	}
	deadline, ok := g.Deadline()
	if !ok {
		t.Fatal("no hold deadline armed")
	}
	if deadline.Before(time.Now()) {
		t.Fatal("deadline is in the past right after the first delta")
	}
	// Deterministic threshold check without sleeping: at first+MaxDelay the
	// hold must expire.
	if !g.ShouldFlush(deadline) {
		t.Fatal("delay threshold did not fire at the deadline")
	}
	time.Sleep(25 * time.Millisecond)
	if !g.ShouldFlush(time.Now()) {
		t.Fatal("delay threshold did not fire on a slow stream")
	}
	out := g.Flush(context.Background())
	if out.Decision != PrefixRelease || out.Text != "tiny" {
		t.Fatalf("slow stream flush = %+v, want release of the partial buffer", out)
	}
}

func TestPrefixGate_TokenThresholdBeatsDelay(t *testing.T) {
	// Whichever fires FIRST flushes: a full token budget must flush even
	// with a delay that has not elapsed.
	g := NewPrefixGate(PrefixConfig{MaxTokens: 2, MaxDelay: time.Hour, TokenCounter: counter()})
	g.Ingest("a")
	g.Ingest("b")
	if !g.ShouldFlush(time.Now()) {
		t.Fatal("full token budget did not flush despite an unelapsed delay")
	}
}

func TestPrefixGate_AbortOnInjection(t *testing.T) {
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, prefixDenyPolicy)
	g := NewPrefixGate(PrefixConfig{Runner: EngineRunner(eng, []pipeline.Compiled{pol}), Endpoint: "chat"})
	g.Ingest("hello, ")
	g.Ingest("please " + testInjectionTrigger)
	out := g.Flush(context.Background())
	if out.Decision != PrefixAbort {
		t.Fatalf("decision = %q, want abort", out.Decision)
	}
	if out.Text != "" {
		t.Fatalf("aborted buffer leaked %q", out.Text)
	}
	if out.Result == nil || out.Result.Verdict != pipeline.ActionDeny {
		t.Fatalf("result = %+v, want deny verdict", out.Result)
	}
	if len(out.Result.Findings) == 0 {
		t.Fatal("no findings recorded for the decision-log")
	}
	// Correct SSE termination: error frame + [DONE] terminator, and the
	// buffered content never appears on the wire.
	frame := AbortFrame("request blocked by policy")
	if !bytes.Contains(frame, []byte("data: [DONE]")) {
		t.Fatalf("abort frame misses the [DONE] terminator: %q", frame)
	}
	if !bytes.Contains(frame, []byte(`"error"`)) {
		t.Fatalf("abort frame misses the error envelope: %q", frame)
	}
	if bytes.Contains(frame, []byte(testInjectionTrigger)) {
		t.Fatal("abort frame quotes the flagged content")
	}
}

func TestPrefixGate_MutateRelease(t *testing.T) {
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, prefixMaskPolicy)
	g := NewPrefixGate(PrefixConfig{Runner: EngineRunner(eng, []pipeline.Compiled{pol})})
	g.Ingest("value is " + testSecretTrigger + " ok")
	out := g.Flush(context.Background())
	if out.Decision != PrefixRelease {
		t.Fatalf("decision = %q, want release", out.Decision)
	}
	if strings.Contains(out.Text, testSecretTrigger) {
		t.Fatalf("released text contains the original secret: %q", out.Text)
	}
	if !strings.Contains(out.Text, testSecretMask) {
		t.Fatalf("released text misses the substitution: %q", out.Text)
	}
	if out.Result.Mutated == nil {
		t.Fatal("engine result did not mark the mutation")
	}
}

func TestPrefixGate_ReleaseUnchanged(t *testing.T) {
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, prefixFlagPolicy)
	g := NewPrefixGate(PrefixConfig{Runner: EngineRunner(eng, []pipeline.Compiled{pol})})
	g.Ingest("clean text")
	out := g.Flush(context.Background())
	if out.Decision != PrefixRelease || out.Text != "clean text" {
		t.Fatalf("clean release = %+v", out)
	}
	if out.Result.Mutated != nil {
		t.Fatalf("unchanged buffer marked mutated: %+v", out.Result.Mutated)
	}
}

func TestPrefixGate_CancelledContextFailsClosed(t *testing.T) {
	g := NewPrefixGate(PrefixConfig{}) // no runner: also the nil-runner path
	g.Ingest("some text")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := g.Flush(ctx)
	if out.Decision != PrefixAbort || out.Err == nil {
		t.Fatalf("cancelled flush = %+v, want fail-closed abort", out)
	}
}

func TestPrefixGate_FlushIdempotent(t *testing.T) {
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, prefixFlagPolicy)
	g := NewPrefixGate(PrefixConfig{Runner: EngineRunner(eng, []pipeline.Compiled{pol})})
	g.Ingest("once")
	first := g.Flush(context.Background())
	g.Ingest("ignored after decision") // must be a no-op
	second := g.Flush(context.Background())
	if first.Text != second.Text || first.Decision != second.Decision {
		t.Fatalf("flush is not idempotent: %+v vs %+v", first, second)
	}
	if !g.Flushed() {
		t.Fatal("Flushed() false after Flush")
	}
	if g.ShouldFlush(time.Now()) {
		t.Fatal("a flushed gate still asks for a flush")
	}
	if _, ok := g.Deadline(); ok {
		t.Fatal("a flushed gate still holds a deadline")
	}
}

func TestPrefixGate_EndOfStreamWhileBuffering(t *testing.T) {
	// A short stream ends before any threshold fires: the end-of-stream
	// Flush must still run the policies over the partial buffer.
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, prefixDenyPolicy)
	g := NewPrefixGate(PrefixConfig{Runner: EngineRunner(eng, []pipeline.Compiled{pol})})
	g.Ingest(testInjectionTrigger)
	out := g.Flush(context.Background())
	if out.Decision != PrefixAbort {
		t.Fatalf("short stream = %+v, want abort (policies must see partial buffers)", out)
	}
}

func TestPrefixGate_ConcurrentStreams(t *testing.T) {
	// One gate per stream, one shared engine: the race detector validates
	// that separate primitives sharing a Runner stay race-free.
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, prefixDenyPolicy)
	runner := EngineRunner(eng, []pipeline.Compiled{pol})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			g := NewPrefixGate(PrefixConfig{Runner: runner, MaxTokens: 2, MaxDelay: time.Hour, TokenCounter: counter()})
			g.Ingest("safe ")
			g.Ingest(testInjectionTrigger)
			out := g.Flush(context.Background())
			if out.Decision != PrefixAbort {
				t.Errorf("goroutine: decision = %q, want abort", out.Decision)
			}
		})
	}
	wg.Wait()
}

func TestParsePrefixParams(t *testing.T) {
	tokens, delay, err := ParsePrefixParams(nil)
	if err != nil || tokens != DefaultPrefixTokens || delay != DefaultPrefixDelay {
		t.Fatalf("defaults = (%d, %v, %v)", tokens, delay, err)
	}
	tokens, delay, err = ParsePrefixParams(map[string]any{ParamPrefixTokens: 128, ParamPrefixDelayMS: 250})
	if err != nil || tokens != 128 || delay != 250*time.Millisecond {
		t.Fatalf("overrides = (%d, %v, %v)", tokens, delay, err)
	}
	tokens, _, err = ParsePrefixParams(map[string]any{ParamPrefixTokens: "64"})
	if err != nil || tokens != 64 {
		t.Fatalf("string form = (%d, %v)", tokens, err)
	}
	tokens, _, err = ParsePrefixParams(map[string]any{ParamPrefixTokens: float64(32)})
	if err != nil || tokens != 32 {
		t.Fatalf("float form = (%d, %v)", tokens, err)
	}
	for name, bad := range map[string]map[string]any{
		"negative tokens": {ParamPrefixTokens: -1},
		"negative delay":  {ParamPrefixDelayMS: -5},
		"garbage":         {ParamPrefixTokens: "soon"},
		"fractional":      {ParamPrefixTokens: 1.5},
		"wrong type":      {ParamPrefixTokens: []any{1}},
	} {
		if _, _, err := ParsePrefixParams(bad); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}

func TestApproxTokenCount(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abcd", 1},
		{"abcde", 2},
		{"12345678", 2},
	}
	for _, tc := range tests {
		if got := approxTokenCount(tc.in); got != tc.want {
			t.Fatalf("approxTokenCount(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
	if approxTokenCount(strings.Repeat("й", 9)) != 3 {
		t.Fatal("multi-byte runes must count per rune, not per byte")
	}
}
