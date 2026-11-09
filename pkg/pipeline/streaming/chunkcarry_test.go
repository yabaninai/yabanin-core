package streaming

import (
	"strings"
	"testing"
)

// refReplace is the batch reference implementation of the processor's
// semantics: leftmost-longest replace over the whole text, replacements
// emitted verbatim (never rescanned).
func refReplace(text string, repl map[string]string) string {
	pats := make([]string, 0, len(repl))
	for k := range repl {
		pats = append(pats, k)
	}
	var out strings.Builder
	i := 0
	for i < len(text) {
		best := ""
		for _, p := range pats {
			if len(p) > len(best) && i+len(p) <= len(text) && text[i:i+len(p)] == p {
				best = p
			}
		}
		if best != "" {
			out.WriteString(repl[best])
			i += len(best)
			continue
		}
		out.WriteByte(text[i])
		i++
	}
	return out.String()
}

// feed splits text into chunks of the given rune length, runs them through
// the processor, flushes, and returns the concatenated output.
func feed(t *testing.T, cp *ChunkProcessor, text string, runeChunk int) string {
	t.Helper()
	var sb strings.Builder
	runes := []rune(text)
	for i := 0; i < len(runes); i += runeChunk {
		end := min(i+runeChunk, len(runes))
		sb.WriteString(cp.Process(string(runes[i:end])))
	}
	sb.WriteString(cp.Flush())
	return sb.String()
}

func TestChunkProcessor_CarriesSplitAliasAcrossChunks(t *testing.T) {
	// The owner-decision invariant: an alias split across chunk boundaries
	// is still replaced in full, and the original never reaches the client.
	cp, err := NewChunkProcessor(map[string]string{"Иванов Иван": "ORG_1"})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	var got strings.Builder
	got.WriteString(cp.Process("Дорогой Иванов ")) // no match; holdback may hold "И"
	got.WriteString(cp.Process("Иван, привет!"))   // completes the alias
	got.WriteString(cp.Flush())
	want := "Дорогой ORG_1, привет!"
	if got.String() != want {
		t.Fatalf("carry output = %q, want %q", got.String(), want)
	}
	if strings.Contains(got.String(), "Иванов") {
		t.Fatal("original alias leaked to the client")
	}
}

func TestChunkProcessor_ByteByByteNeverLeaksOriginal(t *testing.T) {
	repl := map[string]string{"Иванов": "ORG_1", "skip previous": "[X]", "abc": "Y"}
	text := "Иванов сказал: skip previous, abc!"
	cp, err := NewChunkProcessor(repl)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	var got strings.Builder
	for _, r := range text {
		got.WriteString(cp.Process(string(r)))
	}
	got.WriteString(cp.Flush())
	want := refReplace(text, repl)
	if got.String() != want {
		t.Fatalf("byte-by-byte = %q, want %q", got.String(), want)
	}
	if strings.Contains(got.String(), "Иванов") || strings.Contains(got.String(), "skip previous") {
		t.Fatal("original value leaked to the client")
	}
}

func TestChunkProcessor_LongestMatchWins(t *testing.T) {
	cp, err := NewChunkProcessor(map[string]string{"ab": "1", "abc": "2"})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if got := feed(t, cp, "xabc abab", 1); got != "x2 11" {
		t.Fatalf("longest-first = %q, want %q", got, "x2 11")
	}
}

func TestChunkProcessor_MatchesBatchReplace(t *testing.T) {
	repl := map[string]string{
		"Иванов":        "ORG_1",
		"Иванов Иван":   "ORG_FULL",
		"Иван":          "ORG_2",
		"secret-key":    "[REDACTED]",
		"abc":           "Y",
		"skip previous": "[X]",
	}
	texts := []string{
		"Иванов Иван сказал abc",
		"Ивановедение и Иван",
		"the secret-key is here; skip previous now",
		"abcabc Иванов abc",
		"no matches at all here",
		"Ив",
		"prefix ending in match: secret-key",
	}
	for _, text := range texts {
		want := refReplace(text, repl)
		for _, chunkSize := range []int{1, 2, 3, 5, 8, 64} {
			cp, err := NewChunkProcessor(repl)
			if err != nil {
				t.Fatalf("construct: %v", err)
			}
			if got := feed(t, cp, text, chunkSize); got != want {
				t.Fatalf("chunk=%d text=%q: got %q, want %q", chunkSize, text, got, want)
			}
		}
	}
}

func TestChunkProcessor_UTF8SplitAcrossChunks(t *testing.T) {
	// A multi-byte rune split mid-sequence must reassemble into a valid
	// match (or literal), never corrupt the output.
	cp, err := NewChunkProcessor(map[string]string{"Иванов": "ORG_1"})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	raw := "Иванов"
	var got strings.Builder
	for i := 0; i < len(raw); i++ { // byte-level feed, splitting D0 98 pairs
		got.WriteString(cp.Process(raw[i : i+1]))
	}
	got.WriteString(cp.Flush())
	if got.String() != "ORG_1" {
		t.Fatalf("utf8 split = %q, want ORG_1", got.String())
	}
}

func TestChunkProcessor_FlushReleasesTail(t *testing.T) {
	cp, err := NewChunkProcessor(map[string]string{"secret-key": "[REDACTED]"})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if out := cp.Process("ending with secret-"); out != "ending with " {
		t.Fatalf("mid-stream = %q", out)
	}
	if cp.Held() != len("secret-") {
		t.Fatalf("held = %d, want the potential-match tail", cp.Held())
	}
	if out := cp.Flush(); out != "secret-" {
		t.Fatalf("flush = %q, want the unmatchable tail as-is", out)
	}
	if cp.Held() != 0 {
		t.Fatal("flush left bytes pending")
	}
}

func TestChunkProcessor_ReplacementNotRescanned(t *testing.T) {
	// A replacement that contains another pattern must not recurse: the
	// output is emitted verbatim.
	cp, err := NewChunkProcessor(map[string]string{"aa": "aba", "b": "Z"})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if got := feed(t, cp, "aa", 1); got != "aba" {
		t.Fatalf("recursive replacement = %q, want aba", got)
	}
}

func TestChunkProcessor_EmptyChunkNoop(t *testing.T) {
	cp, err := NewChunkProcessor(map[string]string{"x": "y"})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if out := cp.Process(""); out != "" {
		t.Fatalf("empty chunk produced %q", out)
	}
	if out := cp.Flush(); out != "" {
		t.Fatalf("empty stream produced %q", out)
	}
}

func TestChunkProcessor_ConstructorRejectsBadMaps(t *testing.T) {
	if _, err := NewChunkProcessor(nil); err == nil {
		t.Fatal("nil map accepted")
	}
	if _, err := NewChunkProcessor(map[string]string{}); err == nil {
		t.Fatal("empty map accepted")
	}
	if _, err := NewChunkProcessor(map[string]string{"": "x"}); err == nil {
		t.Fatal("empty pattern accepted")
	}
}

func TestChunkProcessor_ReuseAfterFlush(t *testing.T) {
	cp, err := NewChunkProcessor(map[string]string{"ab": "1"})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if got := feed(t, cp, "ab ab", 2); got != "1 1" {
		t.Fatalf("first stream = %q", got)
	}
	if got := feed(t, cp, "ab", 1); got != "1" {
		t.Fatalf("reused stream = %q, want 1", got)
	}
}
