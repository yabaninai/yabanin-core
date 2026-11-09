package streaming

// N03-P03-T05 adversarial chunk-span corpus (packet facet 2: «Отрицательный
// сценарий»). The acceptance is executable: for EVERY chunk split of the
// forbidden-span corpus — exhaustive for short texts, structured and
// seeded for long ones — the forbidden originals never reach the client,
// the decoded stream equals the batch leftmost-longest replace of the
// whole text, and the card's negative is pinned by two per-step invariants:
//
//   - the carry stage holds at most maxLen-1 bytes at every step: it may
//     delay delivery only by what a learned pattern could still complete,
//     never by more (it cannot withhold the stream to validate future
//     tokens, and it cannot withhold-then-flood);
//   - the accumulated emit is always a prefix of the final text.
//
// Byte-level splits cover the ChunkProcessor primitive; rune-level splits
// cover the SSE chain, where a frame boundary cannot cut inside a rune
// (the frame content is a JSON string). This corpus exposed a real
// hold-bound defect: the deferred-match branch of drain() computed its
// hold-back on the literal run ALONE, ignoring the deferred region already
// pending, so Held() could reach 2*maxLen-2 (patterns dab/abc/abcd, split
// ["da","abc"] left 5 of a maxLen-1=3 bound pending).

import (
	"bytes"
	"context"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// spanMaxPat returns the longest pattern length in bytes. The carry stage
// must never hold more than maxPat-1 bytes (pipeline.md §7 item 3).
func spanMaxPat(repl map[string]string) int {
	m := 0
	for k := range repl {
		if len(k) > m {
			m = len(k)
		}
	}
	return m
}

// spanSeqReplace mirrors the sequential fixture replacement
// (advMultiMaskStep): ReplaceAll per pair, longest original first.
func spanSeqReplace(text string, pairs [][2]string) string {
	sorted := make([][2]string, len(pairs))
	copy(sorted, pairs)
	slices.SortStableFunc(sorted, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
	out := text
	for _, p := range sorted {
		out = strings.ReplaceAll(out, p[0], p[1])
	}
	return out
}

// spanSelfCheck validates the corpus row invariants that make the
// sequential fixture replacement equal the batch leftmost-longest replace:
// no replacement may contain any pattern (emitted replacements are never
// rescanned), sequential must equal batch, the expected text must contain
// no pattern, and the buffered head must contain every pattern complete
// (production deriveReplacements learns the carry map from the buffer
// diff). A row failing here is a corpus bug, not a pipeline one.
func spanSelfCheck(t *testing.T, name, head, rest string, pairs [][2]string, want string) {
	t.Helper()
	repl := advReplMap(pairs)
	for _, p := range pairs {
		for _, q := range pairs {
			if strings.Contains(p[1], q[0]) {
				t.Fatalf("%s: replacement %q contains pattern %q (sequential != batch)", name, p[1], q[0])
			}
		}
	}
	full := head + rest
	if seq, ref := spanSeqReplace(full, pairs), refReplace(full, repl); seq != ref {
		t.Fatalf("%s: sequential fixture replace %q != batch replace %q (corpus not parity-safe)", name, seq, ref)
	}
	for _, p := range pairs {
		if strings.Contains(want, p[0]) {
			t.Fatalf("%s: expected output still contains pattern %q", name, p[0])
		}
		if !strings.Contains(head, p[0]) {
			t.Fatalf("%s: head does not contain pattern %q complete (the map would not learn it)", name, p[0])
		}
	}
}

// spanFeed feeds one split through a fresh processor, asserting after every
// step the held-bytes bound and the emit-prefix invariant, and after Flush
// the exact expected total.
func spanFeed(t *testing.T, name string, repl map[string]string, want string, chunks []string) string {
	t.Helper()
	cp, err := NewChunkProcessor(repl)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	maxHold := spanMaxPat(repl) - 1
	var got strings.Builder
	for i, ch := range chunks {
		got.WriteString(cp.Process(ch))
		if cp.Held() > maxHold {
			t.Fatalf("%s: step %d (chunk %q): Held()=%d exceeds maxLen-1=%d — the carry stage withheld more than any learned pattern could still complete", name, i, ch, cp.Held(), maxHold)
		}
		if !strings.HasPrefix(want, got.String()) {
			t.Fatalf("%s: step %d: emitted %q is not a prefix of the expected %q (withhold-then-flood)", name, i, got.String(), want)
		}
	}
	got.WriteString(cp.Flush())
	if cp.Held() != 0 {
		t.Fatalf("%s: flush left %d bytes held", name, cp.Held())
	}
	return got.String()
}

// spanExhaustiveSplits yields every subset of interior byte boundaries —
// 2^(L-1) splits; nil for texts longer than 12 bytes (the structured and
// seeded families cover those).
func spanExhaustiveSplits(text string) [][]string {
	L := len(text)
	if L == 0 || L > 12 {
		return nil
	}
	res := make([][]string, 0, 1<<(L-1))
	for mask := 0; mask < 1<<(L-1); mask++ {
		var chunks []string
		start := 0
		for b := 0; b < L-1; b++ {
			if mask&(1<<b) != 0 {
				chunks = append(chunks, text[start:b+1])
				start = b + 1
			}
		}
		res = append(res, append(chunks, text[start:]))
	}
	return res
}

// spanUniformSplits feeds fixed-size byte chunks for every size 1..max.
func spanUniformSplits(text string, max int) [][]string {
	res := make([][]string, 0, max)
	for size := 1; size <= max; size++ {
		var chunks []string
		for i := 0; i < len(text); i += size {
			chunks = append(chunks, text[i:min(i+size, len(text))])
		}
		res = append(res, chunks)
	}
	return res
}

// spanTwoWaySplits cuts the text into two chunks at every byte offset
// (including the degenerate empty halves — Process("") is a no-op).
func spanTwoWaySplits(text string) [][]string {
	res := make([][]string, 0, len(text)+1)
	for i := 0; i <= len(text); i++ {
		res = append(res, []string{text[:i], text[i:]})
	}
	return res
}

// spanRandomSplits draws count deterministic 2..4-way splits from a fixed
// PCG seed — the same corpus on every machine and run.
func spanRandomSplits(text string, count int) [][]string {
	rng := rand.New(rand.NewPCG(20261025, 1010)) //nolint:gosec // G404: seeded sampler for a reproducible corpus, not a secret
	res := make([][]string, 0, count)
	for i := 0; i < count; i++ {
		cuts := make(map[int]struct{}, 3)
		for len(cuts) < 1+rng.IntN(3) { // 1..3 interior cuts
			cuts[rng.IntN(len(text))] = struct{}{}
		}
		pos := make([]int, 0, len(cuts))
		for p := range cuts {
			pos = append(pos, p)
		}
		slices.Sort(pos)
		var chunks []string
		start := 0
		for _, p := range pos {
			chunks = append(chunks, text[start:p+1])
			start = p + 1
		}
		res = append(res, append(chunks, text[start:]))
	}
	return res
}

// spanRunUnitRow runs one unit row through every split family.
func spanRunUnitRow(t *testing.T, name string, repl map[string]string, text string) {
	t.Helper()
	want := refReplace(text, repl)
	splits := spanExhaustiveSplits(text)
	splits = append(splits, spanUniformSplits(text, spanMaxPat(repl)+1)...)
	splits = append(splits, spanTwoWaySplits(text)...)
	splits = append(splits, spanRandomSplits(text, 256)...)
	for i, chunks := range splits {
		if got := spanFeed(t, name, repl, want, chunks); got != want {
			t.Fatalf("split %d %q: output %q, want %q", i, chunks, got, want)
		}
	}
}

// spanBinom returns C(n, k).
func spanBinom(n, k int) int {
	if k < 0 || k > n {
		return 0
	}
	if k > n-k {
		k = n - k
	}
	r := 1
	for i := 1; i <= k; i++ {
		r = r * (n - k + i) / i
	}
	return r
}

// spanCompositions returns the sorted cut-point sets splitting L items
// into k non-empty parts (C(L-1, k-1) of them), in lexicographic order.
// When the family exceeds limit it stride-samples deterministically — the
// sampled subset is stable for a given (L, k, limit).
func spanCompositions(L, k, limit int) [][]int {
	if k < 1 || k > L {
		return nil
	}
	if k == 1 {
		return [][]int{{}}
	}
	n, m := L-1, k-1
	step := 1
	if total := spanBinom(n, m); total > limit {
		step = (total + limit - 1) / limit
	}
	var res [][]int
	comb := make([]int, m)
	for i := range comb {
		comb[i] = i
	}
	idx := 0
	for {
		if idx%step == 0 {
			res = append(res, append([]int(nil), comb...))
		}
		idx++
		j := m - 1
		for j >= 0 && comb[j] == n-m+j {
			j--
		}
		if j < 0 {
			break
		}
		comb[j]++
		for d := j + 1; d < m; d++ {
			comb[d] = comb[d-1] + 1
		}
	}
	return res
}

// spanRunStream replays the production prefix→carry chain (the advRunStream
// shape) with per-frame assertions: after every released frame the decoded
// wire is a prefix of the expected text and the carry processor holds at
// most maxLen-1 bytes; after the flush frame the decoded stream equals the
// expected text exactly, no pattern survives on the decoded or raw wire,
// and the stream terminates with [DONE]. The runner is built once per row
// and reused: the engine clones the payload per run.
func spanRunStream(t *testing.T, runner Runner, pairs [][2]string, head string, restChunks []string, want string, maxHold int) {
	t.Helper()
	g := NewPrefixGate(PrefixConfig{Runner: runner})
	g.Ingest(head)
	out := g.Flush(context.Background())
	if out.Decision != PrefixRelease {
		t.Fatalf("prefix decision = %q (err %v), want release", out.Decision, out.Err)
	}
	if out.Text == head {
		t.Fatalf("prefix mutation missing (carry map would not be derived): %q", out.Text)
	}
	cp, err := NewChunkProcessor(advReplMap(pairs))
	if err != nil {
		t.Fatalf("carry map: %v", err)
	}
	fp := NewFrameProcessor(cp)
	var wire []byte
	var decoded strings.Builder
	emit := func(content string) {
		frame := fp.ProcessFrame(advChunkFrame(content))
		wire = append(wire, frame...)
		decoded.WriteString(advDecodedStream(t, frame))
		if !strings.HasPrefix(want, decoded.String()) {
			t.Fatalf("decoded %q is not a prefix of the expected %q", decoded.String(), want)
		}
		if cp.Held() > maxHold {
			t.Fatalf("after frame %q: Held()=%d exceeds maxLen-1=%d", content, cp.Held(), maxHold)
		}
	}
	emit(head)
	for _, c := range restChunks {
		emit(c)
	}
	if tail := fp.FlushFrame("adv-1", "adv-model"); tail != nil {
		wire = append(wire, tail...)
		decoded.WriteString(advDecodedStream(t, tail))
		if !strings.HasPrefix(want, decoded.String()) {
			t.Fatalf("flushed tail broke the prefix invariant: %q vs %q", decoded.String(), want)
		}
	}
	if cp.Held() != 0 {
		t.Fatalf("flush left %d bytes held", cp.Held())
	}
	if decoded.String() != want {
		t.Fatalf("decoded stream = %q, want %q", decoded.String(), want)
	}
	wire = append(wire, sseDone...)
	for _, p := range pairs {
		if strings.Contains(decoded.String(), p[0]) {
			t.Fatalf("forbidden span %q leaked to the client view", p[0])
		}
		if bytes.Contains(wire, []byte(p[0])) {
			t.Fatalf("forbidden span %q present in raw wire bytes", p[0])
		}
	}
	if !bytes.HasSuffix(wire, []byte("data: [DONE]\n\n")) {
		t.Fatal("wire does not terminate with [DONE]")
	}
}

// spanE2ERow is one end-to-end corpus row: head is the buffered prefix
// (contains every pattern complete — the carry map learns them all), rest
// is cut into k chunks by two-way splits and k-chunk compositions.
type spanE2ERow struct {
	name  string
	pairs [][2]string
	head  string
	rest  string
	maxK  int // cap on composition size (0 = no cap)
	exhK  int // exhaustive composition sizes up to this k
	sampK int // sampled compositions per larger k (0 = skip larger k)
}

// spanRunE2ERows drives the e2e corpus: per row the rest is split two-ways
// at every rune offset and into every (or sampled) k-chunk composition.
func spanRunE2ERows(t *testing.T, rows []spanE2ERow) {
	t.Helper()
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			repl := advReplMap(row.pairs)
			want := refReplace(row.head+row.rest, repl)
			spanSelfCheck(t, row.name, row.head, row.rest, row.pairs, want)
			maxHold := spanMaxPat(repl) - 1
			runner := advMultiMaskRunner(t, row.pairs)
			runes := []rune(row.rest)
			for i := 0; i <= len(runes); i++ { // two-way at every rune offset
				spanRunStream(t, runner, row.pairs, row.head, []string{string(runes[:i]), string(runes[i:])}, want, maxHold)
			}
			for k := 1; k <= len(runes); k++ { // k-chunk compositions
				if row.maxK > 0 && k > row.maxK {
					break
				}
				limit := 1 << 30
				if k > row.exhK {
					if row.sampK == 0 {
						continue
					}
					limit = row.sampK
				}
				for _, cuts := range spanCompositions(len(runes), k, limit) {
					var chunks []string
					start := 0
					for _, c := range cuts {
						chunks = append(chunks, string(runes[start:c+1]))
						start = c + 1
					}
					chunks = append(chunks, string(runes[start:]))
					spanRunStream(t, runner, row.pairs, row.head, chunks, want, maxHold)
				}
			}
		})
	}
}

// TestChunkSpans_ExhaustiveSplitsForbiddenSpans: unit-level corpus over the
// ChunkProcessor primitive. For every row the full split space (exhaustive
// for short byte strings) plus the structured and seeded families must
// reproduce the batch leftmost-longest replace with the hold bound intact
// at every step. The rows stress the interaction shapes: prefix chains
// (leftmost-longest deferral), suffix chains (shared tails), cyrillic
// multi-byte patterns, and partial runs.
func TestChunkSpans_ExhaustiveSplitsForbiddenSpans(t *testing.T) {
	rows := []struct {
		name string
		repl map[string]string
		text string
	}{
		{"prefix chain", map[string]string{"abc": "1", "abcd": "2", "abcde": "3"}, "abcabcd"},
		{"prefix chain offset", map[string]string{"abc": "1", "abcd": "2", "abcde": "3"}, "xabcdab"},
		{"prefix chain tail", map[string]string{"abc": "1", "abcd": "2", "abcde": "3"}, "abcdeabc"},
		{"suffix chain", map[string]string{"secret-key": "S", "secret": "Q", "key": "K"}, "keysecret"},
		{"suffix chain mixed", map[string]string{"secret-key": "S", "secret": "Q", "key": "K"}, "keysecret-key key"},
		{"cyrillic alias", map[string]string{"Иванов": "ORG_1", "Иванов Иван": "ORG_FULL", "Иван": "ORG_2"}, "ИвановИван"},
		{"partial runs", map[string]string{"aab": "X1", "aac": "X2", "ab": "X3"}, "aabaacab"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			spanRunUnitRow(t, row.name, row.repl, row.text)
		})
	}
}

// TestChunkSpans_HoldbackBounded_NeverWithholdsAllThenFloods pins the
// hold-bound defect this corpus was built to expose: the deferred-match
// branch of drain() held back its literal-run tail computed in isolation,
// so a literal tail that is a proper pattern prefix plus a deferred region
// could push Held() past maxLen-1 (5 pending of a 3-byte bound for
// patterns dab/abc/abcd split as ["da","abc"]). Every split must keep
// Held() <= maxLen-1 at every step, must never emit beyond the expected
// text, and must deliver exactly the batch replace after Flush.
func TestChunkSpans_HoldbackBounded_NeverWithholdsAllThenFloods(t *testing.T) {
	rows := []struct {
		name string
		repl map[string]string
		text string
	}{
		{"deferred match over held prefix", map[string]string{"dab": "1", "abc": "2", "abcd": "3"}, "daabc"},
		{"deferred after leading literal", map[string]string{"dab": "1", "abc": "2", "abcd": "3"}, "x daabc"},
		{"boundary tight", map[string]string{"ab": "1", "abcd": "2"}, "abx"},
		{"mixed runs", map[string]string{"dab": "1", "abc": "2", "abcd": "3"}, "daabc dab abx"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			spanRunUnitRow(t, row.name, row.repl, row.text)
		})
	}
}

// TestAdversarial_SecretSpanning_NChunksNeverLeaks: the secret trigger cut
// into EVERY k-chunk composition of the post-prefix stream (exhaustive for
// the short alias, exhaustive k<=3 plus seeded sampling above for the
// canonical trigger) still never reaches the client — decoded or raw wire
// — and the hold bound survives every frame boundary end-to-end.
func TestAdversarial_SecretSpanning_NChunksNeverLeaks(t *testing.T) {
	rows := []spanE2ERow{
		{
			name:  "short secret",
			pairs: [][2]string{{"zzsecretzz", "[MASK]"}},
			head:  "head zzsecretzz",
			rest:  " zzsecretzz ", // 12 runes: the full 2^11 split space
			exhK:  12,
		},
		{
			name:  "canonical secret",
			pairs: [][2]string{{testSecretTrigger, testSecretMask}},
			head:  "value " + testSecretTrigger,
			rest:  " and " + testSecretTrigger + "!", // 24 runes
			exhK:  3,
			sampK: 100,
			maxK:  12,
		},
	}
	spanRunE2ERows(t, rows)
}

// TestAdversarial_MultiPatternCorpus_PrefixSuffixOverlaps: multi-pattern
// end-to-end rows where patterns overlap each other (prefix chains, shared
// suffixes, partial runs) — the shapes where leftmost-longest deferral and
// the hold-back interact — across two-way splits and k-chunk compositions.
func TestAdversarial_MultiPatternCorpus_PrefixSuffixOverlaps(t *testing.T) {
	rows := []spanE2ERow{
		{
			name:  "prefix chain",
			pairs: [][2]string{{"abcde", "R5"}, {"abcd", "R4"}, {"abc", "R3"}},
			head:  "abc abcd abcde",
			rest:  " abcdeabcd abcd abc",
			exhK:  3,
			sampK: 60,
			maxK:  8,
		},
		{
			name:  "suffix chain",
			pairs: [][2]string{{"secret-key", "T1"}, {"secret", "T2"}, {"key", "T3"}},
			head:  "key secret secret-key",
			rest:  " keysecret secret-key key",
			exhK:  3,
			sampK: 60,
			maxK:  8,
		},
		{
			name:  "cyrillic overlaps",
			pairs: [][2]string{{"Иванов Иван", "ФИО"}, {"Иванов", "Ф1"}, {"Иван", "Ф2"}},
			head:  "Иванов Иван и Иванов",
			rest:  ", Иван и Иванов Иван снова",
			exhK:  3,
			sampK: 60,
			maxK:  8,
		},
		{
			name:  "partial runs",
			pairs: [][2]string{{"aab", "X1"}, {"aac", "X2"}, {"ab", "X3"}},
			head:  "aab aac",
			rest:  " aabaac ab",
			exhK:  10, // 10 runes: the full 2^9 split space
		},
	}
	spanRunE2ERows(t, rows)
}
