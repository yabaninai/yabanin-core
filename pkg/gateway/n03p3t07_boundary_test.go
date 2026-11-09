package cli

// N03-P03-T07 boundary corpus — gateway-glue aspects. The streaming
// primitives' hold/release boundaries live in
// pkg/pipeline/streaming/n03p3t07_boundary_test.go; this file owns the two
// seams the middleware adds on top:
//
//  1. streamPrefixParams: the prefix buffer shape resolved from policy
//     parameters — priority order (the FIRST declaring step in attachment
//     priority order wins, non-declaring steps are skipped), observable
//     errors (a malformed value yields the defaults PLUS an error for the
//     caller to log — one typo must not take the stream down and must not
//     silently change the buffer shape), and the explicit-zero boundary
//     (zero is legal and means "unset" downstream, never "disabled");
//  2. deriveReplacements: the textual diff that reconstructs the carry map
//     the pipeline Result never carried — separated edits pair exactly,
//     degenerate overlaps degrade to one coarse pair (over-segmentation is
//     never invented), pure insertions are unmappable, and every derived
//     map is ChunkProcessor-constructible (the finishPrefix observable
//     error is unreachable for diff-derived maps). Plus the end-to-end
//     parity pin: the derived map rewrites the rest of the stream so the
//     client view and the RT-05 cache document hold the same mutated text.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/streaming"
)

// t07Step renders one policy step carrying exactly params (the kind is
// irrelevant to streamPrefixParams: it reads Params only).
func t07Step(params map[string]any) pipeline.StepSpec {
	return pipeline.StepSpec{ID: "t07-step", Params: params}
}

// t07Plans renders one policyPlan per step group, in attachment priority
// order (the order streamPrefixParams consumes).
func t07Plans(stepGroups ...[]pipeline.StepSpec) []policyPlan {
	plans := make([]policyPlan, 0, len(stepGroups))
	for i, steps := range stepGroups {
		plans = append(plans, policyPlan{
			compiled: pipeline.Compiled{Policy: pipeline.Policy{
				Name:  "t07-plan",
				Steps: steps,
			}},
			priority: i,
		})
	}
	return plans
}

// TestN03P3T07_StreamPrefixParams_BoundaryCorpus pins the params→buffer
// boundary: priority order, error fallback to defaults, and the explicit
// zero shape.
func TestN03P3T07_StreamPrefixParams_BoundaryCorpus(t *testing.T) {
	def := [2]any{streaming.DefaultPrefixTokens, streaming.DefaultPrefixDelay}

	t.Run("no plans yields defaults", func(t *testing.T) {
		tokens, delay, err := streamPrefixParams(nil)
		require.NoError(t, err)
		assert.Equal(t, def[0], tokens)
		assert.Equal(t, def[1], delay)
	})

	t.Run("non-declaring steps are skipped", func(t *testing.T) {
		tokens, delay, err := streamPrefixParams(t07Plans([][]pipeline.StepSpec{
			{t07Step(map[string]any{"detector": "x", "unrelated": 1})},
			{t07Step(map[string]any{"other": "y"})},
		}...))
		require.NoError(t, err)
		assert.Equal(t, def[0], tokens)
		assert.Equal(t, def[1], delay)
	})

	t.Run("explicit nil values are unset", func(t *testing.T) {
		// paramInt treats a present-but-nil value as unset — pinned so a
		// YAML `prefix_tokens:` (empty value) keeps the defaults.
		tokens, delay, err := streamPrefixParams(t07Plans(
			[]pipeline.StepSpec{t07Step(map[string]any{
				streaming.ParamPrefixTokens:  nil,
				streaming.ParamPrefixDelayMS: nil,
			})},
		))
		require.NoError(t, err)
		assert.Equal(t, def[0], tokens)
		assert.Equal(t, def[1], delay)
	})

	t.Run("declared values apply", func(t *testing.T) {
		tokens, delay, err := streamPrefixParams(t07Plans(
			[]pipeline.StepSpec{t07Step(map[string]any{
				streaming.ParamPrefixTokens:  128,
				streaming.ParamPrefixDelayMS: 250,
			})},
		))
		require.NoError(t, err)
		assert.Equal(t, 128, tokens)
		assert.Equal(t, 250*time.Millisecond, delay)
	})

	t.Run("partial params keep the other default", func(t *testing.T) {
		tokens, delay, err := streamPrefixParams(t07Plans(
			[]pipeline.StepSpec{t07Step(map[string]any{streaming.ParamPrefixTokens: 128})},
		))
		require.NoError(t, err)
		assert.Equal(t, 128, tokens)
		assert.Equal(t, def[1], delay)
	})

	t.Run("first declaring step in priority order wins", func(t *testing.T) {
		tokens, _, err := streamPrefixParams(t07Plans(
			[]pipeline.StepSpec{t07Step(map[string]any{streaming.ParamPrefixTokens: 10})},
			[]pipeline.StepSpec{t07Step(map[string]any{streaming.ParamPrefixTokens: 20})},
		))
		require.NoError(t, err)
		assert.Equal(t, 10, tokens, "the higher-priority declaring step wins")
	})

	t.Run("priority skips non-declaring plans", func(t *testing.T) {
		tokens, _, err := streamPrefixParams(t07Plans(
			[]pipeline.StepSpec{t07Step(map[string]any{"unrelated": true})},
			[]pipeline.StepSpec{t07Step(map[string]any{streaming.ParamPrefixTokens: 20})},
		))
		require.NoError(t, err)
		assert.Equal(t, 20, tokens, "the first DECLARING step wins, declared or not above")
	})

	t.Run("malformed high-priority value shadows lower well-formed", func(t *testing.T) {
		// The first declaring step decides — its error returns immediately
		// with the defaults; a well-formed lower-priority plan is never
		// consulted (deterministic, no priority-order ambiguity).
		tokens, delay, err := streamPrefixParams(t07Plans(
			[]pipeline.StepSpec{t07Step(map[string]any{streaming.ParamPrefixTokens: "abc"})},
			[]pipeline.StepSpec{t07Step(map[string]any{streaming.ParamPrefixTokens: 20})},
		))
		require.Error(t, err, "the typo must be observable to the caller")
		assert.Equal(t, def[0], tokens, "the malformed value falls back to the default bound")
		assert.Equal(t, def[1], delay)
	})

	t.Run("malformed shapes error with defaults", func(t *testing.T) {
		for name, params := range map[string]map[string]any{
			"fractional tokens": {streaming.ParamPrefixTokens: 1.5},
			"garbage tokens":    {streaming.ParamPrefixTokens: "soon"},
			"wrong type":        {streaming.ParamPrefixTokens: []any{1}},
			"negative tokens":   {streaming.ParamPrefixTokens: -1},
			"negative delay":    {streaming.ParamPrefixDelayMS: -5},
			"bool delay":        {streaming.ParamPrefixDelayMS: true},
		} {
			t.Run(name, func(t *testing.T) {
				tokens, delay, err := streamPrefixParams(t07Plans(
					[]pipeline.StepSpec{t07Step(params)},
				))
				require.Error(t, err)
				assert.Equal(t, def[0], tokens)
				assert.Equal(t, def[1], delay)
			})
		}
	})

	t.Run("explicit zeros are legal and mean unset downstream", func(t *testing.T) {
		// ParsePrefixParams validates >= 0, so a policy CAN produce zeros;
		// NewPrefixGate maps zero to the package defaults — a policy can
		// tighten a threshold but can never disable one (the hold stays
		// memory-bounded by construction; pinned behaviorally at the gate
		// in streaming/n03p3t07_boundary_test.go).
		tokens, delay, err := streamPrefixParams(t07Plans(
			[]pipeline.StepSpec{t07Step(map[string]any{
				streaming.ParamPrefixTokens:  0,
				streaming.ParamPrefixDelayMS: 0,
			})},
		))
		require.NoError(t, err)
		assert.Equal(t, 0, tokens)
		assert.Equal(t, time.Duration(0), delay)
	})
}

// TestN03P3T07_DeriveReplacements_BoundaryCorpus pins the textual diff that
// reconstructs the carry map (the minimal OP-4/OP-8 glue: the pipeline
// Result carries the mutated payload but no structured map). Every
// non-nil derived map must be ChunkProcessor-constructible — the
// finishPrefix observable-error path is unreachable for diff-derived maps
// (no empty originals: pure insertions are skipped by construction).
func TestN03P3T07_DeriveReplacements_BoundaryCorpus(t *testing.T) {
	rows := []struct {
		name string
		orig string
		mut  string
		want map[string]string
	}{
		{
			name: "separated edits pair exactly",
			orig: "alpha beta-one beta beta-two gamma",
			mut:  "alpha {{YPP_1}} beta {{YPP_2}} gamma",
			want: map[string]string{"beta-one": "{{YPP_1}}", "beta-two": "{{YPP_2}}"},
		},
		{
			name: "production diff recovers the policy map",
			orig: "Отчёт: Ivanov Ivan, ключ 9f2c-77aa, конец.",
			mut:  "Отчёт: ORG_1, ключ {{YPP_1}}, конец.",
			want: map[string]string{"Ivanov Ivan": "ORG_1", "9f2c-77aa": "{{YPP_1}}"},
		},
		{
			name: "mid-text deletion absorbs the following bytes",
			// The resync needs >= 4 common bytes, so the pair necessarily
			// includes the byte after the deleted value. The map mirrors
			// the buffer diff faithfully; the documented consequence: a
			// later BARE occurrence of the value (without the absorbed
			// byte) is not rewritten — the carry map is a diff mirror, not
			// a semantic re-detector.
			orig: "keep beta drop",
			mut:  "keep  drop",
			want: map[string]string{"beta ": " "},
		},
		{
			name: "trailing-only deletion learns nothing",
			// A tail deletion has no resync anchor after it; nothing is
			// paired — the buffer mutation itself carried the whole edit.
			orig: "SECRETX",
			mut:  "SECRET",
			want: nil,
		},
		{
			name: "adjacent edits without resync degrade to one coarse pair",
			orig: "AAABBB",
			mut:  "X1Y2",
			want: map[string]string{"AAABBB": "X1Y2"},
		},
		{
			name: "single-byte insertion with long resync yields a minimal pair",
			// The pair is FAITHFUL for the buffer but degenerate as a
			// carry map: every later "S" would be rewritten to "XS".
			// Prior behavior, pinned: fidelity can degrade to
			// over-replacement (never under-replacement — the span is
			// still covered, safety preserved).
			orig: "head SECRET tail",
			mut:  "head XSECRET tail",
			want: map[string]string{"S": "XS"},
		},
		{
			name: "pure insertion at the end is unmappable",
			orig: "ab",
			mut:  "abX",
			want: nil,
		},
		{
			name: "duplicate originals keep the first pair",
			orig: "aa XX bb XX cc dd ee",
			mut:  "aa T1 bb T2 cc dd ee",
			want: map[string]string{"XX": "T1"},
		},
		{
			name: "identical texts yield no map",
			orig: "same text",
			mut:  "same text",
			want: nil,
		},
		{
			name: "empty original yields no map",
			orig: "",
			mut:  "mutated",
			want: nil,
		},
		{
			name: "empty mutated yields no map",
			orig: "original",
			mut:  "",
			want: nil,
		},
		{
			name: "oversized buffers fall back to no carry map",
			// The quadratic scan is bounded at 64KiB; larger prefix
			// buffers release without a carry map (documented fallback).
			orig: strings.Repeat("a", 64<<10+1) + " SECRET tail",
			mut:  strings.Repeat("a", 64<<10+1) + " X tail",
			want: nil,
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := deriveReplacements(row.orig, row.mut)
			if row.want == nil {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, row.want, got)
			}
			// Every derived map is carry-constructible.
			if len(got) > 0 {
				_, err := streaming.NewChunkProcessor(got)
				require.NoError(t, err, "a diff-derived map must never fail the carry constructor")
			}
		})
	}
}

// TestN03P3T07_DerivedCarry_ClientAndCacheParity pins the end-to-end glue
// shape at unit level: the prefix buffer is mutated by the policy, the
// textual diff reconstructs exactly the policy's map, and that derived map
// governs the rest of the stream so that the client's assembled view and
// the RT-05 cache document (DocumentMutator over the original text) hold
// the SAME mutated bytes — no original span anywhere, for every adversarial
// split of the rest stream.
func TestN03P3T07_DerivedCarry_ClientAndCacheParity(t *testing.T) {
	const (
		person = "Ivanov Ivan"
		secret = "super-secret-value"
		perTok = "ORG_1"
		secTok = "{{YPP_1}}"
	)
	prefix := "Отчёт: " + person + ", ключ " + secret + ", конец."
	mutPrefix := "Отчёт: " + perTok + ", ключ " + secTok + ", конец."

	derived := deriveReplacements(prefix, mutPrefix)
	require.Equal(t, map[string]string{person: perTok, secret: secTok}, derived,
		"the buffer diff must reconstruct exactly the policy's replacement map")

	rest := "Повтор: " + person + " и снова " + secret + " дважды " + secret + "!"
	want := strings.ReplaceAll(strings.ReplaceAll(rest, secret, secTok), person, perTok)

	// Adversarial splits of the rest stream: every rune-boundary two-way
	// split plus the one-rune-per-chunk family — the most adversarial split
	// that is still representable in a real SSE frame (a chunk is a JSON
	// string, so it can never carry a partial rune; mid-byte cuts are the
	// raw-bytes domain and are covered by the streaming-package corpus).
	runes := []rune(rest)
	var splits [][]string
	for i := 0; i <= len(runes); i++ {
		splits = append(splits, []string{string(runes[:i]), string(runes[i:])})
	}
	var perRune []string
	for _, r := range runes {
		perRune = append(perRune, string(r))
	}
	splits = append(splits, perRune)

	for i, chunks := range splits {
		cp, err := streaming.NewChunkProcessor(derived)
		require.NoError(t, err)
		fp := streaming.NewFrameProcessor(cp)
		var wire []byte
		var got strings.Builder
		for _, ch := range chunks {
			// streamChunkFrame renders the bare JSON payload; the gateway
			// handler writes whole SSE events — mirror that shape exactly.
			frame := fp.ProcessFrame([]byte("data: " + streamChunkFrame("c1", ch) + "\n\n"))
			wire = append(wire, frame...)
			got.WriteString(frameDeltaContent(frame))
		}
		if tail := fp.FlushFrame("c1", "m1"); tail != nil {
			wire = append(wire, tail...)
			got.WriteString(frameDeltaContent(tail))
		}
		assert.Equal(t, want, got.String(), "split %d: the client view must equal the batch replace", i)
		assert.NotContains(t, string(wire), secret, "split %d: raw secret on one frame", i)
		assert.NotContains(t, string(wire), person, "split %d: raw person on one frame", i)
	}

	// RT-05 parity: the cache document built from the ORIGINAL rest text
	// and mutated with the SAME derived map equals the client's assembled
	// view — client and cache never diverge.
	doc, err := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": map[string]any{"content": rest}}},
	})
	require.NoError(t, err)
	dm, err := streaming.NewDocumentMutator(derived)
	require.NoError(t, err)
	mutDoc, changed := dm.Mutate(doc)
	require.True(t, changed, "the derived map must mutate the cache document")
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal(mutDoc, &out))
	require.NotEmpty(t, out.Choices)
	assert.Equal(t, want, out.Choices[0].Message.Content,
		"the cache document must hold exactly the client's mutated text")
}
