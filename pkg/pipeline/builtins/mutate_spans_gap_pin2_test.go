package builtins

// Permanent pins for the remaining RV-1 redaction invariant gaps:
//
//   - GAP-R7: JSON validity is a BYTE-SPLICE consequence, not a guarantee —
//     the mutator never re-encodes, so output stays valid JSON exactly while
//     spans lie inside JSON string literals; a match on a structural region
//     intentionally yields invalid JSON.
//   - GAP-R2: a finding span crossing the "\n" message join matches no
//     layout segment and FAILS the step (stale layout, fail-closed) —
//     never a silent wrong-place redaction.
//   - GAP-R4: adjacent (touching) spans stay SEPARATE edits — end ==
//     next.start never merges.
//   - GAP-R8: ctx cancellation is honored inside the redaction path (entry,
//     edit collection, and between segments mid-apply), and the layout skips
//     an empty message without shifting its neighbors' offsets.
//
// These tests PIN current deliberate behavior; a red run is a regression,
// not a license to change the mutation contract.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// GAP-R7: the byte-splice ⇒ JSON-validity-iff-in-string contract.
func TestGapPinByteSpliceJSONValidityContract(t *testing.T) {
	params := map[string]any{"patterns": []any{map[string]any{"category": "d", "pattern": "[0-9]{3}"}}}

	// A span INSIDE a JSON string literal: the spliced token keeps the
	// document valid JSON — no re-encoding, so spacing and keys outside the
	// span are byte-identical.
	in := &pipeline.Payload{Kind: pipeline.KindToolArgs, Body: []byte(`{"a": 1, "b" : "v 555 w"}`)}
	res := runMutatorOne(t, NameRedact, params, in)
	assertRan(t, res)
	got := string(content2Body(t, res))
	if want := `{"a": 1, "b" : "v [REDACTED:d:1] w"}`; got != want {
		t.Errorf("in-string splice = %q, want byte-spliced %q (no re-encode)", got, want)
	}
	if !json.Valid([]byte(got)) {
		t.Errorf("in-string span must leave valid JSON, got %q", got)
	}

	// A span on a BARE NUMBER (structural region): the splice intentionally
	// produces INVALID JSON — this is the documented contract, pinned here by
	// name (TestRedact_BodyAndChunkTargets asserts the text but not the
	// validity invariant).
	in = &pipeline.Payload{Kind: pipeline.KindToolArgs, Body: []byte(`{"ref": 555}`)}
	res = runMutatorOne(t, NameRedact, params, in)
	assertRan(t, res)
	got = string(content2Body(t, res))
	if want := `{"ref": [REDACTED:d:1]}`; got != want {
		t.Errorf("structural splice = %q, want %q", got, want)
	}
	if json.Valid([]byte(got)) {
		t.Errorf("a structural-region span intentionally yields invalid JSON; %q must not silently re-encode", got)
	}
}

// GAP-R2: a span crossing the "\n" message join matches no segment and fails
// the step closed (stale layout) — the payload is never partially mutated.
func TestGapPinSpanAcrossMessageJoinFailsClosed(t *testing.T) {
	st, err := NewRedact(nil)
	if err != nil {
		t.Fatal(err)
	}
	build := func() *pipeline.Payload {
		in := reqPayload("abcdef")
		in.Messages = append(in.Messages, pipeline.Message{Role: "user", Content: "ghijkl"})
		return in
	}
	// Joined text is "abcdef\nghijkl" (len 13): msg 0 covers [0,6), the join
	// byte sits at 6, msg 1 covers [7,13).
	for _, span := range []string{"2:9", "2:7", "5:8"} {
		in := build()
		out := &pipeline.Result{Findings: []pipeline.Finding{
			{Step: "d", Category: "x", Span: span, Action: pipeline.ActionMask},
		}}
		err := st.Run(context.Background(), nil, in, out)
		if err == nil {
			t.Errorf("span %q crosses the message join: want a stale-layout step error", span)
			continue
		}
		if !strings.Contains(err.Error(), "stale") {
			t.Errorf("span %q: error = %v, want the stale-layout message", span, err)
		}
		if in.Messages[0].Content != "abcdef" || in.Messages[1].Content != "ghijkl" {
			t.Errorf("span %q mutated the payload on a failed step: %q / %q", span, in.Messages[0].Content, in.Messages[1].Content)
		}
	}
	// In-span-of-one-message spans around the join still apply normally:
	// end == the join offset is IN message 0.
	in := build()
	out := &pipeline.Result{Findings: []pipeline.Finding{
		{Step: "d", Category: "x", Span: "1:6", Action: pipeline.ActionMask},
	}}
	if err := st.Run(context.Background(), nil, in, out); err != nil {
		t.Fatalf("in-segment span 1:6: %v", err)
	}
	if got, want := in.Messages[0].Content, "a[REDACTED:x:1]"; got != want {
		t.Errorf("in-segment redaction = %q, want %q", got, want)
	}
	if in.Messages[1].Content != "ghijkl" {
		t.Errorf("neighboring message was touched: %q", in.Messages[1].Content)
	}
}

// GAP-R4: adjacent (touching) spans stay SEPARATE edits — end == next.start
// never merges, so each span gets its own token and ordinal.
func TestGapPinAdjacentSpansStaySeparateEdits(t *testing.T) {
	st, err := NewRedact(nil)
	if err != nil {
		t.Fatal(err)
	}
	in := reqPayload("abcdef")
	out := &pipeline.Result{Findings: []pipeline.Finding{
		{Step: "d", Category: "one", Span: "0:2", Action: pipeline.ActionMask},
		{Step: "d", Category: "two", Span: "2:4", Action: pipeline.ActionMask},
	}}
	if err := st.Run(context.Background(), nil, in, out); err != nil {
		t.Fatal(err)
	}
	if got, want := in.Messages[0].Content, "[REDACTED:one:1][REDACTED:two:2]ef"; got != want {
		t.Fatalf("adjacent findings = %q, want two separate tokens %q", got, want)
	}

	// Own-pattern matches can also be adjacent: "12" matches [0-9] twice.
	res := runMutatorOne(t, NameRedact, map[string]any{
		"patterns": []any{map[string]any{"category": "d", "pattern": "[0-9]"}},
	}, &pipeline.Payload{Kind: pipeline.KindToolArgs, Body: []byte("12")})
	assertRan(t, res)
	if got, want := string(content2Body(t, res)), "[REDACTED:d:1][REDACTED:d:2]"; got != want {
		t.Errorf("adjacent pattern matches = %q, want %q", got, want)
	}
}

// GAP-R8a: ctx cancellation inside the redaction path — the entry check, the
// finding scan, and the segment-boundary check mid-apply all stop the step
// with ctx.Err and never write a partial mutation.
func TestGapPinRedactContextCancellation(t *testing.T) {
	st, err := NewRedact(nil)
	if err != nil {
		t.Fatal(err)
	}
	findings := func() []pipeline.Finding {
		return []pipeline.Finding{{Step: "d", Category: "x", Span: "0:3", Action: pipeline.ActionMask}}
	}

	// Entry: a pre-cancelled ctx errors before touching the payload.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := reqPayload("secret")
	if err := st.Run(ctx, nil, in, &pipeline.Result{Findings: findings()}); !errors.Is(err, context.Canceled) {
		t.Errorf("pre-cancelled Run = %v, want context.Canceled", err)
	}
	if in.Messages[0].Content != "secret" {
		t.Errorf("cancelled run mutated the payload: %q", in.Messages[0].Content)
	}

	// Collection: the per-finding loop honors cancellation.
	cfg, err := parseSpanMutator(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collectSpanEdits(ctx, cfg, layoutOf(in), findings()); !errors.Is(err, context.Canceled) {
		t.Errorf("collectSpanEdits with a cancelled ctx = %v, want context.Canceled", err)
	}

	// Mid-apply: cancellation injected while the FIRST of two segments is
	// being built stops the apply at the next segment boundary — no texts
	// are returned, so the caller can never write back a partial plan.
	two := reqPayload("aaaa")
	two.Messages = append(two.Messages, pipeline.Message{Role: "user", Content: "bbbb"})
	l := layoutOf(two)
	edits := []plannedEdit{
		{seg: 0, start: 0, end: 4, category: "x"},
		{seg: 1, start: 0, end: 4, category: "y"},
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	texts, err := applySpanEdits(ctx2, l, edits, func(e plannedEdit, ord int) (string, error) {
		cancel2() // hostile world: the run is cancelled after the first edit
		return "[T]", nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("mid-apply cancellation = %v, want context.Canceled", err)
	}
	if texts != nil {
		t.Errorf("a cancelled apply returned texts %q, want nil (nothing to write back)", texts)
	}
	if two.Messages[0].Content != "aaaa" || two.Messages[1].Content != "bbbb" {
		t.Errorf("cancelled apply mutated the payload: %q / %q", two.Messages[0].Content, two.Messages[1].Content)
	}
}

// GAP-R8b: an empty message among non-empty ones is skipped by the layout —
// it never shifts the offsets of later messages and is never written to.
func TestGapPinEmptyMessageLayoutEdge(t *testing.T) {
	in := reqPayload("first 777")
	in.Messages = append(in.Messages,
		pipeline.Message{Role: "user", Content: ""},
		pipeline.Message{Role: "user", Content: "third 888"})
	res := runMutatorOne(t, NameRedact, map[string]any{
		"patterns": []any{map[string]any{"category": "d", "pattern": "[0-9]{3}"}},
	}, in)
	assertRan(t, res)
	m := res.Mutated.Messages
	if m == nil {
		t.Fatal("Mutated is nil, want a mutated payload")
	}
	want := []string{"first [REDACTED:d:1]", "", "third [REDACTED:d:2]"}
	if len(m) != len(want) {
		t.Fatalf("messages = %d, want %d", len(m), len(want))
	}
	for i := range want {
		if m[i].Content != want[i] {
			t.Errorf("messages[%d] = %q, want %q (empty message must not shift offsets or ordinals)", i, m[i].Content, want[i])
		}
	}
}
