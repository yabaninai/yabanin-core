package builtins

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// runMutatorOne compiles a one-step enforce policy (step id "s1") declaring
// name as a MUTATOR and runs it against in.
func runMutatorOne(t *testing.T, name string, params map[string]any, in *pipeline.Payload, opts ...func(*pipeline.Policy)) *pipeline.Result {
	t.Helper()
	return runStepSpecs(t, []pipeline.StepSpec{{ID: "s1", Mutator: name, Params: params}}, in, opts...)
}

// runStepSpecs compiles and runs the given steps against in.
func runStepSpecs(t *testing.T, specs []pipeline.StepSpec, in *pipeline.Payload, opts ...func(*pipeline.Policy)) *pipeline.Result {
	t.Helper()
	eng := testEngine(t)
	pol := pipeline.Policy{
		APIVersion: pipeline.APIVersionYPP,
		Kind:       pipeline.KindPolicy,
		Name:       "test-policy",
		Mode:       pipeline.ModeEnforce,
		Hooks:      []pipeline.Hook{pipeline.HookPreUpstream},
		Steps:      specs,
	}
	for _, o := range opts {
		o(&pol)
	}
	c, err := eng.CompilePolicy(pol)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return eng.Run(context.Background(), []pipeline.Compiled{c}, in)
}

// detectorPlus builds a two-step detector→mutator policy spec pair.
func detectorPlus(det, mut string, detParams, mutParams map[string]any) []pipeline.StepSpec {
	return []pipeline.StepSpec{
		{ID: "s1", Detector: det, Params: detParams},
		{ID: "s2", Mutator: mut, Params: mutParams},
	}
}

func content(t *testing.T, res *pipeline.Result) string {
	t.Helper()
	if res.Mutated == nil {
		t.Fatal("Mutated is nil, want a mutated payload")
	}
	return payloadText(res.Mutated)
}

// assertAllRan asserts every step of res ran without error.
func assertAllRan(t *testing.T, res *pipeline.Result) {
	t.Helper()
	for i, tr := range res.Trace {
		if tr.Outcome != pipeline.StepRan {
			t.Fatalf("trace[%d] = %+v, want ran", i, tr)
		}
	}
}

func TestRedact_FindingsSpans(t *testing.T) {
	// detector→redact: the SNILS is replaced with a self-describing token.
	res := runStepSpecs(t, detectorPlus(NameNationalPII, NameRedact, map[string]any{"action": "mask"}, nil),
		reqPayload("снилс 112-233-445 95 в анкете"))
	assertAllRan(t, res)
	if res.Mutated == nil {
		t.Fatal("Mutated is nil, want redaction")
	}
	if got, want := payloadText(res.Mutated), "снилс [REDACTED:innsnils:1] в анкете"; got != want {
		t.Errorf("redacted text = %q, want %q", got, want)
	}
	if res.Verdict != pipeline.ActionMask {
		t.Errorf("verdict = %q, want mask (from the detector)", res.Verdict)
	}
	if len(res.Trace) != 2 || res.Trace[1].Outcome != pipeline.StepRan {
		t.Fatalf("trace = %+v, want both steps ran", res.Trace)
	}
}

func TestRedact_CategoryFilter(t *testing.T) {
	// Exact category: only that class is redacted.
	res := runStepSpecs(t, detectorPlus(NameNationalPII, NameRedact,
		map[string]any{"action": "mask"}, map[string]any{"categories": []any{"pan"}}),
		reqPayload("снилс 112-233-445 95 и карта 4111111111111111"))
	assertAllRan(t, res)
	got := content(t, res)
	if !strings.Contains(got, "112-233-445 95") {
		t.Errorf("innsnils must survive a pan-only filter: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:pan:") {
		t.Errorf("pan must be redacted: %q", got)
	}
	// Wildcard "categories" resolve at load: "presidio.*" matches any
	// presidio subcategory (unit-level; OP-1 emits flat categories).
	cfg, err := parseSpanMutator(map[string]any{"categories": []any{"presidio.*", "pan"}}, pipeline.KindRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.categorySelected("presidio.analyze") || !cfg.categorySelected("pan") || cfg.categorySelected("innsnils") {
		t.Errorf("category filter wrong: presidio.analyze=%v pan=%v innsnils=%v",
			cfg.categorySelected("presidio.analyze"), cfg.categorySelected("pan"), cfg.categorySelected("innsnils"))
	}
	// Non-matching filter: nothing redacted, payload untouched.
	res = runStepSpecs(t, detectorPlus(NameNationalPII, NameRedact,
		nil, map[string]any{"categories": []any{"eg"}}),
		reqPayload("снилс 112-233-445 95"))
	assertAllRan(t, res)
	if res.Mutated != nil {
		t.Errorf("unmatched filter mutated the payload: %q", payloadText(res.Mutated))
	}
}

func TestRedact_OwnPatterns(t *testing.T) {
	res := runMutatorOne(t, NameRedact, map[string]any{
		"patterns": []any{map[string]any{"category": "digits", "pattern": "[0-9]{5}"}},
	}, reqPayload("code 12345 and 67890"))
	assertRan(t, res)
	if got, want := content(t, res), "code [REDACTED:digits:1] and [REDACTED:digits:2]"; got != want {
		t.Errorf("pattern redaction = %q, want %q", got, want)
	}
	fs := findingsOf(res, "s1")
	if len(fs) != 2 {
		t.Fatalf("pattern findings = %d, want 2", len(fs))
	}
	for _, f := range fs {
		if f.Category != "digits" || f.Action != pipeline.ActionFlag || f.Span == "" {
			t.Errorf("pattern finding = %+v, want digits/flag/span", f)
		}
		if f.Evidence != "" {
			t.Errorf("pattern finding evidence = %q, want empty (never quote matched content)", f.Evidence)
		}
	}
}

func TestRedact_MultiByteUTF8AndMessageOffsets(t *testing.T) {
	// Multi-byte runes before/around the span: byte-offset spans must stay
	// aligned, and the second message's span accounts for the "\n" join.
	in := reqPayload("Привет, мир! Проверка связи — ёёё")
	in.Messages = append(in.Messages,
		pipeline.Message{Role: "user", Content: "повтор: снилс 112-233-445 95 конец"})
	res := runStepSpecs(t, detectorPlus(NameNationalPII, NameRedact, nil, nil), in)
	assertAllRan(t, res)
	got := content(t, res)
	want := "Привет, мир! Проверка связи — ёёё\nповтор: снилс [REDACTED:innsnils:1] конец"
	if got != want {
		t.Errorf("utf-8 redaction =\n%q\nwant\n%q", got, want)
	}
}

func TestRedact_OverlappingFindings(t *testing.T) {
	// Overlapping spans merge into one replacement (the first/earlier wins).
	st, err := NewRedact(nil)
	if err != nil {
		t.Fatal(err)
	}
	in := reqPayload("abcdef")
	out := &pipeline.Result{Findings: []pipeline.Finding{
		{Step: "d", Category: "one", Span: "0:4", Action: pipeline.ActionMask},
		{Step: "d", Category: "two", Span: "2:6", Action: pipeline.ActionMask},
	}}
	if err := st.Run(context.Background(), nil, in, out); err != nil {
		t.Fatal(err)
	}
	if got, want := in.Messages[0].Content, "[REDACTED:one:1]"; got != want {
		t.Errorf("overlapping redaction = %q, want %q", got, want)
	}
}

func TestRedact_Edges(t *testing.T) {
	// Empty payload, no findings: untouched.
	res := runMutatorOne(t, NameRedact, nil, reqPayload(""))
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("empty payload mutated: %+v", res.Mutated)
	}
	res = runMutatorOne(t, NameRedact, nil, reqPayload("чистый текст"))
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("findingless run mutated: %q", payloadText(res.Mutated))
	}
	// Findings without a span are skipped (credential-keyed values).
	st, err := NewRedact(nil)
	if err != nil {
		t.Fatal(err)
	}
	in := reqPayload("text with no pii")
	out := &pipeline.Result{Findings: []pipeline.Finding{
		{Step: "d", Category: "credential", Action: pipeline.ActionDeny},
	}}
	if err := st.Run(context.Background(), nil, in, out); err != nil {
		t.Fatalf("spanless finding: %v", err)
	}
	if in.Messages[0].Content != "text with no pii" {
		t.Errorf("spanless finding mutated: %q", in.Messages[0].Content)
	}
	// Malformed and stale spans are step errors (fail-closed), not skips.
	for _, span := range []string{"bogus", "0:999", "-1:2", "1:1"} {
		out = &pipeline.Result{Findings: []pipeline.Finding{
			{Step: "d", Category: "x", Span: span, Action: pipeline.ActionMask},
		}}
		if err := st.Run(context.Background(), nil, reqPayload("hello"), out); err == nil {
			t.Errorf("span %q: want error", span)
		}
	}
	res = runMutatorOne(t, NameRedact, map[string]any{"max_input": 4}, reqPayload("way too long"))
	if len(res.Trace) != 1 || res.Trace[0].Outcome != pipeline.StepError {
		t.Errorf("max_input exceeded: trace = %+v, want step error", res.Trace)
	}
	mustCompileErr(t, NameRedact, map[string]any{"categories": []any{"pa*n"}})
	mustCompileErr(t, NameRedact, map[string]any{"patterns": []any{map[string]any{"category": "x", "pattern": "(a+)+"}}})
	mustCompileErr(t, NameRedact, map[string]any{"kinds": []any{"bogus"}})
}

func TestRedact_IdempotencyBoundary(t *testing.T) {
	// Re-running the composed policy on already-redacted text: the detector
	// finds nothing, the redactor is a no-op, Mutated stays nil.
	steps := detectorPlus(NameNationalPII, NameRedact, nil, nil)
	in := reqPayload("снилс 112-233-445 95 и карта 4111111111111111")
	r1 := runStepSpecs(t, steps, in)
	assertAllRan(t, r1)
	redacted := r1.Mutated
	if redacted == nil {
		t.Fatal("first run did not mutate")
	}
	r2 := runStepSpecs(t, steps, redacted)
	assertAllRan(t, r2)
	if len(r2.Findings) != 0 {
		t.Errorf("second run findings = %v, want none (tokens are not re-detected)", r2.Findings)
	}
	if r2.Mutated != nil {
		t.Errorf("second run mutated again: %q", payloadText(r2.Mutated))
	}
	// Determinism: same input → same output.
	r1b := runStepSpecs(t, steps, in)
	if payloadText(r1b.Mutated) != payloadText(r1.Mutated) {
		t.Errorf("nondeterministic redaction: %q vs %q", payloadText(r1b.Mutated), payloadText(r1.Mutated))
	}
	// Own patterns must not match inside existing tokens.
	st, err := NewRedact(map[string]any{
		"patterns": []any{map[string]any{"category": "n", "pattern": "[0-9]+"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	in2 := reqPayload("pin [REDACTED:pan:1] and {{YPP_3}}")
	out := &pipeline.Result{}
	if err := st.Run(context.Background(), nil, in2, out); err != nil {
		t.Fatal(err)
	}
	if got := in2.Messages[0].Content; got != "pin [REDACTED:pan:1] and {{YPP_3}}" {
		t.Errorf("token text was re-redacted: %q", got)
	}
}

func TestRedact_BodyAndChunkTargets(t *testing.T) {
	params := map[string]any{"patterns": []any{map[string]any{"category": "d", "pattern": "[0-9]{3}"}}}
	in := &pipeline.Payload{Kind: pipeline.KindToolArgs, Body: []byte(`{"ref": 555}`)}
	res := runMutatorOne(t, NameRedact, params, in)
	assertRan(t, res)
	if got := string(content2Body(t, res)); got != `{"ref": [REDACTED:d:1]}` {
		t.Errorf("body redaction = %q", got)
	}
	in = &pipeline.Payload{
		Kind:        pipeline.KindStreamPrefix,
		StreamChunk: "id 777 end",
	}
	// with a kinds-less redact step must mutate the buffered prefix.
	res = runMutatorOne(t, NameRedact, params, in)
	assertAllRan(t, res)
	if res.Mutated == nil {
		t.Fatal("stream_prefix default kinds did not mutate")
	}
	if res.Mutated.StreamChunk != "id [REDACTED:d:1] end" {
		t.Errorf("chunk redaction = %q", res.Mutated.StreamChunk)
	}
	// The same kinds-less default applies to the final aggregate. Nonmatching
	// bytes remain intact while the matching span gets the usual token.
	final := &pipeline.Payload{
		Kind: pipeline.KindStreamFinal,
		Body: []byte("id 888 and safe"),
	}
	res = runMutatorOne(t, NameRedact, params, final)
	assertAllRan(t, res)
	if got, want := string(content2Body(t, res)), "id [REDACTED:d:1] and safe"; got != want {
		t.Errorf("stream_final redaction = %q, want %q", got, want)
	}
	// An explicit kinds narrowing still excludes the stream payload.
	res = runMutatorOne(t, NameRedact, map[string]any{
		"kinds":    []any{"request"},
		"patterns": params["patterns"],
	}, in)
	assertAllRan(t, res)
	if res.Mutated != nil {
		t.Errorf("explicit kinds narrowing leaked: %q", res.Mutated.StreamChunk)
	}
}

// content2Body returns the mutated payload Body (tests only).
func content2Body(t *testing.T, res *pipeline.Result) []byte {
	t.Helper()
	if res.Mutated == nil {
		t.Fatal("Mutated is nil")
	}
	return res.Mutated.Body
}

// TestRedact_ToolArgsOverlappingPatterns pins the N02-P06 T02 shared-runtime
// aspect on tool arguments: overlapping OWN-PATTERN matches (and a finding
// overlapping a pattern) merge into ONE replacement — the earlier span's
// category wins, the later edit never lands inside the emitted token, and
// the ordinal numbering stays position-ordered across sources.
func TestRedact_ToolArgsOverlappingPatterns(t *testing.T) {
	// Two own patterns whose matches overlap inside the tool_args body:
	// "secret-123-key" matches both `secret-[0-9]+` and `[0-9]+-key`.
	res := runMutatorOne(t, NameRedact, map[string]any{
		"patterns": []any{
			map[string]any{"category": "cred", "pattern": `secret-[0-9]+`},
			map[string]any{"category": "suffix", "pattern": `[0-9]+-key`},
		},
	}, &pipeline.Payload{Kind: pipeline.KindToolArgs, Body: []byte(`{"auth":"secret-123-key"}`)})
	assertRan(t, res)
	got := string(content2Body(t, res))
	if got != `{"auth":"[REDACTED:cred:1]"}` {
		t.Errorf("overlapping pattern redaction = %q", got)
	}
	// Exactly one flag finding per own-pattern edit that survived the merge;
	// the merged-away span's category emits no flag.
	flags := 0
	for _, f := range res.Findings {
		if f.Category == "cred" || f.Category == "suffix" {
			flags++
		}
	}
	if flags != 1 {
		t.Errorf("own-pattern flag findings = %d, want 1", flags)
	}

	// A detector finding overlapping an own-pattern match: the finding
	// (earlier by the stable sort) wins, the pattern adds no second edit.
	det := detectorPlus(NameSecrets, NameRedact, nil, map[string]any{
		"patterns": []any{map[string]any{"category": "num", "pattern": `[0-9]{3}`}},
	})
	in2 := &pipeline.Payload{Kind: pipeline.KindToolArgs, Body: []byte(`{"k":"sk-tok-123456"}`)}
	res2 := runStepSpecs(t, det, in2)
	assertAllRan(t, res2)
	body := string(content2Body(t, res2))
	for _, tok := range redactTokenRe.FindAllString(body, -1) {
		if strings.Count(body, tok) != 1 {
			t.Errorf("token %q appears inside another token: %q", tok, body)
		}
	}
	if strings.Contains(body, "123456") {
		t.Errorf("the overlapping span was not fully replaced: %q", body)
	}

	// Ordinals stay position-ordered across sources on tool_args: two
	// disjoint matches number 1 then 2 in text order.
	in3 := &pipeline.Payload{Kind: pipeline.KindToolArgs, Body: []byte(`[111,222]`)}
	res3 := runMutatorOne(t, NameRedact, map[string]any{
		"patterns": []any{map[string]any{"category": "d", "pattern": `[0-9]{3}`}},
	}, in3)
	assertRan(t, res3)
	if got, want := string(content2Body(t, res3)), `[[REDACTED:d:1],[REDACTED:d:2]]`; got != want {
		t.Errorf("ordinal order = %q, want %q", got, want)
	}
}
