package builtins

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// namePatterns matches capitalized Cyrillic words — a stable test pattern set.
func namePatterns() map[string]any {
	return map[string]any{
		"patterns": []any{map[string]any{"category": "name", "pattern": "[А-Я][а-яё]+"}},
	}
}

func TestPseudonymize_Aliasing(t *testing.T) {
	// Same original → same alias within the run; new originals get the next
	// number in first-occurrence order.
	res := runMutatorOne(t, NamePseudonymize, namePatterns(),
		reqPayload("Иван встретил Пётра, Иван ушёл"))
	if got, want := content(t, res), "{{YPP_1}} встретил {{YPP_2}}, {{YPP_1}} ушёл"; got != want {
		t.Errorf("aliased text = %q, want %q", got, want)
	}
	// carry=none (default): nothing is written into Meta.
	if got := res.Mutated.Meta.Labels[PseudonymCarrierLabel]; got != "" {
		t.Errorf("carry=none wrote a carrier label: %q", got)
	}
}

func TestPseudonymize_FindingsSpans(t *testing.T) {
	// detector→pseudonymize: the SNILS span becomes an alias.
	res := runStepSpecs(t, detectorPlus(NameNationalPII, NamePseudonymize, nil, nil),
		reqPayload("снилс 112-233-445 95 в анкете"))
	assertAllRan(t, res)
	if got, want := content(t, res), "снилс {{YPP_1}} в анкете"; got != want {
		t.Errorf("aliased text = %q, want %q", got, want)
	}
}

func TestPseudonymize_KindsGate(t *testing.T) {
	// response IS a default kind; tool_args too; embeddings-style payloads of
	// other kinds are skipped silently.
	res := runMutatorOne(t, NamePseudonymize, namePatterns(), respPayload("Иван"))
	if got, want := content(t, res), "{{YPP_1}}"; got != want {
		t.Errorf("response aliasing = %q, want %q", got, want)
	}
	res = runMutatorOne(t, NamePseudonymize, map[string]any{
		"kinds":    []any{"tool_args"},
		"patterns": namePatterns()["patterns"],
	}, &pipeline.Payload{Kind: pipeline.KindToolArgs, Messages: []pipeline.Message{{Role: "tool", Content: "Иван"}}})
	if got, want := content(t, res), "{{YPP_1}}"; got != want {
		t.Errorf("tool_args aliasing = %q, want %q", got, want)
	}
	res = runMutatorOne(t, NamePseudonymize, map[string]any{
		"kinds":    []any{"tool_result"},
		"patterns": namePatterns()["patterns"],
	}, respPayload("Иван"))
	assertAllRan(t, res)
	if res.Mutated != nil {
		t.Errorf("kinds gate leaked: %q", payloadText(res.Mutated))
	}
}

func TestPseudonymize_StreamKindsDefault(t *testing.T) {
	// must alias on the buffered stream prefix — the exact payload shape the
	// PrefixGate runs (Kind: stream_prefix, Body: buffered text). No
	// explicit kinds anywhere.
	res := runStepSpecs(t, detectorPlus(NameNationalPII, NamePseudonymize, nil, nil),
		&pipeline.Payload{Kind: pipeline.KindStreamPrefix, Body: []byte("снилс 112-233-445 95")})
	assertAllRan(t, res)
	if got, want := content(t, res), "снилс {{YPP_1}}"; got != want {
		t.Errorf("stream_prefix aliasing = %q, want %q", got, want)
	}
	// stream_final (the full stream aggregate) mutates too.
	res = runStepSpecs(t, detectorPlus(NameNationalPII, NamePseudonymize, nil, nil),
		&pipeline.Payload{Kind: pipeline.KindStreamFinal, Body: []byte("инн 7707083893")})
	assertAllRan(t, res)
	if got, want := content(t, res), "инн {{YPP_1}}"; got != want {
		t.Errorf("stream_final aliasing = %q, want %q", got, want)
	}
	// An explicit kinds narrowing still excludes the stream payloads.
	narrow := map[string]any{"kinds": []any{"request"}}
	res = runStepSpecs(t, detectorPlus(NameNationalPII, NamePseudonymize, nil, narrow),
		&pipeline.Payload{Kind: pipeline.KindStreamPrefix, Body: []byte("снилс 112-233-445 95")})
	assertAllRan(t, res)
	if res.Mutated != nil {
		t.Errorf("explicit kinds narrowing leaked: %q", payloadText(res.Mutated))
	}
}

func TestPseudonymize_CarrySession(t *testing.T) {
	// carry=session publishes the alias→original carrier in Meta.Labels.
	res := runMutatorOne(t, NamePseudonymize, map[string]any{
		"carry":    "session",
		"patterns": namePatterns()["patterns"],
	}, reqPayload("Иван и Пётр"))
	assertAllRan(t, res)
	raw := res.Mutated.Meta.Labels[PseudonymCarrierLabel]
	if raw == "" {
		t.Fatal("carry=session wrote no carrier")
	}
	var carrier map[string]string
	if err := json.Unmarshal([]byte(raw), &carrier); err != nil {
		t.Fatalf("carrier is not JSON: %v (%q)", err, raw)
	}
	if carrier["{{YPP_1}}"] != "Иван" || carrier["{{YPP_2}}"] != "Пётр" {
		t.Errorf("carrier = %v, want YPP_1→Иван, YPP_2→Пётр", carrier)
	}
}

func TestPseudonymize_CarrySessionSeeded(t *testing.T) {
	// A carrier from the previous turn: aliases stay stable and numbering
	// continues after the highest carried number.
	in := reqPayload("Иван снова написал, пришёл Пётр")
	in.Meta.Labels = map[string]string{
		PseudonymCarrierLabel: `{"{{YPP_1}}":"Иван","{{YPP_7}}":"старое"}`,
	}
	res := runMutatorOne(t, NamePseudonymize, map[string]any{
		"carry":    "session",
		"patterns": namePatterns()["patterns"],
	}, in)
	assertAllRan(t, res)
	// Numbering continues after the highest carried number (7): the new
	// original gets 8, the carried alias 1 stays stable.
	if got, want := content(t, res), "{{YPP_1}} снова написал, пришёл {{YPP_8}}"; got != want {
		t.Errorf("seeded aliasing = %q, want %q", got, want)
	}
	var carrier map[string]string
	if err := json.Unmarshal([]byte(res.Mutated.Meta.Labels[PseudonymCarrierLabel]), &carrier); err != nil {
		t.Fatal(err)
	}
	if carrier["{{YPP_1}}"] != "Иван" || carrier["{{YPP_7}}"] != "старое" || carrier["{{YPP_8}}"] != "Пётр" {
		t.Errorf("updated carrier = %v, want merged with the seed", carrier)
	}
}

func TestPseudonymize_CarrySessionEdges(t *testing.T) {
	params := map[string]any{"carry": "session", "patterns": namePatterns()["patterns"]}
	// nil Meta: fail-closed step error.
	res := runMutatorOne(t, NamePseudonymize, params, &pipeline.Payload{
		Kind:     pipeline.KindRequest,
		Messages: []pipeline.Message{{Role: "user", Content: "Иван"}},
	})
	if len(res.Trace) != 1 || res.Trace[0].Outcome != pipeline.StepError {
		t.Fatalf("nil Meta: trace = %+v, want step error", res.Trace)
	}
	// Corrupt carrier: fail-closed, not silently ignored.
	in := reqPayload("Иван")
	in.Meta.Labels = map[string]string{PseudonymCarrierLabel: "{not json"}
	res = runMutatorOne(t, NamePseudonymize, params, in)
	if len(res.Trace) != 1 || res.Trace[0].Outcome != pipeline.StepError {
		t.Fatalf("corrupt carrier: trace = %+v, want step error", res.Trace)
	}
	// Carrier with a non-alias key: fail-closed.
	in = reqPayload("Иван")
	in.Meta.Labels = map[string]string{PseudonymCarrierLabel: `{"oops":"x"}`}
	res = runMutatorOne(t, NamePseudonymize, params, in)
	if len(res.Trace) != 1 || res.Trace[0].Outcome != pipeline.StepError {
		t.Fatalf("bad alias key: trace = %+v, want step error", res.Trace)
	}
	mustCompileErr(t, NamePseudonymize, map[string]any{"carry": "forever"})
}

func TestPseudonymize_CompositionWithRedact(t *testing.T) {
	// redact→pseudonymize on the SAME findings: the pseudonymizer's spans are
	// stale (the redactor consumed them) and its patterns do not match inside
	// the tokens — the boundary keeps the redaction intact, no corruption.
	res := runStepSpecs(t, []pipeline.StepSpec{
		{ID: "s1", Detector: NameNationalPII, Params: nil},
		{ID: "s2", Mutator: NameRedact, Params: nil},
		{ID: "s3", Mutator: NamePseudonymize, Params: map[string]any{
			"patterns": []any{map[string]any{"category": "d", "pattern": "[0-9]+"}},
		}},
	}, reqPayload("снилс 112-233-445 95"))
	assertAllRan(t, res)
	if got, want := content(t, res), "снилс [REDACTED:innsnils:1]"; got != want {
		t.Errorf("composed text = %q, want %q (redaction intact, no double mutation)", got, want)
	}
	// detector→pseudonymize→redact (reverse order): pseudonymize consumes the
	// spans and rewrites the text, so the redactor's spans are STALE —
	// fail_closed turns that into a loud step error (never a wrong-place
	// redaction); fail_open degrades to a safe no-op.
	steps := []pipeline.StepSpec{
		{ID: "s1", Detector: NameNationalPII, Params: nil},
		{ID: "s2", Mutator: NamePseudonymize, Params: nil},
		{ID: "s3", Mutator: NameRedact, Params: nil},
	}
	res = runStepSpecs(t, steps, reqPayload("снилс 112-233-445 95"))
	if len(res.Trace) != 3 || res.Trace[2].Outcome != pipeline.StepError {
		t.Fatalf("stale redact trace = %+v, want step error", res.Trace)
	}
	if got, want := content(t, res), "снилс {{YPP_1}}"; got != want {
		t.Errorf("aliased text = %q, want %q", got, want)
	}
	steps[2].OnError = pipeline.OnErrorFailOpen
	res = runStepSpecs(t, steps, reqPayload("снилс 112-233-445 95"))
	// fail_open records the error and continues; the alias stays intact.
	if len(res.Trace) != 3 || res.Trace[2].Outcome != pipeline.StepError {
		t.Fatalf("fail_open trace = %+v, want recorded step error", res.Trace)
	}
	if got, want := content(t, res), "снилс {{YPP_1}}"; got != want {
		t.Errorf("fail_open composed text = %q, want %q", got, want)
	}
}

func TestPseudonymize_IdempotencyBoundary(t *testing.T) {
	// Re-running on already-aliased text: numbering continues after the
	// highest existing token and a digit-hungry pattern never re-aliases
	// inside {{YPP_n}}.
	st, err := NewPseudonymize(map[string]any{
		"patterns": []any{map[string]any{"category": "d", "pattern": "[0-9]+"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pv := &pipeline.Pipeline{}
	in := reqPayload("code 777")
	out := &pipeline.Result{}
	if err := st.Run(context.Background(), pv, in, out); err != nil {
		t.Fatal(err)
	}
	if got, want := in.Messages[0].Content, "code {{YPP_1}}"; got != want {
		t.Fatalf("first pass = %q, want %q", got, want)
	}
	out = &pipeline.Result{}
	if err := st.Run(context.Background(), pv, in, out); err != nil {
		t.Fatal(err)
	}
	if got := in.Messages[0].Content; got != "code {{YPP_1}}" {
		t.Errorf("second pass = %q, want unchanged", got)
	}
	// A fresh original after an existing token: numbering continues at 2.
	in = reqPayload("{{YPP_1}} then 555")
	out = &pipeline.Result{}
	if err := st.Run(context.Background(), pv, in, out); err != nil {
		t.Fatal(err)
	}
	if got, want := in.Messages[0].Content, "{{YPP_1}} then {{YPP_2}}"; got != want {
		t.Errorf("continuation = %q, want %q", got, want)
	}
}

func TestPseudonymize_Edges(t *testing.T) {
	// Empty payload and no spans: untouched, Mutated nil.
	res := runMutatorOne(t, NamePseudonymize, namePatterns(), reqPayload(""))
	assertAllRan(t, res)
	if res.Mutated != nil {
		t.Errorf("empty payload mutated: %+v", res.Mutated)
	}
	res = runMutatorOne(t, NamePseudonymize, namePatterns(), reqPayload("нет имён"))
	assertAllRan(t, res)
	if res.Mutated != nil {
		t.Errorf("findingless run mutated: %q", payloadText(res.Mutated))
	}
	// Alias limit: fail-closed beyond maxPseudonyms distinct originals
	// (spans injected as findings; pattern matching caps per segment).
	st, err := NewPseudonymize(nil)
	if err != nil {
		t.Fatal(err)
	}
	in := reqPayload("текст ")
	out := &pipeline.Result{}
	for i := 0; i <= maxPseudonyms; i++ {
		base := 6 + i*7
		out.Findings = append(out.Findings, pipeline.Finding{
			Step: "d", Category: "x", Span: span(base, base+3), Action: pipeline.ActionMask,
		})
	}
	if err := st.Run(context.Background(), &pipeline.Pipeline{}, in, out); err == nil {
		t.Error("alias limit: want error")
	}
	// max_input: fail-closed.
	st, err = NewPseudonymize(map[string]any{"max_input": 4, "patterns": namePatterns()["patterns"]})
	if err != nil {
		t.Fatal(err)
	}
	out = &pipeline.Result{}
	if err := st.Run(context.Background(), &pipeline.Pipeline{}, reqPayload("Иван длиннющий"), out); err == nil {
		t.Error("max_input: want error")
	}
	mustCompileErr(t, NamePseudonymize, map[string]any{"patterns": []any{map[string]any{"pattern": "x"}}})
	mustCompileErr(t, NamePseudonymize, map[string]any{"max_input": -1})
}
