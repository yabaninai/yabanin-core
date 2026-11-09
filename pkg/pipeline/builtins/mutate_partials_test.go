package builtins

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// mapPartials is a test PartialsSource over a static map (goroutine-safe:
// read-only after construction).
type mapPartials map[string]string

// Get resolves from the map.
func (m mapPartials) Get(_ context.Context, name string) (string, bool, error) {
	v, ok := m[name]
	return v, ok, nil
}

func TestPartialsSubstitute_Basic(t *testing.T) {
	params := map[string]any{
		"source": mapPartials{"greeting": "Добрый день", "sign": "— команда"},
	}
	res := runMutatorOne(t, NamePartialsSubstitute, params,
		reqPayload("{{partials.greeting}}, Иван! {{partials.sign}}"))
	assertRan(t, res)
	if got, want := content(t, res), "Добрый день, Иван! — команда"; got != want {
		t.Errorf("substituted = %q, want %q", got, want)
	}
}

func TestPartialsSubstitute_Missing(t *testing.T) {
	params := map[string]any{"source": mapPartials{"a": "A"}}
	// Default on_missing=skip: the unknown token passes through verbatim.
	res := runMutatorOne(t, NamePartialsSubstitute, params,
		reqPayload("{{partials.a}} {{partials.unknown}}"))
	assertRan(t, res)
	if got, want := content(t, res), "A {{partials.unknown}}"; got != want {
		t.Errorf("skip semantics = %q, want %q", got, want)
	}
	// on_missing=error: fail-closed step error.
	params["on_missing"] = "error"
	res = runMutatorOne(t, NamePartialsSubstitute, params,
		reqPayload("{{partials.a}} {{partials.unknown}}"))
	if len(res.Trace) != 1 || res.Trace[0].Outcome != pipeline.StepError {
		t.Fatalf("on_missing=error: trace = %+v, want step error", res.Trace)
	}
	mustCompileErr(t, NamePartialsSubstitute, map[string]any{"on_missing": "explode"})
}

func TestPartialsSubstitute_SinglePass(t *testing.T) {
	// A partial body is inserted verbatim and never rescanned — recursive
	// expansion is impossible by construction.
	params := map[string]any{
		"source": mapPartials{"outer": "{{partials.inner}}", "inner": "boom"},
	}
	res := runMutatorOne(t, NamePartialsSubstitute, params, reqPayload("{{partials.outer}}"))
	assertRan(t, res)
	if got, want := content(t, res), "{{partials.inner}}"; got != want {
		t.Errorf("single pass = %q, want %q", got, want)
	}
}

func TestPartialsSubstitute_NoopStub(t *testing.T) {
	// No source param: NoopPartials resolves nothing, tokens pass through,
	// payload untouched (Mutated nil).
	res := runMutatorOne(t, NamePartialsSubstitute, nil,
		reqPayload("hello {{partials.greeting}}"))
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("noop stub mutated: %q", payloadText(res.Mutated))
	}
}

func TestPartialsSubstitute_Edges(t *testing.T) {
	// Empty payload, no tokens: untouched.
	res := runMutatorOne(t, NamePartialsSubstitute,
		map[string]any{"source": mapPartials{"a": "A"}}, reqPayload(""))
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("empty payload mutated: %+v", res.Mutated)
	}
	res = runMutatorOne(t, NamePartialsSubstitute,
		map[string]any{"source": mapPartials{"a": "A"}}, reqPayload("нет токенов"))
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("tokenless run mutated: %q", payloadText(res.Mutated))
	}
	// Idempotency: substituted text has no tokens → second run is a no-op.
	res = runMutatorOne(t, NamePartialsSubstitute,
		map[string]any{"source": mapPartials{"a": "A"}}, reqPayload("{{partials.a}}"))
	first := payloadText(res.Mutated)
	res = runMutatorOne(t, NamePartialsSubstitute,
		map[string]any{"source": mapPartials{"a": "A"}}, res.Mutated)
	assertRan(t, res)
	if res.Mutated != nil || first != "A" {
		t.Errorf("second run mutated: %q", payloadText(res.Mutated))
	}
	// Source errors fail the step.
	st, err := NewPartialsSubstitute(map[string]any{"source": errPartials{}})
	if err != nil {
		t.Fatal(err)
	}
	out := &pipeline.Result{}
	if err := st.Run(context.Background(), &pipeline.Pipeline{}, reqPayload("{{partials.a}}"), out); err == nil {
		t.Error("source error: want error")
	}
	// Oversized partial: fail-closed.
	st, err = NewPartialsSubstitute(map[string]any{
		"source": mapPartials{"big": strings.Repeat("x", maxPartialBytes+1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Run(context.Background(), &pipeline.Pipeline{}, reqPayload("{{partials.big}}"), out); err == nil {
		t.Error("oversized partial: want error")
	}
	// A non-PartialsSource "source" param is a LOAD error.
	mustCompileErr(t, NamePartialsSubstitute, map[string]any{"source": "nope"})
}

// errPartials always fails.
type errPartials struct{}

// Get always errors.
func (errPartials) Get(context.Context, string) (string, bool, error) {
	return "", false, errors.New("store down")
}

func TestPartialsSubstitute_KindsGate(t *testing.T) {
	// Default request-only: response payloads untouched.
	res := runMutatorOne(t, NamePartialsSubstitute,
		map[string]any{"source": mapPartials{"a": "A"}}, respPayload("{{partials.a}}"))
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("response kind mutated: %q", payloadText(res.Mutated))
	}
	// kinds override opts response in.
	res = runMutatorOne(t, NamePartialsSubstitute, map[string]any{
		"source": mapPartials{"a": "A"},
		"kinds":  []any{"response"},
	}, respPayload("{{partials.a}}"))
	assertRan(t, res)
	if got, want := content(t, res), "A"; got != want {
		t.Errorf("kinds override = %q, want %q", got, want)
	}
}
