package builtins

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

func TestHeaderRewrite_SetAndRemove(t *testing.T) {
	params := map[string]any{
		"set":    map[string]any{"x-trial": "lab", "X-Region": "ru-1"},
		"remove": []any{"x-experimental", "User-Agent"},
	}
	res := runMutatorOne(t, NameHeaderRewrite, params, reqPayload("hello"))
	assertRan(t, res)
	h := res.Mutated.Headers
	if h == nil {
		t.Fatal("Headers not materialized")
	}
	if h["X-Trial"] != "lab" || h["X-Region"] != "ru-1" {
		t.Errorf("set headers = %v", h)
	}
	if _, ok := h["X-Experimental"]; ok {
		t.Errorf("remove failed: %v", h)
	}
	if _, ok := h["User-Agent"]; ok {
		t.Errorf("canonical remove failed: %v", h)
	}
	// Set wins over remove of the same name.
	params = map[string]any{
		"set":    map[string]any{"X-Keep": "v"},
		"remove": []any{"x-keep"},
	}
	res = runMutatorOne(t, NameHeaderRewrite, params, reqPayload("hello"))
	assertRan(t, res)
	if res.Mutated.Headers["X-Keep"] != "v" {
		t.Errorf("set/remove precedence = %v", res.Mutated.Headers)
	}
}

func TestHeaderRewrite_NilHeadersCompat(t *testing.T) {
	// nil Headers: a pure-remove run stays a no-op (no map materialized,
	// Mutated nil); a set run materializes the map on the CLONE only.
	params := map[string]any{"remove": []any{"x-gone"}}
	res := runMutatorOne(t, NameHeaderRewrite, params, reqPayload("hello"))
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("remove on nil Headers mutated: %+v", res.Mutated)
	}
	// Backward compatibility: the caller's payload is never touched.
	caller := reqPayload("hello")
	caller.Headers = map[string]string{"X-A": "1"}
	res = runMutatorOne(t, NameHeaderRewrite, map[string]any{
		"set": map[string]any{"X-A": "2"},
	}, caller)
	assertRan(t, res)
	if caller.Headers["X-A"] != "1" {
		t.Errorf("caller payload mutated: %v", caller.Headers)
	}
	if res.Mutated.Headers["X-A"] != "2" {
		t.Errorf("clone not mutated: %v", res.Mutated.Headers)
	}
	// Engine equality: rewriting a header to its current value is NOT a
	// mutation (nil ≡ empty, equal maps ≡ equal).
	res = runMutatorOne(t, NameHeaderRewrite, map[string]any{
		"set": map[string]any{"X-A": "1"},
	}, caller)
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("no-op rewrite flagged as Mutated: %+v", res.Mutated)
	}
}

func TestHeaderRewrite_KindsGate(t *testing.T) {
	// Request-only by default: a response payload is untouched.
	params := map[string]any{"set": map[string]any{"X-Ypp": "1"}}
	res := runMutatorOne(t, NameHeaderRewrite, params, respPayload("hello"))
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("response kind mutated: %+v", res.Mutated)
	}
	mustCompileErr(t, NameHeaderRewrite, map[string]any{
		"set": map[string]any{"X-Ypp": "1"}, "kinds": []any{"response"},
	})
}

func TestHeaderRewrite_FactoryValidation(t *testing.T) {
	mustCompileErr(t, NameHeaderRewrite, nil)
	mustCompileErr(t, NameHeaderRewrite, map[string]any{"set": map[string]any{"bad name": "v"}})
	mustCompileErr(t, NameHeaderRewrite, map[string]any{"set": map[string]any{"X-Ok": "bad\rvalue"}})
	mustCompileErr(t, NameHeaderRewrite, map[string]any{"set": map[string]any{"X-Ok": "lf\nvalue"}})
	mustCompileErr(t, NameHeaderRewrite, map[string]any{"set": map[string]any{"X-Ok": 3}})
	mustCompileErr(t, NameHeaderRewrite, map[string]any{"remove": []any{""}})
	long := make([]byte, maxHeaderValueLen+1)
	for i := range long {
		long[i] = 'a'
	}
	mustCompileErr(t, NameHeaderRewrite, map[string]any{"set": map[string]any{"X-Ok": string(long)}})
}

func TestHeaderRewrite_ContextCancellation(t *testing.T) {
	st, err := NewHeaderRewrite(map[string]any{"set": map[string]any{"X-Ypp": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := reqPayload("hello")
	if err := st.Run(ctx, nil, in, &pipeline.Result{}); err == nil {
		t.Error("cancelled ctx: want error")
	}
	if in.Headers != nil {
		t.Errorf("cancelled run wrote headers: %v", in.Headers)
	}
}
