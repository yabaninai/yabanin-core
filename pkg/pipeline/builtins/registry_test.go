package builtins

import (
	"context"
	"sort"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// ships. Policies reference these strings; renames are breaking changes.
var wantNames = []string{
	"builtin/national-pii",
	"builtin/secrets",
	"builtin/injection",
	"builtin/word-count",
	"builtin/char-count",
	"builtin/sentence-count",
	"builtin/contains",
	"builtin/regex",
	"builtin/json-schema",
	"builtin/json-keys",
	"builtin/url-check",
	"builtin/code-detect",
	"builtin/language",
	"builtin/model-whitelist",
	"builtin/metadata-required",
	"builtin/redact",
	"builtin/pseudonymize",
	"builtin/header-rewrite",
	"builtin/model-rewrite",
	"builtin/partials-substitute",
	"builtin/compress",
}

// mutatorNames is the mutator subset of wantNames: everything else is a
// read-only Detector (parallel-group eligible).
var mutatorNames = map[string]bool{
	NameRedact:             true,
	NamePseudonymize:       true,
	NameHeaderRewrite:      true,
	NameModelRewrite:       true,
	NamePartialsSubstitute: true,
	NameCompress:           true,
}

func TestRegistry_Names(t *testing.T) {
	got := make([]string, 0, len(wantNames))
	for name := range Registry() {
		got = append(got, name)
	}
	sort.Strings(got)
	want := append([]string(nil), wantNames...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("registry has %d factories, want %d: %v", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("registry name[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRegistry_FreshMapPerCall(t *testing.T) {
	// No global state: mutating a returned map must not affect the next call.
	r1 := Registry()
	for name := range r1 {
		delete(r1, name)
	}
	if got := len(Registry()); got != len(wantNames) {
		t.Errorf("registry after external mutation = %d factories, want %d (no shared state)", got, len(wantNames))
	}
}

// minimalParams builds the smallest valid config per step so every factory
// can be exercised by the sweep tests.
func minimalParams(name string) map[string]any {
	switch name {
	case NameWordCount, NameCharCount, NameSentenceCount:
		return map[string]any{"min": 1}
	case NameContains:
		return map[string]any{"words": []any{"x"}, "mode": "none"}
	case NameRegex:
		return map[string]any{"pattern": "[a-z]{1,4}"}
	case NameJSONSchema:
		return map[string]any{"schema": map[string]any{"type": "object"}}
	case NameJSONKeys:
		return map[string]any{"keys": []any{"a"}}
	case NameLanguage:
		return map[string]any{"allowed": []any{"en"}}
	case NameModelWhitelist:
		return map[string]any{"models": []any{"gpt-4*"}}
	case NameMetadataRequired:
		return map[string]any{"keys": []any{"org"}}
	case NameHeaderRewrite:
		return map[string]any{"set": map[string]any{"X-Ypp": "1"}}
	case NameModelRewrite:
		return map[string]any{"to": "gpt-4o-mini"}
	case NameCompress:
		return nil
	default:
		return nil
	}
}

func TestRegistry_FactoriesBuild(t *testing.T) {
	for name, factory := range Registry() {
		st, err := factory(minimalParams(name))
		if err != nil {
			t.Errorf("%s: factory error: %v", name, err)
			continue
		}
		if st == nil {
			t.Errorf("%s: factory returned nil step", name)
			continue
		}
		if st.Name() == "" {
			t.Errorf("%s: empty step Name()", name)
		}
		_, isDet := st.(pipeline.Detector)
		_, isMut := st.(pipeline.Mutator)
		switch {
		case mutatorNames[name]:
			if !isMut {
				t.Errorf("%s: step %T does not implement pipeline.Mutator", name, st)
			}
			if isDet {
				t.Errorf("%s: mutator must not implement Detector (parallel groups reject it)", name)
			}
		default:
			if !isDet {
				t.Errorf("%s: step %T does not implement pipeline.Detector (parallel groups reject it)", name, st)
			}
			if isMut {
				t.Errorf("%s: detector must not implement Mutator", name)
			}
		}
	}
}

// TestRegistry_EngineRoundTripSweep runs EVERY builtin through the real
// engine path: compile a one-step policy, run a chat payload, require a ran
// trace, step-attributed findings and a defined verdict.
func TestRegistry_EngineRoundTripSweep(t *testing.T) {
	for name := range Registry() {
		spec := pipeline.StepSpec{ID: "s1", Params: minimalParams(name)}
		if mutatorNames[name] {
			spec.Mutator = name
		} else {
			spec.Detector = name
		}
		res := runStepSpecs(t, []pipeline.StepSpec{spec}, reqPayload("hello world a.b@c example"))
		assertRan(t, res)
		for _, f := range res.Findings {
			if f.Step != "s1" {
				t.Errorf("%s: foreign finding step %q", name, f.Step)
			}
			switch f.Action {
			case pipeline.ActionFlag, pipeline.ActionMask, pipeline.ActionDeny:
			default:
				t.Errorf("%s: finding action %q outside the vocabulary", name, f.Action)
			}
			if f.Category == "" || f.Severity == "" {
				t.Errorf("%s: finding %v missing category/severity", name, f)
			}
		}
		switch res.Verdict {
		case pipeline.ActionAllow, pipeline.ActionFlag, pipeline.ActionMask, pipeline.ActionDeny:
		default:
			t.Errorf("%s: verdict %q outside the vocabulary", name, res.Verdict)
		}
	}
}

func TestRegistry_ContextCancellation(t *testing.T) {
	// A pre-cancelled caller context: the engine skips; a step invoked
	// directly with a cancelled ctx must return promptly (cooperative
	// contract), not run its scan.
	for name, factory := range Registry() {
		st, err := factory(minimalParams(name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out := &pipeline.Result{}
		err = st.Run(ctx, nil, reqPayload("some text"), out)
		if err == nil {
			t.Errorf("%s: Run with cancelled ctx = nil error, want ctx error", name)
		}
		if len(out.Findings) != 0 {
			t.Errorf("%s: cancelled run produced findings %v", name, out.Findings)
		}
	}
}
