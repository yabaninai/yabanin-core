package pipeline

import (
	"strings"
	"testing"
)

// validPolicyYAML is the canonical happy-path document (mirrors plan §2.2,
// restricted to the card-fixed schema; extra options travel in params).
const validPolicyYAML = `
apiVersion: ypp/v1
kind: Policy
name: sovereign-pii-v2
attach:
  org: ["org-a"]
  key_labels: ["prod"]
  model_patterns: ["*"]
  endpoints: ["chat", "messages", "mcp.invoke"]
mode: enforce
hooks: [pre_upstream, post_upstream, stream_final, tool_pre]
steps:
  - id: natl_pii
    detector: builtin/noop
    when: "true"
    timeout: 50ms
    on_error: fail_closed
  - id: secret_scan
    detector: builtin/noop
  - id: judge_toxicity
    decide: pass
    when: "false"
    timeout: 2s
    parallel: [secret_scan]
    params:
      threshold: 0.7
`

// validNoWhenYAML mirrors validPolicyYAML without conditions (usable with an
// engine that has no script engines registered).
const validNoWhenYAML = `
apiVersion: ypp/v1
kind: Policy
name: sovereign-pii-v2
attach:
  org: ["org-a"]
  key_labels: ["prod"]
  model_patterns: ["*"]
  endpoints: ["chat", "messages", "mcp.invoke"]
mode: enforce
hooks: [pre_upstream, post_upstream, stream_final, tool_pre]
steps:
  - id: natl_pii
    detector: builtin/noop
    timeout: 50ms
    on_error: fail_closed
  - id: secret_scan
    detector: builtin/noop
  - id: judge_toxicity
    decide: pass
    timeout: 2s
    parallel: [secret_scan]
    params:
      threshold: 0.7
`

// testRegistry builds an engine whose factories cover every step kind.
func testRegistry(tb testing.TB) *Engine {
	tb.Helper()
	eng := NewEngine()
	for _, name := range []string{"builtin/noop", "callout", "llm_judge", "decide", "route_hint"} {
		eng.Steps().MustRegister(name, NoopFactory)
	}
	eng.Steps().MustRegister("test/mutator", func(map[string]any) (Step, error) {
		return &mutatorStep{}, nil
	})
	return eng
}

func mustCompile(t *testing.T, yamlSrc string) Compiled {
	t.Helper()
	eng := testRegistry(t)
	eng.Scripts().MustRegister("test", newTestEngine().Compile)
	c, err := eng.LoadPolicy([]byte(yamlSrc))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return c
}

func TestLoadPolicy_Valid(t *testing.T) {
	c := mustCompile(t, validPolicyYAML)
	p := c.Policy
	if p.Name != "sovereign-pii-v2" || p.Mode != ModeEnforce || len(p.Hooks) != 4 || len(p.Steps) != 3 {
		t.Fatalf("parsed policy mismatch: %+v", p)
	}
	if p.Attach.Orgs[0] != "org-a" || p.Attach.ModelPatterns[0] != "*" || len(p.Attach.Endpoints) != 3 {
		t.Fatalf("attach mismatch: %+v", p.Attach)
	}
	// Normalization: default on_error, timeout parsed.
	if c.steps[1].spec.OnError != OnErrorFailClosed {
		t.Errorf("on_error default: got %q, want fail_closed", c.steps[1].spec.OnError)
	}
	if c.steps[0].dur.String() != "50ms" {
		t.Errorf("timeout parse: got %v", c.steps[0].dur)
	}
	// Units: judge_toxicity heads a group with secret_scan.
	if len(c.units) != 2 {
		t.Fatalf("units = %d, want 2 (linear pii, group judge+secret)", len(c.units))
	}
	if len(c.units[1].members) != 1 || c.units[1].members[0] != 1 {
		t.Fatalf("group members = %v, want [1]", c.units[1].members)
	}
	if got := c.StepIDs(); strings.Join(got, ",") != "natl_pii,secret_scan,judge_toxicity" {
		t.Errorf("StepIDs = %v", got)
	}
}

func TestLoadPolicy_StrictUnknownField(t *testing.T) {
	for name, doc := range map[string]string{
		"top-level":  validPolicyYAML + "\nextra: 1\n",
		"step-level": strings.Replace(validPolicyYAML, "    detector: builtin/noop\n", "    detector: builtin/noop\n    ssrf: internal-allowlist\n", 1),
		"llm_judge-level": strings.Replace(validPolicyYAML, "  - id: secret_scan\n    detector: builtin/noop\n",
			"  - id: secret_scan\n    llm_judge:\n      model: m\n      unknown_key: 1\n", 1),
	} {
		_, err := testRegistry(t).LoadPolicy([]byte(doc))
		if err == nil {
			t.Errorf("%s: unknown field must be a load error", name)
		}
	}
}

func TestLoadPolicy_Empty(t *testing.T) {
	for _, doc := range []string{"", "\n", "   \n"} {
		if _, err := testRegistry(t).LoadPolicy([]byte(doc)); err == nil {
			t.Error("empty document must fail")
		}
	}
}

func TestLoadPolicy_BrokenYAML(t *testing.T) {
	doc := "apiVersion: ypp/v1\nkind: Policy\n name: broken\n\tbad: ["
	if _, err := testRegistry(t).LoadPolicy([]byte(doc)); err == nil {
		t.Fatal("broken YAML must fail")
	}
}

func TestLoadPolicy_ValidationErrors(t *testing.T) {
	cases := map[string]struct {
		mutate   func(p *Policy)
		wantText string
	}{
		"unknown apiVersion": {func(p *Policy) { p.APIVersion = "ypp/v2" }, `apiVersion "ypp/v2"`},
		"unknown kind":       {func(p *Policy) { p.Kind = "Config" }, `kind "Config"`},
		"missing name":       {func(p *Policy) { p.Name = "" }, "name is required"},
		"missing mode":       {func(p *Policy) { p.Mode = "" }, "mode is required"},
		"bad mode":           {func(p *Policy) { p.Mode = "observe" }, `mode "observe"`},
		"no hooks":           {func(p *Policy) { p.Hooks = nil }, "at least one hook"},
		"unknown hook":       {func(p *Policy) { p.Hooks = []Hook{"mid_stream"} }, `hook "mid_stream"`},
		"duplicate hook":     {func(p *Policy) { p.Hooks = []Hook{HookPreUpstream, HookPreUpstream} }, "duplicated"},
		"empty attach entry": {func(p *Policy) { p.Attach.Orgs = []string{""} }, "empty entries"},
		"no steps":           {func(p *Policy) { p.Steps = nil }, "at least one step"},
		"empty step id": {func(p *Policy) {
			p.Steps[0].ID = ""
		}, "id is required"},
		"duplicate step id": {func(p *Policy) {
			p.Steps[1].ID = p.Steps[0].ID
		}, "duplicated"},
		"no kind field": {func(p *Policy) {
			p.Steps[0].Detector = ""
		}, "exactly one kind field"},
		"two kind fields": {func(p *Policy) {
			p.Steps[0].Mutator = "test/mutator"
		}, "mutually exclusive"},
		"bad timeout": {func(p *Policy) {
			p.Steps[0].Timeout = "50"
		}, "invalid timeout"},
		"zero timeout": {func(p *Policy) {
			p.Steps[0].Timeout = "0s"
		}, "must be positive"},
		"negative timeout": {func(p *Policy) {
			p.Steps[0].Timeout = "-1s"
		}, "must be positive"},
		"bad on_error": {func(p *Policy) {
			p.Steps[0].OnError = "fail_soft"
		}, `on_error "fail_soft"`},
		"llm_judge without model": {func(p *Policy) {
			p.Steps[1].Detector = ""
			p.Steps[1].LLMJudge = &LLMJudgeSpec{}
		}, "model is required"},
		"self parallel": {func(p *Policy) {
			p.Steps[0].Parallel = []string{"natl_pii"}
		}, "cannot list itself"},
		"unknown parallel member": {func(p *Policy) {
			p.Steps[0].Parallel = []string{"ghost"}
		}, "not a step of this policy"},
		"member in two groups": {func(p *Policy) {
			p.Steps[0].Parallel = []string{"secret_scan"}
			p.Steps[0].ID = "first"
			p.Steps[2].Parallel = []string{"secret_scan"}
		}, "already a parallel member"},
		"member owns a group": {func(p *Policy) {
			p.Steps[1].Parallel = []string{"judge_toxicity"}
		}, "must not declare its own parallel group"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := mustCompile(t, validNoWhenYAML)
			tc.mutate(&c.Policy)
			eng := testRegistry(t)
			eng.Scripts().MustRegister("test", newTestEngine().Compile)
			_, err := eng.CompilePolicy(c.Policy)
			if err == nil {
				t.Fatalf("expected validation error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantText)
			}
		})
	}
}

func TestCompile_UnknownStepNameListsAvailable(t *testing.T) {
	eng := NewEngine()
	eng.Steps().MustRegister("builtin/noop", NoopFactory)
	p := Policy{
		APIVersion: APIVersionYPP, Kind: KindPolicy, Name: "p", Mode: ModeEnforce,
		Hooks: []Hook{HookPreUpstream},
		Steps: []StepSpec{{ID: "s", Detector: "builtin/national-pii"}},
	}
	_, err := eng.CompilePolicy(p)
	if err == nil {
		t.Fatal("unknown step name must fail")
	}
	for _, want := range []string{`unknown step name "builtin/national-pii"`, "builtin/noop"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestCompile_EmptyRegistryFailsWithHint(t *testing.T) {
	eng := NewEngine()
	p := Policy{
		APIVersion: APIVersionYPP, Kind: KindPolicy, Name: "p", Mode: ModeEnforce,
		Hooks: []Hook{HookPreUpstream},
		Steps: []StepSpec{{ID: "s", Detector: "builtin/noop"}},
	}
	_, err := eng.CompilePolicy(p)
	if err == nil || !strings.Contains(err.Error(), "none (register on the Engine before compiling)") {
		t.Fatalf("empty-registry error should carry a hint, got: %v", err)
	}
}

func TestCompile_ParallelParticipantMustBeDetector(t *testing.T) {
	eng := testRegistry(t)
	p := Policy{
		APIVersion: APIVersionYPP, Kind: KindPolicy, Name: "p", Mode: ModeEnforce,
		Hooks: []Hook{HookPreUpstream},
		Steps: []StepSpec{
			{ID: "head", Detector: "builtin/noop", Parallel: []string{"m"}},
			{ID: "m", Mutator: "test/mutator"},
		},
	}
	_, err := eng.CompilePolicy(p)
	if err == nil || !strings.Contains(err.Error(), "must be read-only Detector steps") {
		t.Fatalf("mutator in parallel group must be a compile error, got: %v", err)
	}
}

func TestCompile_When_NoEngineIsLoadError(t *testing.T) {
	eng := testRegistry(t) // no script engines
	_, err := eng.LoadPolicy([]byte(validPolicyYAML))
	if err == nil {
		t.Fatal("when without registered engine must fail to load")
	}
	if !strings.Contains(err.Error(), "no condition engine is registered") ||
		!strings.Contains(err.Error(), "pkg/pipeline/script") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestCompile_When_UnknownEngineNamed(t *testing.T) {
	eng := testRegistry(t)
	eng.Scripts().MustRegister("lua", newTestEngine().Compile)
	_, err := eng.LoadPolicy([]byte(strings.Replace(validPolicyYAML, `when: "true"`, `when: "true"`+"\n    when_engine: starlark", 1)))
	if err == nil || !strings.Contains(err.Error(), `condition engine "starlark" is not registered`) {
		t.Fatalf("unknown when_engine must be a load error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "lua") {
		t.Fatalf("error should list available engines, got: %v", err)
	}
}

func TestCompile_When_AmbiguousRequiresWhenEngine(t *testing.T) {
	eng := testRegistry(t)
	eng.Scripts().MustRegister("lua", newTestEngine().Compile)
	eng.Scripts().MustRegister("expr", newTestEngine().Compile)
	_, err := eng.LoadPolicy([]byte(validPolicyYAML))
	if err == nil || !strings.Contains(err.Error(), "when_engine is required when 2 condition engines are registered") {
		t.Fatalf("ambiguous engines must fail clearly, got: %v", err)
	}
}

func TestCompile_When_SingleEngineIsDefault(t *testing.T) {
	eng := testRegistry(t)
	eng.Scripts().MustRegister("lua", newTestEngine().Compile)
	c, err := eng.LoadPolicy([]byte(validPolicyYAML))
	if err != nil {
		t.Fatalf("single engine should be the default: %v", err)
	}
	if c.steps[0].when == nil {
		t.Fatal("when program missing on step 0")
	}
}

func TestCompile_When_CompileErrorFailsLoad(t *testing.T) {
	eng := testRegistry(t)
	eng.Scripts().MustRegister("bad", newTestEngine().Compile)
	_, err := eng.LoadPolicy([]byte(strings.Replace(validPolicyYAML, `when: "true"`, `when: "BOOM"`, 1)))
	if err == nil || !strings.Contains(err.Error(), "compile when-condition") {
		t.Fatalf("condition compile error must fail the load, got: %v", err)
	}
}

func TestCompile_KindReservedParamCollision(t *testing.T) {
	eng := testRegistry(t)
	p := Policy{
		APIVersion: APIVersionYPP, Kind: KindPolicy, Name: "p", Mode: ModeEnforce,
		Hooks: []Hook{HookPreUpstream},
		Steps: []StepSpec{{
			ID: "s", Decide: "deny", Params: map[string]any{"expr": "override"},
		}},
	}
	_, err := eng.CompilePolicy(p)
	if err == nil || !strings.Contains(err.Error(), "params.expr collides") {
		t.Fatalf("reserved-key collision must fail, got: %v", err)
	}
}

func TestCompile_KindReservedParamsMerged(t *testing.T) {
	eng := testRegistry(t)
	p := Policy{
		APIVersion: APIVersionYPP, Kind: KindPolicy, Name: "p", Mode: ModeEnforce,
		Hooks: []Hook{HookPreUpstream},
		Steps: []StepSpec{{
			ID: "s", Callout: "http://presidio.internal:3000/analyze",
			Params: map[string]any{"timeout_ms": 250},
		}},
	}
	c, err := eng.CompilePolicy(p)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	params := c.steps[0].params
	if params["url"] != "http://presidio.internal:3000/analyze" || params["timeout_ms"] != 250 {
		t.Fatalf("merged params wrong: %v", params)
	}
}
