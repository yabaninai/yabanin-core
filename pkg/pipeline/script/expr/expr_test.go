package expr

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

func testEnv() pipeline.ConditionEnv {
	return pipeline.ConditionEnv{
		Findings: []pipeline.Finding{
			{Step: "natl_pii", Category: "innsnils", Severity: "high", Span: "10:22", Evidence: "***", Action: pipeline.ActionDeny},
			{Step: "secret_scan", Category: "aws_key", Severity: "medium", Action: pipeline.ActionFlag},
			{Step: "code_detect", Category: "code", Severity: "low", Action: pipeline.ActionAllow},
		},
		Steps: []pipeline.StepTrace{
			{Step: "natl_pii", Duration: 12 * time.Millisecond, Outcome: pipeline.StepRan},
			{Step: "callout_presidio", Duration: 210 * time.Millisecond, Outcome: pipeline.StepTimeout, Error: "deadline"},
		},
		Meta: &pipeline.RequestMeta{
			Org: "org-a", Key: "key-1", Model: "gpt-x", Provider: "openai",
			Labels: map[string]string{"team": "core", "env": "prod"},
			Tags:   []string{"pii", "sovereign"},
		},
	}
}

func evalSource(t *testing.T, source string, env pipeline.ConditionEnv) (bool, error) {
	t.Helper()
	prog, err := New().Compile(source)
	if err != nil {
		return false, err
	}
	return prog.Evaluate(context.Background(), env)
}

func TestExprConditionBooleanContract(t *testing.T) {
	env := testEnv()
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{"any high", `any(Findings, #.Severity == 'high')`, true},
		{"any missing", `any(Findings, #.Category == 'absent')`, false},
		{"count pred", `count(Findings, #.Action == 'deny') == 1`, true},
		{"count all", `len(Findings) == 3`, true},
		{"filter len", `len(filter(Findings, #.Severity == 'high')) == 1`, true},
		{"steps ran method", `StepRan('natl_pii')`, true},
		{"steps ran false", `StepRan('absent')`, false},
		{"steps failed", `StepFailed('callout_presidio')`, true},
		{"steps duration", `StepDurationMs('natl_pii') < 40`, true},
		{"steps outcome method", `StepOutcome('callout_presidio') == 'timeout'`, true},
		{"steps slice index", `Steps[0].DurationMs < 40 and Steps[0].Outcome == 'ran'`, true},
		{"meta fields", `Meta.Org == 'org-a' and Meta.Model != ''`, true},
		{"meta label helper", `Meta.Label('env') == 'prod' and Meta.Label('nope') == ''`, true},
		{"meta has_tag", `Meta.HasTag('pii') and not Meta.HasTag('random')`, true},
		{"meta labels direct", `Meta.Labels['team'] == 'core'`, true},
		{"meta tags direct", `'pii' in Meta.Tags`, true},
	}
	for _, tt := range tests {
		got, err := evalSource(t, tt.source, env)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestExprConditionErrors(t *testing.T) {
	env := testEnv()
	tests := []struct {
		name   string
		source string
	}{
		{"non-bool result", `len(Findings)`},
		{"absent step duration is error", `StepDurationMs('absent') < 40`},
		{"absent step outcome is error", `StepOutcome('absent') == 'ran'`},
		{"nil index", `Findings[99].Severity == 'high'`},
	}
	for _, tt := range tests {
		if _, err := evalSource(t, tt.source, env); err == nil {
			t.Errorf("%s: expected evaluation error, got none", tt.name)
		}
	}
}

// TestExprUnknownNamesFailAtCompile is the expr security headline: the typed
// env rejects any identifier outside Findings/Steps/Meta and the pure
// builtins at COMPILE time (policy load), including I/O, time and randomness.
func TestExprUnknownNamesFailAtCompile(t *testing.T) {
	for _, source := range []string{
		`os.Getenv('HOME') != ''`,           // no such name
		`now() > 0`,                         // disabled for determinism
		`open('/etc/passwd') != nil`,        // no such name
		`exec('id') != nil`,                 // no such name
		`NotAField == 1`,                    // unknown identifier
		`Meta.NoSuchField == 1`,             // unknown field
		`while true { }`,                    // no loop grammar
		`len("a" * (10 * 1000 * 1000)) > 0`, // no repeat operator on strings
		``,
	} {
		if _, err := New().Compile(source); err == nil {
			t.Errorf("source %q: expected compile error", source)
		}
	}
}

// TestExprTerminatesByConstruction: even absurd operand expressions finish
// immediately — there is no loop construct to hang on. The wall ceiling is
// the generous backstop, not the assertion.
func TestExprTerminatesByConstruction(t *testing.T) {
	start := time.Now()
	got, err := evalSource(t, `len('a' + 'b' + 'c') == 3 and (1..10000 | len()) == 10000`, testEnv())
	if err != nil {
		t.Fatalf("bounded ops: %v", err)
	}
	if !got {
		t.Fatal("bounded ops result wrong")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("bounded ops took %s", time.Since(start))
	}
}

// TestExprEvalTimeoutScaledOnRaceBuilds pins the load-tolerance mechanism:
// the wall ceiling is the engine's only wall-clock bound (no deterministic
// step hook exists in expr-lang production builds), so -race builds scale it
// by raceWallScale; production builds keep it unscaled.
func TestExprEvalTimeoutScaledOnRaceBuilds(t *testing.T) {
	want := DefaultEvalTimeout
	if raceEnabled {
		want *= raceWallScale
	}
	if got := New().evalTimeout; got != want {
		t.Fatalf("New() evalTimeout = %s, want %s (raceEnabled=%v)", got, want, raceEnabled)
	}
	wantCustom := 100 * time.Millisecond
	if raceEnabled {
		wantCustom *= raceWallScale
	}
	if got := New(WithEvalTimeout(100 * time.Millisecond)).evalTimeout; got != wantCustom {
		t.Fatalf("WithEvalTimeout(100ms): evalTimeout = %s, want %s", got, wantCustom)
	}
}

// TestExprRunawayAllocationAbortsUnderProductionDefaults is the negative
// control for the DoS guarantee with untouched default budgets: an
// allocation bomb aborts through the VM's tracked memory budget — a
// deterministic byte counter, not a wall clock — so the abort holds under
// -race instrumentation and shared-runner load.
func TestExprRunawayAllocationAbortsUnderProductionDefaults(t *testing.T) {
	prog, err := New().Compile(`len(1..2000000) > 0`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = prog.Evaluate(context.Background(), pipeline.ConditionEnv{})
	if err == nil {
		t.Fatal("allocation bomb passed the default VM memory budget")
	}
}

func TestExprEmptyEnvRoots(t *testing.T) {
	got, err := evalSource(t, `len(Findings) == 0 and Meta.Org == '' and not StepRan('x')`, pipeline.ConditionEnv{})
	if err != nil {
		t.Fatalf("empty env: %v", err)
	}
	if !got {
		t.Fatal("empty env semantics wrong")
	}
}

func TestExprConcurrentEvaluate(t *testing.T) {
	prog, err := New().Compile(`any(Findings, #.Severity == 'high') and Meta.HasTag('pii')`)
	if err != nil {
		t.Fatal(err)
	}
	env := testEnv()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Go(func() {
			for i := 0; i < 100; i++ {
				got, err := prog.Evaluate(context.Background(), env)
				if err != nil {
					t.Errorf("concurrent eval: %v", err)
					return
				}
				if !got {
					t.Error("concurrent eval: inconsistent result")
					return
				}
			}
		})
	}
	wg.Wait()
}

// TestExprAllIsVacuousOnEmpty documents the contract deviation for the owner
// decision: expr's all() over an empty collection is true.
func TestExprAllIsVacuousOnEmpty(t *testing.T) {
	got, err := evalSource(t, `all(Findings, #.Severity == 'high')`, pipeline.ConditionEnv{})
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("expected expr all() to be vacuously true on empty collection")
	}
}

func TestExprCallerContextCancelled(t *testing.T) {
	prog, err := New().Compile(`any(Findings, #.Severity == 'high')`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = prog.Evaluate(ctx, testEnv())
	if err == nil || !strings.Contains(err.Error(), "caller context") {
		t.Fatalf("want caller-context error, got: %v", err)
	}
}

func TestExprRejectsCompileComplexityBeforeCompiler(t *testing.T) {
	engine := New()
	if _, err := engine.Compile(strings.Repeat("x", maxSourceBytes+1)); err == nil {
		t.Fatal("oversized expression accepted")
	}
	deep := strings.Repeat("(", maxSyntaxDepth+1) + "true" + strings.Repeat(")", maxSyntaxDepth+1)
	if _, err := engine.Compile(deep); err == nil {
		t.Fatal("deep expression accepted")
	}
	wide := strings.TrimSuffix(strings.Repeat("true and ", maxSyntaxNodes), " and ")
	if _, err := engine.Compile(wide); err == nil {
		t.Fatal("expression over syntax node budget accepted")
	}
}

func TestExprRejectsOversizedEvaluationInput(t *testing.T) {
	prog, err := New().Compile(`true`)
	if err != nil {
		t.Fatal(err)
	}
	env := pipeline.ConditionEnv{Findings: make([]pipeline.Finding, maxEnvItems+1)}
	if _, err := prog.Evaluate(context.Background(), env); err == nil {
		t.Fatal("oversized environment accepted")
	}
}

func TestExprRejectsOversizedFindingActionBeforeEvaluation(t *testing.T) {
	prog, err := New().Compile(`Findings[0].Action == 'deny'`)
	if err != nil {
		t.Fatal(err)
	}
	env := pipeline.ConditionEnv{
		Findings: []pipeline.Finding{{Action: pipeline.Action(strings.Repeat("x", maxEnvBytes+1))}},
	}
	if _, err := prog.Evaluate(context.Background(), env); err == nil || !strings.Contains(err.Error(), "evaluation input exceeds limits") {
		t.Fatalf("Evaluate error=%v, want environment-budget rejection before execution", err)
	}
}

func TestExprLoopRejectedAndTimeoutHasDeterministicError(t *testing.T) {
	if _, err := New().Compile(`while true {}`); err == nil {
		t.Fatal("Expr accepted a loop despite its bounded, non-Turing-complete grammar")
	}
	program, err := New(WithEvalTimeout(-time.Nanosecond)).Compile(`true`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = program.Evaluate(context.Background(), pipeline.ConditionEnv{})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "evaluation budget exceeded") {
		t.Fatalf("timeout error=%v, want deterministic deadline budget error", err)
	}
}

func TestExprVMRejectsHugeAllocationByMemoryBudget(t *testing.T) {
	program, err := New(WithMemoryBudget(1024)).Compile(`len(1..1000000) > 0`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := program.Evaluate(context.Background(), pipeline.ConditionEnv{}); err == nil {
		t.Fatal("large range allocation passed the VM memory budget")
	}
}

func TestExprTypedDecisionRoots(t *testing.T) {
	program, err := New().Compile(`Principal.ID == 'agent-7' and Action == 'history.read' and Resource.Organization == 'org-B' and Context['environment'] == 'prod'`)
	if err != nil {
		t.Fatal(err)
	}
	input := pipeline.DecisionEnvironment{
		Principal: pipeline.DecisionPrincipal{
			ID:   pipeline.TrustedAttribute{Value: "agent-7", Source: "identity"},
			Kind: pipeline.TrustedAttribute{Value: "agent", Source: "identity"},
		},
		Action: pipeline.TrustedAttribute{Value: "history.read", Source: "authorizer"},
		Resource: pipeline.DecisionResource{
			Type:         pipeline.TrustedAttribute{Value: "request", Source: "history"},
			ID:           pipeline.TrustedAttribute{Value: "request-7", Source: "history"},
			Organization: pipeline.TrustedAttribute{Value: "org-B", Source: "tenant-resolver"},
		},
		Context: map[string]pipeline.TrustedAttribute{
			"environment": {Value: "prod", Source: "deployment"},
		},
	}
	verdict := (pipeline.Evaluator{}).EvaluateAuthorization(context.Background(), program, input)
	if !verdict.Allowed {
		t.Fatalf("typed decision condition denied: %+v", verdict)
	}
}
