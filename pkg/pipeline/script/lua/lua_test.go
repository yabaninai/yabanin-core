package lua

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// testEnv is a representative ConditionEnv: three findings, two step traces,
// full meta.
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
	e := New()
	prog, err := e.Compile(source)
	if err != nil {
		return false, err
	}
	return prog.Evaluate(context.Background(), env)
}

func TestLuaConditionBooleanContract(t *testing.T) {
	env := testEnv()
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{"expr any high", `findings.any(function(f) return f.severity == 'high' end)`, true},
		{"expr any missing", `findings.any(function(f) return f.category == 'absent' end)`, false},
		{"expr count pred", `findings.count(function(f) return f.action == 'deny' end) == 1`, true},
		{"expr count all", `findings.count() == 3`, true},
		{"expr none", `findings.none(function(f) return f.severity == 'critical' end)`, true},
		{"expr all non-empty", `findings.all(function(f) return f.severity ~= '' end)`, true},
		{"chunk explicit return", `local n = findings.count() return n == 3`, true},
		{"steps ran", `steps.ran('natl_pii') and not steps.ran('absent')`, true},
		{"steps skipped", `not steps.skipped('natl_pii')`, true},
		{"steps failed timeout", `steps.failed('callout_presidio')`, true},
		{"steps duration", `steps.duration_ms('natl_pii') < 40 and steps.duration_ms('absent') == nil`, true},
		{"steps outcome", `steps.outcome('callout_presidio') == 'timeout'`, true},
		{"meta fields", `meta.org == 'org-a' and meta.model ~= nil`, true},
		{"meta label helper", `meta.label('env') == 'prod' and meta.label('nope') == nil`, true},
		{"meta has_tag", `meta.has_tag('pii') and not meta.has_tag('random')`, true},
		{"meta labels direct", `meta.labels.team == 'core'`, true},
		{"meta nil-safe absent", `meta.org == 'org-a' and meta.nope == nil`, true},
		{"pcall guarded result", `pcall(function() error('x') end)`, false},
		{"format width bomb neutralized upstream", `#string.format('%999999999d', 1) > 900000000`, false},
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

func TestLuaConditionErrors(t *testing.T) {
	env := testEnv()
	tests := []struct {
		name   string
		source string
	}{
		{"missing return value", `local x = 1`},
		{"bare return", `return`},
		{"non-boolean return", `return findings.count()`},
		{"runtime error", `return error('boom') == nil`},
		{"nil call", `return undefined_fn()`},
		{"index nil", `return meta.nope.field == 1`},
		{"math.random removed", `return math.random() > 0`},
	}
	for _, tt := range tests {
		_, err := evalSource(t, tt.source, env)
		if err == nil {
			t.Errorf("%s: expected evaluation error, got none", tt.name)
		}
	}
}

func TestLuaCompileErrors(t *testing.T) {
	for _, source := range []string{`return (`, `return 1 +`, "\x00\x01", ``} {
		if _, err := New().Compile(source); err == nil {
			t.Errorf("source %q: expected compile error", source)
		}
	}
}

// TestLuaSandboxEscapeAttempts is the OP-7 challenge protocol attack list.
// Every attack must either compile-fail, evaluate-error (fail-closed), or
// evaluate to false — never produce a side effect or an unbounded run.
func TestLuaSandboxEscapeAttempts(t *testing.T) {
	env := testEnv()
	tests := []struct {
		name   string
		source string
	}{
		{"os.execute", `return os.execute('touch /tmp/yabanin-pwned') ~= nil`},
		{"os via global", `return os ~= nil`},
		{"io.open", `return io.open('/etc/passwd') ~= nil`},
		{"io via global", `return io ~= nil`},
		{"debug lib", `return debug ~= nil`},
		{"debug upvalue manipulation", `local f = function() return 1 end return debug.getupvalue(f, 1) ~= nil`},
		{"loadstring", `return loadstring('return 1')() == 1`},
		{"load", `return load('return 1') ~= nil`},
		{"dofile", `return dofile('/etc/passwd') ~= nil`},
		{"loadfile", `return loadfile('/etc/passwd') ~= nil`},
		{"require", `return require('os') ~= nil`},
		{"print", `return print ~= nil`},
		{"_G escape", `return _G ~= nil`},
		{"setfenv", `return setfenv ~= nil`},
		{"getfenv", `return getfenv ~= nil`},
		{"rawset", `return rawset ~= nil`},
		{"collectgarbage", `return collectgarbage ~= nil`},
		{"getmetatable string", `return getmetatable('') ~= nil`},
		{"setmetatable __index recursion", `local t = setmetatable({}, {__index = function(s, k) return s[k] end}) return t.x == nil`},
		{"string.rep OOM", `return #string.rep('a', 1000000000) == 1000000000`},
		{"table.concat bomb", `local t = {} for i = 1, 100000 do t[i] = 'a' end return #table.concat(t, string.rep('b', 1000000)) > 0`},
		{"infinite while", `while true do end return false`},
		{"infinite recursion", `function f() return f() end return f()`},
		{"pcall error-barrier loop", `while true do pcall(function() end) end return false`},
		{"coroutine escape", `return coroutine ~= nil`},
		{"channel escape", `return channel ~= nil`},
		{"math.randomseed", `return math.randomseed ~= nil`},
	}
	for _, tt := range tests {
		got, err := evalSource(t, tt.source, env)
		if err != nil {
			// Budget aborts are expected for loop/recursion attacks; they
			// must be fast (asserted separately in TestLuaBudgetBounded).
			continue // error = fail-closed = pass
		}
		if got {
			t.Errorf("%s: attack evaluated to true (must be false or error)", tt.name)
		}
	}
}

// TestLuaBudgetBounded asserts the DoS guarantee: pathological scripts return
// within the wall-clock budget plus scheduling slack.
func TestLuaBudgetBounded(t *testing.T) {
	e := New(WithEvalTimeout(2 * time.Millisecond))
	attacks := []string{
		`while true do end return false`,
		`function f() return f() end return f()`,
		`while true do pcall(function() end) end return false`,
		`local s = 'a' while true do s = s .. 'x' end return false`,
		`local t = {} while true do t[1] = t end return false`,
	}
	for _, source := range attacks {
		prog, err := e.Compile(source)
		if err != nil {
			t.Fatalf("compile %q: %v", source, err)
		}
		start := time.Now()
		_, err = prog.Evaluate(context.Background(), testEnv())
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("attack %q: expected budget error", source)
		}
		if !strings.Contains(err.Error(), "budget exceeded") {
			t.Errorf("attack %q: want budget abort, got: %v", source, err)
		}
		if elapsed > 2*time.Second {
			t.Errorf("attack %q: unbounded response: %s", source, elapsed)
		}
	}
}

// TestLuaConcatBombDocumentsTransientAllocation documents the KNOWN GAP for
// the owner decision: the deadline bounds wall-clock (and therefore peak
// allocation at wall-clock x copy-rate), but `..` cannot be size-guarded
// without a gopher-lua fork. Here the doubling loop aborts on budget; a
// bounded 24-doubling variant (16 MB) legitimately passes both the budget
// and the (absent) size guard, demonstrating that only the deadline caps it.
func TestLuaConcatBombDocumentsTransientAllocation(t *testing.T) {
	e := New(WithEvalTimeout(250 * time.Millisecond)) // generous: documents alloc-rate gap, not budget
	prog, err := e.Compile(`local s = 'a' for _ = 1, 24 do s = s .. s end return #s == 16777216`)
	if err != nil {
		t.Fatalf("bounded doubling should pass: %v", err)
	}
	got, err := prog.Evaluate(context.Background(), testEnv())
	if err != nil {
		t.Fatalf("bounded doubling should pass: %v", err)
	}
	if !got {
		t.Fatal("doubling result wrong")
	}
}

// TestLuaEvalTimeoutHonorsCallerContext: a cancelled caller context aborts
// immediately.
func TestLuaEvalTimeoutHonorsCallerContext(t *testing.T) {
	prog, err := New(WithEvalTimeout(10 * time.Second)).Compile(`while true do end return false`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err = prog.Evaluate(ctx, testEnv())
	if err == nil || !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "caller context") {
		t.Fatalf("want caller-context abort, got: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("unbounded after cancel: %s", time.Since(start))
	}
}

// TestLuaGlobalsDoNotLeakAcrossEvaluations: pooled states must be reset.
func TestLuaGlobalsDoNotLeakAcrossEvaluations(t *testing.T) {
	e := New()
	prog, err := e.Compile(`return pollution == 42`)
	if err != nil {
		t.Fatal(err)
	}
	pollute, err := e.Compile(`pollution = 42 return true`)
	if err != nil {
		t.Fatal(err)
	}
	env := testEnv()
	ok, err := pollute.Evaluate(context.Background(), env)
	if err != nil || !ok {
		t.Fatalf("pollute: %v %v", ok, err)
	}
	got, err := prog.Evaluate(context.Background(), env)
	if err != nil {
		t.Fatalf("second eval: %v", err)
	}
	if got {
		t.Fatal("global leaked across evaluations on a pooled state")
	}
}

func TestLuaConcurrentEvaluate(t *testing.T) {
	// Generous budget: this test targets thread-safety of pooled states
	// under -race, and wall-clock budgets are load-sensitive by design (see
	// decision doc — instruction budgets do not have this failure mode).
	e := New(WithEvalTimeout(250 * time.Millisecond))
	prog, err := e.Compile(`return findings.any(function(f) return f.severity == 'high' end) and meta.has_tag('pii')`)
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

func TestLuaConcurrentEvaluationsRespectWorkerLimit(t *testing.T) {
	e := New(WithMaxWorkers(2), WithEvalTimeout(5*time.Second))
	prog, err := e.Compile(`local n = 0 for i = 1, 100000 do n = n + i end return n > 0`)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := prog.Evaluate(context.Background(), testEnv()); err != nil {
				t.Errorf("Evaluate(): %v", err)
			}
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	maxObserved := 0
	for i := 0; i < 2000; i++ {
		if running := len(e.evalSlots); running > maxObserved {
			maxObserved = running
		}
		if running := len(e.evalSlots); running > cap(e.evalSlots) {
			t.Fatalf("running evaluations %d exceed limit %d", running, cap(e.evalSlots))
		}
		select {
		case <-done:
			i = 2000
		default:
			time.Sleep(time.Millisecond)
		}
	}
	wg.Wait()
	if maxObserved != 2 {
		t.Fatalf("maximum observed workers = %d, want 2", maxObserved)
	}
}

func TestLuaEmptyEnvRoots(t *testing.T) {
	got, err := evalSource(t, `return findings.count() == 0 and meta.org == nil and steps.ran('x') == false`, pipeline.ConditionEnv{})
	if err != nil {
		t.Fatalf("empty env: %v", err)
	}
	if !got {
		t.Fatal("empty env semantics wrong")
	}
}

func TestLuaRejectsOversizedSourceAndEvaluationEnvironment(t *testing.T) {
	if _, err := New().Compile(strings.Repeat(" ", maxConditionSourceBytes+1)); err == nil {
		t.Fatal("oversized source accepted")
	}
	program, err := New().Compile(`return true`)
	if err != nil {
		t.Fatal(err)
	}
	env := pipeline.ConditionEnv{Findings: make([]pipeline.Finding, maxEnvItems+1)}
	if _, err := program.Evaluate(context.Background(), env); err == nil || !strings.Contains(err.Error(), "evaluation input exceeds limits") {
		t.Fatalf("oversized input error=%v, want explicit budget error", err)
	}
}
