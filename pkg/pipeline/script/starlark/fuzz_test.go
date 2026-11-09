package starlark

import (
	"context"
	"testing"
	"time"
)

// FuzzStarlarkCondition is the OP-7 DoS target: arbitrary condition sources
// must either fail compilation or evaluate within the budgets — never panic,
// never run unbounded.
func FuzzStarlarkCondition(f *testing.F) {
	seeds := []string{
		`findings.any(lambda f: f.severity == 'high')`,
		`findings.count(lambda f: f.action == 'deny') > 0`,
		`steps.duration_ms('natl_pii') < 40 and meta.org != 'trusted-int'`,
		`len([x for x in range(1000 * 1000)]) > 0`,
		`"a" * (10 ** 9) == ""`,
		`findings.list.append(findings.list[0])`,
		`open('/etc/passwd') != None`,
		`meta.labels['a' * 1000] != None`,
		`print('x')`,
		`)`,
		`1 +`,
		`f}{"`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	e := New(WithStepLimit(50_000), WithEvalTimeout(10*time.Millisecond))
	env := testEnv()
	f.Fuzz(func(t *testing.T, source string) {
		prog, err := e.Compile(source)
		if err != nil {
			return // compile failure is a fine outcome (policy load error)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, _ = prog.Evaluate(ctx, env) // any result is fine; panics and hangs are not
	})
}
