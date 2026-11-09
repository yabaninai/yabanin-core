package expr

import (
	"context"
	"testing"
	"time"
)

// FuzzExprCondition is the OP-7 DoS target: arbitrary condition sources must
// either fail compilation or evaluate immediately (no loop constructs exist).
func FuzzExprCondition(f *testing.F) {
	seeds := []string{
		`any(Findings, #.Severity == 'high')`,
		`count(Findings, #.Action == 'deny') > 0`,
		`StepDurationMs('natl_pii') < 40 and Meta.Org != 'trusted-int'`,
		`len(filter(Findings, #.Severity == 'high')) > 0`,
		`os.Getenv('HOME') != ''`,
		`now() > 0`,
		`NotAField == 1`,
		`Meta.NoSuchField == 1`,
		`"a" * 1000000000 == ""`,
		`len('a' + 'b' * 999999999) > 0`,
		`Findings[9999999].Severity == 'high'`,
		`)`,
		`1 +`,
		`#{`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	e := New()
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
