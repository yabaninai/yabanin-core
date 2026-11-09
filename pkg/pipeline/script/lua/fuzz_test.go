package lua

import (
	"context"
	"testing"
	"time"
)

// FuzzLuaCondition is the OP-7 DoS target: arbitrary condition sources must
// either fail compilation or evaluate within the sandbox budget — never
// panic, never run unbounded. The evaluation context is tightly bounded so
// the fuzzing worker itself observes budget aborts as ordinary errors.
func FuzzLuaCondition(f *testing.F) {
	seeds := []string{
		`return findings.any(function(f) return f.severity == 'high' end)`,
		`findings.count(function(f) return f.action == 'deny' end) > 0`,
		`steps.duration_ms('natl_pii') < 40 and meta.org ~= 'trusted-int'`,
		`while true do end`,
		`function f() return f() end return f()`,
		`local s = 'a' while true do s = s .. s end`,
		`return string.rep('a', 10 ^ 12) == ''`,
		`return os.execute('id')`,
		`return loadstring('return 1')`,
		`return debug.getupvalue`,
		`local t = setmetatable({}, {__index = function(s, k) return s[k] end}) return t.x`,
		`while true do pcall(function() end) end`,
		`return meta.labels.org .. meta.tags[1]`,
		`return #findings.count`,
		`return 1 +`,
		"\x00\x01\xff",
		`return pcall(function() while true do end end)`,
		`local t = {} while true do t[1] = t end`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	e := New(WithEvalTimeout(10 * time.Millisecond))
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
