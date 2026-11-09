package labels

import (
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	compiled, err := DefaultPolicy().Compile()
	if err != nil {
		t.Fatal(err)
	}
	got := Resolve(compiled, []Source{
		{Name: "key", Labels: Set{"env": "prod", "team": "core"}, Locked: true},
		{Name: "session", Labels: Set{"service": "api"}},
		{Name: "request", Labels: Set{"env": "dev", "jira.issue": "PAY-9", "git.ref": "feature/PAY-123-x"}},
	}, nil)
	if got.Labels["env"] != "prod" || !hasReason(got.Dropped, "env", DropLocked) {
		t.Fatalf("locked %#v %#v", got.Labels, got.Dropped)
	}
	if got.Labels["issue"] != "PAY-9" {
		t.Fatalf("alias lost, derive overwrote issue: %#v", got.Labels)
	}
	if got.Labels["issue.project"] != "PAY" {
		t.Fatalf("project %#v", got.Labels)
	}
	if got.Rejected {
		t.Fatalf("rejected %+v", got)
	}

	open, err := DefaultPolicy().Compile()
	if err != nil {
		t.Fatal(err)
	}
	unlocked := Resolve(open, []Source{
		{Name: "key", Labels: Set{"env": "prod"}},
		{Name: "request", Labels: Set{"env": "dev"}},
	}, nil)
	if unlocked.Labels["env"] != "dev" {
		t.Fatalf("priority %#v", unlocked.Labels)
	}

	deniedPolicy := DefaultPolicy()
	deniedPolicy.DeniedKeys = []string{"env"}
	deniedCompiled, err := deniedPolicy.Compile()
	if err != nil {
		t.Fatal(err)
	}
	denied := Resolve(deniedCompiled, []Source{{Name: "request", Labels: Set{"env": "prod", "team": "core"}}}, nil)
	if _, ok := denied.Labels["env"]; ok || !hasReason(denied.Dropped, "env", DropNotAllowed) {
		t.Fatalf("denied %#v %#v", denied.Labels, denied.Dropped)
	}

	for _, mode := range []string{"allow", "warn", "reject"} {
		policy := DefaultPolicy()
		policy.RequiredKeys = []string{"team"}
		policy.OnMissing = mode
		c, err := policy.Compile()
		if err != nil {
			t.Fatal(err)
		}
		res := Resolve(c, []Source{{Name: "request", Labels: Set{"env": "prod"}}}, nil)
		if len(res.Missing) != 1 || res.Missing[0] != "team" {
			t.Fatalf("%s missing %#v", mode, res.Missing)
		}
		if mode == "reject" {
			if !res.Rejected || res.RejectCode != "missing_required_labels" {
				t.Fatalf("%s %+v", mode, res)
			}
		} else if res.Rejected {
			t.Fatalf("%s rejected", mode)
		}
	}

	invalid := DefaultPolicy()
	invalid.OnInvalid = "reject"
	invalid.ValueMaxLen = 3
	ic, err := invalid.Compile()
	if err != nil {
		t.Fatal(err)
	}
	bad := Resolve(ic, []Source{{Name: "request", Labels: Set{"env": "prod"}}}, nil)
	if !bad.Rejected || bad.RejectCode != "invalid_labels" || !hasReason(bad.Dropped, "env", DropValueTooLong) {
		t.Fatalf("invalid %+v", bad)
	}

	secret := Resolve(compiled, []Source{{Name: "request", Labels: Set{"token": "sk-live"}}}, func(value string) bool {
		return strings.HasPrefix(value, "sk-")
	})
	if _, ok := secret.Labels["token"]; ok || !hasReason(secret.Dropped, "token", DropSecretLike) || secret.Rejected {
		t.Fatalf("secret %+v", secret)
	}

	plain := Resolve(compiled, nil, nil)
	if plain.Rejected || len(plain.Labels) != 0 {
		t.Fatalf("empty %+v", plain)
	}
}

func TestResolveAndCompileEdges(t *testing.T) {
	if res := Resolve(nil, []Source{{Name: "", Labels: Set{"env": "prod", "A..B": "x", "yabanin.hidden": "1"}}}, nil); res.Labels["env"] != "prod" || !hasReason(res.Dropped, "A..B", DropInvalidKey) || !hasReason(res.Dropped, "yabanin.hidden", DropReserved) {
		t.Fatalf("%+v", res)
	}
	policy := DefaultPolicy()
	policy.OnInvalid = ""
	policy.OnMissing = ""
	policy.MaxLabels = 0
	policy.ValueMaxLen = 0
	policy.AllowedKeys = []string{"ci.*", "team"}
	policy.DeniedKeys = []string{"env"}
	policy.Derive = []DeriveRule{{From: "git.ref", Regex: "nope", To: "issue", Template: "$1"}}
	compiled, err := policy.Compile()
	if err != nil {
		t.Fatal(err)
	}
	res := Resolve(compiled, []Source{{Name: "request", Labels: Set{"ci.pipeline": "1", "ci": "root", "team": "core", "env": "prod", "other": "x", "git.ref": "main"}}}, nil)
	if res.Labels["ci.pipeline"] != "1" || res.Labels["ci"] != "root" || res.Labels["team"] != "core" {
		t.Fatalf("allowed %#v", res.Labels)
	}
	if _, ok := res.Labels["other"]; ok {
		t.Fatalf("filtered %#v %#v", res.Labels, res.Dropped)
	}
	if _, ok := res.Labels["env"]; ok {
		t.Fatalf("filtered %#v %#v", res.Labels, res.Dropped)
	}
	if _, ok := res.Labels["issue"]; ok {
		t.Fatalf("filtered %#v %#v", res.Labels, res.Dropped)
	}
	bad := DefaultPolicy()
	bad.RequiredKeys = []string{"A..B"}
	if _, err := bad.Compile(); err == nil {
		t.Fatal("required")
	}
	bad = DefaultPolicy()
	bad.Aliases = map[string]string{"A..B": "issue"}
	if _, err := bad.Compile(); err == nil {
		t.Fatal("alias")
	}
	bad = DefaultPolicy()
	bad.AllowedKeys = []string{"1bad"}
	if _, err := bad.Compile(); err == nil {
		t.Fatal("pattern")
	}
	bad = DefaultPolicy()
	bad.AllowedKeys = []string{"1bad.*"}
	if _, err := bad.Compile(); err == nil {
		t.Fatal("prefix")
	}
	secretPolicy, err := DefaultPolicy().Compile()
	if err != nil {
		t.Fatal(err)
	}
	secret := Resolve(secretPolicy, []Source{{Name: "request", Labels: Set{"git.ref": "PAY-1"}}}, func(string) bool { return true })
	if !hasReason(secret.Dropped, "issue", DropSecretLike) && !hasReason(secret.Dropped, "git.ref", DropSecretLike) {
		t.Fatalf("derive secret %#v", secret.Dropped)
	}
}

func TestCompileErrors(t *testing.T) {
	policy := DefaultPolicy()
	policy.OnInvalid = "explode"
	if _, err := policy.Compile(); err == nil {
		t.Fatal("on_invalid")
	}
	policy = DefaultPolicy()
	policy.Derive = []DeriveRule{{From: "git.ref", Regex: "(", To: "issue", Template: "$1"}}
	if _, err := policy.Compile(); err == nil {
		t.Fatal("regex")
	}
	policy = DefaultPolicy()
	policy.Derive = []DeriveRule{{From: "git.ref", Regex: strings.Repeat("a", 257), To: "issue", Template: "$1"}}
	if _, err := policy.Compile(); err == nil {
		t.Fatal("regex length")
	}
	policy = DefaultPolicy()
	policy.RollupKeys = make([]string, 41)
	if _, err := policy.Compile(); err == nil {
		t.Fatal("rollup")
	}
}

func TestResolveTrimPrefersDeriveThenRequest(t *testing.T) {
	policy := DefaultPolicy()
	policy.MaxLabels = 2
	policy.Derive = nil
	compiled, err := policy.Compile()
	if err != nil {
		t.Fatal(err)
	}
	res := Resolve(compiled, []Source{
		{Name: "key", Labels: Set{"team": "core"}, Locked: true},
		{Name: "request", Labels: Set{"a": "1", "m": "1", "z": "1"}},
	}, nil)
	if res.Labels["team"] != "core" || res.Labels["a"] != "1" {
		t.Fatalf("kept %#v dropped %#v", res.Labels, res.Dropped)
	}
	if _, ok := res.Labels["z"]; ok || !hasReason(res.Dropped, "z", DropTooMany) {
		t.Fatalf("trim %#v %#v", res.Labels, res.Dropped)
	}
}
