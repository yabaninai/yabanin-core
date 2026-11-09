package sovereign

import "testing"

func TestCNGuard_BlocksWhenNotAllowed(t *testing.T) {
	m := ModelMeta{ModelName: "qwen-max", CNFlagged: true}
	if err := CNGuard(Policy{}, m); err == nil {
		t.Fatal("guard must block CN model when cn_allowed=false")
	}
}

func TestCNGuard_AllowsWhenExplicitOptIn(t *testing.T) {
	m := ModelMeta{ModelName: "qwen-max", CNFlagged: true}
	p := Policy{CNAllowed: true}
	if err := CNGuard(p, m); err != nil {
		t.Fatalf("guard must allow explicit opt-in: %v", err)
	}
}

func TestCNGuard_NonCN_NeverBlocks(t *testing.T) {
	m := ModelMeta{ModelName: "sakana-evo", CNFlagged: false}
	if err := CNGuard(Policy{}, m); err != nil {
		t.Fatalf("guard must not block non-CN: %v", err)
	}
}
