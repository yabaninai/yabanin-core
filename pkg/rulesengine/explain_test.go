package evaluator

import "testing"

// AUX-19: the rules-preview helpers share the parser and comparison semantics
// with the snapshot compiler — these tests pin the contract the admin console
// relies on (parse validity is explicit; clause traces describe, never rule).

func TestExprParses(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want bool
	}{
		{"valid equality", `model_requested == "gpt-4"`, true},
		{"valid or-and", `model_requested starts_with "gpt" || user_agent contains opencode`, true},
		{"valid in list", `model_requested in gpt-4,gpt-4o`, true},
		{"empty", "", false},
		{"whitespace only", "   ", false},
		{"no operator", "gpt-4", false},
		{"unknown field", `nope == "gpt-4"`, true}, // parses; compares against an empty unknown field, never matches
		{"dangling or", `model_requested == "gpt-4" || `, false},
		{"dangling and", `model_requested == "gpt-4" && `, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExprParses(tc.expr); got != tc.want {
				t.Errorf("ExprParses(%q) = %v, want %v", tc.expr, got, tc.want)
			}
		})
	}
}

func TestTraceTerms(t *testing.T) {
	ctx := Context{OrgID: "org-a", SessionID: "s-1", ClientIP: "10.0.0.1", UserAgent: "agent-x"}

	t.Run("equality match and miss", func(t *testing.T) {
		terms := TraceTerms(`model_requested == "gpt-4" && org_id != "org-b"`, ctx, "gpt-4")
		if len(terms) != 2 {
			t.Fatalf("got %d terms, want 2: %+v", len(terms), terms)
		}
		if !terms[0].Matched || terms[0].Actual != "gpt-4" || terms[0].Value != "gpt-4" || terms[0].Operator != "==" {
			t.Errorf("term0 mismatch: %+v", terms[0])
		}
		if !terms[1].Matched || terms[1].Actual != "org-a" {
			t.Errorf("term1 mismatch: %+v", terms[1])
		}
	})

	t.Run("or does not short-circuit the trace", func(t *testing.T) {
		terms := TraceTerms(`model_requested == "claude" || model_requested == "gpt-4"`, ctx, "gpt-4")
		if len(terms) != 2 {
			t.Fatalf("got %d terms, want 2: %+v", len(terms), terms)
		}
		if terms[0].Matched {
			t.Errorf("term0 should be a miss: %+v", terms[0])
		}
		if !terms[1].Matched {
			t.Errorf("term1 should match: %+v", terms[1])
		}
	})

	t.Run("in list and unknown field", func(t *testing.T) {
		terms := TraceTerms(`model_requested in gpt-4,gpt-4o && nope == x`, ctx, "gpt-4o")
		if len(terms) != 2 {
			t.Fatalf("got %d terms, want 2: %+v", len(terms), terms)
		}
		if !terms[0].Matched {
			t.Errorf("in-list should match: %+v", terms[0])
		}
		if terms[1].Matched || terms[1].Actual != "" {
			t.Errorf("unknown field must never match with empty actual: %+v", terms[1])
		}
	})

	t.Run("malformed yields no terms", func(t *testing.T) {
		if terms := TraceTerms(`model_requested ==`, ctx, "gpt-4"); terms != nil {
			t.Errorf("malformed expression should trace to nil, got %+v", terms)
		}
	})
}
