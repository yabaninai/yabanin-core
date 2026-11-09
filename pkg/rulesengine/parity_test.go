package evaluator

// NEXT-20: rules grammar parity. The corpus in contracts/rules-corpus.json
// is the single source of truth shared with the dashboard's client-side
// preview evaluator. Any divergence between backend semantics and the
// corpus is a FAIL, not an approximation.

import (
	"encoding/json"
	"os"
	"testing"
)

type parityCase struct {
	ID       string `json:"id"`
	Expr     string `json:"expr"`
	Expected bool   `json:"expected"`
}

func TestRulesGrammarParityCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/rules-corpus.json")
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	var doc struct {
		Context map[string]string `json:"context"`
		Cases   []parityCase      `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("corpus parse: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("empty corpus")
	}
	ctx := Context{
		OrgID:          doc.Context["org_id"],
		ModelRequested: doc.Context["model_requested"],
		SessionID:      doc.Context["session_id"],
		ClientIP:       doc.Context["client_ip"],
		UserAgent:      doc.Context["user_agent"],
	}
	for _, tc := range doc.Cases {
		got := Match(tc.Expr, ctx, ctx.ModelRequested)
		if got != tc.Expected {
			t.Errorf("case %s: expr %q → %v, corpus says %v", tc.ID, tc.Expr, got, tc.Expected)
		}
	}
}
