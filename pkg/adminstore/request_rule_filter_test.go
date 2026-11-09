package adminstore

// CORE-TRACE-04: the rule_id filter narrows the request list to rows whose
// stored routing_decision names that rule. The predicate lives in the SHARED
// requestListWhere (list/count/stats always agree) and must guard the TEXT
// column: legacy/malformed payloads exist and a failed cast may never 500
// the query. Shape pins only — the real-SQL contract is
// TestSQLContractRequests_RuleIDFilter.

import (
	"strings"
	"testing"
)

const ruleFilterTestID = "9b1deb4d-3b7d-4bec-8a21-7c9d0e1b2a33"

func TestRequestListWhere_RuleIDFilter(t *testing.T) {
	t.Run("absent filter contributes no predicate", func(t *testing.T) {
		where, args := requestListWhere(RequestListFilters{OrgID: "org-a"})
		if strings.Contains(where, "routing_decision") {
			t.Fatalf("empty RuleID must not add a probe: %q", where)
		}
		if len(args) != 1 {
			t.Fatalf("empty RuleID must bind only the org: %#v", args)
		}
	})

	t.Run("set filter probes the rule id behind a validity guard", func(t *testing.T) {
		where, args := requestListWhere(RequestListFilters{OrgID: "org-a", RuleID: ruleFilterTestID})
		for _, fragment := range []string{
			"org_id = $1",
			"routing_decision IS NOT NULL",
			"pg_input_is_valid(routing_decision, 'jsonb')",
			"routing_decision::jsonb->'rule'->>'id' = $2",
			"ELSE false",
		} {
			if !strings.Contains(where, fragment) {
				t.Fatalf("predicate %q missing fragment %q", where, fragment)
			}
		}
		if len(args) != 2 || args[1] != ruleFilterTestID {
			t.Fatalf("filter args = %#v, want the rule id bound at $2", args)
		}
	})
}
