package adminstore

// CORE-TRACE-04 rule→requests lookup against the real stand: the rule_id
// filter must (a) return exactly the org's rows whose routing_decision names
// the rule, (b) agree between ListRequests and RequestStats, (c) stay
// org-scoped both ways, and (d) NEVER fail the query on legacy TEXT values
// (NULL, empty, malformed) — the guarded probe degrades them to non-matches.
// Sibling of the 03a contract files; helpers carry the req prefix there, so
// this file reuses the fixture/contract helpers without touching them.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	ruleFilterID  = "9b1deb4d-3b7d-4bec-8a21-7c9d0e1b2a33"
	ruleFilterID2 = "0bdf49be-c1a5-4f55-8a21-7c9d0e1b2a44"
)

func ruleDecision(id string) string {
	return `{"source":"rule_override","from":"auto","to":"premium",` +
		`"rule":{"namespace":"routing","id":"` + id + `","version":"deadbeefdeadbeef"}}`
}

func TestSQLContractRequests_RuleIDFilter(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)
	ctx := context.Background()

	decision := ruleDecision(ruleFilterID)
	// org-A: r1 names ruleFilterID, r2 names another rule, r3 carries a
	// malformed legacy payload, r4/r5/rx stay NULL. org-B: rb1 names the SAME
	// rule (cross-tenant non-leak probe).
	for _, seed := range []struct{ req, org, val string }{
		{fx.Token + "-r1", fx.OrgA, decision},
		{fx.Token + "-r2", fx.OrgA, ruleDecision(ruleFilterID2)},
		{fx.Token + "-r3", fx.OrgA, "not-json{"},
		{fx.Token + "-rb1", fx.OrgB, decision},
	} {
		_, err := pool.Exec(ctx,
			`UPDATE request_logs SET routing_decision = $1 WHERE request_id = $2 AND org_id = $3::uuid`,
			seed.val, seed.req, seed.org)
		require.NoError(t, err, "seed %s", seed.req)
	}

	run := func(name string, wantRows int, f RequestListFilters) {
		t.Helper()
		rows, total, err := store.ListRequests(ctx, f)
		require.NoError(t, err, name)
		require.Equal(t, wantRows, total, "%s: total", name)
		require.Len(t, rows, wantRows, "%s: page", name)
		stats, err := store.RequestStats(ctx, f)
		require.NoError(t, err, name)
		require.Equal(t, int64(wantRows), stats.TotalRequests, "%s: stats must agree with the list", name)
	}

	// Exactly the org-A row naming the rule; malformed/NULL/other-rule rows
	// are non-matches, never errors.
	run("orgA-rule-hit", 1, RequestListFilters{OrgID: fx.OrgA, RuleID: ruleFilterID})
	require.Equal(t, fx.Token+"-r1", func() string {
		rows, _, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, RuleID: ruleFilterID})
		require.NoError(t, err)
		if len(rows) == 0 {
			return ""
		}
		return rows[0].RequestID
	}())

	run("orgA-other-rule", 1, RequestListFilters{OrgID: fx.OrgA, RuleID: ruleFilterID2})
	run("orgA-unknown-rule-empty", 0, RequestListFilters{
		OrgID:  fx.OrgA,
		RuleID: "00000000-0000-0000-0000-000000000000",
	})
	// Org scoping holds in both directions: org-B sees its own row for the
	// same rule id, and the zero-org honest-empty answer stays empty.
	run("orgB-rule-hit", 1, RequestListFilters{OrgID: fx.OrgB, RuleID: ruleFilterID})
	run("unknown-org-empty", 0, RequestListFilters{
		OrgID:  "00000000-0000-0000-0000-000000000000",
		RuleID: ruleFilterID,
	})

	// Composes with the other shared filters.
	run("rule-and-model", 1, RequestListFilters{OrgID: fx.OrgA, RuleID: ruleFilterID, Model: fx.Token + "-m-smart"})
	run("rule-and-model-miss", 0, RequestListFilters{OrgID: fx.OrgA, RuleID: ruleFilterID, Model: fx.Token + "-m-fast"})
}
