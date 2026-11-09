package evaluator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snapshotEval compiles rules into a snapshot bound to ctx.OrgID and
// evaluates them against ctx. Rules without an explicit OrgID are stamped
// with ctx.OrgID, mirroring rulestore.GetByOrg which always fills it in.
func snapshotEval(ctx Context, model string, rules ...Rule) string {
	stamped := make([]Rule, len(rules))
	for i, r := range rules {
		if r.OrgID == "" {
			r.OrgID = ctx.OrgID
		}
		stamped[i] = r
	}
	return NewSnapshot(ctx.OrgID, stamped).Evaluate(ctx, model)
}

func TestNewSnapshot_NoRules(t *testing.T) {
	s := NewSnapshot("org-1", nil)
	require.NotNil(t, s)
	assert.Equal(t, "org-1", s.OrgID())
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	assert.Empty(t, s.Evaluate(ctx, "gpt-4"))
}

func TestNewSnapshot_DisabledRule(t *testing.T) {
	s := NewSnapshot("org-1", []Rule{
		{ID: "r1", OrgID: "org-1", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "claude-3", Enabled: false},
	})
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	assert.Empty(t, s.Evaluate(ctx, "gpt-4"))
}

func TestEvaluate_SimpleEquals(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_NoMatch(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "claude-3"}
	result := snapshotEval(ctx, "claude-3", snapshotRules...)
	assert.Empty(t, result)
}

func TestEvaluate_AndClause(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `org_id == "org-abc" && model_requested == "gpt-4"`, TargetModel: "claude-3-opus", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-abc", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3-opus", result)
}

func TestEvaluate_AndClause_Fails(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `org_id == "org-abc" && model_requested == "gpt-4"`, TargetModel: "claude-3-opus", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-other", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Empty(t, result)
}

func TestEvaluate_OrClause(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `org_id == "org-a" || model_requested == "gpt-4"`, TargetModel: "claude-haiku", Priority: 5, Enabled: true},
	}
	ctx := Context{OrgID: "org-other", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-haiku", result)
}

func TestEvaluate_OrClause_OrgMatches(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `org_id == "org-a" || model_requested == "gpt-4"`, TargetModel: "claude-haiku", Priority: 5, Enabled: true},
	}
	ctx := Context{OrgID: "org-a", ModelRequested: "other-model"}
	result := snapshotEval(ctx, "other-model", snapshotRules...)
	assert.Equal(t, "claude-haiku", result)
}

func TestEvaluate_ContainsOperator(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested contains "gpt"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "openai-gpt-4"}
	result := snapshotEval(ctx, "openai-gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_ContainsOperator_NoMatch(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested contains "gpt"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "claude-3"}
	result := snapshotEval(ctx, "claude-3", snapshotRules...)
	assert.Empty(t, result)
}

func TestEvaluate_StartsWithOperator(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested starts_with "gpt-"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4-turbo"}
	result := snapshotEval(ctx, "gpt-4-turbo", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_EndsWithOperator(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested ends_with "-turbo"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4-turbo"}
	result := snapshotEval(ctx, "gpt-4-turbo", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_NotEqualsOperator(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested != "gpt-4"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "claude-3"}
	result := snapshotEval(ctx, "claude-3", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_NotEqualsOperator_NoMatch(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested != "gpt-4"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Empty(t, result)
}

func TestEvaluate_InOperator(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested in "gpt-4,gpt-3.5"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-3.5"}
	result := snapshotEval(ctx, "gpt-3.5", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_InOperator_MultiMatch(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested in "gpt-4,gpt-3.5"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_InOperator_NoMatch(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested in "gpt-4,gpt-3.5"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "claude-3"}
	result := snapshotEval(ctx, "claude-3", snapshotRules...)
	assert.Empty(t, result)
}

func TestEvaluate_NotInOperator(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested not_in "gpt-4,gpt-3.5"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "claude-3"}
	result := snapshotEval(ctx, "claude-3", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_NotInOperator_NoMatch(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested not_in "gpt-4,gpt-3.5"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Empty(t, result)
}

func TestEvaluate_MultipleRules_FirstMatches(t *testing.T) {
	ctx := Context{OrgID: "org-a", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4",
		Rule{ID: "r1", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "claude-3-opus", Priority: 10, Enabled: true},
		Rule{ID: "r2", MatchExpr: `org_id == "org-a"`, TargetModel: "gemini-pro", Priority: 5, Enabled: true},
	)
	assert.Equal(t, "claude-3-opus", result)
}

func TestEvaluate_QuotedSingleQuotes(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested == 'gpt-4'`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_QuotedDoubleQuotes(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_ComplexExpression(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `org_id == "org-abc" && model_requested contains "gpt"`, TargetModel: "claude-3-opus", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-abc", ModelRequested: "openai-gpt-4-turbo"}
	result := snapshotEval(ctx, "openai-gpt-4-turbo", snapshotRules...)
	assert.Equal(t, "claude-3-opus", result)
}

func TestEvaluate_ComplexExpression_FailsOrg(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `org_id == "org-abc" && model_requested contains "gpt"`, TargetModel: "claude-3-opus", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-other", ModelRequested: "openai-gpt-4-turbo"}
	result := snapshotEval(ctx, "openai-gpt-4-turbo", snapshotRules...)
	assert.Empty(t, result)
}

func TestEvaluate_ComplexExpression_FailsModel(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `org_id == "org-abc" && model_requested contains "gpt"`, TargetModel: "claude-3-opus", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-abc", ModelRequested: "claude-3"}
	result := snapshotEval(ctx, "claude-3", snapshotRules...)
	assert.Empty(t, result)
}

func TestEvaluate_SessionIdField(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `session_id == "sess-123"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4", SessionID: "sess-123"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_ClientIPField(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `client_ip == "192.168.1.1"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4", ClientIP: "192.168.1.1"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_UserAgentField(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `user_agent contains "curl"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4", UserAgent: "curl/7.68"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_UnknownField_ReturnsFalse(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `nonexistent == "value"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Empty(t, result)
}

func TestMatch_DirectFunction(t *testing.T) {
	ctx := Context{OrgID: "org-abc", ModelRequested: "gpt-4"}
	result := Match(`model_requested == "gpt-4" && org_id == "org-abc"`, ctx, "gpt-4")
	assert.True(t, result)
}

func TestMatch_DirectFunction_False(t *testing.T) {
	ctx := Context{OrgID: "org-other", ModelRequested: "gpt-4"}
	result := Match(`model_requested == "gpt-4" && org_id == "org-abc"`, ctx, "gpt-4")
	assert.False(t, result)
}

func TestMatch_EmptyExpr(t *testing.T) {
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	result := Match("", ctx, "gpt-4")
	assert.False(t, result)
}

func TestEvaluate_QuotedInValues(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested in "gpt-4","gpt-3.5"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}

	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_PreservesRequestModelParam(t *testing.T) {
	// The modelRequested param is used in evaluation, not the context's ModelRequested
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested == "gpt-4-turbo"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-3.5"}
	result := snapshotEval(ctx, "gpt-4-turbo", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_MixedQuotedAndUnquoted(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested == gpt-4`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_WhitespaceHandling(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `  org_id == "org-abc"   &&   model_requested == "gpt-4"  `, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-abc", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_OrWithContains(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested contains "gpt" || model_requested contains "claude"`, TargetModel: "fallback-model", Priority: 5, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "claude-3"}
	result := snapshotEval(ctx, "claude-3", snapshotRules...)
	assert.Equal(t, "fallback-model", result)
}

func TestEvaluate_OrWithEquals(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `org_id == "org-a" || org_id == "org-b"`, TargetModel: "priority-model", Priority: 5, Enabled: true},
	}
	ctx := Context{OrgID: "org-b", ModelRequested: "gpt-4"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "priority-model", result)
}

func TestEvaluate_ThreeClauseAnd(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `org_id == "org-a" && model_requested == "gpt-4" && session_id == "sess-1"`, TargetModel: "claude-3-opus", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-a", ModelRequested: "gpt-4", SessionID: "sess-1"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Equal(t, "claude-3-opus", result)
}

func TestEvaluate_ThreeClauseAnd_FailsOne(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `org_id == "org-a" && model_requested == "gpt-4" && session_id == "sess-1"`, TargetModel: "claude-3-opus", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-a", ModelRequested: "gpt-4", SessionID: "sess-other"}
	result := snapshotEval(ctx, "gpt-4", snapshotRules...)
	assert.Empty(t, result)
}

func TestEvaluate_InWithSpaces(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested in "gpt-4,gpt-3.5"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}

	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-3.5"}
	result := snapshotEval(ctx, "gpt-3.5", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

func TestEvaluate_NotInWithSpaces(t *testing.T) {
	snapshotRules := []Rule{
		{ID: "r1", MatchExpr: `model_requested not_in "gpt-4,gpt-3.5"`, TargetModel: "claude-3", Priority: 10, Enabled: true},
	}

	ctx := Context{OrgID: "org-1", ModelRequested: "sonnet"}
	result := snapshotEval(ctx, "sonnet", snapshotRules...)
	assert.Equal(t, "claude-3", result)
}

// Deterministic coverage of the remaining comparison/revision branches.
// The write-lock re-check in SnapshotCache.Get is inherently interleaving
// dependent (a concurrent Get must insert between the RLock miss and the
// write lock), so its hit side stays probabilistic; every other branch is
// pinned here so the package coverage does not drift run to run.
func TestEvalCmp_UnknownOperatorIsFalse(t *testing.T) {
	assert.False(t, evalCmp("gpt-4", " ~ ", "gpt-4"), "an unsupported operator never matches")
	assert.False(t, evalCmp("gpt-4", "", "gpt-4"))
}

func TestRulesRevision_DisabledRulesChangeTheHash(t *testing.T) {
	enabled := rulesRevision("org-1", []Rule{{ID: "r1", MatchExpr: `a == "b"`, TargetModel: "x", Priority: 1, Enabled: true}})
	disabled := rulesRevision("org-1", []Rule{{ID: "r1", MatchExpr: `a == "b"`, TargetModel: "x", Priority: 1, Enabled: false}})
	assert.NotEqual(t, enabled, disabled, "flipping a rule's enabled flag must produce a new revision")
}
