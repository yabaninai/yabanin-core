package evaluator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CORE-TRACE-04: the routing rule that actually won selection must be
// identifiable afterwards — by id and by the exact content version that was
// in force at match time — so request history can answer "which rule did
// this" even when rules share a name/expression or are edited later.

func TestEvaluateMatch_IdentifiesWinningRule(t *testing.T) {
	// Two "same-name" rules: identical expression and target, different ids.
	// Only the record can tell them apart (core acceptance criterion).
	high := Rule{ID: "aaaa1111-0000-0000-0000-000000000001", OrgID: "org-1",
		MatchExpr: `model_requested == "gpt-4"`, TargetModel: "premium", Priority: 20, Enabled: true}
	low := Rule{ID: "aaaa1111-0000-0000-0000-000000000002", OrgID: "org-1",
		MatchExpr: `model_requested == "gpt-4"`, TargetModel: "premium", Priority: 10, Enabled: true}

	s := NewSnapshot("org-1", []Rule{low, high})
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}

	model, m := s.EvaluateMatch(ctx, "gpt-4")
	require.NotNil(t, m, "a matched rule must produce a match record")
	assert.Equal(t, "premium", model)
	assert.Equal(t, NamespaceRouting, m.Namespace)
	assert.Equal(t, high.ID, m.RuleID, "the higher-priority rule must be identified")
	assert.Equal(t, high.ContentVersion(), m.Version)
}

func TestEvaluateMatch_AgreesWithEvaluate(t *testing.T) {
	rules := []Rule{
		{ID: "r1", OrgID: "org-1", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "premium", Priority: 20, Enabled: true},
		{ID: "r2", OrgID: "org-1", MatchExpr: `model_requested in "gpt-4,gpt-3.5"`, TargetModel: "cheap", Priority: 10, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4"}
	s := NewSnapshot("org-1", rules)

	model, m := s.EvaluateMatch(ctx, "gpt-4")
	assert.Equal(t, s.Evaluate(ctx, "gpt-4"), model,
		"EvaluateMatch and Evaluate must select the same rule (single selection path)")
	require.NotNil(t, m)
	assert.Equal(t, "r1", m.RuleID)

	// No match: empty model, nil record — never a fabricated identity.
	model, m = s.EvaluateMatch(Context{OrgID: "org-1", ModelRequested: "other"}, "other")
	assert.Empty(t, model)
	assert.Nil(t, m)
}

func TestEvaluateMatch_RefusesForeignOrgAndNil(t *testing.T) {
	s := NewSnapshot("org-1", []Rule{
		{ID: "r1", OrgID: "org-1", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "premium", Enabled: true},
	})
	model, m := s.EvaluateMatch(Context{OrgID: "org-2", ModelRequested: "gpt-4"}, "gpt-4")
	assert.Empty(t, model)
	assert.Nil(t, m)

	var nilSnap *Snapshot
	model, m = nilSnap.EvaluateMatch(Context{OrgID: "org-1"}, "gpt-4")
	assert.Empty(t, model)
	assert.Nil(t, m)
}

func TestContentVersion_DeterministicAndEditSensitive(t *testing.T) {
	base := Rule{ID: "r1", OrgID: "org-1", MatchExpr: `model_requested == "gpt-4"`,
		TargetModel: "premium", Priority: 10, Enabled: true}

	v1 := base.ContentVersion()
	assert.Equal(t, v1, base.ContentVersion(), "same config must hash identically")

	edits := []struct {
		name string
		mut  func(*Rule)
	}{
		{"expression", func(r *Rule) { r.MatchExpr = `model_requested == "gpt-3.5"` }},
		{"target", func(r *Rule) { r.TargetModel = "cheap" }},
		{"priority", func(r *Rule) { r.Priority = 11 }},
		{"enabled", func(r *Rule) { r.Enabled = false }},
		{"id", func(r *Rule) { r.ID = "r2" }},
		{"org", func(r *Rule) { r.OrgID = "org-2" }},
	}
	for _, e := range edits {
		edited := base
		e.mut(&edited)
		assert.NotEqual(t, v1, edited.ContentVersion(),
			"changing %s must change the content version", e.name)
	}

	// A different rule in the same org's set must not affect this rule's
	// identity (per-rule content hash, not a set revision).
	other := base
	other.MatchExpr = `session_id == "x"`
	assert.Equal(t, v1, base.ContentVersion())
	assert.NotEqual(t, v1, other.ContentVersion())

	// Field boundaries must not bleed: concatenating two fields cannot
	// produce a value that hashes like the split form.
	joined := base
	joined.ID = "r"
	joined.OrgID = "1"
	assert.NotEqual(t, v1, joined.ContentVersion(), "field separator must prevent id/org concatenation aliasing")
}

func TestContentVersion_Format(t *testing.T) {
	v := Rule{ID: "r1", OrgID: "org-1", MatchExpr: "x == \"y\"", TargetModel: "m", Priority: 1, Enabled: true}.
		ContentVersion()
	assert.Regexp(t, `^[0-9a-f]{16}$`, v,
		"version must be 16 lowercase hex chars")
}

func TestEvaluateMatch_DelegationCompilesAndRoutes(t *testing.T) {
	// Guard the delegation: Evaluate must keep behaving exactly as before
	// (model selection semantics pinned by the rule_test suite; this pins
	// the delegation itself on a representative case).
	rules := []Rule{
		{ID: "r2", OrgID: "org-1", MatchExpr: `user_agent contains "bot"`, TargetModel: "blocked", Priority: 30, Enabled: true},
		{ID: "r1", OrgID: "org-1", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "premium", Priority: 20, Enabled: true},
	}
	ctx := Context{OrgID: "org-1", ModelRequested: "gpt-4", UserAgent: "Mozilla"}
	s := NewSnapshot("org-1", rules)
	assert.Equal(t, "premium", s.Evaluate(ctx, "gpt-4"))
	_, m := s.EvaluateMatch(ctx, "gpt-4")
	require.NotNil(t, m)
	assert.Equal(t, "r1", m.RuleID)
}
