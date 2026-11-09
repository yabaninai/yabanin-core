package adminstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(v string) *string { return &v }

func containsSQL(s, sub string) bool { return strings.Contains(s, sub) }

func TestAgentProfile_Create_Get_List_Update_Delete(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	capVal := int64(5000)
	// One live profile row; the delete step removes it.
	row := func() []interface{} {
		return []interface{}{"profile-1", "org-1", "builder", "premium",
			[]byte(`["search"]`), capVal, "strict", now, now}
	}
	mockDB := &mockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			switch {
			case containsSQL(sql, "INSERT INTO agent_profiles"):
				return &mockPGXRow{data: [][]interface{}{row()}}
			case containsSQL(sql, "UPDATE agent_profiles"):
				// simulate the update applying: tier→cheap, grants→[search,web]
				return &mockPGXRow{data: [][]interface{}{{"profile-1", "org-1", "builder", "cheap",
					[]byte(`["search","web"]`), capVal, "strict", now, now}}}
			case containsSQL(sql, "FROM agent_profiles"):
				return &mockPGXRow{data: [][]interface{}{row()}}
			}
			return &mockPGXRow{}
		},
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			if containsSQL(sql, "FROM agent_profiles") {
				return &mockPGXRows{data: [][]interface{}{row()}}, nil
			}
			return nil, assert.AnError
		},
		execFn: func(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
			if containsSQL(sql, "DELETE FROM agent_profiles") {
				return pgconn.NewCommandTag("DELETE 1"), nil
			}
			return pgconn.NewCommandTag("DELETE 0"), nil
		},
	}
	s := newForTest(mockDB, newTestLogger(), nil)

	created, err := s.CreateAgentProfile(ctx, AgentProfileCreateParams{
		OrgID: "org-1", Name: "builder", TierHint: "premium",
		MCPGrants: []string{"search"}, BudgetCapCents: &capVal, GuardMode: "strict",
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.Equal(t, "profile-1", created.ID)
	assert.Equal(t, "org-1", created.OrgID)
	assert.Equal(t, "premium", created.TierHint)
	assert.Equal(t, []string{"search"}, created.MCPGrants)
	require.NotNil(t, created.BudgetCapCents)
	assert.Equal(t, int64(5000), *created.BudgetCapCents)
	assert.Equal(t, "strict", created.GuardMode)

	got, err := s.GetAgentProfile(ctx, "profile-1")
	require.NoError(t, err)
	assert.Equal(t, "builder", got.Name)

	list, err := s.ListAgentProfiles(ctx, "org-1")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "profile-1", list[0].ID)

	updated, err := s.UpdateAgentProfile(ctx, "profile-1", AgentProfileUpdateParams{
		TierHint:  strPtr("cheap"),
		MCPGrants: &[]string{"search", "web"},
	})
	require.NoError(t, err)
	assert.Equal(t, "cheap", updated.TierHint)
	assert.Equal(t, []string{"search", "web"}, updated.MCPGrants)

	require.NoError(t, s.DeleteAgentProfile(ctx, "profile-1"))
}

func TestAgentProfile_GrantDefaultsAndNotClearableOnUpdate(t *testing.T) {
	// Update with no BudgetCapCents change and an empty grant list: the grants
	// round-trip as [] (never nil) and the cap is untouched (nil **int64).
	ctx := context.Background()
	capVal := int64(999)
	now := time.Now()
	mockDB := &mockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			if containsSQL(sql, "FROM agent_profiles") {
				return &mockPGXRow{data: [][]interface{}{{"p1", "org-1", "x", "",
					[]byte(`[]`), capVal, "standard", now, now}}}
			}
			return &mockPGXRow{}
		},
	}
	s := newForTest(mockDB, newTestLogger(), nil)
	got, err := s.GetAgentProfile(ctx, "p1")
	require.NoError(t, err)
	assert.Equal(t, []string{}, got.MCPGrants)
	require.NotNil(t, got.BudgetCapCents)
	assert.Equal(t, int64(999), *got.BudgetCapCents)
}

func TestAgentProfile_NilDB(t *testing.T) {
	s := newForTest(nil, newTestLogger(), nil)
	ctx := context.Background()
	_, err := s.CreateAgentProfile(ctx, AgentProfileCreateParams{OrgID: "org-1", Name: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
}
