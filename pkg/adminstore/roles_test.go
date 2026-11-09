package adminstore

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENT-02: RBAC — role model + org membership.

func TestOrgRoleRank_OrderingAndFailClosed(t *testing.T) {
	// Total order: org-admin > operator > reader > partner.
	assert.Greater(t, OrgRoleRank(RoleOrgAdmin), OrgRoleRank(RoleOperator))
	assert.Greater(t, OrgRoleRank(RoleOperator), OrgRoleRank(RoleReader))
	assert.Equal(t, OrgRoleRank(RoleReader), OrgRoleRank(RoleSecurityAuditor))
	assert.Greater(t, OrgRoleRank(RoleReader), OrgRoleRank(RolePartner))
	// Unknown/empty roles rank 0 (least) — a typo cannot grant access.
	assert.Equal(t, 0, OrgRoleRank(OrgRole("superuser")))
	assert.Equal(t, 0, OrgRoleRank(""))
	assert.False(t, ValidOrgRole(OrgRole("superuser")))
	assert.True(t, ValidOrgRole(RoleOrgAdmin))
	assert.ElementsMatch(t, []OrgRole{RoleOrgAdmin, RoleOperator, RoleReader, RoleSecurityAuditor, RolePartner}, AllOrgRoles())
}

func TestOrgMembership_Create_Set_Delete_List(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	members := map[string]*OrgMembership{} // key: userID/orgID
	row := func(m *OrgMembership) []interface{} {
		return []interface{}{m.ID, m.UserID, m.OrgID, string(m.Role), m.CreatedAt, m.UpdatedAt}
	}
	mockDB := &mockDB{
		queryRowFn: func(_ context.Context, sql string, args ...interface{}) pgx.Row {
			userID, orgID, role := args[0].(string), args[1].(string), args[2].(OrgRole)
			k := userID + "/" + orgID
			if containsSQL(sql, "ON CONFLICT") { // SetOrgMembership (upsert)
				if e, ok := members[k]; ok {
					e.Role, e.UpdatedAt = role, now
					return &mockPGXRow{data: [][]interface{}{row(e)}}
				}
				m := &OrgMembership{ID: "mem-" + k, UserID: userID, OrgID: orgID, Role: role, CreatedAt: now, UpdatedAt: now}
				members[k] = m
				return &mockPGXRow{data: [][]interface{}{row(m)}}
			}
			// CreateOrgMembership: simulate the (user,org) unique violation.
			if _, ok := members[k]; ok {
				return &mockPGXRow{err: &pgconn.PgError{Code: "23505"}}
			}
			m := &OrgMembership{ID: "mem-" + k, UserID: userID, OrgID: orgID, Role: role, CreatedAt: now, UpdatedAt: now}
			members[k] = m
			return &mockPGXRow{data: [][]interface{}{row(m)}}
		},
		execFn: func(_ context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			if containsSQL(sql, "DELETE FROM admin_org_memberships") {
				k := args[0].(string) + "/" + args[1].(string)
				if _, ok := members[k]; !ok {
					return pgconn.NewCommandTag("DELETE 0"), nil
				}
				delete(members, k)
				return pgconn.NewCommandTag("DELETE 1"), nil
			}
			return pgconn.NewCommandTag(""), nil
		},
		queryFn: func(_ context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			if containsSQL(sql, "WHERE user_id") { // GetUserOrgRoles
				userID := args[0].(string)
				var data [][]interface{}
				for _, m := range members {
					if m.UserID == userID {
						data = append(data, []interface{}{m.OrgID, string(m.Role)})
					}
				}
				return &mockPGXRows{data: data}, nil
			}
			orgID := args[0].(string) // ListOrgMembers
			var data [][]interface{}
			for _, m := range members {
				if m.OrgID == orgID {
					data = append(data, row(m))
				}
			}
			return &mockPGXRows{data: data}, nil
		},
	}
	s := newForTest(mockDB, newTestLogger(), nil)

	created, err := s.CreateOrgMembership(ctx, OrgMembership{UserID: "u1", OrgID: "o1", Role: RoleOrgAdmin})
	require.NoError(t, err)
	assert.Equal(t, "o1", created.OrgID)
	assert.Equal(t, RoleOrgAdmin, created.Role)

	// Duplicate create → unique-violation error (handler maps to 409).
	_, err = s.CreateOrgMembership(ctx, OrgMembership{UserID: "u1", OrgID: "o1", Role: RoleOperator})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// SetOrgMembership (upsert) changes the role.
	set, err := s.SetOrgMembership(ctx, "u1", "o1", RoleOperator)
	require.NoError(t, err)
	assert.Equal(t, RoleOperator, set.Role)

	roles, err := s.GetUserOrgRoles(ctx, "u1")
	require.NoError(t, err)
	assert.Equal(t, RoleOperator, roles["o1"])

	list, err := s.ListOrgMembers(ctx, "o1")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "u1", list[0].UserID)

	require.NoError(t, s.DeleteOrgMembership(ctx, "u1", "o1"))
	err = s.DeleteOrgMembership(ctx, "u1", "o1")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestOrgMembership_InvalidRole(t *testing.T) {
	s := newForTest(&mockDB{}, newTestLogger(), nil)
	_, err := s.CreateOrgMembership(context.Background(), OrgMembership{UserID: "u", OrgID: "o", Role: "superuser"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
}

func TestOrgMembership_NilDB(t *testing.T) {
	s := newForTest(nil, newTestLogger(), nil)
	_, err := s.GetUserOrgRoles(context.Background(), "u")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
}
