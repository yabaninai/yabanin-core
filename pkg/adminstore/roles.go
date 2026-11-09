package adminstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// ENT-02: RBAC — server-side role checks for org-scoped admin access.
//
// An admin user holds a ROLE on a SPECIFIC organization (admin_org_memberships).
// Roles form a total order; a request is allowed when the caller's role on the
// target org meets the route's required role. Root (is_root) is the platform
// operator and bypasses membership (handled in the handlers, not here).

// OrgRole is a role an admin user may hold on an organization.
type OrgRole string

const (
	// RoleOrgAdmin grants full control of the org (org-scoped operations).
	RoleOrgAdmin OrgRole = "org-admin"
	// RoleOperator grants read plus operate (spend, routing within policy).
	RoleOperator OrgRole = "operator"
	// RoleReader grants read-only access.
	RoleReader OrgRole = "reader"
	// RoleSecurityAuditor ranks with reader so RequireOrgRole(reader) admits it
	// and RequireOrgRole(operator) does not. Payload and audit rights are
	// permissions, not a higher rank.
	RoleSecurityAuditor OrgRole = "security_auditor"
	// RolePartner grants the reseller partner view.
	RolePartner OrgRole = "partner"
)

// OrgRoleRank orders the roles (higher = more privileged). Unknown roles rank
// 0 (least) so a typo in the DB cannot grant access — fail-closed.
func OrgRoleRank(role OrgRole) int {
	switch role {
	case RoleOrgAdmin:
		return 4
	case RoleOperator:
		return 3
	case RoleReader, RoleSecurityAuditor:
		return 2
	case RolePartner:
		return 1
	default:
		return 0
	}
}

// AllOrgRoles is the set of valid role values (for input validation).
func AllOrgRoles() []OrgRole {
	return []OrgRole{RoleOrgAdmin, RoleOperator, RoleReader, RoleSecurityAuditor, RolePartner}
}

// ValidOrgRole reports whether role is a known role value.
func ValidOrgRole(role OrgRole) bool { return OrgRoleRank(role) > 0 }

// OrgMembership is one row of admin_org_memberships.
type OrgMembership struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	OrgID     string    `json:"org_id"`
	Role      OrgRole   `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const orgMembershipCols = `id::text, user_id::text, org_id::text, role, created_at, updated_at`

// isUniqueViolation reports a Postgres unique-violation (23505), the signal for
// the (user_id, org_id) conflict on CreateOrgMembership.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// CreateOrgMembership grants a role to a user on an org. A conflicting
// (user, org) row is a unique violation → the caller 409s.
func (s *Store) CreateOrgMembership(ctx context.Context, m OrgMembership) (*OrgMembership, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if !ValidOrgRole(m.Role) {
		return nil, fmt.Errorf("invalid role %q", m.Role)
	}
	out := &OrgMembership{}
	err := s.db.QueryRow(ctx,
		`INSERT INTO admin_org_memberships (user_id, org_id, role)
		 VALUES ($1, $2, $3)
		 RETURNING `+orgMembershipCols,
		m.UserID, m.OrgID, m.Role,
	).Scan(&out.ID, &out.UserID, &out.OrgID, &out.Role, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("membership for that user and org already exists")
		}
		return nil, fmt.Errorf("create org membership: %w", err)
	}
	return out, nil
}

// SetOrgMembership upserts a user's role on an org (create or change). This is
// the idempotent form used by the admin "grant role" action.
func (s *Store) SetOrgMembership(ctx context.Context, userID, orgID string, role OrgRole) (*OrgMembership, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if !ValidOrgRole(role) {
		return nil, fmt.Errorf("invalid role %q", role)
	}
	out := &OrgMembership{}
	err := s.db.QueryRow(ctx,
		`INSERT INTO admin_org_memberships (user_id, org_id, role)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, org_id) DO UPDATE SET role = EXCLUDED.role, updated_at = now()
		 RETURNING `+orgMembershipCols,
		userID, orgID, role,
	).Scan(&out.ID, &out.UserID, &out.OrgID, &out.Role, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("set org membership: %w", err)
	}
	return out, nil
}

// DeleteOrgMembership removes a user's role on an org.
func (s *Store) DeleteOrgMembership(ctx context.Context, userID, orgID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx,
		`DELETE FROM admin_org_memberships WHERE user_id = $1 AND org_id = $2`,
		userID, orgID)
	if err != nil {
		return fmt.Errorf("delete org membership: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetUserOrgRoles returns the caller's roles on every org (org_id → role).
func (s *Store) GetUserOrgRoles(ctx context.Context, userID string) (map[string]OrgRole, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT org_id::text, role FROM admin_org_memberships WHERE user_id = $1`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("list user org roles: %w", err)
	}
	defer rows.Close()
	out := map[string]OrgRole{}
	for rows.Next() {
		var orgID string
		var role OrgRole
		if err := rows.Scan(&orgID, &role); err != nil {
			return nil, fmt.Errorf("scan user org role: %w", err)
		}
		out[orgID] = role
	}
	return out, rows.Err()
}

// ListOrgMembers returns the memberships (roles) for an org.
func (s *Store) ListOrgMembers(ctx context.Context, orgID string) ([]*OrgMembership, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+orgMembershipCols+` FROM admin_org_memberships WHERE org_id = $1 ORDER BY created_at`,
		orgID)
	if err != nil {
		return nil, fmt.Errorf("list org members: %w", err)
	}
	defer rows.Close()
	var out []*OrgMembership
	for rows.Next() {
		m := &OrgMembership{}
		if err := rows.Scan(&m.ID, &m.UserID, &m.OrgID, &m.Role, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan org member: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
