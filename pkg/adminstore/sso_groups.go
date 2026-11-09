package adminstore

// N04-P01: SSO group → local-role mapping.
//
// Each organization may DECLARE rules binding IdP group memberships to local
// admin roles (sso_group_role_rules, migration 0012). The rules are applied
// at every SSO login: ResolveSSORole decides, per org, whether the caller's
// groups map onto a role. The decision model is deliberately small and
// fail-closed:
//
//   - DENY WINS: any matching deny rule suppresses every grant for the login;
//   - a CONFLICT (matching grant rules naming DIFFERENT roles) denies — an
//     ambiguous declaration must never silently pick the higher role;
//   - identical duplicate grants (same role) stay a plain grant;
//   - an UNMATCHED group grants nothing — mapping only ever applies where a
//     declared rule matches;
//   - group matching is exact (byte equality, no case folding): IdP group
//     names are opaque identifiers, and silent normalization would widen the
//     rule beyond what the org declared.
//
// Provenance (sso_role_grants) records which memberships the mapping set, so
// a later sync can revoke exactly those — and never a role an admin granted
// by hand. The revocation itself runs at the next SSO login (the sync point
// in services/admin/handlers); SCIM keeps its own role-sync semantics.
//
// ISOLATION POSTURE — NO RLS, org predicate in every query: the SSO login
// path runs before any org context exists, so an app.current_org-gated RLS
// policy would hide every row at the only moment the mapping is applied (the
// full rationale is on migration 0012). Every query below carries the
// explicit org predicate; the int tests assert cross-org isolation.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SSOGroupRuleEffect is the effect one declared rule has on a matching login.
type SSOGroupRuleEffect string

const (
	// SSOGrantRuleEffect maps the group onto the rule's local role.
	SSOGrantRuleEffect SSOGroupRuleEffect = "grant"
	// SSODenyRuleEffect blocks every mapping grant for holders of the group
	// (deny-wins; it never widens anything).
	SSODenyRuleEffect SSOGroupRuleEffect = "deny"
)

// ValidSSOGroupRuleEffect reports whether effect is a declared effect value.
func ValidSSOGroupRuleEffect(effect SSOGroupRuleEffect) bool {
	return effect == SSOGrantRuleEffect || effect == SSODenyRuleEffect
}

// ssoGroupNameMaxLen bounds a declared group name (the DB CHECK enforces the
// same bound — the store must reject before the DB does).
const ssoGroupNameMaxLen = 256

// SSOGroupRoleRule is one row of sso_group_role_rules: an org-declared
// binding of an IdP group to an effect. Role is the granted local role for
// grant rules and empty for deny rules.
type SSOGroupRoleRule struct {
	ID        string             `json:"id"`
	OrgID     string             `json:"org_id"`
	Group     string             `json:"group_name"`
	Effect    SSOGroupRuleEffect `json:"effect"`
	Role      OrgRole            `json:"role,omitempty"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// SSORoleDecision is the outcome of resolving one org's declared rules
// against the groups presented at an SSO login.
type SSORoleDecision struct {
	// Granted reports that matching grant rules name exactly one role and no
	// deny rule matched. Role/Group identify the mapped role and the group
	// whose rule produced it (audit attribution).
	Granted bool
	Role    OrgRole
	Group   string
	// Denied reports deny-wins: a matching deny rule, or matching grant
	// rules naming DIFFERENT roles (a declared conflict denies by design).
	Denied bool
}

// ResolveSSORole applies one org's declared rules to the IdP group set of a
// login. It is pure: the same rules and groups always produce the same
// decision, which is what makes repeated logins idempotent.
func ResolveSSORole(rules []SSOGroupRoleRule, groups []string) SSORoleDecision {
	held := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		held[g] = struct{}{}
	}
	var (
		dec      SSORoleDecision
		roleSeen bool
	)
	for _, r := range rules {
		if _, ok := held[r.Group]; !ok {
			continue
		}
		switch r.Effect {
		case SSODenyRuleEffect:
			dec.Denied = true
		case SSOGrantRuleEffect:
			if roleSeen && r.Role != dec.Role {
				dec.Denied = true // conflicting grants — deny-wins
			}
			if !roleSeen {
				roleSeen = true
				dec.Granted, dec.Role, dec.Group = true, r.Role, r.Group
			}
		}
	}
	if dec.Denied {
		return SSORoleDecision{Denied: true}
	}
	return dec
}

const ssoGroupRuleCols = `id::text, org_id::text, group_name, effect, COALESCE(role, ''), created_at, updated_at`

func scanSSOGroupRule(row interface{ Scan(dest ...any) error }) (*SSOGroupRoleRule, error) {
	r := &SSOGroupRoleRule{}
	var role string
	err := row.Scan(&r.ID, &r.OrgID, &r.Group, &r.Effect, &role, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	r.Role = OrgRole(role)
	return r, nil
}

// SetSSOGroupRoleRule upserts one declared rule for the org (the natural
// key is (org, group, effect)): changing a grant's role updates the same
// row. A grant requires a valid local role; a deny must not carry one.
func (s *Store) SetSSOGroupRoleRule(ctx context.Context, orgID string, rule SSOGroupRoleRule) (*SSOGroupRoleRule, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if orgID == "" {
		return nil, fmt.Errorf("org id is required")
	}
	rule.Group = strings.TrimSpace(rule.Group)
	if rule.Group == "" || len(rule.Group) > ssoGroupNameMaxLen {
		return nil, fmt.Errorf("sso group rule: group name must be 1..%d characters", ssoGroupNameMaxLen)
	}
	if !ValidSSOGroupRuleEffect(rule.Effect) {
		return nil, fmt.Errorf("sso group rule: invalid effect %q", rule.Effect)
	}
	if rule.Effect == SSOGrantRuleEffect && !ValidOrgRole(rule.Role) {
		return nil, fmt.Errorf("sso group rule: grant effect requires a valid role, got %q", rule.Role)
	}
	if rule.Effect == SSODenyRuleEffect && rule.Role != "" {
		return nil, fmt.Errorf("sso group rule: deny effect must not carry a role")
	}
	roleArg := ""
	if rule.Effect == SSOGrantRuleEffect {
		roleArg = string(rule.Role)
	}
	out, err := scanSSOGroupRule(s.db.QueryRow(ctx,
		`INSERT INTO sso_group_role_rules (org_id, group_name, effect, role)
		 VALUES ($1::uuid, $2, $3, NULLIF($4, ''))
		 ON CONFLICT (org_id, group_name, effect)
		 DO UPDATE SET role = NULLIF($4, ''), updated_at = now()
		 RETURNING `+ssoGroupRuleCols,
		orgID, rule.Group, rule.Effect, roleArg,
	))
	if err != nil {
		return nil, fmt.Errorf("set sso group rule: %w", err)
	}
	return out, nil
}

// ListSSOGroupRoleRules returns the org's declared rules (org predicate
// mandatory — another org's rules are never visible here).
func (s *Store) ListSSOGroupRoleRules(ctx context.Context, orgID string) ([]SSOGroupRoleRule, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+ssoGroupRuleCols+` FROM sso_group_role_rules WHERE org_id = $1::uuid ORDER BY group_name, effect`,
		orgID)
	if err != nil {
		return nil, fmt.Errorf("list sso group rules: %w", err)
	}
	defer rows.Close()
	var out []SSOGroupRoleRule
	for rows.Next() {
		r, err := scanSSOGroupRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan sso group rule: %w", err)
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// DeleteSSOGroupRoleRule removes one of the org's declared rules. A foreign
// org's rule id resolves as ErrNotFound (never a cross-org delete).
func (s *Store) DeleteSSOGroupRoleRule(ctx context.Context, orgID, ruleID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx,
		`DELETE FROM sso_group_role_rules WHERE org_id = $1::uuid AND id = $2::uuid`,
		orgID, ruleID)
	if err != nil {
		return fmt.Errorf("delete sso group rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetSSOGrantedRole reads the mapping provenance for (org, user): the role
// the mapping granted, and whether such a grant exists at all.
func (s *Store) GetSSOGrantedRole(ctx context.Context, orgID, userID string) (OrgRole, bool, error) {
	if s.db == nil {
		return "", false, fmt.Errorf("database not available")
	}
	var role OrgRole
	err := s.db.QueryRow(ctx,
		`SELECT role FROM sso_role_grants WHERE org_id = $1::uuid AND user_id = $2::uuid`,
		orgID, userID,
	).Scan(&role)
	if IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get sso granted role: %w", err)
	}
	return role, true, nil
}

// SetSSOGrantedRole records/refreshes the mapping provenance. granted_at is
// stable across no-op re-grants of the SAME role (idempotent repeated
// logins must not churn the row).
func (s *Store) SetSSOGrantedRole(ctx context.Context, orgID, userID string, role OrgRole) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if !ValidOrgRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO sso_role_grants (org_id, user_id, role)
		 VALUES ($1::uuid, $2::uuid, $3)
		 ON CONFLICT (org_id, user_id) DO UPDATE
		     SET role = EXCLUDED.role,
		         granted_at = CASE WHEN sso_role_grants.role IS DISTINCT FROM EXCLUDED.role
		                           THEN now() ELSE sso_role_grants.granted_at END`,
		orgID, userID, role,
	)
	if err != nil {
		return fmt.Errorf("set sso granted role: %w", err)
	}
	return nil
}

// DeleteSSOGrantedRole clears the mapping provenance (idempotent: clearing
// an absent grant is a no-op — the sync converges either way).
func (s *Store) DeleteSSOGrantedRole(ctx context.Context, orgID, userID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`DELETE FROM sso_role_grants WHERE org_id = $1::uuid AND user_id = $2::uuid`,
		orgID, userID)
	if err != nil {
		return fmt.Errorf("delete sso granted role: %w", err)
	}
	return nil
}
