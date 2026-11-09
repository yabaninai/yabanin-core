package adminstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// (migration 0012_scim).
//
// ISOLATION POSTURE — NO RLS, org predicate in every query. Both tables are
// platform objects with the org bound in the row (migration 0012 header
// documents the full rationale): the bearer-auth lookup resolves the org
// FROM the token hash, so an app.current_org-gated RLS policy (which hides
// every row while the GUC is unset — production connections start fresh,
// migration 0002) would make token authentication impossible. The explicit
// `org_id = $n` predicate in EVERY query below is the primary isolation
// layer (same discipline as member_invites.go: "correct under any role");
// the handler tests and the DB-gated integration tests assert it.

// ScimToken is one org-scoped SCIM bearer credential (scim_tokens row).
//
// W-SECADM parity: TokenHash is internal-only (`json:"-"`) — the sha256
// material never leaves the process; HTTP callers report HasHash. The raw
// token exists only as the CreateScimToken return value (shown once).
type ScimToken struct {
	ID         string     `json:"id"`
	TokenHash  string     `json:"-"`
	HasHash    bool       `json:"has_hash"`
	OrgID      string     `json:"org_id"`
	Label      string     `json:"label"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// Revoked reports whether the token has been revoked.
func (t *ScimToken) Revoked() bool { return t.RevokedAt != nil }

// scimTokenCols is the canonical scim_tokens SELECT list. ListScimTokens
// deliberately selects WITHOUT token_hash (no listing path needs the hash);
// the auth lookup reads the full list to re-verify the presented token in
// constant time after the index lookup.
//
// #nosec G101 -- the string is a SQL SELECT column list; the credential
// material column (token_hash) is deliberately NOT part of it, and no
// secret value is hardcoded anywhere in this constant.
const scimTokenCols = `id::text, org_id::text, label, created_by::text, created_at, last_used_at, revoked_at`

// ScimTokenPrefix is the raw token namespace marker ("scim_<64hex>").
const ScimTokenPrefix = "scim_"

// NewScimToken mints a raw SCIM bearer token ("scim_" + 64 hex chars, 32
// bytes of crypto/rand) together with its sha256-hex storage form.
func NewScimToken() (rawToken, tokenHash string, err error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", fmt.Errorf("generate scim token: %w", err)
	}
	rawToken = ScimTokenPrefix + hex.EncodeToString(secret)
	sum := sha256.Sum256([]byte(rawToken))
	return rawToken, hex.EncodeToString(sum[:]), nil
}

// ScimTokenHash is the stored form of a raw token (sha256 hex).
func ScimTokenHash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// ScimTokenMatches re-verifies a presented raw token against a fetched row
// in constant time (hmac-free variant: length-independent compare of the
// fixed-length hex digests). The DB unique index on token_hash finds the
// candidate row without comparing secret material; this compare is the
// timing-safe confirmation before the token is trusted.
func ScimTokenMatches(rawToken, storedHash string) bool {
	presented := ScimTokenHash(rawToken)
	return len(presented) == len(storedHash) &&
		subtle.ConstantTimeCompare([]byte(presented), []byte(storedHash)) == 1
}

// CreateScimToken inserts a new SCIM bearer token (hash-only) and returns
// the row together with the raw token — the raw token is returned NOWHERE
// else (never on lists, never again after this call).
func (s *Store) CreateScimToken(ctx context.Context, orgID, label, createdBy string) (*ScimToken, string, error) {
	if s.db == nil {
		return nil, "", fmt.Errorf("database not available")
	}
	if orgID == "" {
		return nil, "", fmt.Errorf("org id is required")
	}
	if createdBy == "" {
		return nil, "", fmt.Errorf("creator id is required")
	}
	rawToken, hash, err := NewScimToken()
	if err != nil {
		return nil, "", err
	}
	t := &ScimToken{}
	err = s.db.QueryRow(ctx,
		`INSERT INTO scim_tokens (org_id, token_hash, label, created_by)
		 VALUES ($1::uuid, $2, $3, $4::uuid)
		 RETURNING `+scimTokenCols,
		orgID, hash, label, createdBy,
	).Scan(&t.ID, &t.OrgID, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt)
	if err != nil {
		return nil, "", fmt.Errorf("create scim token: %w", err)
	}
	t.HasHash = true
	return t, rawToken, nil
}

// ListScimTokens returns the org's tokens, newest first. Token hashes are
// never selected (nothing outside the auth path may see even the hash).
func (s *Store) ListScimTokens(ctx context.Context, orgID string) ([]*ScimToken, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+scimTokenCols+` FROM scim_tokens WHERE org_id = $1::uuid ORDER BY created_at DESC`,
		orgID)
	if err != nil {
		return nil, fmt.Errorf("list scim tokens: %w", err)
	}
	defer rows.Close()
	var out []*ScimToken
	for rows.Next() {
		t := &ScimToken{}
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan scim token: %w", err)
		}
		t.HasHash = false
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeScimToken stamps revoked_at on one of the org's tokens. The org
// predicate makes a foreign org's id resolve as ErrNotFound (not a revoke).
func (s *Store) RevokeScimToken(ctx context.Context, orgID, tokenID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE scim_tokens SET revoked_at = now() WHERE id = $1::uuid AND org_id = $2::uuid AND revoked_at IS NULL`,
		tokenID, orgID)
	if err != nil {
		return fmt.Errorf("revoke scim token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FindScimTokenByHash resolves the bearer-auth candidate row by the token's
// sha256 (unique index). The caller MUST confirm with ScimTokenMatches
// (constant time) before trusting the row, and treat Revoked() as 401.
func (s *Store) FindScimTokenByHash(ctx context.Context, tokenHash string) (*ScimToken, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	t := &ScimToken{}
	err := s.db.QueryRow(ctx,
		`SELECT id::text, token_hash, org_id::text, label, created_by::text, created_at, last_used_at, revoked_at
		 FROM scim_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(&t.ID, &t.TokenHash, &t.OrgID, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt)
	if IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find scim token by hash: %w", err)
	}
	t.HasHash = true
	return t, nil
}

// TouchScimToken refreshes last_used_at for one of the org's tokens. The
// handlers throttle this to at most once per minute per token (off the hot
// path); a failure here is logged, never surfaced to the IdP.
func (s *Store) TouchScimToken(ctx context.Context, orgID, tokenID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`UPDATE scim_tokens SET last_used_at = now() WHERE id = $1::uuid AND org_id = $2::uuid`,
		tokenID, orgID)
	if err != nil {
		return fmt.Errorf("touch scim token: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// SCIM identities (scim_identities) — the IdP resource ↔ admin user mapping.
// ---------------------------------------------------------------------------

// ScimUser is one scim_identities row joined with the admin_users state the
// SCIM resources expose (display_name from admin_users, active from both —
// the admin_users.active flag is authoritative for login, the identity flag
// records the last synced intent).
type ScimUser struct {
	ID           string `json:"id"` // the SCIM resource id (scim_identities.scim_user_id)
	OrgID        string `json:"org_id"`
	ExternalID   string `json:"external_id,omitempty"`
	AdminUserID  string `json:"admin_user_id"`
	UserName     string `json:"user_name"`
	GivenName    string `json:"given_name,omitempty"`
	FamilyName   string `json:"family_name,omitempty"`
	DisplayName  string `json:"display_name,omitempty"`
	Active       bool   `json:"active"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastSyncedAt time.Time
}

// ScimUserParams is the provisioned profile of a POST/PUT /Users payload.
type ScimUserParams struct {
	UserName   string
	ExternalID string
	GivenName  string
	FamilyName string
	Active     bool
	Role       OrgRole // membership role applied on CREATE only (default reader)
}

// scimUserCols is the canonical joined SELECT list (identity + admin user).
const scimUserCols = `si.scim_user_id, si.org_id::text, si.external_id, si.admin_user_id::text,
	si.user_name, si.given_name, si.family_name, COALESCE(au.display_name, ''), au.active AND si.active,
	si.created_at, si.updated_at, si.last_synced_at`

// ErrScimConflict reports an (org, userName) / (org, externalId) collision
// that cannot be resolved as an idempotent re-provision (a different SCIM
// resource id already owns it).
var ErrScimConflict = errors.New("scim identity conflict")

// ProvisionScimUser creates or idempotently returns the identity for one
// SCIM POST /Users in ONE transaction (org GUC pinned by withOrgTx):
//
//  1. an existing identity for the same (org, userName) or (org, externalId)
//     is returned as-is (created=false) — a resync never duplicates;
//  2. otherwise a NEW admin user is created (active, EMPTY password hash —
//     password login is impossible by construction; SSO is the login path)
//     with a membership in the token org holding p.Role;
//  3. the scim_identities row links org ↔ admin_user ↔ scim_user_id.
//
// The SCIM resource id is generated here (uuid) and globally unique.
func (s *Store) ProvisionScimUser(ctx context.Context, orgID string, p ScimUserParams) (*ScimUser, bool, error) {
	if s.db == nil {
		return nil, false, fmt.Errorf("database not available")
	}
	if orgID == "" || p.UserName == "" {
		return nil, false, fmt.Errorf("org id and user name are required")
	}
	if !ValidOrgRole(p.Role) {
		return nil, false, fmt.Errorf("invalid role %q", p.Role)
	}

	getScimUserTx := func(tx auditTx, scimUserID string) (*ScimUser, error) {
		return getScimUserTx(tx, ctx, orgID, scimUserID)
	}
	var (
		out     *ScimUser
		created bool
	)
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		// Idempotent resync: same userName OR same externalId in this org →
		// return the existing resource untouched (the caller decides whether
		// to follow with a sync update).
		var existingID string
		err := tx.QueryRow(ctx,
			`SELECT scim_user_id FROM scim_identities
			 WHERE org_id = $1::uuid AND (user_name = $2 OR (external_id <> '' AND external_id = $3))
			 LIMIT 1`,
			orgID, p.UserName, p.ExternalID,
		).Scan(&existingID)
		switch {
		case err == nil:
			u, err := getScimUserTx(tx, existingID)
			if err != nil {
				return err
			}
			out = u
			return nil
		case !IsNotFound(err):
			return fmt.Errorf("look up scim identity: %w", err)
		}

		// Create. The empty password_hash fails closed for password logins
		// (bcrypt rejects it); the OIDC SSO mapping resolves the account by
		// verified email instead.
		var adminUserID string
		if err := tx.QueryRow(ctx,
			`INSERT INTO admin_users (email, password_hash, display_name, active)
			 VALUES ($1, '', $2, $3)
			 RETURNING id::text`,
			p.UserName, ScimDisplayName(p.GivenName, p.FamilyName), p.Active,
		).Scan(&adminUserID); err != nil {
			return fmt.Errorf("create admin user from scim: %w", err)
		}

		scimUserID := uuid.NewString()
		if _, err := tx.Exec(ctx,
			`INSERT INTO scim_identities (org_id, scim_user_id, external_id, admin_user_id, user_name, given_name, family_name, active)
			 VALUES ($1::uuid, $2, $3, $4::uuid, $5, $6, $7, $8)`,
			orgID, scimUserID, p.ExternalID, adminUserID, p.UserName, p.GivenName, p.FamilyName, p.Active,
		); err != nil {
			return fmt.Errorf("create scim identity: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO admin_org_memberships (user_id, org_id, role)
			 VALUES ($1::uuid, $2::uuid, $3)
			 ON CONFLICT (user_id, org_id) DO NOTHING`,
			adminUserID, orgID, p.Role,
		); err != nil {
			return fmt.Errorf("attach scim membership: %w", err)
		}

		u, err := getScimUserTx(tx, scimUserID)
		if err != nil {
			return err
		}
		out = u
		created = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, created, nil
}

// ScimDisplayName renders the SCIM name fields into admin_users.display_name.
func ScimDisplayName(given, family string) string {
	switch {
	case given == "" && family == "":
		return ""
	case family == "":
		return given
	case given == "":
		return family
	default:
		return given + " " + family
	}
}

// getScimUserTx reads one identity (org predicate mandatory) inside a tx.
func getScimUserTx(tx auditTx, ctx context.Context, orgID, scimUserID string) (*ScimUser, error) {
	u := &ScimUser{}
	err := tx.QueryRow(ctx, `SELECT `+scimUserCols+`
		FROM scim_identities si LEFT JOIN admin_users au ON au.id = si.admin_user_id
		WHERE si.org_id = $1::uuid AND si.scim_user_id = $2`,
		orgID, scimUserID,
	).Scan(&u.ID, &u.OrgID, &u.ExternalID, &u.AdminUserID, &u.UserName, &u.GivenName, &u.FamilyName,
		&u.DisplayName, &u.Active, &u.CreatedAt, &u.UpdatedAt, &u.LastSyncedAt)
	if IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get scim user: %w", err)
	}
	return u, nil
}

// GetScimUser returns one of the org's SCIM identities (org predicate: a
// foreign org's scim_user_id is ErrNotFound, never a cross-org read).
func (s *Store) GetScimUser(ctx context.Context, orgID, scimUserID string) (*ScimUser, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	u := &ScimUser{}
	err := s.db.QueryRow(ctx,
		`SELECT `+scimUserCols+`
		 FROM scim_identities si LEFT JOIN admin_users au ON au.id = si.admin_user_id
		 WHERE si.org_id = $1::uuid AND si.scim_user_id = $2`,
		orgID, scimUserID,
	).Scan(&u.ID, &u.OrgID, &u.ExternalID, &u.AdminUserID, &u.UserName, &u.GivenName, &u.FamilyName,
		&u.DisplayName, &u.Active, &u.CreatedAt, &u.UpdatedAt, &u.LastSyncedAt)
	if IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get scim user: %w", err)
	}
	return u, nil
}

// ListScimUsers returns active SCIM identities of the org, oldest first
// (stable pagination for IdP list requests; inactive identities remain
// addressable by GetScimUser for explicit reconciliation).
func (s *Store) ListScimUsers(ctx context.Context, orgID string) ([]*ScimUser, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+scimUserCols+`
		 FROM scim_identities si LEFT JOIN admin_users au ON au.id = si.admin_user_id
		 WHERE si.org_id = $1::uuid AND au.active AND si.active
		 ORDER BY si.created_at, si.scim_user_id`,
		orgID)
	if err != nil {
		return nil, fmt.Errorf("list scim users: %w", err)
	}
	defer rows.Close()
	var out []*ScimUser
	for rows.Next() {
		u := &ScimUser{}
		if err := rows.Scan(&u.ID, &u.OrgID, &u.ExternalID, &u.AdminUserID, &u.UserName, &u.GivenName, &u.FamilyName,
			&u.DisplayName, &u.Active, &u.CreatedAt, &u.UpdatedAt, &u.LastSyncedAt); err != nil {
			return nil, fmt.Errorf("scan scim user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SyncScimUser applies the synced profile fields of a PUT/PATCH /Users to
// BOTH the identity row and the backing admin user, in one transaction:
// given/family names (→ admin_users.display_name), externalId, and active
// (admin_users.active is the authoritative login gate; sessions of a
// deactivated user are invalidated via the sessions_changed_at watermark
// like the admin UI does). userName is IMMUTABLE — a changed userName is
// ErrScimConflict (the handler 400s it before calling here).
func (s *Store) SyncScimUser(ctx context.Context, orgID, scimUserID string, p ScimUserParams) (*ScimUser, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var out *ScimUser
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		var adminUserID string
		err := tx.QueryRow(ctx,
			`UPDATE scim_identities si
			 SET given_name = $3, family_name = $4, external_id = $5, active = $6,
			     last_synced_at = now(), updated_at = now()
			 WHERE si.org_id = $1::uuid AND si.scim_user_id = $2
			 RETURNING si.admin_user_id::text`,
			orgID, scimUserID, p.GivenName, p.FamilyName, p.ExternalID, p.Active,
		).Scan(&adminUserID)
		if IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sync scim identity: %w", err)
		}
		display := ScimDisplayName(p.GivenName, p.FamilyName)
		if _, err := tx.Exec(ctx,
			`UPDATE admin_users
			 SET display_name = $2,
			     active = $3,
			     sessions_changed_at = CASE WHEN active AND NOT $3 THEN now() ELSE sessions_changed_at END,
			     updated_at = now()
			 WHERE id = $1::uuid
			   AND (display_name IS DISTINCT FROM $2 OR active IS DISTINCT FROM $3)`,
			adminUserID, display, p.Active,
		); err != nil {
			return fmt.Errorf("sync scim admin user: %w", err)
		}
		// The transition to inactive updates sessions_changed_at atomically
		// with the user state. Repeated deactivation and name-only syncs are
		// idempotent and do not keep invalidating sessions or churn updated_at.
		u, err := getScimUserTx(tx, ctx, orgID, scimUserID)
		if err != nil {
			return err
		}
		out = u
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeactivateScimUser is the SCIM DELETE /Users semantic: the admin user and
// the identity are DEACTIVATED (login-gating flag false), never deleted —
// the IdP may reactivate by syncing active=true. ErrNotFound for a foreign
// org's scim_user_id.
func (s *Store) DeactivateScimUser(ctx context.Context, orgID, scimUserID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	return s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		var adminUserID string
		err := tx.QueryRow(ctx,
			`UPDATE scim_identities SET active = false, last_synced_at = now(), updated_at = now()
			 WHERE org_id = $1::uuid AND scim_user_id = $2
			 RETURNING admin_user_id::text`,
			orgID, scimUserID,
		).Scan(&adminUserID)
		if IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("deactivate scim identity: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE admin_users SET active = false, sessions_changed_at = now(), updated_at = now()
			 WHERE id = $1::uuid AND active`,
			adminUserID,
		); err != nil {
			return fmt.Errorf("deactivate scim admin user: %w", err)
		}
		return nil
	})
}

// ScimGroupMember is one SCIM-visible member of a role group: the member's
// SCIM resource id and userName.
type ScimGroupMember struct {
	Value   string `json:"value"` // scim_user_id
	Display string `json:"display,omitempty"`
}

// ListScimRoleMembers returns the SCIM-visible members of one role group in
// the org: users with a membership of that role AND a scim identity in the
// org (identities created by other means are not SCIM-addressable). A
// DEACTIVATED admin user (SCIM DELETE /Users or an admin-side disable) is
// excluded — group member lists never present stale members to the IdP; the
// membership row itself stays (idempotent on reactivation).
func (s *Store) ListScimRoleMembers(ctx context.Context, orgID string, role OrgRole) ([]*ScimGroupMember, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT si.scim_user_id, si.user_name
		 FROM scim_identities si
		 JOIN admin_org_memberships m ON m.user_id = si.admin_user_id AND m.org_id = si.org_id
		 JOIN admin_users au ON au.id = si.admin_user_id
		 WHERE si.org_id = $1::uuid AND m.role = $2 AND au.active
		 ORDER BY si.created_at, si.scim_user_id`,
		orgID, role)
	if err != nil {
		return nil, fmt.Errorf("list scim role members: %w", err)
	}
	defer rows.Close()
	var out []*ScimGroupMember
	for rows.Next() {
		m := &ScimGroupMember{}
		if err := rows.Scan(&m.Value, &m.Display); err != nil {
			return nil, fmt.Errorf("scan scim role member: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetScimMemberRole upserts the membership role for one SCIM-synced user in
// the org (PATCH /Groups/{id} add). ErrNotFound when the scim_user_id is
// not an identity of this org (a foreign-org member value must never widen
// into a membership).
func (s *Store) SetScimMemberRole(ctx context.Context, orgID, scimUserID string, role OrgRole) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if !ValidOrgRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	var adminUserID string
	err := s.db.QueryRow(ctx,
		`SELECT admin_user_id::text FROM scim_identities WHERE org_id = $1::uuid AND scim_user_id = $2`,
		orgID, scimUserID,
	).Scan(&adminUserID)
	if IsNotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("resolve scim member: %w", err)
	}
	if _, err := s.db.Exec(ctx,
		`INSERT INTO admin_org_memberships (user_id, org_id, role)
		 VALUES ($1::uuid, $2::uuid, $3)
		 ON CONFLICT (user_id, org_id) DO UPDATE SET role = EXCLUDED.role, updated_at = now()`,
		adminUserID, orgID, role,
	); err != nil {
		return fmt.Errorf("set scim member role: %w", err)
	}
	return nil
}

// RemoveScimMemberRole removes one SCIM-synced user's membership in the org
// (PATCH /Groups/{id} remove). ErrNotFound when the identity does not exist
// in this org; a missing membership itself is fine (idempotent). The role
// must be a valid OrgRole (an empty or unknown role is a validation error,
// never a silent no-op delete).
func (s *Store) RemoveScimMemberRole(ctx context.Context, orgID, scimUserID string, role OrgRole) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if !ValidOrgRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	var adminUserID string
	err := s.db.QueryRow(ctx,
		`SELECT admin_user_id::text FROM scim_identities WHERE org_id = $1::uuid AND scim_user_id = $2`,
		orgID, scimUserID,
	).Scan(&adminUserID)
	if IsNotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("resolve scim member: %w", err)
	}
	if _, err := s.db.Exec(ctx,
		`DELETE FROM admin_org_memberships WHERE user_id = $1::uuid AND org_id = $2::uuid AND role = $3`,
		adminUserID, orgID, role,
	); err != nil {
		return fmt.Errorf("remove scim member role: %w", err)
	}
	return nil
}

// RemoveScimRoleMembers revokes the role membership for EVERY member of the
// org (DELETE /Groups/{id} semantic: the group is a role alias; removing it
// strips the role from all its members in this org). Returns the number of
// memberships removed. The group itself keeps existing (roles are not
// deletable platform objects).
func (s *Store) RemoveScimRoleMembers(ctx context.Context, orgID string, role OrgRole) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx,
		`DELETE FROM admin_org_memberships WHERE org_id = $1::uuid AND role = $2`,
		orgID, role)
	if err != nil {
		return 0, fmt.Errorf("remove scim role members: %w", err)
	}
	return tag.RowsAffected(), nil
}
