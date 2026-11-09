package adminstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// PrincipalDelegation is one link of the scoped principal delegation chain
// (N04-P05 T03): a human principal (an org admin or the platform root)
// delegates a bounded permission subset to an agent/CI subject inside exactly
// one organization. The record IS the chain
// provenance: grantor (type + id) → subject (type + id) + permission subset,
// with a mandatory bounded expiry and an explicit revocation stamp.
//
// Invariants (all fail-closed):
//   - Issuance never escalates: every delegated permission must be in the
//     delegatable subset AND held by the grantor on the org (checked by the
//     handler at issue time; the store re-validates the subset bound).
//   - requests.read_originals is NEVER delegatable — original payloads stay a
//     separately assigned capability (N04-P04 posture).
//   - Evaluation re-checks the whole chain each time: the delegation row is
//     unrevoked and unexpired, the delegate agent key is still active, and
//     the grantor still holds the permission (org membership role for admin
//     grantors, is_root+active for root grantors). Removing the grantor's
//     membership or root flag therefore cascades to the delegate on the next
//     evaluation — no propagation job, no cache to invalidate.
type PrincipalDelegation struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	GrantorType string     `json:"grantor_type"` // "admin" | "root"
	GrantorID   string     `json:"grantor_id"`
	SubjectType string     `json:"subject_type"` // "agent" | "ci"
	SubjectID   string     `json:"subject_id"`
	Permissions []string   `json:"permissions"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// PrincipalDelegationCreateParams is the input for CreatePrincipalDelegation.
type PrincipalDelegationCreateParams struct {
	OrgID       string
	GrantorType string // "admin" | "root"
	GrantorID   string
	SubjectType string // "agent" | "ci"
	SubjectID   string
	Permissions []string
	TTL         time.Duration
}

const (
	// PrincipalDelegationGrantorAdmin is a human grantor whose authority comes
	// from an org membership role.
	PrincipalDelegationGrantorAdmin = "admin"
	// PrincipalDelegationGrantorRoot is the platform operator. The delegation
	// stays valid only while the account is still root+active.
	PrincipalDelegationGrantorRoot = "root"
	// PrincipalDelegationSubjectAgent delegates to an autonomous agent key.
	PrincipalDelegationSubjectAgent = "agent"
	// PrincipalDelegationSubjectCI delegates to a CI key.
	PrincipalDelegationSubjectCI = "ci"
	// MaxPrincipalDelegationTTL bounds every delegation; delegations are a
	// bounded borrow of authority, never a permanent role transfer.
	MaxPrincipalDelegationTTL = 30 * 24 * time.Hour
)

// maxPrincipalDelegationPermissions bounds one delegation's subset: at most
// the whole delegatable set.
func maxPrincipalDelegationPermissions() int { return len(DelegatablePermissions()) }

var (
	// ErrInvalidPrincipalDelegation indicates invalid grantor, subject,
	// permission subset, or TTL.
	ErrInvalidPrincipalDelegation = errors.New("invalid principal delegation")
	// ErrPrincipalDelegationUnavailable indicates durable storage is unavailable.
	ErrPrincipalDelegationUnavailable = errors.New("principal delegation store unavailable")
)

// DelegatablePermissions is the bounded permission subset a delegation may
// carry: read-only capabilities. Manage permissions and
// requests.read_originals are never delegatable.
func DelegatablePermissions() []Permission {
	return []Permission{
		PermAnalyticsRead,
		PermRequestsRead,
		PermRequestsPayloads,
		PermLineageRead,
		PermAuditRead,
	}
}

// IsDelegatablePermission reports whether p may appear in a delegation.
func IsDelegatablePermission(p Permission) bool {
	return slices.Contains(DelegatablePermissions(), p)
}

func validPrincipalDelegationGrantor(t string) bool {
	return t == PrincipalDelegationGrantorAdmin || t == PrincipalDelegationGrantorRoot
}

func validPrincipalDelegationSubject(t string) bool {
	return t == PrincipalDelegationSubjectAgent || t == PrincipalDelegationSubjectCI
}

// normalizePrincipalDelegationPermissions validates and deduplicates the
// requested subset. Anything non-delegatable is rejected (never silently
// dropped — a grant that says less than the caller asked for must be visible,
// not implicit).
func normalizePrincipalDelegationPermissions(perms []string) ([]string, error) {
	if len(perms) == 0 || len(perms) > maxPrincipalDelegationPermissions() {
		return nil, ErrInvalidPrincipalDelegation
	}
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		if !IsDelegatablePermission(Permission(p)) {
			return nil, ErrInvalidPrincipalDelegation
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// CreatePrincipalDelegation persists one delegation after validating the
// bounded scope. The database is authoritative; failures never yield a
// partially-granted delegation.
func (s *Store) CreatePrincipalDelegation(ctx context.Context, p PrincipalDelegationCreateParams, now time.Time) (*PrincipalDelegation, error) {
	if s == nil || s.db == nil {
		return nil, ErrPrincipalDelegationUnavailable
	}
	if p.OrgID == "" || p.GrantorID == "" || p.SubjectID == "" ||
		!validPrincipalDelegationGrantor(p.GrantorType) ||
		!validPrincipalDelegationSubject(p.SubjectType) {
		return nil, ErrInvalidPrincipalDelegation
	}
	perms, err := normalizePrincipalDelegationPermissions(p.Permissions)
	if err != nil {
		return nil, err
	}
	if p.TTL <= 0 || p.TTL > MaxPrincipalDelegationTTL {
		return nil, ErrInvalidPrincipalDelegation
	}
	d := &PrincipalDelegation{
		OrgID: p.OrgID, GrantorType: p.GrantorType, GrantorID: p.GrantorID,
		SubjectType: p.SubjectType, SubjectID: p.SubjectID,
		Permissions: perms, ExpiresAt: now.Add(p.TTL), CreatedAt: now,
	}
	// The id is generated server-side: 0014 declares id uuid PRIMARY KEY
	// without the DEFAULT gen_random_uuid() every other table carries, so
	// the column must be part of the INSERT (caught by the real-DB suite,
	// N04-P05-T07 — the mirror fakes generated ids and never saw this).
	err = s.db.QueryRow(ctx,
		`INSERT INTO principal_delegations (id, org_id, grantor_type, grantor_id, subject_type, subject_id, permissions, expires_at, created_at)
		 VALUES (gen_random_uuid(), $1::uuid, $2, $3::uuid, $4, $5::uuid, $6, $7, $8)
		 RETURNING id::text`,
		p.OrgID, p.GrantorType, p.GrantorID, p.SubjectType, p.SubjectID, perms, d.ExpiresAt, now,
	).Scan(&d.ID)
	if err != nil {
		return nil, fmt.Errorf("create principal delegation: %w", err)
	}
	return d, nil
}

// principalDelegationEvaluationRow is one candidate delegation joined with its
// grantor's current authority snapshot. Field names mirror the selected
// columns exactly (RV-n04p5c scan-name fix): isRoot carries COALESCE(u.is_root,
// false) — the bare flag; accountActive carries (u.id IS NOT NULL AND
// u.active) — the row exists AND is active. Both must hold for a root
// grantor; neither column alone means "usable root".
type principalDelegationEvaluationRow struct {
	id            string
	grantorType   string
	memberRole    string // empty when the grantor has no org membership
	isRoot        bool   // the grantor account carries the is_root flag
	accountActive bool   // the grantor account row exists AND is active
}

// evaluatePrincipalDelegationQuery is the candidate fetch; the grantor
// authority decision stays in Go so the role matrix has a single definition
// (RoleHas) and cannot drift from the HTTP layer.
//
// LIMIT 25 is an availability bound, not an authorization decision (record
// N04-P05-T07): it caps how many candidate rows one evaluation scans so a
// subject carrying many delegations cannot turn the shared store into a scan
// amplifier. It is fail-closed with respect to authorization — the
// org/subject/permission/live-row filters run in SQL BEFORE the cap, so a
// capped-off row can only ever withhold a grant, never create one — but a
// pathological subject holding >25 simultaneously-live delegations for the
// same permission may observe later-issued rows denied while earlier ones
// remain inside the window. Under-grant under load, never over-grant.
const evaluatePrincipalDelegationQuery = `
	SELECT d.id::text, d.grantor_type, COALESCE(m.role, ''), COALESCE(u.is_root, false), (u.id IS NOT NULL AND u.active)
	FROM principal_delegations d
	JOIN agent_keys k ON k.id = d.subject_id AND k.active = true
	LEFT JOIN admin_org_memberships m ON m.user_id = d.grantor_id AND m.org_id = d.org_id
	LEFT JOIN admin_users u ON u.id = d.grantor_id
	WHERE d.org_id = $1::uuid AND d.subject_type = $2 AND d.subject_id = $3::uuid
	  AND $4::text = ANY(d.permissions)
	  AND d.revoked_at IS NULL AND d.expires_at > $5
	LIMIT 25`

// EvaluatePrincipalDelegation reports whether a live delegation grants perm to
// the subject in the org right now. Any store error returns (false, err) —
// callers must treat error as denial (fail-closed).
func (s *Store) EvaluatePrincipalDelegation(ctx context.Context, orgID, subjectType, subjectID string, perm Permission, now time.Time) (bool, error) {
	if s == nil || s.db == nil {
		return false, ErrPrincipalDelegationUnavailable
	}
	if orgID == "" || subjectID == "" || !validPrincipalDelegationSubject(subjectType) || !IsDelegatablePermission(perm) {
		return false, nil
	}
	rows, err := s.db.Query(ctx, evaluatePrincipalDelegationQuery, orgID, subjectType, subjectID, string(perm), now)
	if err != nil {
		return false, fmt.Errorf("evaluate principal delegation: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r principalDelegationEvaluationRow
		if err := rows.Scan(&r.id, &r.grantorType, &r.memberRole, &r.isRoot, &r.accountActive); err != nil {
			return false, fmt.Errorf("scan principal delegation evaluation: %w", err)
		}
		if principalDelegationGrantorHolds(r, perm) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// principalDelegationGrantorHolds re-derives the grantor's CURRENT authority:
// an admin grantor must still hold an org membership whose role carries the
// permission; a root grantor must still be an existing, active root account
// (isRoot flag AND an active row — either alone is not authority).
// This is the cascade point — demotion, membership removal, or deactivation
// of the grantor ends the delegation at the next evaluation.
func principalDelegationGrantorHolds(r principalDelegationEvaluationRow, perm Permission) bool {
	switch r.grantorType {
	case PrincipalDelegationGrantorAdmin:
		return RoleHas(r.memberRole, perm)
	case PrincipalDelegationGrantorRoot:
		return r.isRoot && r.accountActive
	default:
		return false
	}
}

// RevokePrincipalDelegation stamps revoked_at on a live delegation in the org.
// Unknown id, a foreign org, or an already-revoked row is ErrNotFound.
func (s *Store) RevokePrincipalDelegation(ctx context.Context, id, orgID string, now time.Time) error {
	if s == nil || s.db == nil {
		return ErrPrincipalDelegationUnavailable
	}
	if id == "" || orgID == "" {
		return ErrInvalidPrincipalDelegation
	}
	result, err := s.db.Exec(ctx,
		`UPDATE principal_delegations SET revoked_at = $3
		 WHERE id = $1::uuid AND org_id = $2::uuid AND revoked_at IS NULL`,
		id, orgID, now)
	if err != nil {
		return fmt.Errorf("revoke principal delegation: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListPrincipalDelegations returns the delegation chain provenance for an org
// (optionally narrowed to one subject), newest first. Metadata only — a
// delegation carries no secrets.
func (s *Store) ListPrincipalDelegations(ctx context.Context, orgID, subjectID string) ([]PrincipalDelegation, error) {
	if s == nil || s.db == nil {
		return nil, ErrPrincipalDelegationUnavailable
	}
	if orgID == "" {
		return nil, ErrInvalidPrincipalDelegation
	}
	q := `SELECT id::text, org_id::text, grantor_type, grantor_id::text, subject_type, subject_id::text,
	             permissions, expires_at, created_at, revoked_at
	      FROM principal_delegations WHERE org_id = $1::uuid`
	args := []interface{}{orgID}
	if subjectID != "" {
		q += ` AND subject_id = $2::uuid`
		args = append(args, subjectID)
	}
	q += ` ORDER BY created_at DESC LIMIT 500`
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list principal delegations: %w", err)
	}
	defer rows.Close()
	out := []PrincipalDelegation{}
	for rows.Next() {
		var d PrincipalDelegation
		if err := rows.Scan(&d.ID, &d.OrgID, &d.GrantorType, &d.GrantorID, &d.SubjectType, &d.SubjectID,
			&d.Permissions, &d.ExpiresAt, &d.CreatedAt, &d.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan principal delegation: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
