package adminstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// W-INV: org member invitations (migration 0004, table member_invites).
//
// A member invite is a one-time, 72h capability: the inviter receives the raw
// token once (POST .../members/invite response) and hands it over out of
// band; the database stores only its sha256. The public acceptance endpoint
// is the single consumer. All org-scoped operations run through withOrgTx so
// the member_invites RLS policy (org_isolation on app.current_org) holds
// under the least-privilege application role; the acceptance path resolves
// the org FROM the token (the token embeds the org id prefix) and pins the
// same GUC before its first read.

// InviteTTL is the strict validity window of a member invite (card W-INV).
// Resending restarts the window.
const InviteTTL = 72 * time.Hour

// MemberInvite errors surface as distinct HTTP statuses in the handlers:
// ErrNotFound → 404 (unknown or revoked token), ErrInviteExpired and
// ErrInviteAccepted → 410 (gone), ErrInvitePending → 409 (duplicate active
// invite).
var (
	// ErrInvitePending reports that an active (unaccepted, unexpired) invite
	// already exists for this (org, email) pair.
	ErrInvitePending = errors.New("an active invite for this email already exists")
	// ErrInviteExpired reports that the invite's 72h window has passed.
	ErrInviteExpired = errors.New("invite expired")
	// ErrInviteAccepted reports that the invite was already accepted
	// (single-use).
	ErrInviteAccepted = errors.New("invite already accepted")
)

// MemberInvite is one row of member_invites. It never carries token
// material: the raw token exists only as a Create/Resend return value and
// the sha256 stays in the database.
type MemberInvite struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Email     string    `json:"email"`
	Role      OrgRole   `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	// AcceptedAt is nil until the invite is consumed (single-use marker).
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	// CreatedBy is the admin user id of the inviter.
	CreatedBy string `json:"created_by"`
	// InvitedUserID is the admin user id bound at acceptance ("" before).
	InvitedUserID string    `json:"invited_user_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// InvitePreview is the public, token-gated view of an invite (the
// acceptance page payload). It carries no ids of the inviter.
type InvitePreview struct {
	OrgName   string    `json:"org_name"`
	Email     string    `json:"email"`
	Role      OrgRole   `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AcceptInviteResult is the outcome of a successful acceptance.
type AcceptInviteResult struct {
	Invite *MemberInvite
	// OrgName is the display name of the org joined (for the confirmation UI).
	OrgName string
	// UserID is the admin user the membership was attached to.
	UserID string
	// UserCreated is true when a new admin user was provisioned by the
	// acceptance (false = an existing user logged in / was bound).
	UserCreated bool
}

// memberInviteColumns is the canonical SELECT list (token_hash deliberately
// absent: no read path has a reason to see even the hash).
const memberInviteColumns = `id::text, org_id::text, email, role, expires_at, accepted_at, created_by::text, COALESCE(invited_user_id::text, ''), created_at, updated_at`

// NormalizeInviteEmail canonicalizes an invite email: trimmed and lowercased,
// so the (org, email) uniqueness and the acceptance-time user match are
// case-insensitive.
func NormalizeInviteEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// newInviteToken mints a one-time invite token: "<org-uuid>.<64 hex chars>"
// — 32 bytes of crypto/rand for the secret part. Only the sha256 of the
// whole string is persisted.
func newInviteToken(orgID string) (token, hash string, err error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", fmt.Errorf("generate invite token: %w", err)
	}
	token = orgID + "." + hex.EncodeToString(secret)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// inviteTokenHash is the stored form of a token (sha256 hex).
func inviteTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// parseInviteToken splits a token into its org prefix and validates the
// shape: the org segment must be a UUID (it is pinned into the RLS GUC, and
// an invalid uuid cast would error instead of yielding no rows) and the
// secret segment exactly 64 hex chars. ok=false for anything else.
func parseInviteToken(token string) (orgID string, ok bool) {
	org, secret, found := strings.Cut(token, ".")
	if !found {
		return "", false
	}
	if _, err := uuid.Parse(org); err != nil {
		return "", false
	}
	if len(secret) != 64 {
		return "", false
	}
	for _, r := range secret {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", false
		}
	}
	return org, true
}

// CreateMemberInvite inserts a pending invite and returns it together with
// the raw one-time token (returned NOWHERE else — not on lists, not on
// resend responses' rows). email is normalized; role must be a valid org
// role; createdBy is the inviter's admin user id. A duplicate ACTIVE invite
// for the same (org, email) is ErrInvitePending.
func (s *Store) CreateMemberInvite(ctx context.Context, orgID, email string, role OrgRole, createdBy string) (*MemberInvite, string, error) {
	if s.db == nil {
		return nil, "", fmt.Errorf("database not available")
	}
	if orgID == "" {
		return nil, "", fmt.Errorf("org id is required")
	}
	email = NormalizeInviteEmail(email)
	if email == "" {
		return nil, "", fmt.Errorf("email is required")
	}
	if createdBy == "" {
		return nil, "", fmt.Errorf("inviter id is required")
	}
	if !ValidOrgRole(role) {
		return nil, "", fmt.Errorf("invalid role %q", role)
	}
	token, hash, err := newInviteToken(orgID)
	if err != nil {
		return nil, "", err
	}

	var out *MemberInvite
	err = s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		inv := &MemberInvite{}
		err := tx.QueryRow(ctx,
			`INSERT INTO member_invites (org_id, email, role, token_hash, expires_at, created_by)
			 VALUES ($1::uuid, $2, $3, $4, now() + interval '72 hours', $5::uuid)
			 RETURNING `+memberInviteColumns,
			orgID, email, role, hash, createdBy,
		).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.ExpiresAt,
			&inv.AcceptedAt, &inv.CreatedBy, &inv.InvitedUserID, &inv.CreatedAt, &inv.UpdatedAt)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrInvitePending
			}
			return fmt.Errorf("create member invite: %w", err)
		}
		out = inv
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return out, token, nil
}

// ListMemberInvites returns the org's PENDING invites (accepted excluded),
// newest first. Expired-but-unaccepted invites stay listed: the UI offers
// resend/revoke for them.
func (s *Store) ListMemberInvites(ctx context.Context, orgID string) ([]*MemberInvite, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	// The row set is aggregated to a single json payload: the withOrgTx
	// transaction surface exposes QueryRow only (the same shape as
	// ListOrgCustomModels), and the list is bounded by one org's pending
	// invites.
	var raw []byte
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		// The explicit org_id predicate is the primary isolation layer
		// (correct under any role); the app.current_org GUC pinned by
		// withOrgTx is defense in depth under the least-privilege
		// application role.
		return tx.QueryRow(ctx, `
			SELECT COALESCE(json_agg(t), '[]'::json)
			FROM (
			    SELECT id::text AS id, org_id::text AS org_id, email, role,
			           expires_at, accepted_at, created_by::text AS created_by,
			           COALESCE(invited_user_id::text, '') AS invited_user_id,
			           created_at, updated_at
			    FROM member_invites
			    WHERE org_id = $1::uuid AND accepted_at IS NULL
			    ORDER BY created_at DESC
			) t`, orgID).Scan(&raw)
	})
	if err != nil {
		return nil, fmt.Errorf("list member invites: %w", err)
	}
	var out []*MemberInvite
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode member invites: %w", err)
	}
	return out, nil
}

// ResendMemberInvite rotates the token of a PENDING invite and restarts its
// 72h window, returning the fresh raw token. An accepted invite cannot be
// resent (ErrInviteAccepted); an unknown id is ErrNotFound.
func (s *Store) ResendMemberInvite(ctx context.Context, orgID, inviteID, actorID string) (*MemberInvite, string, error) {
	if s.db == nil {
		return nil, "", fmt.Errorf("database not available")
	}
	if orgID == "" {
		return nil, "", fmt.Errorf("org id is required")
	}
	if inviteID == "" {
		return nil, "", fmt.Errorf("invite id is required")
	}
	token, hash, err := newInviteToken(orgID)
	if err != nil {
		return nil, "", err
	}

	var out *MemberInvite
	err = s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		// Distinguish the two empty-result causes first: accepted invites
		// must not be silently treatable as missing (audit clarity).
		var acceptedAt *time.Time
		err := tx.QueryRow(ctx,
			`SELECT accepted_at FROM member_invites WHERE id = $1::uuid AND org_id = $2::uuid`,
			inviteID, orgID,
		).Scan(&acceptedAt)
		if IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("load member invite for resend: %w", err)
		}
		if acceptedAt != nil {
			return ErrInviteAccepted
		}

		inv := &MemberInvite{}
		err = tx.QueryRow(ctx,
			`UPDATE member_invites SET token_hash = $3, expires_at = now() + interval '72 hours', updated_at = now()
			 WHERE id = $1::uuid AND org_id = $2::uuid AND accepted_at IS NULL
			 RETURNING `+memberInviteColumns,
			inviteID, orgID, hash,
		).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.ExpiresAt,
			&inv.AcceptedAt, &inv.CreatedBy, &inv.InvitedUserID, &inv.CreatedAt, &inv.UpdatedAt)
		if err != nil {
			return fmt.Errorf("resend member invite: %w", err)
		}
		out = inv
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return out, token, nil
}

// RevokeMemberInvite removes a PENDING invite (the row is deleted, so the
// token immediately stops resolving — a revoked token answers 404 like any
// unknown token). An accepted invite cannot be revoked (ErrInviteAccepted);
// an unknown id is ErrNotFound.
func (s *Store) RevokeMemberInvite(ctx context.Context, orgID, inviteID, actorID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if orgID == "" {
		return fmt.Errorf("org id is required")
	}
	if inviteID == "" {
		return fmt.Errorf("invite id is required")
	}
	return s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM member_invites WHERE id = $1::uuid AND org_id = $2::uuid AND accepted_at IS NULL`,
			inviteID, orgID,
		)
		if err != nil {
			return fmt.Errorf("revoke member invite: %w", err)
		}
		if tag.RowsAffected() > 0 {
			return nil
		}
		// Nothing deleted: missing vs accepted.
		var acceptedAt *time.Time
		err = tx.QueryRow(ctx,
			`SELECT accepted_at FROM member_invites WHERE id = $1::uuid AND org_id = $2::uuid`,
			inviteID, orgID,
		).Scan(&acceptedAt)
		if IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("load member invite for revoke: %w", err)
		}
		return ErrInviteAccepted
	})
}

// PreviewMemberInvite is the public, token-gated read behind the acceptance
// page: org name, invited email, role and expiry. Unknown/revoked tokens are
// ErrNotFound; expired and accepted invites are ErrInviteExpired /
// ErrInviteAccepted (the handler maps all three to distinct statuses).
func (s *Store) PreviewMemberInvite(ctx context.Context, token string) (*InvitePreview, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	orgID, ok := parseInviteToken(token)
	if !ok {
		return nil, ErrNotFound
	}
	var out *InvitePreview
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		p := &InvitePreview{}
		var acceptedAt *time.Time
		err := tx.QueryRow(ctx,
			`SELECT o.name, mi.email, mi.role, mi.expires_at, mi.accepted_at
			 FROM member_invites mi JOIN organizations o ON o.id = mi.org_id
			 WHERE mi.token_hash = $1`,
			inviteTokenHash(token),
		).Scan(&p.OrgName, &p.Email, &p.Role, &p.ExpiresAt, &acceptedAt)
		if IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("preview member invite: %w", err)
		}
		if acceptedAt != nil {
			return ErrInviteAccepted
		}
		if !p.ExpiresAt.After(time.Now()) {
			return ErrInviteExpired
		}
		out = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AcceptMemberInvite consumes a pending invite in ONE transaction:
//
//  1. the invite row is locked and re-checked (pending + unexpired — the
//     accepted_at predicate plus the row lock make the acceptance single-use
//     even under concurrent submits of the same token);
//  2. an existing admin user with the invite email is bound; a missing one is
//     created with passwordHash (empty passwordHash + no existing user is a
//     hard error — the handler has verified credentials before this call);
//  3. the membership is upserted with the invited role;
//  4. accepted_at + invited_user_id close the invite.
//
// An existing user's password is NEVER touched by an invite. Unknown/revoked
// tokens are ErrNotFound; consumed/expired invites are ErrInviteAccepted /
// ErrInviteExpired.
func (s *Store) AcceptMemberInvite(ctx context.Context, token, passwordHash string) (*AcceptInviteResult, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	orgID, ok := parseInviteToken(token)
	if !ok {
		return nil, ErrNotFound
	}

	var res *AcceptInviteResult
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		inv := &MemberInvite{}
		err := tx.QueryRow(ctx,
			`SELECT `+memberInviteColumns+` FROM member_invites
			 WHERE token_hash = $1
			 FOR UPDATE`,
			inviteTokenHash(token),
		).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.ExpiresAt,
			&inv.AcceptedAt, &inv.CreatedBy, &inv.InvitedUserID, &inv.CreatedAt, &inv.UpdatedAt)
		if IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("load member invite: %w", err)
		}
		if inv.AcceptedAt != nil {
			return ErrInviteAccepted
		}
		if !inv.ExpiresAt.After(time.Now()) {
			return ErrInviteExpired
		}

		// Bind the existing account or provision a new one. The lookup runs
		// inside the same transaction as the insert, so the existence race
		// collapses into a single serialized decision.
		var userID string
		err = tx.QueryRow(ctx,
			`SELECT id::text FROM admin_users WHERE email = $1`,
			inv.Email,
		).Scan(&userID)
		userCreated := false
		switch {
		case IsNotFound(err):
			if passwordHash == "" {
				return fmt.Errorf("accept member invite: no existing account for %s and no new credentials supplied", inv.Email)
			}
			if err := tx.QueryRow(ctx,
				`INSERT INTO admin_users (email, password_hash, display_name, active)
				 VALUES ($1, $2, $3, true)
				 RETURNING id::text`,
				inv.Email, passwordHash, inv.Email,
			).Scan(&userID); err != nil {
				return fmt.Errorf("create admin user from invite: %w", err)
			}
			userCreated = true
		case err != nil:
			return fmt.Errorf("look up admin user for invite: %w", err)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO admin_org_memberships (user_id, org_id, role)
			 VALUES ($1::uuid, $2::uuid, $3)
			 ON CONFLICT (user_id, org_id) DO UPDATE SET role = EXCLUDED.role, updated_at = now()`,
			userID, inv.OrgID, inv.Role,
		); err != nil {
			return fmt.Errorf("attach org membership from invite: %w", err)
		}

		if _, err := tx.Exec(ctx,
			`UPDATE member_invites SET accepted_at = now(), invited_user_id = $2::uuid, updated_at = now()
			 WHERE id = $1::uuid AND accepted_at IS NULL`,
			inv.ID, userID,
		); err != nil {
			return fmt.Errorf("mark member invite accepted: %w", err)
		}

		var orgName string
		if err := tx.QueryRow(ctx,
			`SELECT name FROM organizations WHERE id = $1::uuid`, inv.OrgID,
		).Scan(&orgName); err != nil {
			return fmt.Errorf("load org for invite: %w", err)
		}

		res = &AcceptInviteResult{Invite: inv, OrgName: orgName, UserID: userID, UserCreated: userCreated}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
