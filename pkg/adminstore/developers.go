package adminstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// DeveloperUser is a portal principal. Keys hang off user_id; the org and
// team are fixed at invite time so a developer cannot mint a key elsewhere.
type DeveloperUser struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	OIDCSubject string `json:"oidc_subject,omitempty"`
	DisplayName string `json:"display_name"`
	OrgID       string `json:"org_id"`
	TeamID      string `json:"team_id"`
	Active      bool   `json:"active"`
}

// DeveloperKey is a personal api_keys row. KeyHash is never serialized.
type DeveloperKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	KeyHash   string     `json:"-"`
}

// GetDeveloperByEmail returns the developer with this email, or ErrNotFound.
func (s *Store) GetDeveloperByEmail(ctx context.Context, email string) (*DeveloperUser, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	u, err := scanDeveloper(s.db.QueryRow(ctx,
		`SELECT id::text, email, COALESCE(oidc_subject, ''), display_name, org_id::text, team_id::text, active
		 FROM developer_users WHERE lower(email) = lower($1)`, email))
	if err != nil {
		if IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get developer: %w", err)
	}
	return u, nil
}

// GetDeveloperByID returns one developer, or ErrNotFound.
func (s *Store) GetDeveloperByID(ctx context.Context, id string) (*DeveloperUser, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	u, err := scanDeveloper(s.db.QueryRow(ctx,
		`SELECT id::text, email, COALESCE(oidc_subject, ''), display_name, org_id::text, team_id::text, active
		 FROM developer_users WHERE id = $1`, id))
	if err != nil {
		if IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get developer: %w", err)
	}
	return u, nil
}

// CreateDeveloper inserts an invited or domain-provisioned user.
func (s *Store) CreateDeveloper(ctx context.Context, u DeveloperUser) (*DeveloperUser, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	created, err := scanDeveloper(s.db.QueryRow(ctx,
		`INSERT INTO developer_users (email, oidc_subject, display_name, org_id, team_id, active)
		 VALUES (lower($1), NULLIF($2, ''), $3, $4, $5, $6)
		 RETURNING id::text, email, COALESCE(oidc_subject, ''), display_name, org_id::text, team_id::text, active`,
		u.Email, u.OIDCSubject, u.DisplayName, u.OrgID, u.TeamID, u.Active))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("developer already exists")
		}
		return nil, fmt.Errorf("create developer: %w", err)
	}
	return created, nil
}

// BindDeveloperSubject records the OIDC subject the first time this user
// signs in. A different subject on an already-bound account is refused.
func (s *Store) BindDeveloperSubject(ctx context.Context, id, subject string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE developer_users
		 SET oidc_subject = $2, updated_at = now()
		 WHERE id = $1 AND (oidc_subject IS NULL OR oidc_subject = $2)`,
		id, subject)
	if err != nil {
		return fmt.Errorf("bind developer subject: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("developer subject mismatch")
	}
	return nil
}

// ListDevelopers returns the developers of one org.
func (s *Store) ListDevelopers(ctx context.Context, orgID string) ([]DeveloperUser, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT id::text, email, COALESCE(oidc_subject, ''), display_name, org_id::text, team_id::text, active
		 FROM developer_users WHERE org_id = $1 ORDER BY email`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list developers: %w", err)
	}
	defer rows.Close()
	var out []DeveloperUser
	for rows.Next() {
		u, err := scanDeveloper(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// SetDeveloperActive flips the portal account. Deactivation is done by the
// handler together with key revocation.
func (s *Store) SetDeveloperActive(ctx context.Context, id string, active bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE developer_users SET active = $2, updated_at = now() WHERE id = $1`, id, active)
	if err != nil {
		return fmt.Errorf("set developer active: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountActiveDeveloperKeys counts live personal keys for the limit check.
func (s *Store) CountActiveDeveloperKeys(ctx context.Context, userID string) (int, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not available")
	}
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM api_keys WHERE user_id = $1 AND active = true`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count developer keys: %w", err)
	}
	return n, nil
}

// ListDeveloperKeys returns the caller's keys without hashes.
func (s *Store) ListDeveloperKeys(ctx context.Context, userID string) ([]DeveloperKey, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT id::text, name, active, created_at, expires_at
		 FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list developer keys: %w", err)
	}
	defer rows.Close()
	var out []DeveloperKey
	for rows.Next() {
		var k DeveloperKey
		if err := rows.Scan(&k.ID, &k.Name, &k.Active, &k.CreatedAt, &k.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// CreateDeveloperKey inserts a personal key. org and team come from the profile.
func (s *Store) CreateDeveloperKey(ctx context.Context, userID, orgID, teamID, name, keyHash string, expiresAt *time.Time) (*DeveloperKey, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var k DeveloperKey
	err := s.db.QueryRow(ctx,
		`INSERT INTO api_keys (key_hash, org_id, team_id, name, active, user_id, expires_at)
		 VALUES ($1, $2, $3, $4, true, $5, $6)
		 RETURNING id::text, name, active, created_at, expires_at`,
		keyHash, orgID, teamID, name, userID, expiresAt).Scan(&k.ID, &k.Name, &k.Active, &k.CreatedAt, &k.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("create developer key: %w", err)
	}
	k.KeyHash = keyHash
	return &k, nil
}

// DeactivateDeveloperKey turns off one key owned by userID. A missing or
// foreign id is ErrNotFound. The hash is returned so the caller can purge it.
func (s *Store) DeactivateDeveloperKey(ctx context.Context, userID, keyID string) (string, error) {
	if s.db == nil {
		return "", fmt.Errorf("database not available")
	}
	var hash string
	err := s.db.QueryRow(ctx,
		`UPDATE api_keys SET active = false, updated_at = now()
		 WHERE id = $1 AND user_id = $2 AND active = true
		 RETURNING key_hash`, keyID, userID).Scan(&hash)
	if err != nil {
		if IsNotFound(err) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("deactivate developer key: %w", err)
	}
	return hash, nil
}

// DeactivateDeveloperKeys turns off every live key of the user and returns
// the hashes that were active.
func (s *Store) DeactivateDeveloperKeys(ctx context.Context, userID string) ([]string, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`UPDATE api_keys SET active = false, updated_at = now()
		 WHERE user_id = $1 AND active = true
		 RETURNING key_hash`, userID)
	if err != nil {
		return nil, fmt.Errorf("deactivate developer keys: %w", err)
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	return hashes, rows.Err()
}

func scanDeveloper(row scanner) (*DeveloperUser, error) {
	var u DeveloperUser
	if err := row.Scan(&u.ID, &u.Email, &u.OIDCSubject, &u.DisplayName, &u.OrgID, &u.TeamID, &u.Active); err != nil {
		return nil, err
	}
	return &u, nil
}
