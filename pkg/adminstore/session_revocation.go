package adminstore

import (
	"context"
	"time"
)

// Revoke records a session revocation until the signed cookie expires.
func (s *Store) Revoke(ctx context.Context, sessionID string, expiresAt time.Time) error {
	if s.db == nil {
		return ErrNotFound
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM revoked_admin_sessions WHERE expires_at < now()`); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO revoked_admin_sessions (session_id, revoked_at, expires_at)
		VALUES ($1, now(), $2)
		ON CONFLICT (session_id) DO UPDATE SET
			revoked_at = EXCLUDED.revoked_at,
			expires_at = EXCLUDED.expires_at`, sessionID, expiresAt)
	return err
}

// IsRevoked reports whether a live session revocation exists.
func (s *Store) IsRevoked(ctx context.Context, sessionID string) (bool, error) {
	if s.db == nil {
		return false, ErrNotFound
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM revoked_admin_sessions WHERE expires_at < now()`); err != nil {
		return false, err
	}
	var revoked bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM revoked_admin_sessions
			WHERE session_id = $1 AND expires_at >= now()
		)`, sessionID).Scan(&revoked)
	return revoked, err
}
