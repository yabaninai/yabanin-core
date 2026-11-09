package adminstore

import (
	"context"
	"fmt"
)

// RevokeSessionKeysByParent marks every live session of a parent key revoked
// and returns the hashes so the caller can drop them from the resolver cache.
func (s *Store) RevokeSessionKeysByParent(ctx context.Context, parentID string) ([]string, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`UPDATE session_keys SET revoked_at = now()
		  WHERE parent_api_key_id = $1 AND revoked_at IS NULL
		  RETURNING key_hash`, parentID)
	if err != nil {
		return nil, fmt.Errorf("revoke session keys: %w", err)
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("revoke session keys: %w", err)
		}
		if hash != "" {
			hashes = append(hashes, hash)
		}
	}
	return hashes, rows.Err()
}
