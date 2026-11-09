package adminstore

import (
	"context"
	"fmt"
	"time"
)

// CreateAdminUser creates a new admin user with a hashed password.
func (s *Store) CreateAdminUser(ctx context.Context, email, displayName, passwordHash string, isRoot bool) (*AdminUser, error) {
	if s.db == nil {
		return nil, fmt.Errorf("create admin user: database not available")
	}
	var u AdminUser
	err := s.db.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, display_name, is_root)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id::text, email, display_name, is_root, active, created_at, updated_at`,
		email, passwordHash, displayName, isRoot,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsRoot, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create admin user: %w", err)
	}
	return &u, nil
}

// GetAdminUserByID returns an admin user by ID.
func (s *Store) GetAdminUserByID(ctx context.Context, id string) (*AdminUser, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var u AdminUser
	err := s.db.QueryRow(ctx,
		`SELECT id::text, email, display_name, is_root, active, created_at, updated_at
		 FROM admin_users WHERE id = $1`,
		id,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsRoot, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get admin user: %w", err)
	}
	return &u, nil
}

// GetAdminUserByEmail returns an admin user by email.
func (s *Store) GetAdminUserByEmail(ctx context.Context, email string) (*AdminUser, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var u AdminUser
	err := s.db.QueryRow(ctx,
		`SELECT id::text, email, display_name, is_root, active, created_at, updated_at
		 FROM admin_users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsRoot, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get admin user by email: %w", err)
	}
	return &u, nil
}

// GetAdminUserGlobalRole returns the platform-level global role of an admin
// user (admin_users.global_role; NULL → ""). This is the ONLY authority
// source for the global audit route: org memberships must never admit a
// cross-org surface (AUTH-01). Unknown user → ErrNotFound (callers 403,
// fail-closed). The column's CHECK constraint admits only
// GlobalRoleSecurityAuditor or NULL; rows are provisioned by the operator,
// not by any handler — an org admin cannot mint this grant.
func (s *Store) GetAdminUserGlobalRole(ctx context.Context, userID string) (string, error) {
	if s.db == nil {
		return "", fmt.Errorf("database not available")
	}
	var role *string
	err := s.db.QueryRow(ctx,
		`SELECT global_role FROM admin_users WHERE id = $1`,
		userID,
	).Scan(&role)
	if err != nil {
		if IsNotFound(err) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("get admin user global role: %w", err)
	}
	if role == nil {
		return "", nil
	}
	return *role, nil
}

// ListAdminUsers returns a page of admin users (optionally filtered by active status).
func (s *Store) ListAdminUsers(ctx context.Context, onlyActive bool, f PageFilter) ([]*AdminUser, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not available")
	}
	if f.PageSize <= 0 {
		f = NewPageFilter(f.Page, f.PageSize)
	}
	var args []interface{}
	var conditions []string
	if onlyActive {
		conditions = append(conditions, "active = true")
	}
	countQuery := `SELECT count(*) FROM admin_users`
	listQuery := `SELECT id::text, email, display_name, is_root, active, created_at, updated_at
              FROM admin_users`
	if len(conditions) > 0 {
		clause := " WHERE " + joinConditions(conditions)
		countQuery += clause
		listQuery += clause
	}

	var total int64
	if err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count admin users: %w", err)
	}

	listQuery += f.OrderBy(AdminUserSortColumns, "created_at", true) +
		" LIMIT $" + fmt.Sprintf("%d", len(args)+1) +
		" OFFSET $" + fmt.Sprintf("%d", len(args)+2)
	args = append(args, f.PageSize, f.Offset())

	rows, err := s.db.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list admin users: %w", err)
	}
	defer rows.Close()

	var users []*AdminUser
	for rows.Next() {
		var u AdminUser
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsRoot, &u.Active, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan admin user: %w", err)
		}
		users = append(users, &u)
	}
	return users, total, rows.Err()
}

// UpdateAdminUserActive toggles the active status of an admin user.
func (s *Store) UpdateAdminUserActive(ctx context.Context, id string, active bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`UPDATE admin_users SET active = $1, updated_at = now() WHERE id = $2`,
		active, id,
	)
	if err != nil {
		return fmt.Errorf("update admin user active: %w", err)
	}
	return nil
}

// UpdateAdminUserPasswordHash updates the password hash for an admin user.
func (s *Store) UpdateAdminUserPasswordHash(ctx context.Context, id, passwordHash string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`UPDATE admin_users
			SET password_hash = $1,
				sessions_changed_at = now(),
				updated_at = now()
			WHERE id = $2`,
		passwordHash, id,
	)
	if err != nil {
		return fmt.Errorf("update admin user password: %w", err)
	}
	return nil
}

// UpdateAdminUser updates display_name and/or is_root for an admin user.
func (s *Store) UpdateAdminUser(ctx context.Context, id string, displayName *string, isRoot *bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if displayName == nil && isRoot == nil {
		return nil
	}
	var set []string
	var args []interface{}
	n := 1
	if displayName != nil {
		set = append(set, fmt.Sprintf("display_name = $%d", n))
		args = append(args, *displayName)
		n++
	}
	if isRoot != nil {
		set = append(set, fmt.Sprintf("is_root = $%d", n))
		args = append(args, *isRoot)
		n++
	}
	set = append(set, "updated_at = now()")
	args = append(args, id)
	query := fmt.Sprintf(`UPDATE admin_users SET %s WHERE id = $%d`, joinSetClauses(set), n)
	if _, err := s.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("update admin user: %w", err)
	}
	return nil
}

// GetAdminUserByEmailWithHash returns an admin user by email including the password_hash.
func (s *Store) GetAdminUserByEmailWithHash(ctx context.Context, email string) (*AdminUserWithHash, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var u AdminUserWithHash
	err := s.db.QueryRow(ctx,
		`SELECT id::text, email, password_hash, display_name, is_root, active, created_at, updated_at
		 FROM admin_users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.IsRoot, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get admin user by email with hash: %w", err)
	}
	return &u, nil
}

// DeleteAdminUser deletes an admin user by ID.
func (s *Store) DeleteAdminUser(ctx context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	result, err := s.db.Exec(ctx,
		`DELETE FROM admin_users WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("delete admin user: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("admin user not found")
	}
	return nil
}

// --- Organizations ---

// GetAdminUserSessionsInvalidatedAt returns the admin_users.sessions_changed_at
// zero time (never invalidated).
func (s *Store) GetAdminUserSessionsInvalidatedAt(ctx context.Context, userID string) (time.Time, error) {
	if s.db == nil {
		return time.Time{}, fmt.Errorf("database not available")
	}
	var changedAt *time.Time
	err := s.db.QueryRow(ctx,
		`SELECT sessions_changed_at FROM admin_users WHERE id = $1`, userID,
	).Scan(&changedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("get admin sessions_changed_at: %w", err)
	}
	if changedAt == nil {
		return time.Time{}, nil
	}
	return *changedAt, nil
}
