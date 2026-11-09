package adminstore

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestLogger returns a logger that discards all output.
func newTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// mockDB implements pgxdb for testing.
type mockDB struct {
	queryFn        func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	queryRowFn     func(ctx context.Context, sql string, args ...interface{}) pgx.Row
	execFn         func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	beginAuditTxFn func(ctx context.Context) (auditTx, error)
}

func (m *mockDB) BeginAuditTx(ctx context.Context) (auditTx, error) {
	if m.beginAuditTxFn != nil {
		return m.beginAuditTxFn(ctx)
	}
	// W-VER RLS fix default: org-scoped stores now run every operation inside
	// the isolation tx, so unit fixtures get a passthrough tx reusing the same
	// hooks unless a test overrides beginAuditTxFn.
	return &passthroughAuditTx{db: m}, nil
}

// passthroughAuditTx forwards QueryRow/Exec to the owning mockDB hooks and
// records the SQL on the mock's shared log hooks.
type passthroughAuditTx struct{ db *mockDB }

func (t *passthroughAuditTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return t.db.queryRowFn(ctx, sql, args...)
}
func (t *passthroughAuditTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	if t.db.queryFn == nil {
		return nil, pgx.ErrNoRows
	}
	return t.db.queryFn(ctx, sql, args...)
}
func (t *passthroughAuditTx) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if t.db.execFn == nil {
		return pgconn.NewCommandTag("OK"), nil
	}
	return t.db.execFn(ctx, sql, args...)
}
func (t *passthroughAuditTx) Commit(context.Context) error   { return nil }
func (t *passthroughAuditTx) Rollback(context.Context) error { return nil }

func (m *mockDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	if m.queryFn != nil {
		return m.queryFn(ctx, sql, args...)
	}
	return nil, errors.New("no query mock")
}

func (m *mockDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if m.queryRowFn != nil {
		return m.queryRowFn(ctx, sql, args...)
	}
	return &mockPGXRow{}
}

func (m *mockDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if m.execFn != nil {
		return m.execFn(ctx, sql, args...)
	}
	return pgconn.NewCommandTag("OK"), nil
}

// mockPGXRows implements pgx.Rows.
type mockPGXRows struct {
	data [][]interface{}
	idx  int
	err  error
}

func (r *mockPGXRows) Next() bool                                   { r.idx++; return r.idx <= len(r.data) }
func (r *mockPGXRows) Err() error                                   { return r.err }
func (r *mockPGXRows) Close()                                       {}
func (r *mockPGXRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *mockPGXRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *mockPGXRows) Conn() *pgx.Conn                              { return nil }
func (r *mockPGXRows) RawValues() [][]byte                          { return nil }
func (r *mockPGXRows) Values() ([]any, error)                       { return nil, nil }

func (r *mockPGXRows) Scan(dest ...interface{}) error {
	if r.idx == 0 || r.idx > len(r.data) {
		return errors.New("no row")
	}
	row := r.data[r.idx-1]
	for i, v := range dest {
		if i >= len(row) {
			break
		}
		switch d := v.(type) {
		case *string:
			if s, ok := row[i].(string); ok {
				*d = s
			}
		case *OrgRole:
			if s, ok := row[i].(string); ok {
				*d = OrgRole(s)
			}
		case *int64:
			if n, ok := row[i].(int64); ok {
				*d = n
			} else if n, ok := row[i].(int); ok {
				*d = int64(n)
			}
		case *bool:
			*d = row[i].(bool)
		case **string:
			if s, ok := row[i].(string); ok {
				*d = &s
			} else if row[i] == nil {
				*d = nil
			}
		case **int64:
			if row[i] == nil {
				*d = nil
			} else if n, ok := row[i].(int64); ok {
				*d = &n
			}
		case *[]byte:
			if b, ok := row[i].([]byte); ok {
				*d = b
			} else if s, ok := row[i].(string); ok {
				*d = []byte(s)
			}
		case *time.Time:
			if t, ok := row[i].(time.Time); ok {
				*d = t
			}
		case **time.Time:
			if row[i] == nil {
				*d = nil
			} else if t, ok := row[i].(time.Time); ok {
				*d = &t
			}
		case *int:
			if n, ok := row[i].(int64); ok {
				*d = int(n)
			} else if n, ok := row[i].(int); ok {
				*d = n
			}
		case *float64:
			if n, ok := row[i].(int64); ok {
				*d = float64(n)
			} else if n, ok := row[i].(float64); ok {
				*d = n
			}
		case *sql.NullString:
			if s, ok := row[i].(string); ok {
				d.String = s
				d.Valid = true
			}
		}
	}
	return nil
}

// mockPGXRow implements pgx.Row for single-row queries.
type mockPGXRow struct {
	data [][]interface{}
	idx  int
	err  error
}

func (r *mockPGXRow) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	if r.idx >= len(r.data) {
		return errors.New("no row")
	}
	row := r.data[r.idx]
	r.idx++
	for i, v := range dest {
		if i >= len(row) {
			break
		}
		switch d := v.(type) {
		case *string:
			if s, ok := row[i].(string); ok {
				*d = s
			}
		case *OrgRole:
			if s, ok := row[i].(string); ok {
				*d = OrgRole(s)
			}
		case *int64:
			if n, ok := row[i].(int64); ok {
				*d = n
			} else if n, ok := row[i].(int); ok {
				*d = int64(n)
			}
		case *bool:
			*d = row[i].(bool)
		case **string:
			if s, ok := row[i].(string); ok {
				*d = &s
			} else if row[i] == nil {
				*d = nil
			}
		case **int64:
			if row[i] == nil {
				*d = nil
			} else if n, ok := row[i].(int64); ok {
				*d = &n
			}
		case *[]byte:
			if b, ok := row[i].([]byte); ok {
				*d = b
			} else if s, ok := row[i].(string); ok {
				*d = []byte(s)
			}
		case *time.Time:
			if t, ok := row[i].(time.Time); ok {
				*d = t
			}
		case **time.Time:
			if row[i] == nil {
				*d = nil
			} else if t, ok := row[i].(time.Time); ok {
				*d = &t
			}
		case *int:
			if n, ok := row[i].(int64); ok {
				*d = int(n)
			} else if n, ok := row[i].(int); ok {
				*d = n
			}
		case *float64:
			if n, ok := row[i].(int64); ok {
				*d = float64(n)
			} else if n, ok := row[i].(float64); ok {
				*d = n
			}
		case *sql.NullString:
			if s, ok := row[i].(string); ok {
				d.String = s
				d.Valid = true
			}
		}
	}
	return nil
}

func TestStore_New(t *testing.T) {
	s := newForTest(nil, newTestLogger(), nil)
	require.NotNil(t, s)
	assert.Equal(t, newTestLogger(), s.Log())
}

func TestStore_New_NilPool(t *testing.T) {
	store := newForTest(nil, nil, nil)
	require.NotNil(t, store)
	assert.Nil(t, store.db)
	assert.Nil(t, store.Log())
}

func TestStore_Log_Nil(t *testing.T) {
	store := newForTest(nil, nil, nil)
	assert.Nil(t, store.Log())
}

func TestStore_ListOrganizations_Empty(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(0)}}}
		},
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: [][]interface{}{}}, nil
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	result, total, err := store.ListOrganizations(ctx, PageFilter{})
	require.NoError(t, err)
	assert.Empty(t, result)
	assert.Equal(t, int64(0), total)
}

func TestStore_ListOrganizations_Success(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(2)}}}
		},
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: [][]interface{}{
				{"org-1", "Acme Corp", "acme"},
				{"org-2", "Globex", "globex"},
			}}, nil
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	result, total, err := store.ListOrganizations(ctx, PageFilter{})
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, int64(2), total)
	assert.Equal(t, "org-1", result[0].ID)
	assert.Equal(t, "Acme Corp", result[0].Name)
	assert.Equal(t, "acme", result[0].Slug)
}

func TestStore_ListOrganizations_DBError(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(0)}}}
		},
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			return nil, errors.New("connection refused")
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	result, _, err := store.ListOrganizations(ctx, PageFilter{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list organizations")
	assert.Nil(t, result)
}

func TestStore_ListOrganizations_NilDB(t *testing.T) {
	ctx := context.Background()
	store := newForTest(nil, newTestLogger(), nil)

	result, _, err := store.ListOrganizations(ctx, PageFilter{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
	assert.Nil(t, result)
}

func TestStore_GetOrganizationBySlug(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			assert.Equal(t, "acme", args[0])
			return &mockPGXRow{data: [][]interface{}{{"org-1", "Acme Corp", "acme"}}}
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	result, err := store.GetOrganizationBySlug(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, "org-1", result.ID)
	assert.Equal(t, "Acme Corp", result.Name)
}

func TestStore_GetOrganizationBySlug_NotFound(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{err: pgx.ErrNoRows}
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	result, err := store.GetOrganizationBySlug(ctx, "nonexistent")
	require.ErrorIs(t, err, pgx.ErrNoRows)
	assert.Nil(t, result)
}

func TestStore_GetOrganizationBySlug_NilDB(t *testing.T) {
	ctx := context.Background()
	store := newForTest(nil, newTestLogger(), nil)

	_, err := store.GetOrganizationBySlug(ctx, "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
}

func TestStore_CreateAdminUser(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			assert.Equal(t, "test@example.com", args[0])
			return &mockPGXRow{data: [][]interface{}{{"admin-1", "test@example.com", "Test User", false, true, time.Now(), time.Now()}}}
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	result, err := store.CreateAdminUser(ctx, "test@example.com", "Test User", "$2a$10$hash", false)
	require.NoError(t, err)
	assert.Equal(t, "admin-1", result.ID)
	assert.Equal(t, "test@example.com", result.Email)
	assert.False(t, result.IsRoot)
}

func TestStore_CreateAdminUser_NilDB(t *testing.T) {
	ctx := context.Background()
	store := newForTest(nil, newTestLogger(), nil)

	_, err := store.CreateAdminUser(ctx, "test@example.com", "Test", "$2a$10$hash", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create admin user")
}

func TestStore_GetAdminUserByEmail(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			assert.Equal(t, "test@example.com", args[0])
			return &mockPGXRow{data: [][]interface{}{{"admin-1", "test@example.com", "Test User", true, true, time.Now(), time.Now()}}}
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	result, err := store.GetAdminUserByEmail(ctx, "test@example.com")
	require.NoError(t, err)
	assert.Equal(t, "admin-1", result.ID)
	assert.Equal(t, "test@example.com", result.Email)
	assert.Contains(t, result.DisplayName, "Test")
}

func TestStore_GetAdminUserByEmail_NotFound(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{err: pgx.ErrNoRows}
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	result, err := store.GetAdminUserByEmail(ctx, "nonexistent@example.com")
	require.ErrorIs(t, err, pgx.ErrNoRows)
	assert.Nil(t, result)
}

func TestStore_GetAdminUserByEmail_NilDB(t *testing.T) {
	ctx := context.Background()
	store := newForTest(nil, newTestLogger(), nil)

	_, err := store.GetAdminUserByEmail(ctx, "test@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
}

func TestStore_GetAdminUserByID(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			assert.Equal(t, "admin-1", args[0])
			return &mockPGXRow{data: [][]interface{}{{"admin-1", "test@example.com", "Test User", true, true, time.Now(), time.Now()}}}
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	result, err := store.GetAdminUserByID(ctx, "admin-1")
	require.NoError(t, err)
	assert.Equal(t, "admin-1", result.ID)
}

func TestStore_GetAdminUserByID_NilDB(t *testing.T) {
	ctx := context.Background()
	store := newForTest(nil, newTestLogger(), nil)

	_, err := store.GetAdminUserByID(ctx, "admin-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
}

func TestStore_UpdateAdminUserActive(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		execFn: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			assert.Equal(t, true, args[0])
			assert.Equal(t, "admin-1", args[1])
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	err := store.UpdateAdminUserActive(ctx, "admin-1", true)
	require.NoError(t, err)
}

func TestStore_UpdateAdminUserActive_NilDB(t *testing.T) {
	ctx := context.Background()
	store := newForTest(nil, newTestLogger(), nil)

	err := store.UpdateAdminUserActive(ctx, "admin-1", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
}

func TestStore_DeleteAdminUser(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		execFn: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			assert.Equal(t, "admin-1", args[0])
			return pgconn.NewCommandTag("DELETE 1"), nil
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	err := store.DeleteAdminUser(ctx, "admin-1")
	require.NoError(t, err)
}

func TestStore_DeleteAdminUser_NilDB(t *testing.T) {
	ctx := context.Background()
	store := newForTest(nil, newTestLogger(), nil)

	err := store.DeleteAdminUser(ctx, "admin-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
}

func TestStore_UpdateAdminUser(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		execFn: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			assert.Equal(t, "New Name", args[0])
			assert.Equal(t, "admin-1", args[1])
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	displayName := "New Name"
	err := store.UpdateAdminUser(ctx, "admin-1", &displayName, nil)
	require.NoError(t, err)
}

func TestStore_UpdateAdminUser_NilDB(t *testing.T) {
	ctx := context.Background()
	store := newForTest(nil, newTestLogger(), nil)

	err := store.UpdateAdminUser(ctx, "admin-1", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
}

func TestStore_ListUsers(t *testing.T) {
	ctx := context.Background()
	mockDB := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(2)}}}
		},
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: [][]interface{}{
				{"admin-1", "test@example.com", "Test User", true, true, time.Now(), time.Now()},
				{"admin-2", "admin@example.com", "Admin", false, true, time.Now(), time.Now()},
			}}, nil
		},
	}
	store := newForTest(mockDB, newTestLogger(), nil)

	result, total, err := store.ListAdminUsers(ctx, true, PageFilter{})
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, int64(2), total)
	assert.Equal(t, "admin-1", result[0].ID)
	assert.False(t, result[1].IsRoot)
}

func TestStore_ListUsers_NilDB(t *testing.T) {
	ctx := context.Background()
	store := newForTest(nil, newTestLogger(), nil)

	_, _, err := store.ListAdminUsers(ctx, false, PageFilter{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *mockPGXRows) TypeMap() *pgtype.Map { return nil }
