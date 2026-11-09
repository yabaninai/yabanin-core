package adminstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeveloperStore_NilDB(t *testing.T) {
	s := &Store{}
	ctx := context.Background()
	_, err := s.GetDeveloperByEmail(ctx, "a@b.c")
	require.Error(t, err)
	_, err = s.GetDeveloperByID(ctx, "id")
	require.Error(t, err)
	_, err = s.CreateDeveloper(ctx, DeveloperUser{Email: "a@b.c"})
	require.Error(t, err)
	require.Error(t, s.BindDeveloperSubject(ctx, "id", "sub"))
	_, err = s.ListDevelopers(ctx, "org")
	require.Error(t, err)
	require.Error(t, s.SetDeveloperActive(ctx, "id", false))
	_, err = s.CountActiveDeveloperKeys(ctx, "id")
	require.Error(t, err)
	_, err = s.ListDeveloperKeys(ctx, "id")
	require.Error(t, err)
	_, err = s.CreateDeveloperKey(ctx, "u", "o", "t", "n", "h", nil)
	require.Error(t, err)
	_, err = s.DeactivateDeveloperKey(ctx, "u", "k")
	require.Error(t, err)
	_, err = s.DeactivateDeveloperKeys(ctx, "u")
	require.Error(t, err)
}

func TestDeveloperStore_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	db := &mockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			switch {
			case strings.Contains(sql, "count(*)"):
				return &mockPGXRow{data: [][]interface{}{{2}}}
			case strings.Contains(sql, "INSERT INTO developer_users"):
				return &mockPGXRow{data: [][]interface{}{{"id-1", "a@b.c", "sub", "Ada", "org-1", "team-1", true}}}
			case strings.Contains(sql, "INSERT INTO api_keys"):
				return &mockPGXRow{data: [][]interface{}{{"key-1", "mine", true, now, now}}}
			case strings.Contains(sql, "RETURNING key_hash"):
				return &mockPGXRow{data: [][]interface{}{{"hash-1"}}}
			case strings.Contains(sql, "WHERE lower"):
				return &mockPGXRow{data: [][]interface{}{{"id-1", "a@b.c", "sub", "Ada", "org-1", "team-1", true}}}
			case strings.Contains(sql, "WHERE id"):
				return &mockPGXRow{data: [][]interface{}{{"id-1", "a@b.c", "", "Ada", "org-1", "team-1", true}}}
			default:
				return &mockPGXRow{err: pgx.ErrNoRows}
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			if strings.Contains(sql, "FROM developer_users") {
				return &mockPGXRows{data: [][]interface{}{{"id-1", "a@b.c", "sub", "Ada", "org-1", "team-1", true}}}, nil
			}
			if strings.Contains(sql, "FROM api_keys") {
				return &mockPGXRows{data: [][]interface{}{{"key-1", "mine", true, now, nil}}}, nil
			}
			return &mockPGXRows{data: [][]interface{}{{"hash-1"}, {"hash-2"}}}, nil
		},
		execFn: func(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	s := &Store{db: db}
	ctx := context.Background()

	u, err := s.GetDeveloperByEmail(ctx, "a@b.c")
	require.NoError(t, err)
	assert.Equal(t, "id-1", u.ID)
	u, err = s.GetDeveloperByID(ctx, "id-1")
	require.NoError(t, err)
	assert.Empty(t, u.OIDCSubject)

	created, err := s.CreateDeveloper(ctx, DeveloperUser{Email: "a@b.c", DisplayName: "Ada", OrgID: "org-1", TeamID: "team-1", Active: true})
	require.NoError(t, err)
	assert.Equal(t, "Ada", created.DisplayName)
	require.NoError(t, s.BindDeveloperSubject(ctx, "id-1", "sub"))
	require.NoError(t, s.SetDeveloperActive(ctx, "id-1", false))

	list, err := s.ListDevelopers(ctx, "org-1")
	require.NoError(t, err)
	require.Len(t, list, 1)

	n, err := s.CountActiveDeveloperKeys(ctx, "id-1")
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	keys, err := s.ListDeveloperKeys(ctx, "id-1")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Nil(t, keys[0].ExpiresAt)

	key, err := s.CreateDeveloperKey(ctx, "id-1", "org-1", "team-1", "mine", "hash", &now)
	require.NoError(t, err)
	assert.Equal(t, "key-1", key.ID)
	assert.Equal(t, "hash", key.KeyHash)

	hash, err := s.DeactivateDeveloperKey(ctx, "id-1", "key-1")
	require.NoError(t, err)
	assert.Equal(t, "hash-1", hash)
	hashes, err := s.DeactivateDeveloperKeys(ctx, "id-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"hash-1", "hash-2"}, hashes)
}

func TestDeveloperStore_NotFoundAndConflict(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			if strings.Contains(sql, "INSERT INTO developer_users") {
				return &mockPGXRow{err: &pgconn.PgError{Code: "23505"}}
			}
			return &mockPGXRow{err: pgx.ErrNoRows}
		},
		execFn: func(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "oidc_subject") {
				return pgconn.CommandTag{}, assertErr("bind failed")
			}
			return pgconn.NewCommandTag("UPDATE 0"), nil
		},
		queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
			return nil, assertErr("query failed")
		},
	}
	s := &Store{db: db}
	ctx := context.Background()
	_, err := s.GetDeveloperByEmail(ctx, "missing@b.c")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.GetDeveloperByID(ctx, "missing")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.CreateDeveloper(ctx, DeveloperUser{Email: "a@b.c"})
	require.ErrorContains(t, err, "already exists")
	require.Error(t, s.BindDeveloperSubject(ctx, "id", "sub"))
	require.ErrorIs(t, s.SetDeveloperActive(ctx, "id", true), ErrNotFound)
	_, err = s.DeactivateDeveloperKey(ctx, "u", "k")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.ListDevelopers(ctx, "org")
	require.Error(t, err)
	_, err = s.ListDeveloperKeys(ctx, "u")
	require.Error(t, err)
	_, err = s.DeactivateDeveloperKeys(ctx, "u")
	require.Error(t, err)
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
