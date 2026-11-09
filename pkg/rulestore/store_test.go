package rulestore

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDB implements dbConn for testing.
type mockDB struct {
	queryFn func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
}

func (m *mockDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return m.queryFn(ctx, sql, args...)
}

// mockCache implements cacheOps for testing.
type mockCache struct {
	getFn func(ctx context.Context, key string) *redis.StringCmd
	setFn func(ctx context.Context, key string, val interface{}, ttl time.Duration) *redis.StatusCmd
	delFn func(ctx context.Context, keys ...string) *redis.IntCmd
}

func (m *mockCache) Get(ctx context.Context, key string) *redis.StringCmd {
	if m.getFn != nil {
		return m.getFn(ctx, key)
	}
	return redis.NewStringResult("", nil)
}

func (m *mockCache) Set(ctx context.Context, key string, val interface{}, ttl time.Duration) *redis.StatusCmd {
	if m.setFn != nil {
		return m.setFn(ctx, key, val, ttl)
	}
	return redis.NewStatusResult("OK", nil)
}

func (m *mockCache) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	if m.delFn != nil {
		return m.delFn(ctx, keys...)
	}
	return redis.NewIntResult(1, nil)
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// mockPGXRows implements pgx.Rows.
type mockPGXRows struct {
	data [][]interface{}
	idx  int
	err  error
}

func (r *mockPGXRows) Next() bool { r.idx++; return r.idx <= len(r.data) }
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
			*d = row[i].(string)
		case *int64:
			if n, ok := row[i].(int64); ok {
				*d = n
			} else if n, ok := row[i].(int); ok {
				*d = int64(n)
			}
		case *bool:
			*d = row[i].(bool)
		}
	}
	return nil
}
func (r *mockPGXRows) Err() error                                   { return r.err }
func (r *mockPGXRows) Close()                                       {}
func (r *mockPGXRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *mockPGXRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *mockPGXRows) Conn() *pgx.Conn                              { return nil }
func (r *mockPGXRows) RawValues() [][]byte                          { return nil }
func (r *mockPGXRows) Values() ([]any, error)                       { return nil, nil }

func TestGetByOrg_CacheHit(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-1"
	rules := []evaluator.Rule{
		{ID: "r1", OrgID: orgID, MatchExpr: "org_id == 'test'", TargetModel: "gpt-4", Priority: 10, Enabled: true},
	}
	data, _ := json.Marshal(rules)

	mockRDB := &mockCache{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			if key == cacheKeyPrefix+orgID {
				return redis.NewStringResult(string(data), nil)
			}
			return redis.NewStringResult("", redis.Nil)
		},
	}

	store := New(nil, mockRDB, 0, nil, newTestLogger())

	result, err := store.GetByOrg(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, rules, result)
}

func TestGetByOrg_CacheMissNoPool(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-2"

	mockRDB := &mockCache{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			return redis.NewStringResult("", redis.Nil)
		},
	}

	store := New(nil, mockRDB, 0, nil, newTestLogger())

	result, err := store.GetByOrg(ctx, orgID)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestGetByOrg_CacheMissDBSuccess(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-3"

	mockRDB := &mockCache{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			return redis.NewStringResult("", redis.Nil)
		},
		setFn: func(ctx context.Context, key string, val interface{}, ttl time.Duration) *redis.StatusCmd {
			assert.Equal(t, cacheKeyPrefix+orgID, key)
			return redis.NewStatusResult("OK", nil)
		},
	}

	mockDB := &mockDB{
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			assert.Equal(t, orgID, args[0])
			return &mockPGXRows{data: [][]interface{}{{"r3", orgID, "model_requested == 'auto'", "claude-3", int64(5), true}}}, nil
		},
	}

	store := New(mockDB, mockRDB, 0, nil, newTestLogger())

	result, err := store.GetByOrg(ctx, orgID)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "claude-3", result[0].TargetModel)
}

func TestGetByOrg_DBOtherThanNilError(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-4"

	mockRDB := &mockCache{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			return redis.NewStringResult("", redis.Nil)
		},
	}

	mockDB := &mockDB{
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			return nil, errors.New("connection refused")
		},
	}

	store := New(mockDB, mockRDB, 0, nil, newTestLogger())

	_, err := store.GetByOrg(ctx, orgID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load rules from db")
	assert.Contains(t, err.Error(), "connection refused")
}

func TestGetByOrg_CacheReadError(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-5"

	mockRDB := &mockCache{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			return redis.NewStringResult("", errors.New("redis timeout"))
		},
	}

	store := New(nil, mockRDB, 0, nil, newTestLogger())

	result, err := store.GetByOrg(ctx, orgID)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestGetByOrg_CacheDecodeFail(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-6"
	badData := []byte("not valid json{{{")

	mockRDB := &mockCache{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			return redis.NewStringResult(string(badData), nil)
		},
	}

	store := New(nil, mockRDB, 0, nil, newTestLogger())

	result, err := store.GetByOrg(ctx, orgID)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestGetByOrg_EmptyRules(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-7"

	mockRDB := &mockCache{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			return redis.NewStringResult("", redis.Nil)
		},
	}

	mockDB := &mockDB{
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: [][]interface{}{}}, nil
		},
	}

	store := New(mockDB, mockRDB, 0, nil, newTestLogger())

	result, err := store.GetByOrg(ctx, orgID)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestGetByOrg_NoRedisNoPool(t *testing.T) {
	ctx := context.Background()

	store := New(nil, nil, 0, nil, newTestLogger())

	result, err := store.GetByOrg(ctx, "any-org")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestInvalidate_NoRedis(t *testing.T) {
	ctx := context.Background()

	store := New(nil, nil, 0, nil, newTestLogger())

	assert.NotPanics(t, func() {
		store.Invalidate(ctx, "any-org")
	})
}

func TestInvalidate_Success(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-8"

	mockRDB := &mockCache{
		delFn: func(ctx context.Context, keys ...string) *redis.IntCmd {
			assert.Equal(t, cacheKeyPrefix+orgID, keys[0])
			return redis.NewIntResult(1, nil)
		},
	}

	store := New(nil, mockRDB, 0, nil, newTestLogger())

	store.Invalidate(ctx, orgID)
}

func TestInvalidate_Error(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-9"

	mockRDB := &mockCache{
		delFn: func(ctx context.Context, keys ...string) *redis.IntCmd {
			return redis.NewIntResult(0, errors.New("redis error"))
		},
	}

	store := New(nil, mockRDB, 0, nil, newTestLogger())

	assert.NotPanics(t, func() {
		store.Invalidate(ctx, orgID)
	})
}

func TestGetByOrg_CacheMissDBSuccess_setsCache(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-cache-write"

	var cachedKey string
	var cachedData []byte

	mockRDB := &mockCache{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			if key == cacheKeyPrefix+orgID && len(cachedData) > 0 {
				return redis.NewStringResult(string(cachedData), nil)
			}
			return redis.NewStringResult("", redis.Nil)
		},
		setFn: func(ctx context.Context, key string, val interface{}, ttl time.Duration) *redis.StatusCmd {
			cachedKey = key
			if b, ok := val.([]byte); ok {
				cachedData = make([]byte, len(b))
				copy(cachedData, b)
			} else if s, ok := val.(string); ok {
				cachedData = []byte(s)
			} else {
				cachedData, _ = json.Marshal(val)
			}
			return redis.NewStatusResult("OK", nil)
		},
	}

	mockDB := &mockDB{
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: [][]interface{}{{"r-cw", orgID, "org_id == 'x'", "gpt-5", int64(100), true}}}, nil
		},
	}

	store := New(mockDB, mockRDB, 2*time.Minute, nil, newTestLogger())

	result, err := store.GetByOrg(ctx, orgID)
	require.NoError(t, err)
	assert.Len(t, result, 1)

	assert.Equal(t, cacheKeyPrefix+orgID, cachedKey)
	var decoded []evaluator.Rule
	require.NoError(t, json.Unmarshal(cachedData, &decoded))
	assert.Equal(t, result, decoded)
}

func TestGetByOrg_ZeroRulesCachedWithTTL(t *testing.T) {
	ctx := context.Background()
	orgID := "test-org-empty"

	var setVal interface{}
	mockRDB := &mockCache{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			switch v := setVal.(type) {
			case string:
				return redis.NewStringResult(v, nil)
			case []byte:
				return redis.NewStringResult(string(v), nil)
			}
			return redis.NewStringResult("", redis.Nil)
		},
		setFn: func(ctx context.Context, key string, val interface{}, ttl time.Duration) *redis.StatusCmd {
			assert.Equal(t, cacheKeyPrefix+orgID, key)
			assert.Equal(t, defaultTTL, ttl, "empty rules use the store TTL")
			setVal = val
			return redis.NewStatusResult("OK", nil)
		},
	}

	queries := 0
	mockDB := &mockDB{
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			queries++
			return &mockPGXRows{data: [][]interface{}{}}, nil
		},
	}

	store := New(mockDB, mockRDB, 0, nil, newTestLogger())

	// RT-06: an org without rules is cached as "[]" — the first call loads
	// from the DB, subsequent calls within the TTL must not.
	result, err := store.GetByOrg(ctx, orgID)
	require.NoError(t, err)
	assert.Empty(t, result)
	assert.Equal(t, 1, queries)

	for i := 0; i < 5; i++ {
		result, err = store.GetByOrg(ctx, orgID)
		require.NoError(t, err)
		assert.Empty(t, result)
	}
	assert.Equal(t, 1, queries, "warm empty rules must not re-query the DB before the TTL")

	// The cached value is the JSON empty set, decodable back to zero rules.
	var data []byte
	switch v := setVal.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	}
	require.NotEmpty(t, data)
	var decoded []evaluator.Rule
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Empty(t, decoded)
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *mockPGXRows) TypeMap() *pgtype.Map { return nil }
