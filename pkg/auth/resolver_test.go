package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRow implements pgx.Row interface.
//
// It serves two shapes by destination count:
//   - the regular api_keys path (3 string dests: apiKeyID, orgID, teamID);
//   - the agent-principal path (ADL-03): 2 string dests (agentID, orgID) plus
//     an optional *time.Time (expires_at) — set AgentID/OrgID/ExpiresAt to
//     drive the delegation-TTL tests.
type mockRow struct {
	scanErr   error
	orgID     string
	apiKeyID  string
	teamID    string
	agentID   string
	userID    string
	labels    map[string]string
	locked    bool
	mint      bool
	usage     bool
	expiresAt *time.Time
}

func (m *mockRow) Scan(dest ...interface{}) error {
	if m.scanErr != nil {
		return m.scanErr
	}
	// api_keys scans four strings (id, org, team, user) plus expires_at.
	// agent_keys scans two strings plus expires_at. String count tells them
	// apart: both paths now carry a *time.Time.
	stringDests := 0
	for _, d := range dest {
		if _, ok := d.(*string); ok {
			stringDests++
		}
	}
	agentPath := stringDests < 3
	strIdx := 0
	boolIdx := 0
	for _, d := range dest {
		switch v := d.(type) {
		case *string:
			if agentPath {
				switch strIdx {
				case 0:
					*v = m.agentID
				case 1:
					*v = m.orgID
				}
			} else {
				switch strIdx {
				case 0:
					*v = m.apiKeyID
				case 1:
					*v = m.orgID
				case 2:
					*v = m.teamID
				case 3:
					*v = m.userID
				}
			}
			strIdx++
		case *bool:
			switch boolIdx {
			case 0:
				*v = m.locked
			case 1:
				*v = m.mint
			case 2:
				*v = m.usage
			}
			boolIdx++
		case *[]byte:
			if m.labels == nil {
				*v = []byte(`{}`)
			} else if raw, err := json.Marshal(m.labels); err == nil {
				*v = raw
			} else {
				*v = []byte(`{}`)
			}
		case *map[string]string:
			if m.labels != nil {
				*v = m.labels
			}
		case *int64:
			*v = 123
		case **time.Time:
			// pgx pointer-to-pointer for NULL detection: NULL → nil, value →
			// the pointed time.
			if m.expiresAt != nil {
				*v = m.expiresAt
			} else {
				*v = nil
			}
		}
	}
	return nil
}

// mockPool implements auth.DBPool interface. agentPath selects whether a
// non-nil QueryRowFunc returns the agent-principal shape (3 dests incl.
// *time.Time) or the regular api_keys shape; the resolver queries api_keys
// FIRST, then agent_keys, so tests that exercise the agent path must also make
// the api_keys query return no rows.
type mockPool struct {
	QueryRowFunc func(ctx context.Context, query string, args ...interface{}) pgx.Row
}

func (m *mockPool) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	if m.QueryRowFunc != nil {
		row := m.QueryRowFunc(ctx, query, args...)
		return row
	}
	return &mockRow{scanErr: errors.New("no rows")}
}

// mockRedisClient implements auth.RedisClient interface
type mockRedisClient struct {
	getFunc   func(ctx context.Context, key string) (string, error)
	setCalls  []string
	setValues []string
	setTTLs   []time.Duration
}

func (m *mockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	if m.getFunc != nil {
		val, err := m.getFunc(ctx, key)
		return redis.NewStringResult(val, err)
	}
	return redis.NewStringResult("", errors.New("not found"))
}

func (m *mockRedisClient) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd {
	m.setCalls = append(m.setCalls, key)
	m.setValues = append(m.setValues, fmt.Sprint(value))
	m.setTTLs = append(m.setTTLs, ttl)
	return redis.NewStatusResult("", nil)
}

func TestResolve_EmptyKey(t *testing.T) {
	r := auth.NewResolver(nil, nil, 300, nil)
	res, err := r.Resolve(context.Background(), "")
	require.NoError(t, err)
	assert.Nil(t, res)
}

func TestResolve_WhitespaceKey(t *testing.T) {
	r := auth.NewResolver(nil, nil, 300, nil)
	res, err := r.Resolve(context.Background(), "   ")
	require.NoError(t, err)
	assert.Nil(t, res)
}

func TestResolve_NoRedisNoPool(t *testing.T) {
	r := auth.NewResolver(nil, nil, 300, nil)
	_, err := r.Resolve(context.Background(), "some-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api key not found")
}

func TestResolve_DBSuccess_CachesInRedis(t *testing.T) {
	pool := &mockPool{
		QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			return &mockRow{apiKeyID: "key-123", orgID: "org-db-resolved", teamID: "team-general"}
		},
	}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "", errors.New("cache miss")
		},
	}
	r := auth.NewResolver(pool, rdb, 300, nil)

	res, err := r.Resolve(context.Background(), "my-api-key")
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, "org-db-resolved", res.OrgID)
	assert.Equal(t, "key-123", res.APIKeyID)
	assert.Equal(t, "team-general", res.TeamID)
	assert.Len(t, rdb.setCalls, 1)
	assert.Contains(t, rdb.setCalls[0], "org:resolve:")
}

func TestResolve_CacheHit_NoDBCall(t *testing.T) {
	pool := &mockPool{
		QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			t.Error("QueryRow should not be called on cache hit")
			return &mockRow{}
		},
	}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "org-cached|key-456|team-prod", nil
		},
	}
	r := auth.NewResolver(pool, rdb, 300, nil)

	res, err := r.Resolve(context.Background(), "any-key")
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, "org-cached", res.OrgID)
	assert.Equal(t, "key-456", res.APIKeyID)
	assert.Equal(t, "team-prod", res.TeamID)
	assert.Empty(t, rdb.setCalls)
}

func TestResolve_CacheHitSigned_VerifyPass(t *testing.T) {
	pool := &mockPool{
		QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			t.Error("QueryRow should not be called on cache hit")
			return &mockRow{}
		},
	}
	signer, err := auth.NewCacheSigner("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)

	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			cached := signer.Sign(key, "org-signed-cached|key-789|team-staging")
			return cached, nil
		},
	}
	r := auth.NewResolver(pool, rdb, 300, signer)

	res, err := r.Resolve(context.Background(), "my-api-key")
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, "org-signed-cached", res.OrgID)
	assert.Equal(t, "key-789", res.APIKeyID)
	assert.Equal(t, "team-staging", res.TeamID)
	assert.Empty(t, rdb.setCalls)
}

func TestResolve_CacheHitSigned_VerifyFail(t *testing.T) {
	pool := &mockPool{
		QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			return &mockRow{apiKeyID: "key-123", orgID: "org-db-resolved", teamID: "team-general"}
		},
	}
	signer, err := auth.NewCacheSigner("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)

	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			forgedKey := "org:resolve:forgedkey"
			forged := signer.Sign(forgedKey, "org-forged")
			return forged, nil
		},
	}
	r := auth.NewResolver(pool, rdb, 300, signer)

	res, err := r.Resolve(context.Background(), "my-api-key")
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, "org-db-resolved", res.OrgID)
	assert.Equal(t, "key-123", res.APIKeyID)
	assert.Equal(t, "team-general", res.TeamID)
	assert.Len(t, rdb.setCalls, 1)
}

func TestResolve_CacheHit_NoSigner(t *testing.T) {
	pool := &mockPool{
		QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			t.Error("QueryRow should not be called on cache hit")
			return &mockRow{}
		},
	}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "org-cached-nosigner|key-no-signer|team-default", nil
		},
	}
	r := auth.NewResolver(pool, rdb, 300, nil)

	res, err := r.Resolve(context.Background(), "any-key")
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, "org-cached-nosigner", res.OrgID)
	assert.Equal(t, "key-no-signer", res.APIKeyID)
	assert.Equal(t, "team-default", res.TeamID)
	assert.Empty(t, rdb.setCalls)
}

// resolve; a past instant is rejected with the distinct ErrKeyExpired the
// gateway maps to 401 code "key_expired". The rejection is never cached.

func apiKeyQueryRow(row *mockRow) func(ctx context.Context, query string, args ...interface{}) pgx.Row {
	return func(ctx context.Context, query string, args ...interface{}) pgx.Row {
		if strings.Contains(query, "api_keys") && !strings.Contains(query, "agent_keys") {
			return row
		}
		return &mockRow{scanErr: errors.New("no rows")}
	}
}

func TestResolve_APIKey_NoExpiry_Resolves(t *testing.T) {
	pool := &mockPool{QueryRowFunc: apiKeyQueryRow(&mockRow{apiKeyID: "key-1", orgID: "org-1", teamID: "team-1"})}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "", errors.New("cache miss")
		},
	}
	r := auth.NewResolver(pool, rdb, 300, nil)

	res, err := r.Resolve(context.Background(), "sk_never_expires")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "org-1", res.OrgID)
	assert.Equal(t, "key-1", res.APIKeyID)
	assert.Len(t, rdb.setCalls, 1, "a never-expiring key resolve is cached")
}

func TestResolve_APIKey_ExpiresAt_Future_Resolves(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	pool := &mockPool{QueryRowFunc: apiKeyQueryRow(&mockRow{apiKeyID: "key-2", orgID: "org-1", teamID: "team-1", expiresAt: &future})}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "", errors.New("cache miss")
		},
	}
	r := auth.NewResolver(pool, rdb, 300, nil)

	res, err := r.Resolve(context.Background(), "sk_future_expiry")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "org-1", res.OrgID)
	assert.Len(t, rdb.setCalls, 1)
}

func TestResolve_APIKey_ExpiresAt_Past_ErrKeyExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	pool := &mockPool{QueryRowFunc: apiKeyQueryRow(&mockRow{apiKeyID: "key-3", orgID: "org-1", teamID: "team-1", expiresAt: &past})}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "", errors.New("cache miss")
		},
	}
	r := auth.NewResolver(pool, rdb, 300, nil)

	res, err := r.Resolve(context.Background(), "sk_expired")
	require.Error(t, err)
	assert.Nil(t, res)
	require.ErrorIs(t, err, auth.ErrKeyExpired,
		"an expired key must be distinguishable from an unknown key (401 code key_expired)")
	// The rejection must NOT be cached: once past expires_at, no TTL may keep
	// the key resolving.
	assert.Empty(t, rdb.setCalls)
}

// ADL-03: delegation TTL. A child agent key carries expires_at; the resolver
// rejects it once past that instant (and does not cache the rejection, so the
// TTL is honored on every miss). A root key (expires_at NULL) is unaffected.

// agentQueryRow returns the agent-principal shape when the query targets
// agent_keys, and "no rows" otherwise — so the resolver's api_keys-first
// lookup misses and the agent path is actually exercised.
func agentQueryRow(row *mockRow) func(ctx context.Context, query string, args ...interface{}) pgx.Row {
	return func(ctx context.Context, query string, args ...interface{}) pgx.Row {
		if strings.Contains(query, "agent_keys") {
			return row
		}
		return &mockRow{scanErr: errors.New("no rows")}
	}
}

func TestResolve_AgentKey_ExpiresAt_Past_Rejected(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	pool := &mockPool{QueryRowFunc: agentQueryRow(&mockRow{agentID: "agent-1", orgID: "org-1", expiresAt: &past})}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "", errors.New("cache miss")
		},
	}
	r := auth.NewResolver(pool, rdb, 300, nil)

	res, err := r.Resolve(context.Background(), "yag_child_expired")
	require.Error(t, err)
	assert.Nil(t, res)
	// The rejection must NOT be cached (caching would extend the expiry).
	assert.Empty(t, rdb.setCalls)
}

func TestResolve_AgentKey_ExpiresAt_Future_Resolves(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	pool := &mockPool{QueryRowFunc: agentQueryRow(&mockRow{agentID: "agent-1", orgID: "org-1", expiresAt: &future})}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "", errors.New("cache miss")
		},
	}
	r := auth.NewResolver(pool, rdb, 300, nil)

	res, err := r.Resolve(context.Background(), "yag_child_valid")
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, "org-1", res.OrgID)
	assert.Equal(t, "agent-1", res.AgentID)
	// A valid (non-expired) resolve IS cached — the S02 bound applies here.
	assert.Len(t, rdb.setCalls, 1)
	require.Len(t, rdb.setValues, 1)
	assert.True(t, strings.HasPrefix(rdb.setValues[0], "v2:"))
	assert.Contains(t, rdb.setValues[0], `"agent":"agent-1"`)
}

func TestResolve_AgentKey_Root_NoExpiry_Resolves(t *testing.T) {
	// A root agent key has expires_at NULL → no TTL, resolves normally.
	pool := &mockPool{QueryRowFunc: agentQueryRow(&mockRow{agentID: "agent-root", orgID: "org-1", expiresAt: nil})}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "", errors.New("cache miss")
		},
	}
	r := auth.NewResolver(pool, rdb, 300, nil)

	res, err := r.Resolve(context.Background(), "yag_root")
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, "org-1", res.OrgID)
	assert.Equal(t, "agent-root", res.AgentID)
}

func TestResolve_DBNotFound_ReturnsError_NoCache(t *testing.T) {
	pool := &mockPool{
		QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			return &mockRow{scanErr: errors.New("no rows")}
		},
	}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "", errors.New("cache miss")
		},
	}
	r := auth.NewResolver(pool, rdb, 300, nil)

	res, err := r.Resolve(context.Background(), "nonexistent-key")
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "not found or inactive")
	assert.Empty(t, rdb.setCalls)
}

func TestNewCacheSigner_InvalidHex(t *testing.T) {
	_, err := auth.NewCacheSigner("not-a-hex-value!@#$%")
	assert.Error(t, err)
}

func TestNewCacheSigner_TooShort(t *testing.T) {
	_, err := auth.NewCacheSigner("deadbeef")
	assert.Error(t, err)
}

func TestNewCacheSigner_Empty(t *testing.T) {
	_, err := auth.NewCacheSigner("")
	assert.Error(t, err)
}

func TestCacheSigner_SignVerify(t *testing.T) {
	signer, err := auth.NewCacheSigner("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)

	signed := signer.Sign("my-key", "my-value")
	// Sign returns "value:sig", Verify takes the full signed string
	value, ok := signer.Verify("my-key", signed)
	assert.True(t, ok, "expected valid verification")
	assert.Equal(t, "my-value", value, "expected extracted value to match original")
}

func TestCacheSigner_VerifyWrongKey(t *testing.T) {
	signer, err := auth.NewCacheSigner("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)

	signed := signer.Sign("key-a", "value-a")
	_, ok := signer.Verify("key-b", signed)
	assert.False(t, ok)
}

func TestCacheSigner_VerifyTampered(t *testing.T) {
	signer, err := auth.NewCacheSigner("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)

	signed := signer.Sign("my-key", "my-value")
	tampered := "my-valX" + ":" + signed[len("my-value")+1:]
	_, ok := signer.Verify("my-key", tampered)
	assert.False(t, ok)
}

func TestCacheSigner_VerifyNoColon(t *testing.T) {
	signer, err := auth.NewCacheSigner("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)

	_, ok := signer.Verify("my-key", "nosignaturehere")
	assert.False(t, ok)
}

func TestResolve_PersonalKey_UserIDAndFiveFieldCache(t *testing.T) {
	pool := &mockPool{
		QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			return &mockRow{apiKeyID: "key-1", orgID: "org-1", teamID: "team-1", userID: "user-9"}
		},
	}
	rdb := &mockRedisClient{getFunc: func(ctx context.Context, key string) (string, error) {
		return "", errors.New("cache miss")
	}}
	r := auth.NewResolver(pool, rdb, 300, nil)
	res, err := r.Resolve(context.Background(), "yb_personal")
	require.NoError(t, err)
	assert.Equal(t, "user-9", res.UserID)
	require.Len(t, rdb.setValues, 1)
	assert.True(t, strings.HasPrefix(rdb.setValues[0], "v2:"))
	assert.Contains(t, rdb.setValues[0], `"user":"user-9"`)
	assert.Contains(t, rdb.setValues[0], `"org":"org-1"`)
}

func TestResolve_ExpiredAPIKey_RejectedAndNotCached(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	pool := &mockPool{
		QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			if strings.Contains(query, "agent_keys") {
				return &mockRow{scanErr: errors.New("no rows")}
			}
			return &mockRow{apiKeyID: "key-1", orgID: "org-1", teamID: "team-1", userID: "user-9", expiresAt: &past}
		},
	}
	rdb := &mockRedisClient{getFunc: func(ctx context.Context, key string) (string, error) {
		return "", errors.New("cache miss")
	}}
	r := auth.NewResolver(pool, rdb, 300, nil)
	res, err := r.Resolve(context.Background(), "yb_expired")
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Empty(t, rdb.setCalls)
}

func TestResolve_CacheHit_LegacyAndFifthField(t *testing.T) {
	pool := &mockPool{QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
		t.Error("db should not be called")
		return &mockRow{}
	}}
	rdb := &mockRedisClient{getFunc: func(ctx context.Context, key string) (string, error) {
		return "org-1|key-1|team-1|agent-1|user-9", nil
	}}
	res, err := auth.NewResolver(pool, rdb, 300, nil).Resolve(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, "agent-1", res.AgentID)
	assert.Equal(t, "user-9", res.UserID)

	rdb.getFunc = func(ctx context.Context, key string) (string, error) {
		return "org-1|key-1|team-1|agent-1", nil
	}
	res, err = auth.NewResolver(pool, rdb, 300, nil).Resolve(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, "agent-1", res.AgentID)
	assert.Empty(t, res.UserID)
}

func TestResolve_CacheHit_V2JSON(t *testing.T) {
	pool := &mockPool{QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
		t.Error("db should not be called")
		return &mockRow{}
	}}
	raw := `v2:{"org":"org-1","key":"key-1","team":"team-1","agent":"","user":"user-9","labels":{"team":"payments"},"locked":true,"mint":true,"usage":false}`
	rdb := &mockRedisClient{getFunc: func(ctx context.Context, key string) (string, error) {
		return raw, nil
	}}
	res, err := auth.NewResolver(pool, rdb, 300, nil).Resolve(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, "payments", res.Labels["team"])
	assert.True(t, res.LabelsLocked)
	assert.True(t, res.CanMintSessions)
	assert.False(t, res.CanReadUsage)
}

func TestResolve_BrokenV2FallsThroughToDB(t *testing.T) {
	pool := &mockPool{QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
		return &mockRow{apiKeyID: "key-db", orgID: "org-db", teamID: "team-db", labels: map[string]string{"env": "ci"}}
	}}
	rdb := &mockRedisClient{getFunc: func(ctx context.Context, key string) (string, error) {
		return "v2:{not-json", nil
	}}
	res, err := auth.NewResolver(pool, rdb, 300, nil).Resolve(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, "org-db", res.OrgID)
	assert.Equal(t, "ci", res.Labels["env"])
}

func TestCacheSigner_RoundTripV2JSON(t *testing.T) {
	signer, err := auth.NewCacheSigner("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	raw := `v2:{"org":"org-1","labels":{"team":"a:b"}}`
	signed := signer.Sign("org:resolve:abc", raw)
	got, ok := signer.Verify("org:resolve:abc", signed)
	require.True(t, ok)
	assert.Equal(t, raw, got)
}

type sessionResolveRow struct {
	err error
	// sessionExpires/parentExpires override the canned defaults (AUTH-03
	// tests). parentExpires seeds the parent api_key's expires_at column the
	// fixed resolveSession SQL must select; nil keeps the old 12-column shape.
	sessionExpires *time.Time
	parentExpires  *time.Time
}

func (m sessionResolveRow) Scan(dest ...any) error {
	if m.err != nil {
		return m.err
	}
	expires := time.Now().Add(30 * time.Second).UTC()
	if m.sessionExpires != nil {
		expires = *m.sessionExpires
	}
	cost := "1.5"
	var tokens int64 = 100
	values := []any{
		"sess-1", "org-1", "parent-1", []byte(`{"job":"lint"}`), true,
		&tokens, &cost, expires, "team-1", []byte(`{"team":"payments"}`), true, "user-1",
	}
	if m.parentExpires != nil {
		values = append(values, m.parentExpires)
	}
	for i, d := range dest {
		if i >= len(values) {
			break
		}
		if err := assignScan(d, values[i]); err != nil {
			return err
		}
	}
	return nil
}

func assignScan(dest, src any) error {
	dv := reflect.ValueOf(dest)
	if dv.Kind() != reflect.Pointer || dv.IsNil() {
		return errors.New("scan dest")
	}
	sv := reflect.ValueOf(src)
	target := dv.Elem()
	if sv.Type().AssignableTo(target.Type()) {
		target.Set(sv)
		return nil
	}
	if sv.Kind() == reflect.Pointer && !sv.IsNil() && sv.Elem().Type().AssignableTo(target.Type()) {
		target.Set(sv.Elem())
		return nil
	}
	return fmt.Errorf("cannot assign %s to %s", sv.Type(), target.Type())
}

func TestResolve_SessionKey_ParentIdentityAndShortCache(t *testing.T) {
	key, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	pool := &mockPool{QueryRowFunc: func(ctx context.Context, query string, args ...any) pgx.Row {
		if !strings.Contains(query, "session_keys") {
			t.Fatalf("query %s", query)
		}
		return sessionResolveRow{}
	}}
	rdb := &mockRedisClient{getFunc: func(ctx context.Context, key string) (string, error) {
		return "", errors.New("miss")
	}}
	res, err := auth.NewResolver(pool, rdb, 300, nil).Resolve(context.Background(), key)
	require.NoError(t, err)
	assert.Equal(t, "parent-1", res.APIKeyID)
	assert.Equal(t, "sess-1", res.SessionKeyID)
	assert.Equal(t, "payments", res.Labels["team"])
	assert.Equal(t, "lint", res.SessionLabels["job"])
	assert.True(t, res.SessionLabelsLocked)
	assert.False(t, res.CanMintSessions)
	require.NotNil(t, res.SessionMaxTokens)
	assert.Equal(t, int64(100), *res.SessionMaxTokens)
	require.Len(t, rdb.setTTLs, 1)
	assert.LessOrEqual(t, rdb.setTTLs[0], 30*time.Second)

	miss := &mockPool{QueryRowFunc: func(ctx context.Context, query string, args ...any) pgx.Row {
		return sessionResolveRow{err: errors.New("no rows")}
	}}
	_, err = auth.NewResolver(miss, rdb, 300, nil).Resolve(context.Background(), key)
	require.Error(t, err)
}

// AUTH-03: a session key must carry its parent key's expiry as an identity
// property, so minting and cache logic can never let the session outlive
// the parent.
func TestResolve_SessionCarriesParentKeyExpiry(t *testing.T) {
	key, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	parentExpires := time.Now().UTC().Add(45 * time.Second)
	pool := &mockPool{QueryRowFunc: func(ctx context.Context, query string, args ...any) pgx.Row {
		if !strings.Contains(query, "session_keys") {
			t.Fatalf("expected session_keys query, got %s", query)
		}
		return sessionResolveRow{parentExpires: &parentExpires}
	}}
	res, err := auth.NewResolver(pool, nil, 300, nil).Resolve(context.Background(), key)
	require.NoError(t, err)
	require.False(t, res.KeyExpiresAt.IsZero(), "parent expiry must ride on the resolve result")
	assert.WithinDuration(t, parentExpires, res.KeyExpiresAt, 2*time.Second)
}

// --- AUTH-04: the warm cache must never resurrect an expired identity ---

func TestResolve_WarmCacheRechecksParentKeyExpiry(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	keyExpires := base.Add(60 * time.Second)
	now := base
	pool := &mockPool{QueryRowFunc: func(ctx context.Context, query string, args ...any) pgx.Row {
		return &mockRow{apiKeyID: "key-1", orgID: "org-1", teamID: "team-1", expiresAt: &keyExpires}
	}}
	var rdb *mockRedisClient
	rdb = &mockRedisClient{getFunc: func(ctx context.Context, key string) (string, error) {
		if n := len(rdb.setValues); n > 0 {
			return rdb.setValues[n-1], nil
		}
		return "", errors.New("miss")
	}}
	r := auth.NewResolver(pool, rdb, 300, nil).WithNow(func() time.Time { return now })

	res, err := r.Resolve(context.Background(), "auth04-expiring-key")
	require.NoError(t, err)
	require.False(t, res.KeyExpiresAt.IsZero(), "effective expiry must be an identity property")

	// The key expires; the cache entry (TTL 300s) is still warm.
	now = keyExpires.Add(time.Second)
	_, err = r.Resolve(context.Background(), "auth04-expiring-key")
	assert.ErrorIs(t, err, auth.ErrKeyExpired,
		"a warm cache entry past the key's expiry must fall through to the DB, not authenticate")
}

func TestResolve_WarmCacheRechecksSessionExpiry(t *testing.T) {
	key, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	base := time.Now().UTC().Truncate(time.Second)
	now := base
	gone := false
	pool := &mockPool{QueryRowFunc: func(ctx context.Context, query string, args ...any) pgx.Row {
		if !strings.Contains(query, "session_keys") {
			t.Fatalf("expected session_keys query, got %s", query)
		}
		if gone {
			return sessionResolveRow{err: errors.New("no rows")}
		}
		return sessionResolveRow{sessionExpires: ptrTime(base.Add(30 * time.Second))}
	}}
	var rdb *mockRedisClient
	rdb = &mockRedisClient{getFunc: func(ctx context.Context, key string) (string, error) {
		if n := len(rdb.setValues); n > 0 {
			return rdb.setValues[n-1], nil
		}
		return "", errors.New("miss")
	}}
	r := auth.NewResolver(pool, rdb, 300, nil).WithNow(func() time.Time { return now })

	_, err = r.Resolve(context.Background(), key)
	require.NoError(t, err)

	now = base.Add(60 * time.Second) // session expired
	gone = true                      // ...and the row is gone server-side
	_, err = r.Resolve(context.Background(), key)
	assert.Error(t, err, "a warm session cache entry past its own expiry must not authenticate")
}

func TestResolve_CacheTTLBoundedByKeyExpiry(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	keyExpires := base.Add(60 * time.Second)
	pool := &mockPool{QueryRowFunc: func(ctx context.Context, query string, args ...any) pgx.Row {
		return &mockRow{apiKeyID: "key-1", orgID: "org-1", teamID: "team-1", expiresAt: &keyExpires}
	}}
	rdb := &mockRedisClient{}
	r := auth.NewResolver(pool, rdb, 300, nil).WithNow(func() time.Time { return base })
	_, err := r.Resolve(context.Background(), "auth04-ttl-key")
	require.NoError(t, err)
	require.Len(t, rdb.setTTLs, 1)
	assert.LessOrEqual(t, rdb.setTTLs[0], 60*time.Second,
		"the cache entry must not outlive the key it represents")
}

func TestResolve_CachedEntryCarriesKeyExpiry(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	keyExpires := base.Add(60 * time.Second)
	pool := &mockPool{QueryRowFunc: func(ctx context.Context, query string, args ...any) pgx.Row {
		return &mockRow{apiKeyID: "key-1", orgID: "org-1", teamID: "team-1", expiresAt: &keyExpires}
	}}
	var rdb *mockRedisClient
	rdb = &mockRedisClient{getFunc: func(ctx context.Context, key string) (string, error) {
		if n := len(rdb.setValues); n > 0 {
			return rdb.setValues[n-1], nil
		}
		return "", errors.New("miss")
	}}

	cold, err := auth.NewResolver(pool, rdb, 300, nil).WithNow(func() time.Time { return base }).
		Resolve(context.Background(), "auth04-roundtrip-key")
	require.NoError(t, err)
	require.False(t, cold.KeyExpiresAt.IsZero())

	warm, err := auth.NewResolver(pool, rdb, 300, nil).WithNow(func() time.Time { return base }).
		Resolve(context.Background(), "auth04-roundtrip-key")
	require.NoError(t, err)
	assert.WithinDuration(t, cold.KeyExpiresAt, warm.KeyExpiresAt, time.Second,
		"the cached doc must round-trip the key expiry (AUTH-04 identity property)")
}

func ptrTime(t time.Time) *time.Time { return &t }
