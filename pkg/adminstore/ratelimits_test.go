package adminstore

// live in ratelimits_int_test.go against a disposable Postgres.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidRateLimitScope(t *testing.T) {
	assert.True(t, ValidRateLimitScope(RateLimitScopeKey))
	assert.True(t, ValidRateLimitScope(RateLimitScopeTeam))
	assert.True(t, ValidRateLimitScope(RateLimitScopeOrg))
	for _, bad := range []string{"", "KEY", "user", "global"} {
		assert.False(t, ValidRateLimitScope(bad), "scope %q must be rejected", bad)
	}
}

func TestValidRateLimitValue(t *testing.T) {
	assert.False(t, ValidRateLimitValue(0), "zero is 'disabled', not a limit")
	assert.False(t, ValidRateLimitValue(-5))
	assert.True(t, ValidRateLimitValue(1))
	assert.True(t, ValidRateLimitValue(MaxRateLimitValue))
	assert.False(t, ValidRateLimitValue(MaxRateLimitValue+1))
}

func int64p(v int64) *int64 { return &v }

func TestValidateKeyRateLimit(t *testing.T) {
	const id = "11111111-1111-1111-1111-111111111111"
	valid := &KeyRateLimit{Scope: RateLimitScopeKey, SubjectID: id, RPM: int64p(60)}
	require.NoError(t, ValidateKeyRateLimit(valid))
	require.NoError(t, ValidateKeyRateLimit(&KeyRateLimit{
		Scope: RateLimitScopeOrg, SubjectID: id, TPM: int64p(100_000), Enabled: true,
	}))

	t.Run("nil", func(t *testing.T) {
		require.Error(t, ValidateKeyRateLimit(nil))
	})
	t.Run("bad scope", func(t *testing.T) {
		require.Error(t, ValidateKeyRateLimit(&KeyRateLimit{Scope: "user", SubjectID: id, RPM: int64p(1)}))
	})
	t.Run("bad subject", func(t *testing.T) {
		require.Error(t, ValidateKeyRateLimit(&KeyRateLimit{Scope: RateLimitScopeKey, SubjectID: "not-a-uuid", RPM: int64p(1)}))
	})
	t.Run("zero rpm", func(t *testing.T) {
		require.Error(t, ValidateKeyRateLimit(&KeyRateLimit{Scope: RateLimitScopeKey, SubjectID: id, RPM: int64p(0)}))
	})
	t.Run("negative tpm", func(t *testing.T) {
		require.Error(t, ValidateKeyRateLimit(&KeyRateLimit{Scope: RateLimitScopeKey, SubjectID: id, TPM: int64p(-1)}))
	})
	t.Run("no dimension set", func(t *testing.T) {
		require.Error(t, ValidateKeyRateLimit(&KeyRateLimit{Scope: RateLimitScopeKey, SubjectID: id}))
	})
}
