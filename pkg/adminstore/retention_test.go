package adminstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NEXT-21 unit contract: the validation helpers mirror the migration 0026
// CHECK constraints exactly — these tests pin the boundary so the admin API
// cannot accept what the schema would reject (and vice versa).

func TestValidRetentionDays(t *testing.T) {
	assert.False(t, ValidRetentionDays(0), "zero-day retention would delete before export")
	assert.False(t, ValidRetentionDays(-1))
	assert.True(t, ValidRetentionDays(MinRetentionDays))
	assert.True(t, ValidRetentionDays(30))
	assert.True(t, ValidRetentionDays(MaxRetentionDays))
	assert.False(t, ValidRetentionDays(MaxRetentionDays+1), "sanity cap keeps retention finite")
}

func TestValidColdDestination(t *testing.T) {
	for _, ok := range []string{
		"",
		"file:///var/cold/yabanin",
		"file:///a",
		"s3://bucket",
		"s3://bucket/prefix/path",
	} {
		assert.True(t, ValidColdDestination(ok), "want valid: %q", ok)
	}
	for _, bad := range []string{
		"file://",
		"file://relative/path",
		"file:/var/cold",
		"s3://",
		"http://bucket",
		"/var/cold",
		"var/cold",
	} {
		assert.False(t, ValidColdDestination(bad), "want invalid: %q", bad)
	}
}

func TestValidateRetentionDays_Policy(t *testing.T) {
	ten := 10
	p := &TeamRetentionPolicy{TeamID: "t", RequestLogsDays: &ten}
	require.NoError(t, ValidateRetentionDays(p), "nil siblings are legal (no window)")

	zero := 0
	p.CacheEntriesDays = &zero
	require.Error(t, ValidateRetentionDays(p))

	p.CacheEntriesDays = nil
	p.ColdDestination = "http://nope"
	require.Error(t, ValidateRetentionDays(p))

	p.ColdDestination = "file:///var/cold"
	require.NoError(t, ValidateRetentionDays(p))
}
