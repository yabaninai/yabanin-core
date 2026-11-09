package testdb

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fixture schema name is executed as a SQL identifier: it must stay
// inside Postgres's identifier charset and NAMEDATALEN budget no matter
// what label a suite passes, or two fixtures could collide into one schema
// after silent truncation (A05).
func TestFixtureSchemaNameIsSafeIdentifier(t *testing.T) {
	labels := []string{
		"credits",
		"My Org!",
		"a/b\\c",
		"..",
		"погружение-credits",
		strings.Repeat("x", 100),
		"",
	}
	const pattern = `^fx_[a-z0-9_]{1,24}_[0-9a-f]{16}$`
	seen := make(map[string]bool, len(labels))
	for _, label := range labels {
		name := fixtureSchemaName(label, "0123456789abcdef")
		require.Regexp(t, pattern, name, "label %q produced unsafe schema name", label)
		require.False(t, seen[name], "schema name %q repeated across labels", name)
		seen[name] = true
	}

	// Randomness suffix is part of the uniqueness contract.
	require.NotEqual(t,
		fixtureSchemaName("credits", "0000000000000000"),
		fixtureSchemaName("credits", "1111111111111111"))

	// Long labels are truncated deterministically, never silently by the DB:
	// two independent invocations with identical inputs must agree.
	first := fixtureSchemaName(strings.Repeat("x", 100), "0123456789abcdef")
	second := fixtureSchemaName(strings.Repeat("x", 100), "0123456789abcdef")
	require.Equal(t, first, second)
}
