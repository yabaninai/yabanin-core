package auth_test

import (
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSessionKey_FormatAndHash(t *testing.T) {
	key, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	assert.True(t, auth.IsSessionKey(key))
	assert.Len(t, key, auth.SessionKeyLen)
	assert.True(t, strings.HasPrefix(key, "ybs_"))
	assert.Len(t, auth.HashKey(key), 64)
	other, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	assert.NotEqual(t, key, other)
}

func TestIsSessionKey_RejectsOtherShapes(t *testing.T) {
	good, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	assert.False(t, auth.IsSessionKey("ybs_"))
	assert.False(t, auth.IsSessionKey(good+"aa"))
	assert.False(t, auth.IsSessionKey("yb_"+good[4:]))
	assert.False(t, auth.IsSessionKey("ybs_"+strings.Repeat("G", 64)))
	assert.False(t, auth.IsSessionKey(strings.ToUpper(good)))
}
