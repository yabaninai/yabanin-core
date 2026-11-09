package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasCacheControl(t *testing.T) {
	assert.True(t, hasCacheControl([]byte(`{"cache_control":{"type":"ephemeral"}}`)))
	assert.True(t, hasCacheControl([]byte(`"cache_control"`)))
	assert.True(t, hasCacheControl([]byte(`[{"content":"hi","cache_control":1}]`)))
	assert.False(t, hasCacheControl([]byte(`{"model":"claude-3","messages":[]}`)))
	assert.False(t, hasCacheControl([]byte(`{}`)))
	assert.False(t, hasCacheControl(nil))
}
