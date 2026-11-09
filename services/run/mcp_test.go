package run

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMCP_MissingPartnerKey pins the error path: without a partner key MCP()
// must return an error, never start a server or crash the process.
func TestMCP_MissingPartnerKey(t *testing.T) {
	t.Setenv("YABANIN_PARTNER_API_KEY", "")
	t.Setenv("YABANIN_GATEWAY_URL", "")
	t.Setenv("YABANIN_ADMIN_URL", "")

	err := MCP()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "YABANIN_PARTNER_API_KEY")
}
