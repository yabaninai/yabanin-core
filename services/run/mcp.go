package run

import (
	"errors"

	"github.com/reireirei/yabanin/pkg/config"
	mcp "github.com/reireirei/yabanin/pkg/mcppartner"
)

// MCP starts the MCP partner bridge. Mode is env-driven, matching the
// standalone binary: stdio for Claude Code by default, HTTP-SSE on :8787 when
// YABANIN_MCP_HTTP=1. A missing partner API key returns an error instead of
// log.Fatal so in-process callers can exit cleanly.
func MCP() error {
	env := config.MCPBridgeFromEnv()
	baseURL := env.GatewayURL
	if baseURL == "" {
		baseURL = "http://localhost:8082" // on-prem default; override via env for saas
	}
	adminURL := env.AdminURL
	if adminURL == "" {
		adminURL = "http://localhost:18086" // admin panel REST API (not gateway-admin :9090)
	}
	apiKey := env.PartnerAPIKey
	if apiKey == "" {
		return errors.New("mcp: YABANIN_PARTNER_API_KEY must be set")
	}
	// Admin calls use the stateless /internal service API (X-Admin-Key).
	// Single-operator stands share the partner key; SaaS sets a dedicated
	// YABANIN_ADMIN_API_KEY issued for the /internal group.
	adminKey := env.AdminAPIKey
	if adminKey == "" {
		adminKey = apiKey
	}

	client := mcp.NewGatewayClient(baseURL, adminURL, apiKey, adminKey)

	if env.HTTP {
		// HTTP-SSE mode for Cursor remote agents.
		return mcp.ServeHTTP(client, ":8787")
	}

	// Stdio mode for Claude Code.
	return mcp.ServeStdio(client)
}
