// Command mcp runs the MCP partner bridge (stdio or HTTP-SSE). The
// implementation lives in services/run so the unified binary can start it
// in-process; this main is a thin wrapper for standalone deploys.
package main

import (
	"log"

	"github.com/reireirei/yabanin/services/run"
)

func main() {
	if err := run.MCP(); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}
