// Command gateway runs the Yabanin gateway API server (HTTP + optional ops
// admin listener). The implementation lives in services/run so the unified
// binary can start it in-process; this main is a thin wrapper for standalone
// deploys.
package main

import (
	"context"
	"os"

	// automaxprocs sets GOMAXPROCS to the container CPU limit instead of
	// the host core count (avoids scheduler overload under K8s CPU limits).
	// Kept on the standalone entrypoint on purpose: a blank import in the
	// shared services/run package would add a package-init side effect to
	// every binary that imports it (unified, loggerd, mcp).
	_ "go.uber.org/automaxprocs"

	"github.com/reireirei/yabanin/services/run"
)

func main() {
	if err := run.Gateway(context.Background()); err != nil {
		os.Exit(1)
	}
}
