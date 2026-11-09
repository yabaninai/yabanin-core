// Command yabanin-admin runs the admin control-plane server. The
// implementation lives in services/run so the unified binary can start it
// in-process; this main is a thin wrapper for standalone deploys.
package main

import (
	"context"
	"os"

	"github.com/reireirei/yabanin/services/run"
)

func main() {
	if err := run.AdminServer(context.Background()); err != nil {
		os.Exit(1)
	}
}
