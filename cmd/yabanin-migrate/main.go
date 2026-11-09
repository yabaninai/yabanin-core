// Package main is the standalone region-aware migration runner. It is a thin
// wrapper over pkg/migrate, which owns the embedded migrations and runner logic
// shared with the unified binary's in-process dispatch.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/migrate"
)

func main() {
	env := config.MigrateFromEnv()
	pgURI := env.PGURI
	if pgURI == "" {
		fmt.Fprintln(os.Stderr, "error: YABANIN_PG_URI or YABANIN_PG_URI_FILE is required")
		os.Exit(1)
	}

	region := env.Region
	if region == "" {
		fmt.Fprintln(os.Stderr, "error: YABANIN_REGION is required (e.g. sg, in, eu)")
		os.Exit(1)
	}

	res, err := migrate.Run(context.Background(), pgURI, region)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ applied %d migration(s) in region %s (%.2fs)\n", res.Applied, res.Region, res.Duration.Seconds())
	if res.Version > 0 {
		fmt.Printf("  latest version: %d\n", res.Version)
	}
}
