package trcli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/lineage"
	"github.com/spf13/cobra"
)

// lineageCmd groups the `yb lineage` subcommands (H1: hash-chain verify).
func lineageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lineage",
		Short: "Lineage ledger operations (hash-chain verify)",
	}
	cmd.AddCommand(lineageVerifyCmd())
	cmd.AddCommand(lineageExportCmd())
	return cmd
}

// lineageVerifyCmd verifies the per-org hash chain of request_lineage.
func lineageVerifyCmd() *cobra.Command {
	var (
		pgURI string
		orgID string
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the per-org hash chain for request_lineage",
		Long: `Walk the org's request_lineage rows in ts order and re-verify the
per-org hash chain (record_hash / prev_hash). Legacy rows (record_hash='')
are skipped. Exit non-zero if the chain is broken.

  yb lineage verify --pg-uri postgres://... --org <org_id>`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLineageVerify(cmd.OutOrStdout(), pgURI, orgID)
		},
	}
	cmd.Flags().StringVar(&pgURI, "pg-uri", "", "Postgres URI (required)")
	cmd.Flags().StringVar(&orgID, "org", "", "Organization ID whose chain to verify (required)")
	_ = cmd.MarkFlagRequired("pg-uri")
	_ = cmd.MarkFlagRequired("org")
	return cmd
}

// runLineageVerify is the pure core: connects to Postgres, runs VerifyChain,
// prints the status, and returns an error if the chain is broken (so the
// command exits non-zero). It never calls os.Exit.
func runLineageVerify(out io.Writer, pgURI, orgID string) error {
	if out == nil {
		out = io.Discard
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, pgURI)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}

	store := lineage.NewLedgerStore(pool)
	status, err := store.VerifyChain(ctx, orgID)
	if err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "org=%s rows=%d chained=%d legacy=%d\n",
		status.OrgID, status.Rows, status.Chained, status.Legacy)
	if !status.Intact {
		fmt.Fprintf(&b, "chain BROKEN at request_id=%s\n", status.BrokenAt)
		_, werr := fmt.Fprint(out, b.String())
		if werr != nil {
			return werr
		}
		return fmt.Errorf("hash chain broken at request_id=%s", status.BrokenAt)
	}
	b.WriteString("chain intact\n")
	_, err = fmt.Fprint(out, b.String())
	return err
}
