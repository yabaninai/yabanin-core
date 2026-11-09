package trcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// The canonical public source is LiteLLM's community-maintained cost map.
// The URL is never fetched implicitly: a network call happens only when the
// operator passes --url. The upstream file is a moving main branch, so
// operators who need reproducibility pin a commit in --url and record the
// snapshot date with --date.
const pricingSyncDay0CanonicalURL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"

// pricingSyncDay0MaxBytes bounds the catalog download; the real upstream
// file is a few MB, so 64 MiB is a generous ceiling against bad responses.
const pricingSyncDay0MaxBytes = 64 << 20

const pricingSyncDay0UserAgent = "yabanin-pricing-sync"

// pricingSyncDay0Timeout bounds one whole run (fetch + plan + apply).
const pricingSyncDay0Timeout = 2 * time.Minute

func pricingSyncDay0Cmd() *cobra.Command {
	var opts pricingSyncDay0Options
	cmd := &cobra.Command{
		Use:   "pricing-sync",
		Short: "Day-0 import of public model prices into models_pricing",
		Long: `Import per-model prices from a public cost map into models_pricing.

Source: exactly one of
  --file PATH   local LiteLLM model_prices JSON (air-gap; fully offline)
  --url URL     fetch the LiteLLM model_prices JSON over HTTP(S). The
                network call happens ONLY when this flag is passed.
                Canonical: ` + pricingSyncDay0CanonicalURL + `

UNIT CONVERSION: LiteLLM prices are USD per token, while models_pricing
input_per_m / output_per_m are USD per 1,000,000 tokens (numeric(10,6)).
The sync multiplies by 1e6 (pricing.ImportLiteLLM) before writing, so
input_cost_per_token: 2.5e-6 becomes input_per_m: 2.5.

CLOBBER POLICY: rows are never overwritten blindly. models_pricing.source
decides ownership (no schema change needed):
  no open row                 → INSERT with source='catalog'   (add)
  open row source='catalog'   → close + re-insert on a price change
                                (update); equal prices write nothing
                                (skip "unchanged")
  open row any other source   → SKIP — manual/seed/local_gpu overrides
                                are never touched
Re-running an applied sync is a no-op (idempotent).

DRY-RUN BY DEFAULT: without --apply nothing is written — the command
prints the plan (one row per catalog entry, sorted by provider+model)
and a summary. A run is one transaction: a failure writes nothing.

The gateway's DBPricer caches prices per key for 5 minutes: newly added
keys price immediately on first use, updated keys become visible within
that window after an apply.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPricingSyncDay0(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.File, "file", "", "Local LiteLLM model_prices JSON path (air-gap source)")
	cmd.Flags().StringVar(&opts.URL, "url", "", "HTTP(S) URL of the LiteLLM model_prices JSON (explicit network fetch)")
	cmd.Flags().StringVar(&opts.PGURI, "pg-uri", "", "Postgres URI of the gateway database (required)")
	cmd.Flags().StringVar(&opts.Source, "source", "litellm-model-prices", "Provenance label recorded in models_pricing.source_ref")
	cmd.Flags().StringVar(&opts.Date, "date", "unknown", "Upstream snapshot date (YYYY-MM-DD) recorded in source_ref")
	cmd.Flags().BoolVar(&opts.Apply, "apply", false, "Write the planned rows (default: dry run)")
	return cmd
}

// pricingSyncDay0Options carries the parsed flags of `yb pricing-sync`.
type pricingSyncDay0Options struct {
	File   string
	URL    string
	PGURI  string
	Source string
	Date   string
	Apply  bool
}

func runPricingSyncDay0(cmd *cobra.Command, opts pricingSyncDay0Options) error {
	w := cmd.OutOrStdout()
	if opts.PGURI == "" {
		return fmt.Errorf("--pg-uri required (Postgres URI of the gateway database)")
	}
	switch {
	case opts.File != "" && opts.URL != "":
		return fmt.Errorf("--file and --url are mutually exclusive")
	case opts.File == "" && opts.URL == "":
		return fmt.Errorf("exactly one of --file (air-gap) or --url (explicit fetch) is required; canonical URL:\n  %s",
			pricingSyncDay0CanonicalURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), pricingSyncDay0Timeout)
	defer cancel()

	var data []byte
	var origin string
	if opts.File != "" {
		origin = opts.File
		raw, err := os.ReadFile(opts.File)
		if err != nil {
			return err
		}
		data = raw
	} else {
		origin = opts.URL
		raw, err := fetchPricingSyncDay0Catalog(ctx, opts.URL)
		if err != nil {
			return err
		}
		data = raw
	}

	catalog, stats, err := pricing.ImportLiteLLM(bytes.NewReader(data), opts.Source, opts.Date)
	if err != nil {
		return annotatePricingSyncDay0JSON(err, origin, data)
	}

	pool, err := pgxpool.New(ctx, opts.PGURI)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}

	active, err := pricing.LoadActivePricing(ctx, pool)
	if err != nil {
		return err
	}
	report := pricing.PlanDay0Sync(catalog, active)
	if err := printPricingSyncDay0Plan(w, origin, stats, report); err != nil {
		return err
	}

	if !opts.Apply {
		_, err = fmt.Fprintf(w, "dry-run: nothing written; pass --apply to write added=%d updated=%d\n",
			report.Added, report.Updated)
		return err
	}
	if err := pricing.ApplyDay0Sync(ctx, pool, report); err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "applied: added=%d updated=%d skipped=%d\n",
		report.Added, report.Updated, report.Skipped)
	return err
}

// fetchPricingSyncDay0Catalog downloads the catalog over HTTP(S). Only the
// explicit --url flow reaches this function; it validates the scheme, bounds
// the response size, and never follows non-HTTP schemes.
func fetchPricingSyncDay0Catalog(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse --url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("--url must be an absolute http(s) URL, got %q", rawURL)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", pricingSyncDay0UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: unexpected status %d", rawURL, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, pricingSyncDay0MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	if len(data) > pricingSyncDay0MaxBytes {
		return nil, fmt.Errorf("fetch %s: catalog exceeds the %d byte limit", rawURL, pricingSyncDay0MaxBytes)
	}
	return data, nil
}

// annotatePricingSyncDay0JSON prefixes catalog parse failures with the input
// origin and the 1-based line:column of the offending byte, so an operator
// can open the exact spot of a broken JSON file.
func annotatePricingSyncDay0JSON(err error, origin string, data []byte) error {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		line, col := pricingSyncDay0LineCol(data, se.Offset)
		return fmt.Errorf("%s:%d:%d: %w", origin, line, col, err)
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		line, col := pricingSyncDay0LineCol(data, te.Offset)
		return fmt.Errorf("%s:%d:%d: %w", origin, line, col, err)
	}
	return fmt.Errorf("%s: %w", origin, err)
}

func pricingSyncDay0LineCol(data []byte, offset int64) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	line := 1 + bytes.Count(data[:offset], []byte{'\n'})
	col := int(offset) - bytes.LastIndexByte(data[:offset], '\n')
	if col < 1 {
		col = 1
	}
	return line, col
}

func printPricingSyncDay0Plan(w io.Writer, origin string, stats pricing.LiteLLMImportStats, report pricing.Day0Report) error {
	if _, err := fmt.Fprintf(w, "catalog origin: %s\n", origin); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w,
		"catalog stats: total=%d imported=%d skipped_mode=%d skipped_no_price=%d skipped_invalid=%d duplicates=%d tiered_ignored=%d\n",
		stats.Total, stats.Imported, stats.SkippedMode, stats.SkippedNoPrice, stats.SkippedInvalid, stats.Duplicates, stats.TieredIgnored); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw,
		"provider\tmodel\taction\tinput_per_m\toutput_per_m\tcache_w_per_m\tcache_r_per_m\treason"); err != nil {
		return err
	}
	for _, op := range report.Ops {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%g\t%g\t%g\t%g\t%s\n",
			op.Provider, op.Model, op.Action,
			op.Insert.InputPerM, op.Insert.OutputPerM, op.Insert.CacheWritePerM, op.Insert.CacheReadPerM,
			op.Reason); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "plan: added=%d updated=%d skipped=%d total=%d\n",
		report.Added, report.Updated, report.Skipped, report.Total)
	return err
}
