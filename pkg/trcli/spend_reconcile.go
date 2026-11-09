package trcli

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// invoice with the spend request_logs actually captured for one org and
// period, and print the capture rate (parity: LiteLLM spend tracking).
//
// The command is REPORT-ONLY: it exits 0 with the report unless
// --fail-over turns a capture shortfall into a CI failure. It reads only
// data that exists (the CSV and request_logs) — it never estimates or
// extrapolates missing values; a missing day is reported as a shortfall.
//
// Invoice CSV format (RFC 4180, UTF-8, header row REQUIRED; extra columns
// are ignored):
//
//	date,usage_type,cost_usd
//	2026-10-01,completion,12.40
//	2026-10-02,"embedding, batch",0.85
//
//	date        — YYYY-MM-DD, the UTC day the invoice line covers
//	usage_type  — free text (completion/embedding/...), informational
//	cost_usd    — decimal amount (dot separator), USD
//
// Lines whose date falls outside --period are counted and EXCLUDED from the
// totals (they would silently distort the capture rate otherwise).
//
// Example fixture: scripts/pricing/fixtures/invoice_openai_2026-10.csv.

// providerHostAliases maps --provider names to the distinguishing substring
// of the provider's public API host (request_logs.upstream_url). This is a
// MATCHING HEURISTIC over a real column — not fabricated data — and
// --upstream-host overrides it for anything the aliases do not cover
// (private gateways, azure deployments with custom hosts, bedrock, which
// carries no upstream URL at all).
var providerHostAliases = map[string]string{
	"openai":     "openai.com",
	"anthropic":  "anthropic.com",
	"google":     "googleapis.com",
	"azure":      "openai.azure.com",
	"groq":       "groq.com",
	"mistral":    "mistral.ai",
	"deepseek":   "deepseek.com",
	"xai":        "x.ai",
	"openrouter": "openrouter.ai",
}

// periodRE pins --period to YYYY-MM (UTC month, the invoice granularity).
var periodRE = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])$`)

// invoiceLine is one parsed CSV row.
type invoiceLine struct {
	Date      time.Time
	UsageType string
	CostUSD   float64
	Line      int // 1-based file line for error messages
}

// SpendReconcileOptions carries the resolved command flags.
type SpendReconcileOptions struct {
	PGURI        string
	OrgID        string
	Provider     string
	UpstreamHost string // override for the provider alias
	CSVPath      string
	Period       string
	FailOver     float64 // percent; 0 = never fail
	Format       string  // text (default) or json
}

// SpendDayReport is one day of the comparison.
type SpendDayReport struct {
	Date       string  `json:"date"`
	OurUSD     float64 `json:"our_usd"`
	InvoiceUSD float64 `json:"invoice_usd"`
	DiffUSD    float64 `json:"diff_usd"`
}

// SpendReconcileReport is the full reconciliation result.
type SpendReconcileReport struct {
	OrgID           string           `json:"org"`
	Provider        string           `json:"provider"`
	UpstreamHost    string           `json:"upstream_host"`
	Period          string           `json:"period"`
	OurTotalUSD     float64          `json:"our_total_usd"`
	InvoiceTotalUSD float64          `json:"invoice_total_usd"`
	CaptureRatePct  float64          `json:"capture_rate_pct"`
	ShortfallPct    float64          `json:"shortfall_pct"`
	InvoiceLines    int              `json:"invoice_lines"`
	OutsidePeriod   int              `json:"outside_period_lines"`
	Days            []SpendDayReport `json:"days"`
	Notes           []string         `json:"notes,omitempty"`
}

// SpendStore is the read seam over request_logs (satisfied by pgStore;
// tests inject fakes).
type SpendStore interface {
	DailyProviderSpend(ctx context.Context, orgID string, from, to time.Time, hostSubstring string) (map[string]float64, error)
}

// pgStore reads the captured spend straight from request_logs. cost_in_usd
// is the captured column (numeric(12,6)); rows whose upstream_url does not
// mention the provider host are excluded (upstream matching, see
// providerHostAliases).
type pgStore struct{ pool *pgxpool.Pool }

func (s pgStore) DailyProviderSpend(ctx context.Context, orgID string, from, to time.Time, hostSubstring string) (map[string]float64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS day,
		       COALESCE(SUM(cost_in_usd), 0) AS cost
		FROM request_logs
		WHERE org_id = $1 AND created_at >= $2 AND created_at < $3
		  AND upstream_url ILIKE $4
		GROUP BY 1 ORDER BY 1`,
		orgID, from, to, "%"+hostSubstring+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]float64)
	for rows.Next() {
		var day string
		var cost float64
		if err := rows.Scan(&day, &cost); err != nil {
			return nil, err
		}
		out[day] = cost
	}
	return out, rows.Err()
}

func spendReconcileCmd() *cobra.Command {
	var opts SpendReconcileOptions
	cmd := &cobra.Command{
		Use:   "spend-reconcile",
		Short: "Compare a provider invoice CSV with captured request_logs spend",
		Long: `Reconcile a provider invoice against the spend request_logs captured for
one org and period (UTC month). Prints our total, the invoice total, the
capture rate and the per-day differences.

EXIT CODE: 0 with the report (report-only). --fail-over N turns a capture
shortfall larger than N% into exit code 1 for CI.

INVOICE CSV (header required; extra columns ignored):
  date,usage_type,cost_usd
  2026-10-01,completion,12.40

Provider matching maps --provider to the provider's API host substring in
request_logs.upstream_url (e.g. openai -> openai.com); --upstream-host
overrides the mapping. Only CSV and database data are compared — nothing is
estimated.`,
		Example: `  yb spend-reconcile --provider openai --csv invoices.csv --org <uuid> \
    --period 2026-10 --pg-uri postgres://...
  yb spend-reconcile ... --fail-over 20 --format json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pool, err := openSpendStore(cmd.Context(), opts.PGURI)
			if err != nil {
				return err
			}
			defer pool.Close()
			return runSpendReconcile(cmd.OutOrStdout(), pgStore{pool: pool}, opts)
		},
		SilenceUsage: true,
	}
	cmd.Flags().StringVar(&opts.PGURI, "pg-uri", "", "Postgres URI (required, read-only access suffices)")
	cmd.Flags().StringVar(&opts.OrgID, "org", "", "Organization UUID (required)")
	cmd.Flags().StringVar(&opts.Provider, "provider", "", "Provider name, e.g. openai (required; see --upstream-host)")
	cmd.Flags().StringVar(&opts.UpstreamHost, "upstream-host", "", "Override the provider->host mapping with this substring")
	cmd.Flags().StringVar(&opts.CSVPath, "csv", "", "Invoice CSV path, '-' for stdin (required)")
	cmd.Flags().StringVar(&opts.Period, "period", "", "UTC month YYYY-MM (required)")
	cmd.Flags().Float64Var(&opts.FailOver, "fail-over", 0, "Fail (exit 1) when the capture shortfall exceeds N percent")
	cmd.Flags().StringVar(&opts.Format, "format", "text", "Report format: text|json")
	_ = cmd.MarkFlagRequired("pg-uri")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("provider")
	_ = cmd.MarkFlagRequired("csv")
	_ = cmd.MarkFlagRequired("period")
	return cmd
}

// openSpendStore validates the org id and connects. Kept separate from the
// pure core so tests can inject a fake store.
func openSpendStore(ctx context.Context, pgURI string) (*pgxpool.Pool, error) {
	if strings.TrimSpace(pgURI) == "" {
		return nil, fmt.Errorf("--pg-uri required")
	}
	pool, err := pgxpool.New(ctx, pgURI)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return pool, nil
}

// runSpendReconcile validates the flags, reads the CSV and the database and
// prints the report. Exit code contract: always 0 unless --fail-over is
// breached.
func runSpendReconcile(out io.Writer, store SpendStore, opts SpendReconcileOptions) error {
	if _, err := uuid.Parse(opts.OrgID); err != nil {
		return fmt.Errorf("--org must be a UUID: %w", err)
	}
	periodStart, periodEnd, err := parseMonth(opts.Period)
	if err != nil {
		return fmt.Errorf("--period: %w", err)
	}
	host := opts.UpstreamHost
	if host == "" {
		alias, ok := providerHostAliases[strings.ToLower(strings.TrimSpace(opts.Provider))]
		if !ok {
			return fmt.Errorf("unknown provider %q; pass --upstream-host <substring> or use one of: %s",
				opts.Provider, aliasList())
		}
		host = alias
	}
	lines, err := readInvoiceCSV(opts.CSVPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	our, err := store.DailyProviderSpend(ctx, opts.OrgID, periodStart, periodEnd, host)
	if err != nil {
		return fmt.Errorf("query request_logs spend: %w", err)
	}

	report, fail := reconcileSpend(opts, lines, our, periodStart, periodEnd, host)
	if err := renderSpendReport(out, &report, opts.Format); err != nil {
		return err
	}
	if fail != nil {
		return fail
	}
	return nil
}

// parseMonth parses YYYY-MM into [start, next-month-start) in UTC.
func parseMonth(period string) (time.Time, time.Time, error) {
	if !periodRE.MatchString(period) {
		return time.Time{}, time.Time{}, fmt.Errorf("expected YYYY-MM, got %q", period)
	}
	start, err := time.Parse("2006-01", period)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return start, start.AddDate(0, 1, 0), nil
}

func aliasList() string {
	names := make([]string, 0, len(providerHostAliases))
	for name := range providerHostAliases {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// readInvoiceCSV reads and parses the invoice file ("-" = stdin).
func readInvoiceCSV(path string) ([]invoiceLine, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path) //nolint:gosec // the path is an explicit operator-provided flag
		if err != nil {
			return nil, fmt.Errorf("open invoice csv: %w", err)
		}
		defer f.Close()
		r = f
	}
	return parseInvoiceCSV(r)
}

// parseInvoiceCSV parses the documented format. Header column names are
// order-insensitive; extra columns are ignored; fully empty lines are
// skipped; every error names the offending file line.
func parseInvoiceCSV(r io.Reader) ([]invoiceLine, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.ReuseRecord = false
	// Invoice exports are ragged in the wild (trailing blank lines, rows
	// with dropped columns). Variable field count + explicit bounds checks
	// below: blank lines are skipped, rows missing the required columns are
	// a hard error (a silently dropped invoice line would fake a good
	// capture rate).
	cr.FieldsPerRecord = -1
	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse invoice csv: %w", err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("parse invoice csv: empty file (expected header: date,usage_type,cost_usd)")
	}

	header := make(map[string]int, len(records[0]))
	for i, name := range records[0] {
		header[strings.ToLower(strings.TrimSpace(name))] = i
	}
	dateCol, okDate := header["date"]
	typeCol, okType := header["usage_type"]
	costCol, okCost := header["cost_usd"]
	if !okDate || !okCost {
		return nil, fmt.Errorf("parse invoice csv: header must contain 'date' and 'cost_usd' columns (usage_type recommended); got %v", records[0])
	}

	var lines []invoiceLine
	for i, rec := range records[1:] {
		fileLine := i + 2
		if isBlankRecord(rec) {
			continue
		}
		if dateCol >= len(rec) || costCol >= len(rec) {
			return nil, fmt.Errorf("invoice csv line %d: missing fields", fileLine)
		}
		date, err := time.Parse("2006-01-02", strings.TrimSpace(rec[dateCol]))
		if err != nil {
			return nil, fmt.Errorf("invoice csv line %d: bad date %q (want YYYY-MM-DD): %w", fileLine, rec[dateCol], err)
		}
		cost, err := strconv.ParseFloat(strings.TrimSpace(rec[costCol]), 64)
		if err != nil {
			return nil, fmt.Errorf("invoice csv line %d: bad cost_usd %q: %w", fileLine, rec[costCol], err)
		}
		usage := ""
		if okType && typeCol < len(rec) {
			usage = strings.TrimSpace(rec[typeCol])
		}
		lines = append(lines, invoiceLine{Date: date, UsageType: usage, CostUSD: cost, Line: fileLine})
	}
	return lines, nil
}

func isBlankRecord(rec []string) bool {
	for _, field := range rec {
		if strings.TrimSpace(field) != "" {
			return false
		}
	}
	return true
}

// reconcileSpend is the pure comparison core: totals, capture rate,
// shortfall and the per-day table. Invoice lines outside the period are
// counted in report.OutsidePeriod and excluded from the totals; days with
// activity on only one side still appear (diff makes missing days visible).
// Returns the report and an optional --fail-over failure.
func reconcileSpend(opts SpendReconcileOptions, lines []invoiceLine, our map[string]float64, periodStart, periodEnd time.Time, host string) (SpendReconcileReport, error) {
	invoiceByDay := make(map[string]float64)
	report := SpendReconcileReport{
		OrgID: opts.OrgID, Provider: opts.Provider, UpstreamHost: host,
		Period: opts.Period,
	}
	for _, line := range lines {
		if line.Date.Before(periodStart) || !line.Date.Before(periodEnd) {
			report.OutsidePeriod++
			continue
		}
		report.InvoiceLines++
		day := line.Date.UTC().Format("2006-01-02")
		invoiceByDay[day] += line.CostUSD
		report.InvoiceTotalUSD += line.CostUSD
	}
	for day, cost := range our {
		report.OurTotalUSD += cost
		if _, known := invoiceByDay[day]; !known {
			invoiceByDay[day] = 0
		}
	}

	seen := make(map[string]struct{}, len(invoiceByDay))
	for day := range invoiceByDay {
		seen[day] = struct{}{}
		report.Days = append(report.Days, SpendDayReport{
			Date:       day,
			OurUSD:     our[day],
			InvoiceUSD: invoiceByDay[day],
			DiffUSD:    our[day] - invoiceByDay[day],
		})
	}
	sort.Slice(report.Days, func(i, j int) bool { return report.Days[i].Date < report.Days[j].Date })

	switch {
	case report.InvoiceTotalUSD > 0:
		report.CaptureRatePct = 100 * report.OurTotalUSD / report.InvoiceTotalUSD
		report.ShortfallPct = 100 * (report.InvoiceTotalUSD - report.OurTotalUSD) / report.InvoiceTotalUSD
		if report.ShortfallPct < 0 {
			report.ShortfallPct = 0
		}
	case report.OurTotalUSD == 0:
		report.CaptureRatePct = 100
		report.Notes = append(report.Notes, "invoice and captured spend are both empty for the period")
	default:
		report.Notes = append(report.Notes, "invoice total is zero while captured spend is not; capture rate undefined (reported as 0)")
	}

	if opts.FailOver > 0 && report.ShortfallPct > opts.FailOver {
		return report, fmt.Errorf("capture shortfall %.2f%% exceeds --fail-over %.2f%% (our $%.6f vs invoice $%.6f)",
			report.ShortfallPct, opts.FailOver, report.OurTotalUSD, report.InvoiceTotalUSD)
	}
	return report, nil
}

func renderSpendReport(out io.Writer, r *SpendReconcileReport, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "text", "":
		return renderSpendReportText(out, r)
	default:
		return fmt.Errorf("unknown --format %q (text|json)", format)
	}
}

func renderSpendReportText(out io.Writer, r *SpendReconcileReport) error {
	if _, err := fmt.Fprintf(out, "spend-reconcile org=%s provider=%s (upstream ~%q) period=%s\n",
		r.OrgID, r.Provider, r.UpstreamHost, r.Period); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "our_total=$%.6f invoice_total=$%.6f capture_rate=%.2f%% shortfall=%.2f%%\n",
		r.OurTotalUSD, r.InvoiceTotalUSD, r.CaptureRatePct, r.ShortfallPct); err != nil {
		return err
	}
	if r.OutsidePeriod > 0 {
		if _, err := fmt.Fprintf(out, "note: %d invoice line(s) outside the period excluded\n", r.OutsidePeriod); err != nil {
			return err
		}
	}
	for _, note := range r.Notes {
		if _, err := fmt.Fprintf(out, "note: %s\n", note); err != nil {
			return err
		}
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "DATE\tOUR_USD\tINVOICE_USD\tDIFF_USD"); err != nil {
		return err
	}
	for _, d := range r.Days {
		if _, err := fmt.Fprintf(tw, "%s\t%.6f\t%.6f\t%+.6f\n", d.Date, d.OurUSD, d.InvoiceUSD, d.DiffUSD); err != nil {
			return err
		}
	}
	return tw.Flush()
}
