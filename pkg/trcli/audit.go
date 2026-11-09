package trcli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	audit "github.com/reireirei/yabanin/pkg/costsim"
)

// auditCmd is the offline spend-audit command. It ingests a customer's own LLM
// request log, computes what they spent and what caching + tier-routing would
// have saved, and renders the report. It makes no network calls and requires no
// gateway, admin, key, or organization — it is fully self-contained.
func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit [input]",
		Short: "Audit a request log for spend, waste, and cache/routing savings (offline)",
		Long: `Audit a customer's LLM request log offline.

The command ingests a request log (OpenAI-style JSONL, CSV, or this gateway's
format), computes what was actually spent, and simulates what semantic caching
plus tier-routing would have saved. It renders the report as markdown (default),
JSON, or self-contained HTML. It makes no network calls and needs no gateway,
admin URL, key, or organization.

Input is a single file path, or '-' to read stdin.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var input string
			if len(args) == 1 {
				input = args[0]
			} else {
				input = "-"
			}
			format, _ := cmd.Flags().GetString("format")
			cacheMode, _ := cmd.Flags().GetString("cache-mode")
			output, _ := cmd.Flags().GetString("output")
			maxRecords, _ := cmd.Flags().GetInt("max-records")
			noPrompts, _ := cmd.Flags().GetBool("no-prompts")
			provider, _ := cmd.Flags().GetString("provider")
			lang, _ := cmd.Flags().GetString("lang")

			mode, err := parseCacheMode(cacheMode)
			if err != nil {
				return err
			}

			if mode == audit.ModeSemantic {
				return fmt.Errorf("semantic audit is unavailable in this CLI: no embedder is configured; use --cache-mode exact or off")
			}

			// Resolve input: a path, or stdin copied to a temp file (Ingest reads
			// a file path).
			resolved, tmp, err := resolveAuditInput(input)
			if err != nil {
				return err
			}
			if tmp != "" {
				defer func() { _ = os.Remove(tmp) }() // best-effort temp cleanup
			}

			recs, stats, err := audit.Ingest(cmd.Context(), resolved, audit.IngestOptions{
				MaxRecords: maxRecords,
				NoPrompts:  noPrompts,
				Provider:   provider,
			})
			if err != nil {
				return err
			}
			if len(recs) == 0 {
				return fmt.Errorf("no records ingested from %s (parsed=0, parse-errors=%d)", input, stats.ParseErrorCount)
			}

			report := audit.GenerateReport(recs, mode)
			report.Source = input
			// A04: ingestion regression account — parsed / skipped / cap and
			// the denominator (parsed + skipped) so a report always shows how
			// many input lines produced records.
			report.S5.Skipped = stats.ParseErrorCount
			report.S5.Cap = stats.Cap
			report.S5.Denominator = stats.Parsed + stats.ParseErrorCount
			if stats.WasSymlink {
				report.Source += " (symlink, not followed silently)"
			}

			body, err := renderAuditReport(report, format, lang)
			if err != nil {
				return err
			}

			if output == "" {
				_, err = cmd.OutOrStdout().Write([]byte(body))
				return err
			}
			return os.WriteFile(output, []byte(body), 0o644) //nolint:gosec // operator-chosen output path
		},
	}
	cmd.Flags().StringP("format", "f", "md", "Report format: md | json | html")
	cmd.Flags().String("cache-mode", "exact", "Cache simulation mode: exact | semantic | off")
	cmd.Flags().StringP("output", "o", "", "Write the report to this file instead of stdout")
	cmd.Flags().Int("max-records", 0, "Cap on ingested records (0 = default)")
	cmd.Flags().Bool("no-prompts", false, "Drop raw prompt text after hashing (share the report without leaking content)")
	cmd.Flags().String("provider", "", "Override provider inference for the whole file")
	cmd.Flags().StringP("lang", "l", "", "Report language for render templates (e.g. en, ru); empty = English")
	return cmd
}

// parseCacheMode maps the --cache-mode flag value to the audit mode, rejecting
// anything that is not a valid mode so a typo does not silently run "off".
func parseCacheMode(s string) (audit.SimCacheMode, error) {
	switch s {
	case "exact":
		return audit.ModeExact, nil
	case "semantic":
		return audit.ModeSemantic, nil
	case "off":
		return audit.ModeOff, nil
	default:
		return "", fmt.Errorf("invalid --cache-mode %q (want exact, semantic, or off)", s)
	}
}

// renderAuditReport dispatches on the requested format. `lang` selects the
// render-template locale for md/html (I18N-12); JSON is data and ignores it.
func renderAuditReport(report audit.AuditReport, format string, lang string) (string, error) {
	switch format {
	case "md", "markdown":
		return audit.RenderMarkdownLang(report, lang), nil
	case "json":
		return audit.RenderJSON(report)
	case "html":
		return audit.RenderHTMLLang(report, lang), nil
	default:
		return "", fmt.Errorf("invalid --format %q (want md, json, or html)", format)
	}
}

// resolveAuditInput returns the file path to ingest. If input is "-" it copies
// stdin to a temp file and returns that path plus the temp path to clean up.
func resolveAuditInput(input string) (path, tmp string, err error) {
	if input != "-" {
		return input, "", nil
	}
	tmpFile, err := os.CreateTemp("", "tr-audit-*.tmp")
	if err != nil {
		return "", "", fmt.Errorf("create temp file for stdin: %w", err)
	}
	tmp = tmpFile.Name()
	if _, err := io.Copy(tmpFile, os.Stdin); err != nil {
		_ = tmpFile.Close() // best-effort cleanup on failure path
		_ = os.Remove(tmp)
		return "", "", fmt.Errorf("read stdin: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", "", err
	}
	return tmp, tmp, nil
}
