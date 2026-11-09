package trcli

// The migrate-litellm command family (N16-P02-T04): reviewed dry-run,
// preview-gated apply and byte-identical rollback over a LiteLLM
// proxy-config migration. The apply consumes only a reviewed dry-run
// report — never raw LiteLLM configuration — and refuses before writing
// anything when the report does not clear the apply gate.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/reireirei/yabanin/pkg/clientconfig"
)

func migrateLiteLLMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate-litellm",
		Short: "Review and apply a LiteLLM proxy-config migration",
	}
	cmd.AddCommand(migrateLiteLLMDryRunCmd(), migrateLiteLLMApplyCmd(), migrateLiteLLMRollbackCmd())
	return cmd
}

// liteLLMFormatOK validates the shared --format flag.
func liteLLMFormatOK(format string) error {
	if format != "text" && format != "json" {
		return fmt.Errorf("--format must be \"text\" or \"json\" (got %q)", format)
	}
	return nil
}

func liteLLMOut(cmd *cobra.Command, body string) error {
	if _, err := fmt.Fprint(cmd.OutOrStdout(), body); err != nil {
		return err
	}
	return nil
}

// liteLLMReadFile reads an operator-supplied path. Absence is reported to
// the caller through os.IsNotExist so commands can distinguish.
func liteLLMReadFile(path, what string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator's --report/--catalog/--ledger file, not a secret or remote path
	if err != nil {
		return nil, fmt.Errorf("read %s %s: %w", what, path, err)
	}
	return data, nil
}

// liteLLMRefusalError renders an aggregated apply refusal as one loud
// multi-line error naming every problem.
func liteLLMRefusalError(what string, refusal *clientconfig.LiteLLMApplyRefusal) error {
	return fmt.Errorf("%s refused; nothing was written:\n  - %s",
		what, strings.Join(refusal.Problems, "\n  - "))
}

func migrateLiteLLMDryRunCmd() *cobra.Command {
	var configPath, outPath, format string
	cmd := &cobra.Command{
		Use:   "dry-run",
		Short: "Analyze a LiteLLM config into the reviewed migration report (no writes)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := liteLLMFormatOK(format); err != nil {
				return err
			}
			data, err := liteLLMReadFile(configPath, "--config")
			if err != nil {
				return err
			}
			rep, err := clientconfig.LiteLLMDryRun(data)
			if err != nil {
				return err
			}
			var body string
			if format == "json" {
				body, err = clientconfig.LiteLLMReportJSON(rep)
				if err != nil {
					return err
				}
			} else {
				body = clientconfig.RenderLiteLLMReport(rep)
			}
			if outPath == "" {
				if err := liteLLMOut(cmd, body); err != nil {
					return err
				}
			} else if err := os.WriteFile(outPath, []byte(body), 0o600); err != nil {
				return fmt.Errorf("write --out %s: %w", outPath, err)
			}
			_, err = fmt.Fprintf(cmd.ErrOrStderr(),
				"dry-run: transferable=%d differences=%d conflicts=%d unsupported=%d secrets_redacted=%d plan_entries=%d\n",
				rep.Summary.Transferable, rep.Summary.Differences, rep.Summary.Conflicts,
				rep.Summary.Unsupported, rep.Summary.Secrets, rep.Summary.PlanEntries)
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "LiteLLM proxy config path (YAML)")
	cmd.Flags().StringVar(&outPath, "out", "", "report output path (stdout when empty)")
	cmd.Flags().StringVar(&format, "format", "json", "report format: text or json")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

// migrateLiteLLMApplyCmd implements the reviewed apply: without --yes it
// prints the execution preview against the current catalog and writes
// nothing; with --yes it prints the preview, runs the gated apply and
// prints the result. Refusals exit non-zero with every problem listed.
func migrateLiteLLMApplyCmd() *cobra.Command {
	var reportPath, catalogPath, ledgerPath, format string
	var yes bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a reviewed migration report to the catalog (preview without --yes)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := liteLLMFormatOK(format); err != nil {
				return err
			}
			if catalogPath == "" {
				return fmt.Errorf("--catalog is required")
			}
			reportData, err := liteLLMReadFile(reportPath, "--report")
			if err != nil {
				return err
			}
			var rep clientconfig.LiteLLMMigrationReport
			if err := json.Unmarshal(reportData, &rep); err != nil {
				return fmt.Errorf("parse --report %s: %w", reportPath, err)
			}
			targets := clientconfig.LiteLLMApplyTargets{
				CatalogPath: catalogPath,
				LedgerPath:  ledgerPath,
			}
			// Current catalog bytes for the preview (nil when absent). The
			// apply re-reads and re-verifies everything itself; the preview
			// is the review surface, not the authority.
			var currentCatalog []byte
			if data, readErr := os.ReadFile(catalogPath); readErr == nil { //nolint:gosec // G304: path is the operator's --catalog file, not a secret or remote path
				currentCatalog = data
			} else if !os.IsNotExist(readErr) {
				return fmt.Errorf("read --catalog %s: %w", catalogPath, readErr)
			}
			preview, err := clientconfig.BuildLiteLLMApplyPreview(&rep, targets, currentCatalog)
			if err != nil {
				var refusal *clientconfig.LiteLLMApplyRefusal
				if errors.As(err, &refusal) {
					return liteLLMRefusalError("apply", refusal)
				}
				return err
			}
			var body string
			if format == "json" {
				body, err = clientconfig.LiteLLMApplyPreviewJSON(preview)
			} else {
				body = clientconfig.RenderLiteLLMApplyPreview(preview)
			}
			if err != nil {
				return err
			}
			if err := liteLLMOut(cmd, body); err != nil {
				return err
			}
			if !yes {
				_, err = fmt.Fprintln(cmd.ErrOrStderr(),
					"preview only — nothing was written; rerun with --yes to execute this plan")
				return err
			}
			res, err := clientconfig.LiteLLMApply(&rep, targets)
			if err != nil {
				var refusal *clientconfig.LiteLLMApplyRefusal
				if errors.As(err, &refusal) {
					return liteLLMRefusalError("apply", refusal)
				}
				return err
			}
			if format == "json" {
				body, err = clientconfig.LiteLLMApplyResultJSON(res)
			} else {
				body = clientconfig.RenderLiteLLMApplyResult(res)
			}
			if err != nil {
				return err
			}
			return liteLLMOut(cmd, body)
		},
	}
	cmd.Flags().StringVar(&reportPath, "report", "", "reviewed dry-run report JSON path")
	cmd.Flags().StringVar(&catalogPath, "catalog", "", "target catalog document path")
	cmd.Flags().StringVar(&ledgerPath, "ledger", "", "apply ledger path (default: <catalog>.litellm-apply-ledger.json)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&yes, "yes", false, "execute the plan (omit for a write-free preview)")
	_ = cmd.MarkFlagRequired("report")
	return cmd
}

func migrateLiteLLMRollbackCmd() *cobra.Command {
	var catalogPath, ledgerPath, format string
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Roll back the last apply, restoring byte-identical pre-state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := liteLLMFormatOK(format); err != nil {
				return err
			}
			if catalogPath == "" {
				return fmt.Errorf("--catalog is required")
			}
			targets := clientconfig.LiteLLMApplyTargets{
				CatalogPath: catalogPath,
				LedgerPath:  ledgerPath,
			}
			res, err := clientconfig.LiteLLMRollback(targets)
			if err != nil {
				return err
			}
			var body string
			if format == "json" {
				body, err = clientconfig.LiteLLMRollbackResultJSON(res)
			} else {
				body = clientconfig.RenderLiteLLMRollbackResult(res)
			}
			if err != nil {
				return err
			}
			return liteLLMOut(cmd, body)
		},
	}
	cmd.Flags().StringVar(&catalogPath, "catalog", "", "target catalog document path")
	cmd.Flags().StringVar(&ledgerPath, "ledger", "", "apply ledger path (default: <catalog>.litellm-apply-ledger.json)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}
