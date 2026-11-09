package trcli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/reireirei/yabanin/pkg/pricing"
)

func pricingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pricing",
		Short: "Import model price catalogs",
	}
	cmd.AddCommand(pricingImportLiteLLMCmd(), pricingImportLiteLLMUnitsCmd(), pricingLiteLLMFormatCmd(), pricingSyncCmd(),
		pricingRefPackCmd(), pricingRefVerifyCmd(), pricingRefDiffCmd(), pricingRefChainCmd())
	return cmd
}

func pricingImportLiteLLMCmd() *cobra.Command {
	var inPath, outPath, source, date string
	cmd := &cobra.Command{
		Use:   "import-litellm",
		Short: "Convert a LiteLLM price catalog into a Yabanin price file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := time.Parse("2006-01-02", date); err != nil {
				return fmt.Errorf("--date must be YYYY-MM-DD")
			}
			f, err := os.Open(inPath) //nolint:gosec // G304: path is the operator's --in catalog, not a secret or a remote path
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()

			pf, stats, err := pricing.ImportLiteLLM(f, source, date)
			if err != nil {
				return err
			}
			if err := pricing.ValidatePriceFile(pf); err != nil {
				return err
			}
			body, err := json.MarshalIndent(pf, "", "  ")
			if err != nil {
				return err
			}
			body = append(body, '\n')
			if outPath == "" {
				if _, err := cmd.OutOrStdout().Write(body); err != nil {
					return err
				}
			} else if err := os.WriteFile(outPath, body, 0o600); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(),
				"total=%d imported=%d skipped_mode=%d skipped_no_price=%d skipped_invalid=%d duplicates=%d tiered_ignored=%d\n",
				stats.Total, stats.Imported, stats.SkippedMode, stats.SkippedNoPrice, stats.SkippedInvalid, stats.Duplicates, stats.TieredIgnored); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "", "LiteLLM model_prices JSON path")
	cmd.Flags().StringVar(&outPath, "out", "", "price file path (stdout when empty)")
	cmd.Flags().StringVar(&source, "source", "", "provenance string stored in the price file")
	cmd.Flags().StringVar(&date, "date", "", "catalog date, YYYY-MM-DD")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("source")
	_ = cmd.MarkFlagRequired("date")
	return cmd
}

// pricingLiteLLMFormatCmd prints the pinned LiteLLM catalog contract:
// supported layout/modes, provider aliases, pinned upstream commit, the
// non-token unit modes and the field-by-field mapping with explicit
// refusals. This is the report-before-apply data for the price/unit slice
// of the LiteLLM migration wizard (N16-P02); it carries no file input and
// no credentials — the pin refuses credential fields by contract.
func pricingLiteLLMFormatCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "litellm-format",
		Short: "Print the pinned LiteLLM catalog format contract and field map (JSON)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			doc := struct {
				Format    pricing.LiteLLMFormat         `json:"format"`
				UnitModes []pricing.LiteLLMUnitMode     `json:"unit_modes"`
				FieldMap  []pricing.LiteLLMFieldMapping `json:"field_map"`
			}{
				Format:    pricing.LiteLLMFormatPin(),
				UnitModes: pricing.LiteLLMUnitModePin(),
				FieldMap:  pricing.LiteLLMFieldMap(),
			}
			body, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				return err
			}
			body = append(body, '\n')
			_, err = cmd.OutOrStdout().Write(body)
			return err
		},
	}
}

// pricingImportLiteLLMUnitsCmd converts the non-token unit rates (audio
// seconds / characters / images) of a LiteLLM catalog into a Yabanin unit
// file. Conversion does not activate the output or modify built-in prices.
// It must run against the same catalog commit as import-litellm so the two
// snapshots share provenance.
func pricingImportLiteLLMUnitsCmd() *cobra.Command {
	var inPath, outPath, source, date string
	cmd := &cobra.Command{
		Use:   "import-litellm-units",
		Short: "Convert non-token LiteLLM unit rates (audio/images) into a Yabanin unit file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := time.Parse("2006-01-02", date); err != nil {
				return fmt.Errorf("--date must be YYYY-MM-DD")
			}
			f, err := os.Open(inPath) //nolint:gosec // G304: path is the operator's --in catalog, not a secret or a remote path
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()

			uf, stats, err := pricing.ImportLiteLLMUnits(f, source, date)
			if err != nil {
				return err
			}
			if err := pricing.ValidateUnitFile(uf); err != nil {
				return err
			}
			body, err := json.MarshalIndent(uf, "", "  ")
			if err != nil {
				return err
			}
			body = append(body, '\n')
			if outPath == "" {
				if _, err := cmd.OutOrStdout().Write(body); err != nil {
					return err
				}
			} else if err := os.WriteFile(outPath, body, 0o600); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(),
				"total=%d imported=%d skipped_mode=%d skipped_no_price=%d skipped_invalid=%d duplicates=%d\n",
				stats.Total, stats.Imported, stats.SkippedMode, stats.SkippedNoPrice, stats.SkippedInvalid, stats.Duplicates); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "", "LiteLLM model_prices JSON path")
	cmd.Flags().StringVar(&outPath, "out", "", "unit file path (stdout when empty)")
	cmd.Flags().StringVar(&source, "source", "", "provenance string stored in the unit file")
	cmd.Flags().StringVar(&date, "date", "", "catalog date, YYYY-MM-DD")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("source")
	_ = cmd.MarkFlagRequired("date")
	return cmd
}
