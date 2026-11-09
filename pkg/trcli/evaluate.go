package trcli

import (
	"encoding/json"
	"os"

	"github.com/reireirei/yabanin/pkg/qualityeval"
	"github.com/spf13/cobra"
)

func evaluateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evaluate pairs.json",
		Short: "Compare structured model outputs offline; report verdicts without payloads",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rate, err := cmd.Flags().GetFloat64("min-pass-rate")
			if err != nil {
				return err
			}
			file, err := os.Open(args[0])
			if err != nil {
				return err
			}
			report, evalErr := qualityeval.Evaluate(file, rate)
			closeErr := file.Close()
			if evalErr != nil {
				return evalErr
			}
			if closeErr != nil {
				return closeErr
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		},
	}
	cmd.Flags().Float64("min-pass-rate", 1, "Minimum candidate pass fraction; baseline regressions always fail the gate")
	cmd.AddCommand(evaluateRoutingCmd())
	cmd.AddCommand(evaluateGuardsCmd())
	return cmd
}
