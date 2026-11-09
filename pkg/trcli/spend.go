package trcli

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func spendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spend",
		Short: "Show cost analytics",
		RunE: func(cmd *cobra.Command, _ []string) error {
			getString := func(name string) (string, error) { return cmd.Flags().GetString(name) }
			baseURL, apiKey, org, err := resolveAdminFlags(getString, "org")
			if err != nil {
				return err
			}
			days, _ := cmd.Flags().GetInt("days")

			report, err := NewAdminClient(baseURL, apiKey).SavingsReport(cmd.Context(), org, days)
			if err != nil {
				return err
			}
			printSavingsReport(cmd.OutOrStdout(), report)
			return nil
		},
	}
	cmd.Flags().IntP("days", "d", 7, "Number of days to look back")
	return cmd
}

// printSavingsReport renders the summary block and the top-models breakdown.
// Write errors are tolerated: a dead terminal (e.g. piped to a closed head)
// should not turn a successful fetch into a CLI failure.
func printSavingsReport(w io.Writer, r *SavingsReportSummary) {
	_, _ = fmt.Fprintf(w, "Period %s — requests: %d\n", r.Period, r.TotalRequests)
	_, _ = fmt.Fprintf(w, "Actual cost: $%.2f | Counterfactual: $%.2f | Combined savings: %.1f%%\n",
		r.ActualCostUSD, r.CounterfactualCost, r.CombinedSavingsPct)

	if len(r.TopModelsByCost) == 0 {
		_, _ = fmt.Fprintln(w, "No per-model breakdown available for this period.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "\nMODEL\tREQUESTS\tCOST\tSAVINGS%")
	for _, m := range r.TopModelsByCost {
		_, _ = fmt.Fprintf(tw, "%s\t%d\t$%.2f\t%.1f%%\n", m.Model, m.Requests, m.ActualCostUSD, m.SavingsPct)
	}
	_ = tw.Flush()
}
