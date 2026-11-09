package trcli

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func keysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage API keys",
	}
	cmd.AddCommand(keysListCmd())
	return cmd
}

func keysListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your organization's API keys",
		RunE: func(cmd *cobra.Command, _ []string) error {
			getString := func(name string) (string, error) { return cmd.Flags().GetString(name) }
			baseURL, apiKey, org, err := resolveAdminFlags(getString, "org")
			if err != nil {
				return err
			}
			page, _ := cmd.Flags().GetInt("page")
			pageSize, _ := cmd.Flags().GetInt("page-size")

			res, err := NewAdminClient(baseURL, apiKey).ListAPIKeys(cmd.Context(), org, page, pageSize)
			if err != nil {
				return err
			}
			printKeysPage(cmd.OutOrStdout(), res)
			return nil
		},
	}
	cmd.Flags().Int("page", 0, "Page number (server default when 0)")
	cmd.Flags().Int("page-size", 0, "Items per page (server default when 0)")
	return cmd
}

// printKeysPage renders the key list. APIKey has no plaintext prefix by
// design (the admin store keeps hashes only), so name/age status is all we show.
func printKeysPage(w io.Writer, p *APIKeyPage) {
	if len(p.Data) == 0 {
		_, _ = fmt.Fprintln(w, "No API keys found for this organization.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tSTATUS\tCREATED")
	for _, k := range p.Data {
		status := "inactive"
		if k.Active {
			status = "active"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", k.Name, status, k.CreatedAt.Format("2006-01-02"))
	}
	_ = tw.Flush()
	if p.HasMore {
		// Write errors are tolerated: a closed pipe (e.g. `| head`) must not
		// turn a successful fetch into a CLI failure.
		_, _ = fmt.Fprintf(w, "\nShowing %d of %d keys — use --page/--page-size to page.\n", len(p.Data), p.Total)
	}
}
