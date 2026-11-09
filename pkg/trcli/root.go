package trcli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version and commit are overridable at build time via
// -ldflags "-X github.com/reireirei/yabanin/pkg/trcli.version=... -X ...commit=..."
// (used by the audit-dist release target). They are vars, not consts, so the
// linker can replace them.
var (
	version = "yb 0.1.0"
	commit  = "dev"
)

// Backronym is the canonical expansion of the YABANIN name
// (Y-A-B-A-N-I-N). Shipped by `yb version` and the help surface.
const Backronym = "Your Agnostic Bridge Across Numerous Inference Networks"

// RootCommand creates the root CLI command.
func RootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "yb",
		Short: "Yabanin AI gateway CLI — route, manage keys, check spend",
		Long: `Yabanin CLI for managing your AI model routing.
` + Backronym + ` (the YABANIN backronym).

Renamed from the legacy "tr" command (the project is Yabanin).`,
	}

	cmd.AddCommand(versionCmd())
	cmd.AddCommand(keysCmd())
	cmd.AddCommand(spendCmd())
	cmd.AddCommand(spendReconcileCmd())
	cmd.AddCommand(doctorCmd())
	cmd.AddCommand(preflightCmd())
	cmd.AddCommand(delegateCmd())
	cmd.AddCommand(bootstrapCmd())
	cmd.AddCommand(auditCmd())
	cmd.AddCommand(evaluateCmd())
	cmd.AddCommand(datasetCmd())
	cmd.AddCommand(lineageCmd())
	cmd.AddCommand(labelsCmd())
	cmd.AddCommand(loginCmd())
	cmd.AddCommand(logoutCmd())
	cmd.AddCommand(keyCmd())
	cmd.AddCommand(clientConfigCmd())
	cmd.AddCommand(harnessCmd())
	cmd.AddCommand(runCmd())
	cmd.AddCommand(ciCmd())
	cmd.AddCommand(pricingCmd())
	cmd.AddCommand(pricingSyncDay0Cmd())
	cmd.AddCommand(migrateLiteLLMCmd())
	cmd.AddCommand(dlqCmd())
	cmd.AddCommand(policiesCmd())
	cmd.AddCommand(supportBundleCmd())

	// Global flags
	cmd.PersistentFlags().String("base-url", "", "Gateway base URL (default: auto-detect)")
	cmd.PersistentFlags().String("admin-url", "", "Admin base URL (default: http://localhost:8086)")
	cmd.PersistentFlags().String("api-key", "", "Yabanin API key")
	cmd.PersistentFlags().String("org", "", "Organization ID (required for keys/spend service commands)")

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, _ []string) {
			// First line stays machine-parseable (x.y[.z]); the backronym
			// tagline follows so it never breaks version probes.
			w := cmd.OutOrStdout()
			_, _ = fmt.Fprintln(w, version, "(commit", commit+")")
			_, _ = fmt.Fprintln(w, Backronym)
		},
	}
}
