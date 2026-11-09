package license

import (
	"fmt"

	"github.com/spf13/cobra"
)

// AddLicenseCommands registers offline license verification commands.
func AddLicenseCommands(root *cobra.Command) {
	licenseCmd := &cobra.Command{
		Use:   "license",
		Short: "Verify an offline license",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	// ---- verify ----
	var (
		licenseFile      string
		rootPubHex       string
		crlPath          string
		intermediateCert string // --intermediate-cert flag to override env var default
	)
	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a license token end-to-end",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := verifyLicenseChainInternal(licenseFile, rootPubHex, crlPath, intermediateCert); err != nil {
				return fmt.Errorf("verification failed: %w", err)
			}
			fmt.Println("LICENSE VALID")
			return nil
		},
	}
	verifyCmd.Flags().StringVar(&licenseFile, "license-file", "",
		"License token JSON file (required)")
	_ = verifyCmd.MarkFlagRequired("license-file")
	verifyCmd.Flags().StringVar(&rootPubHex, "root-pubkey", "",
		"Root public key (hex, 64 chars)")
	_ = verifyCmd.MarkFlagRequired("root-pubkey")
	verifyCmd.Flags().StringVar(&crlPath, "crl-file", "",
		"CRL JSON file (optional — no revocation check if omitted)")
	verifyCmd.Flags().StringVar(&intermediateCert, "intermediate-cert", "",
		"Override default intermediate cert path (env: YABANIN_LICENSE_INTERMEDIATE_CERT)")
	licenseCmd.AddCommand(verifyCmd)

	root.AddCommand(licenseCmd)
}
