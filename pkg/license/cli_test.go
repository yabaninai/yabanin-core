package license

import (
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func verificationCLI(args ...string) *cobra.Command {
	root := &cobra.Command{Use: "yabanin", SilenceErrors: true, SilenceUsage: true}
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	AddLicenseCommands(root)
	root.SetArgs(args)
	return root
}

func TestLicenseCLIRejectsIssuance(t *testing.T) {
	for _, command := range []string{"gen-root", "issue-intermediate", "issue"} {
		t.Run(command, func(t *testing.T) {
			root := verificationCLI("license", command)
			group, _, err := root.Find([]string{"license"})
			require.NoError(t, err)
			for _, child := range group.Commands() {
				require.NotEqual(t, command, child.Name(), "issuance must not be registered")
			}
			require.ErrorContains(t, root.Execute(), "unknown command")
		})
	}
}

func TestLicenseCLIVerifiesAndRejectsTampering(t *testing.T) {
	path, rootKey, crl, token := offlineChain(t, 24*time.Hour, time.Hour)
	args := []string{"license", "verify", "--license-file", path, "--root-pubkey", rootKey, "--crl-file", crl}
	require.NoError(t, verificationCLI(args...).Execute())
	token.CustomerID = "modified-customer"
	modified, err := json.Marshal(token)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, modified, 0o600))
	require.ErrorContains(t, verificationCLI(args...).Execute(), "license signature invalid")
}
