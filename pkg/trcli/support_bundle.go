package trcli

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"runtime"

	"github.com/spf13/cobra"
)

const supportBundleCreateError = "support bundle could not be created"

var (
	supportBundleVersionPattern = regexp.MustCompile(`^yb [0-9]+(?:\.[0-9]+)*$`)
	supportBundleCommitPattern  = regexp.MustCompile(`^[a-fA-F0-9]{7,40}$`)
)

type supportBundle struct {
	SchemaVersion int                  `json:"schema_version"`
	Build         supportBundleBuild   `json:"build"`
	Runtime       supportBundleRuntime `json:"runtime"`
	LocalConfig   supportBundleConfig  `json:"local_config"`
}

type supportBundleBuild struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type supportBundleRuntime struct {
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

type supportBundleConfig struct {
	CLIProfileFilePresent bool `json:"cli_profile_file_present"`
	GatewayURLEnvSet      bool `json:"gateway_url_env_set"`
	AdminURLEnvSet        bool `json:"admin_url_env_set"`
	APIKeyEnvSet          bool `json:"api_key_env_set"`
}

func supportBundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "support-bundle",
		Short:        "Preview or create a local support diagnostics bundle",
		SilenceUsage: true,
	}
	cmd.AddCommand(supportBundlePreviewCmd())
	cmd.AddCommand(supportBundleCreateCmd())
	cmd.AddCommand(supportBundleDiagnosticsCmd())
	return cmd
}

func supportBundlePreviewCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "preview",
		Short:        "Print the local support bundle without writing a file",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			payload, err := collectSupportBundle()
			if err != nil {
				return err
			}
			return writeSupportBundle(cmd.OutOrStdout(), payload)
		},
	}
}

func supportBundleCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "create",
		Short:        "Create a local support bundle file",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, _ := cmd.Flags().GetString("output")
			if path == "" {
				return errors.New("--output is required")
			}
			payload, err := collectSupportBundle()
			if err != nil {
				return err
			}
			data, err := marshalSupportBundle(payload)
			if err != nil {
				return errors.New(supportBundleCreateError)
			}
			// #nosec G304 -- The operator selects this output path; O_EXCL prevents replacing an existing file or symlink, and permissions are fixed to 0600.
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return errors.New(supportBundleCreateError)
			}
			if n, err := file.Write(data); err != nil || n != len(data) {
				_ = file.Close()
				return errors.New(supportBundleCreateError)
			}
			if err := file.Close(); err != nil {
				return errors.New(supportBundleCreateError)
			}
			if n, err := cmd.OutOrStdout().Write(data); err != nil || n != len(data) {
				return errors.New(supportBundleCreateError)
			}
			return nil
		},
	}
	cmd.Flags().String("output", "", "Path for the newly created local bundle file")
	return cmd
}

func collectSupportBundle() (supportBundle, error) {
	home, err := credentialHome()
	if err != nil {
		return supportBundle{}, errors.New("support bundle metadata unavailable")
	}
	profilePresent, err := supportProfilePresent(configPath(home))
	if err != nil {
		return supportBundle{}, errors.New("support bundle metadata unavailable")
	}
	return supportBundle{
		SchemaVersion: 1,
		Build: supportBundleBuild{
			Version: safeSupportVersion(version),
			Commit:  safeSupportCommit(commit),
		},
		Runtime: supportBundleRuntime{
			GoVersion: runtime.Version(),
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
		},
		LocalConfig: supportBundleConfig{
			CLIProfileFilePresent: profilePresent,
			GatewayURLEnvSet:      supportEnvSet("YABANIN_GATEWAY_URL"),
			AdminURLEnvSet:        supportEnvSet("YABANIN_ADMIN_URL"),
			APIKeyEnvSet:          supportEnvSet("YABANIN_API_KEY"),
		},
	}, nil
}

func supportProfilePresent(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, errors.New("support bundle metadata unavailable")
}

func supportEnvSet(name string) bool {
	value, ok := os.LookupEnv(name)
	return ok && value != ""
}

func safeSupportVersion(value string) string {
	if supportBundleVersionPattern.MatchString(value) {
		return value
	}
	return "unknown"
}

func safeSupportCommit(value string) string {
	if supportBundleCommitPattern.MatchString(value) {
		return value
	}
	return "unknown"
}

func marshalSupportBundle(payload supportBundle) ([]byte, error) {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func writeSupportBundle(w io.Writer, payload supportBundle) error {
	data, err := marshalSupportBundle(payload)
	if err != nil {
		return errors.New(supportBundleCreateError)
	}
	if n, err := w.Write(data); err != nil || n != len(data) {
		return errors.New(supportBundleCreateError)
	}
	return nil
}
