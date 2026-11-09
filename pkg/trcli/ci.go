package trcli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/spf13/cobra"
)

func ciCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Apply CI attribution in header mode",
	}
	cmd.PersistentFlags().String("key-env", "YABANIN_CI_KEY", "Environment variable that holds the CI API key")
	cmd.AddCommand(ciEnvCmd(), ciExecCmd(), ciFinishCmd(), ciReportCmd())
	return cmd
}

func ciEnvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Print CI attribution variables",
		RunE: func(cmd *cobra.Command, _ []string) error {
			plan, err := buildCIPlan(cmd, false)
			if err != nil {
				return err
			}
			format, _ := cmd.Flags().GetString("format")
			withKey, _ := cmd.Flags().GetBool("with-key")
			allow, _ := cmd.Flags().GetBool("allow-secret-dotenv")
			session, _ := cmd.Flags().GetBool("session")
			if withKey || session {
				if err := requireCIKey(cmd, plan); err != nil {
					return err
				}
			}
			if session {
				minted, err := mintCISession(cmd, plan)
				if err != nil {
					return err
				}
				plan.Key = minted.Key
				plan.SessionID = minted.ID
				withKey = true
			}
			if format == "gitlab-dotenv" && withKey && !allow {
				return errors.New("gitlab-dotenv must not contain secrets; use yb ci exec or pass --allow-secret-dotenv")
			}
			text, err := formatCIEnv(format, plan, withKey)
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), text)
			return err
		},
	}
	cmd.Flags().String("format", "shell", "shell, github, gitlab-dotenv, or json")
	cmd.Flags().Bool("with-key", false, "Include the CI API key")
	cmd.Flags().Bool("session", false, "Mint a session key and print it")
	cmd.Flags().String("session-ttl", "", "Session TTL (Go duration or seconds)")
	cmd.Flags().Bool("allow-secret-dotenv", false, "Allow secrets in gitlab-dotenv output")
	cmd.Flags().Bool("openai-env", false, "Also set OPENAI_BASE_URL")
	addLabelInputs(cmd)
	return cmd
}

func ciReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Write a pipeline usage report",
		RunE: func(cmd *cobra.Command, _ []string) error {
			plan, err := buildCIPlan(cmd, true)
			if err != nil {
				return err
			}
			sinceFlag, _ := cmd.Flags().GetString("since")
			since, err := pipelineSince(sinceFlag)
			if err != nil {
				return err
			}
			group, _ := cmd.Flags().GetString("group-by")
			usage, err := fetchPipelineUsage(cmd.Context(), plan, since, group)
			if errors.Is(err, errUsageDenied) {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "CI key cannot read usage; enable can_read_usage on the key")
				usage = nil
			} else if err != nil {
				return err
			}
			out, _ := cmd.Flags().GetString("out")
			if err := writeCIReport(out, ciReport{
				Version: 1, Mode: "header", Labels: plan.Labels, Usage: usage,
				StartedAt: since.Format(time.RFC3339), FinishedAt: ciNow().UTC().Format(time.RFC3339),
				DashboardURL: dashboardURL(plan.Labels),
			}); err != nil {
				return err
			}
			metrics, _ := cmd.Flags().GetString("gitlab-metrics")
			if err := writeOpenMetrics(metrics, usage); err != nil {
				return err
			}
			_, _ = fmt.Fprint(cmd.OutOrStdout(), usageSummary(usage))
			limit, _ := cmd.Flags().GetString("fail-over-cost")
			return failOverCost(limit, usage)
		},
	}
	cmd.Flags().Bool("pipeline", true, "Report the current pipeline")
	cmd.Flags().String("since", "24h", "Lookback window, or CI_PIPELINE_CREATED_AT on GitLab")
	cmd.Flags().String("group-by", "label:ci.job_name", "group_by for the usage request")
	cmd.Flags().String("out", "yabanin-pipeline.json", "Report path")
	cmd.Flags().String("gitlab-metrics", "", "OpenMetrics path for GitLab")
	cmd.Flags().String("fail-over-cost", "", "Exit 4 when cost_usd is above this amount")
	addLabelInputs(cmd)
	return cmd
}

func ciFinishCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "finish",
		Short: "Write a CI attribution report",
		RunE: func(cmd *cobra.Command, _ []string) error {
			plan, err := buildCIPlan(cmd, false)
			if err != nil {
				return err
			}
			if id, _ := cmd.Flags().GetString("session-id"); id != "" {
				status, _ := cmd.Flags().GetString("status")
				switch status {
				case "success", "failed", "canceled":
				default:
					return fmt.Errorf("status must be success, failed, or canceled")
				}
				if err := requireCIKey(cmd, plan); err != nil {
					return err
				}
				code := 0
				if status != "success" {
					code = 1
				}
				if err := finishSessionKey(cmd.Context(), plan.Gateway, plan.Key, id, status, code, 0); err != nil {
					return err
				}
			}
			path, _ := cmd.Flags().GetString("report")
			now := time.Now().UTC()
			return writeCIReport(path, ciReport{
				Labels:     plan.Labels,
				StartedAt:  now.Format(time.RFC3339),
				FinishedAt: now.Format(time.RFC3339),
				Usage:      nil,
			})
		},
	}
	cmd.Flags().String("report", "yabanin-ci.json", "Report path")
	cmd.Flags().String("session-id", "", "Session key id to finish")
	cmd.Flags().String("status", "", "success, failed, or canceled")
	addLabelInputs(cmd)
	return cmd
}

type ciPlan struct {
	Gateway   string
	Key       string
	Labels    labels.Set
	Encoded   string
	Headers   string
	OpenAI    bool
	SessionID string
}

type ciReport struct {
	Version      int        `json:"version"`
	Mode         string     `json:"mode"`
	Labels       labels.Set `json:"labels"`
	SessionKeyID *string    `json:"session_key_id"`
	StartedAt    string     `json:"started_at"`
	FinishedAt   string     `json:"finished_at"`
	ExitCode     *int       `json:"exit_code"`
	Usage        *ciUsage   `json:"usage"`
	DashboardURL string     `json:"dashboard_url,omitempty"`
}

func buildCIPlan(cmd *cobra.Command, needKey bool) (ciPlan, error) {
	set, _, _, err := collectLabels(cmd)
	if err != nil {
		return ciPlan{}, err
	}
	if set == nil {
		set = labels.Set{}
	}
	gateway := strings.TrimRight(strings.TrimSpace(os.Getenv("YABANIN_GATEWAY_URL")), "/")
	if gateway == "" {
		return ciPlan{}, errors.New("YABANIN_GATEWAY_URL is required")
	}
	key, err := lookupCIKey(cmd)
	if err != nil {
		return ciPlan{}, err
	}
	if needKey && key == "" {
		name, _ := cmd.Flags().GetString("key-env")
		return ciPlan{}, fmt.Errorf("%s is required", name)
	}
	openai := false
	if cmd.Flags().Lookup("openai-env") != nil {
		openai, _ = cmd.Flags().GetBool("openai-env")
	}
	encoded := labels.Encode(set)
	return ciPlan{
		Gateway: gateway,
		Key:     key,
		Labels:  set,
		Encoded: encoded,
		Headers: appendLabelHeader(os.Getenv("ANTHROPIC_CUSTOM_HEADERS"), encoded),
		OpenAI:  openai,
	}, nil
}

func lookupCIKey(cmd *cobra.Command) (string, error) {
	name, err := cmd.Flags().GetString("key-env")
	if err != nil || name == "" {
		name = "YABANIN_CI_KEY"
	}
	return os.Getenv(name), nil
}

func requireCIKey(cmd *cobra.Command, plan ciPlan) error {
	if plan.Key != "" {
		return nil
	}
	name, _ := cmd.Flags().GetString("key-env")
	if name == "" {
		name = "YABANIN_CI_KEY"
	}
	return fmt.Errorf("%s is required", name)
}

func formatCIEnv(format string, plan ciPlan, withKey bool) (string, error) {
	switch format {
	case "", "shell":
		return shellCIEnv(plan, withKey), nil
	case "github":
		return githubCIEnv(plan, withKey), nil
	case "gitlab-dotenv":
		return dotenvCIEnv(plan, withKey), nil
	case "json":
		body, err := json.MarshalIndent(ciEnvMap(plan, withKey), "", "  ")
		if err != nil {
			return "", err
		}
		return string(body) + "\n", nil
	default:
		return "", fmt.Errorf("unknown format %q", format)
	}
}

func ciEnvMap(plan ciPlan, withKey bool) map[string]string {
	out := map[string]string{
		"YABANIN_GATEWAY_URL":      plan.Gateway,
		"YABANIN_LABELS":           plan.Encoded,
		"ANTHROPIC_BASE_URL":       plan.Gateway,
		"ANTHROPIC_CUSTOM_HEADERS": plan.Headers,
	}
	if plan.OpenAI {
		out["OPENAI_BASE_URL"] = gatewayV1(plan.Gateway)
	}
	if withKey {
		out["OPENAI_API_KEY"] = plan.Key
		out["ANTHROPIC_AUTH_TOKEN"] = plan.Key
		out["YABANIN_API_KEY"] = plan.Key
	}
	if plan.SessionID != "" {
		out["YABANIN_SESSION_KEY_ID"] = plan.SessionID
	}
	return out
}

func shellCIEnv(plan ciPlan, withKey bool) string {
	var b strings.Builder
	for _, item := range orderedCIVars(plan, withKey) {
		fmt.Fprintf(&b, "export %s=%s\n", item.name, shellQuote(item.value))
	}
	return b.String()
}

func dotenvCIEnv(plan ciPlan, withKey bool) string {
	var b strings.Builder
	for _, item := range orderedCIVars(plan, withKey) {
		fmt.Fprintf(&b, "%s=%s\n", item.name, item.value)
	}
	return b.String()
}

func githubCIEnv(plan ciPlan, withKey bool) string {
	var b strings.Builder
	for _, item := range orderedCIVars(plan, withKey) {
		if item.secret {
			fmt.Fprintf(&b, "::add-mask::%s\n", item.value)
		}
		if strings.Contains(item.value, "\n") {
			delim := "EOF_" + randomToken()
			fmt.Fprintf(&b, "%s<<%s\n%s\n%s\n", item.name, delim, item.value, delim)
			continue
		}
		fmt.Fprintf(&b, "%s=%s\n", item.name, item.value)
	}
	return b.String()
}

type ciVar struct {
	name   string
	value  string
	secret bool
}

func orderedCIVars(plan ciPlan, withKey bool) []ciVar {
	vars := []ciVar{
		{name: "YABANIN_GATEWAY_URL", value: plan.Gateway},
		{name: "YABANIN_LABELS", value: plan.Encoded},
		{name: "ANTHROPIC_BASE_URL", value: plan.Gateway},
		{name: "ANTHROPIC_CUSTOM_HEADERS", value: plan.Headers},
	}
	if plan.OpenAI {
		vars = append(vars, ciVar{name: "OPENAI_BASE_URL", value: gatewayV1(plan.Gateway)})
	}
	if withKey {
		for _, name := range []string{"OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN", "YABANIN_API_KEY"} {
			vars = append(vars, ciVar{name: name, value: plan.Key, secret: true})
		}
	}
	if plan.SessionID != "" {
		vars = append(vars, ciVar{name: "YABANIN_SESSION_KEY_ID", value: plan.SessionID})
	}
	return vars
}

func gatewayV1(base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.HasSuffix(base, "/v1") {
		return base
	}
	return base + "/v1"
}

func randomToken() string {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

func writeCIReport(path string, report ciReport) error {
	if report.Version == 0 {
		report.Version = 1
	}
	if report.Mode == "" {
		report.Mode = "header"
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return os.WriteFile(path, body, 0o600)
}
