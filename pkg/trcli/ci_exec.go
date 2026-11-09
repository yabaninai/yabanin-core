package trcli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/clientconfig"
	"github.com/spf13/cobra"
)

var toolOnPath = exec.LookPath

func ciExecCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec -- <command> [args]",
		Short: "Run a command with CI attribution in its environment",
		Args:  cobra.MinimumNArgs(1),
		RunE:  runCIExec,
	}
	cmd.Flags().Bool("isolate", false, "Point CLAUDE_CONFIG_DIR at an empty temporary directory")
	cmd.Flags().String("report", "yabanin-ci.json", "Report path")
	cmd.Flags().String("codex-model", "", "Model written into the temporary Codex config")
	cmd.Flags().Bool("openai-env", false, "Also set OPENAI_BASE_URL")
	cmd.Flags().String("session", "auto", "Session key mode: auto, on, or off")
	cmd.Flags().String("session-ttl", "", "Session TTL (Go duration or seconds)")
	cmd.Flags().String("gitlab-metrics", "", "OpenMetrics path for GitLab")
	cmd.Flags().String("fail-over-cost", "", "Exit 4 when cost_usd is above this amount")
	addLabelInputs(cmd)
	return cmd
}

func runCIExec(cmd *cobra.Command, args []string) error {
	plan, err := buildCIPlan(cmd, true)
	if err != nil {
		return err
	}
	parentKey := plan.Key
	mode, _ := cmd.Flags().GetString("session")
	var minted *sessionMinted
	if mode != "off" {
		minted, err = mintCISession(cmd, plan)
		if err != nil {
			if mode == "on" {
				return &cictx.ExitError{Code: 5}
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), sessionFallbackMessage(err))
		} else if minted != nil {
			plan.Key = minted.Key
			plan.SessionID = minted.ID
		}
	}
	extra := childCIEnv(plan)
	cleanup, err := applyToolOverlays(cmd, plan, extra)
	if err != nil {
		return err
	}
	defer cleanup()
	started := time.Now().UTC()
	runErr := execInherited(cmd.Context(), args[0], args[1:], extra)
	finished := time.Now().UTC()
	code := 0
	if child, ok := runErr.(*ChildExit); ok {
		code = child.Code
	} else if runErr != nil {
		return runErr
	}
	if minted != nil {
		status, exitCode := finishStatus(runErr)
		_ = finishSessionKey(cmd.Context(), plan.Gateway, parentKey, minted.ID, status, exitCode, finished.Sub(started))
	}
	path, _ := cmd.Flags().GetString("report")
	mode = "header"
	var sessionID *string
	usageKey := parentKey
	if minted != nil {
		mode = "session"
		sessionID = &minted.ID
	}
	usagePlan := plan
	usagePlan.Key = usageKey
	usage := collectCIUsage(cmd.Context(), cmd, usagePlan, mintedID(minted), started, finished)
	if err := writeCIReport(path, ciReport{
		Version:      1,
		Mode:         mode,
		Labels:       plan.Labels,
		SessionKeyID: sessionID,
		StartedAt:    started.Format(time.RFC3339),
		FinishedAt:   finished.Format(time.RFC3339),
		ExitCode:     &code,
		Usage:        usage,
		DashboardURL: dashboardURL(plan.Labels),
	}); err != nil {
		return err
	}
	if err := githubStepSummary(os.Getenv("GITHUB_STEP_SUMMARY"), usage); err != nil {
		return err
	}
	metrics, _ := cmd.Flags().GetString("gitlab-metrics")
	if err := writeOpenMetrics(metrics, usage); err != nil {
		return err
	}
	_, _ = fmt.Fprint(cmd.OutOrStdout(), usageSummary(usage))
	if limit, _ := cmd.Flags().GetString("fail-over-cost"); limit != "" {
		if err := failOverCost(limit, usage); err != nil {
			return err
		}
	}
	return runErr
}

func mintedID(minted *sessionMinted) string {
	if minted == nil {
		return ""
	}
	return minted.ID
}

func childCIEnv(plan ciPlan) map[string]string {
	extra := map[string]string{
		"YABANIN_GATEWAY_URL":      plan.Gateway,
		"YABANIN_LABELS":           plan.Encoded,
		"ANTHROPIC_BASE_URL":       plan.Gateway,
		"ANTHROPIC_CUSTOM_HEADERS": plan.Headers,
		"YABANIN_API_KEY":          plan.Key,
		"OPENAI_API_KEY":           plan.Key,
		"ANTHROPIC_AUTH_TOKEN":     plan.Key,
	}
	if plan.SessionID != "" {
		extra["YABANIN_SESSION_KEY_ID"] = plan.SessionID
	}
	if plan.OpenAI {
		extra["OPENAI_BASE_URL"] = gatewayV1(plan.Gateway)
	}
	return extra
}

func applyToolOverlays(cmd *cobra.Command, plan ciPlan, extra map[string]string) (func(), error) {
	var dirs []string
	cleanup := func() {
		for _, dir := range dirs {
			_ = os.RemoveAll(dir)
		}
	}
	if _, err := toolOnPath("codex"); err == nil {
		dir, err := os.MkdirTemp("", "yabanin-codex-")
		if err != nil {
			cleanup()
			return nil, err
		}
		dirs = append(dirs, dir)
		model, _ := cmd.Flags().GetString("codex-model")
		body := clientconfig.Codex(clientconfig.Params{
			BaseURL: plan.Gateway, Model: model, KeyMode: "env", KeyEnv: "YABANIN_API_KEY", ProviderID: "yabanin",
		}).RenderTOML()
		if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
			cleanup()
			return nil, err
		}
		extra["CODEX_HOME"] = dir
	}
	if _, err := toolOnPath("opencode"); err == nil {
		merged, err := openCodeCIContent(os.Getenv("OPENCODE_CONFIG_CONTENT"), plan)
		if err != nil {
			cleanup()
			return nil, err
		}
		extra["OPENCODE_CONFIG_CONTENT"] = merged
	}
	isolate, _ := cmd.Flags().GetBool("isolate")
	if isolate {
		dir, err := os.MkdirTemp("", "yabanin-claude-")
		if err != nil {
			cleanup()
			return nil, err
		}
		dirs = append(dirs, dir)
		extra["CLAUDE_CONFIG_DIR"] = dir
	}
	return cleanup, nil
}

func mintCISession(cmd *cobra.Command, plan ciPlan) (*sessionMinted, error) {
	_, _, _, _, profile, err := assembleLabels(cmd)
	if err != nil {
		return nil, err
	}
	ttlFlag, _ := cmd.Flags().GetString("session-ttl")
	ttl, err := sessionTTLSeconds(ttlFlag, profile)
	if err != nil {
		return nil, err
	}
	body := sessionMintBody{
		Name: sessionName(plan.Labels), TTL: ttl, Labels: plan.Labels, Lock: true,
	}
	if profile != nil {
		if profile.Session.MaxTokens > 0 {
			n := profile.Session.MaxTokens
			body.MaxTokens = &n
		}
		if profile.Session.MaxCostUSD > 0 {
			n := profile.Session.MaxCostUSD
			body.MaxCostUSD = &n
		}
	}
	minted, err := mintSessionKey(cmd.Context(), plan.Gateway, plan.Key, body)
	if err != nil {
		return nil, err
	}
	return &minted, nil
}

func sessionFallbackMessage(err error) string {
	var httpErr *sessionHTTPError
	if errorsAsHTTP(err, &httpErr) {
		switch httpErr.Status {
		case 404, 501:
			return "session keys unavailable; using header labels"
		case 403:
			return "CI key cannot mint session keys (can_mint_sessions is false); using header labels"
		}
	}
	return "session key mint failed; using header labels"
}

func errorsAsHTTP(err error, target **sessionHTTPError) bool {
	httpErr, ok := err.(*sessionHTTPError)
	if !ok {
		return false
	}
	*target = httpErr
	return true
}

func openCodeCIContent(existing string, plan ciPlan) (string, error) {
	provider := clientconfig.OpenCode(clientconfig.Params{
		BaseURL: plan.Gateway,
		KeyMode: "env",
		KeyEnv:  "YABANIN_API_KEY",
		Labels:  plan.Labels,
	}, nil)
	raw, err := json.Marshal(provider)
	if err != nil {
		return "", err
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return "", err
	}
	base := map[string]any{}
	if existing != "" {
		if err := json.Unmarshal([]byte(existing), &base); err != nil {
			return "", err
		}
	}
	deepMerge(base, map[string]any{"provider": map[string]any{"yabanin": asMap}})
	body, err := json.Marshal(base)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
