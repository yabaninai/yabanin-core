package trcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/spf13/cobra"
)

// ChildExit is a child process status that yb should use as its own exit code.
type ChildExit struct {
	Code     int
	Signaled bool
}

func (e *ChildExit) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

func runCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run <tool> -- <command> [args]",
		Short: "Run a command with dynamic attribution labels",
		Args:  cobra.MinimumNArgs(2),
		RunE:  runTool,
	}
	addLabelInputs(cmd)
	return cmd
}

func runTool(cmd *cobra.Command, args []string) error {
	tool, command, commandArgs := args[0], args[1], args[2:]
	set, _, _, err := collectLabels(cmd)
	if err != nil {
		return err
	}
	home, err := credentialHome()
	if err != nil {
		return err
	}
	set, err = addProfileLabels(home, set)
	if err != nil {
		return err
	}
	encoded := labels.Encode(set)
	extra, err := toolEnv(cmd, home, tool, encoded)
	if err != nil {
		return err
	}
	return execInherited(cmd.Context(), command, commandArgs, extra)
}

func addProfileLabels(home string, set labels.Set) (labels.Set, error) {
	cfg, err := loadConfig(home)
	if err != nil {
		return nil, err
	}
	if set == nil {
		set = labels.Set{}
	}
	for key, value := range cfg.Profiles["default"].Labels {
		if _, exists := set[key]; exists {
			continue
		}
		set[key] = value
	}
	return set, nil
}

func toolEnv(cmd *cobra.Command, home, tool, encoded string) (map[string]string, error) {
	switch tool {
	case "codex":
		return map[string]string{"YABANIN_LABELS": encoded}, nil
	case "claude-code":
		if claudeSettingsOverride(home) {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: Claude settings env.ANTHROPIC_CUSTOM_HEADERS overrides the process environment; run yb harness connect claude-code --labels-mode dynamic")
		}
		return map[string]string{"ANTHROPIC_CUSTOM_HEADERS": appendLabelHeader(os.Getenv("ANTHROPIC_CUSTOM_HEADERS"), encoded)}, nil
	case "opencode":
		merged, err := mergeOpenCodeConfig(os.Getenv("OPENCODE_CONFIG_CONTENT"), encoded)
		if err != nil {
			return nil, err
		}
		return map[string]string{"OPENCODE_CONFIG_CONTENT": merged}, nil
	default:
		return map[string]string{"YABANIN_LABELS": encoded}, nil
	}
}

func appendLabelHeader(existing, encoded string) string {
	line := "X-Yabanin-Labels: " + encoded
	if strings.TrimSpace(existing) == "" {
		return line
	}
	if strings.Contains(existing, line) {
		return existing
	}
	return existing + "\n" + line
}

func claudeSettingsOverride(home string) bool {
	body, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json")) //nolint:gosec // G304: path is the Claude settings file under the user home
	if err != nil {
		return false
	}
	var doc struct {
		Env map[string]any `json:"env"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return false
	}
	value, ok := doc.Env["ANTHROPIC_CUSTOM_HEADERS"].(string)
	return ok && strings.TrimSpace(value) != ""
}

func mergeOpenCodeConfig(existing, encoded string) (string, error) {
	patch := map[string]any{
		"provider": map[string]any{
			"yabanin": map[string]any{
				"options": map[string]any{
					"headers": map[string]any{"X-Yabanin-Labels": encoded},
				},
			},
		},
	}
	base := map[string]any{}
	if strings.TrimSpace(existing) != "" {
		if err := json.Unmarshal([]byte(existing), &base); err != nil {
			return "", fmt.Errorf("OPENCODE_CONFIG_CONTENT is not JSON: %w", err)
		}
	}
	deepMerge(base, patch)
	body, err := json.Marshal(base)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func deepMerge(dst, src map[string]any) {
	for key, value := range src {
		child, ok := value.(map[string]any)
		if !ok {
			dst[key] = value
			continue
		}
		current, ok := dst[key].(map[string]any)
		if !ok {
			dst[key] = child
			continue
		}
		deepMerge(current, child)
	}
}

func execInherited(ctx context.Context, name string, args []string, extra map[string]string) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: yb run executes the program named after --; it is not a shell
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = mergeEnv(os.Environ(), extra)
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = 3 * time.Second
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case sig := <-sigs:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(sig)
				}
			}
		}
	}()
	return childResult(cmd.Wait())
}

func childResult(err error) error {
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		child := &ChildExit{Code: exit.ExitCode()}
		if status, ok := exit.Sys().(interface{ Signaled() bool }); ok {
			child.Signaled = status.Signaled()
		}
		return child
	}
	return err
}

func mergeEnv(base []string, extra map[string]string) []string {
	skip := map[string]bool{}
	for key := range extra {
		skip[key] = true
	}
	out := make([]string, 0, len(base)+len(extra))
	for _, item := range base {
		key, _, ok := strings.Cut(item, "=")
		if ok && skip[key] {
			continue
		}
		out = append(out, item)
	}
	for key, value := range extra {
		out = append(out, key+"="+value)
	}
	return out
}
