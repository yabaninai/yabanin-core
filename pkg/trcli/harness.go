package trcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/harness"
	"github.com/reireirei/yabanin/pkg/harness/adapters"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func harnessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "harness",
		Short: "Connect client tools to the gateway",
	}
	cmd.AddCommand(harnessListCmd(), harnessConnectCmd(), harnessDisconnectCmd(), harnessStatusCmd(), harnessDoctorCmd(), harnessKeyCmd())
	return cmd
}

func harnessListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List client tools and whether they are connected",
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := credentialHome()
			if err != nil {
				return err
			}
			eng := &harness.Engine{Home: home}
			status, err := eng.Status()
			if err != nil {
				return err
			}
			drift := map[string]harness.ToolStatus{}
			for _, item := range status {
				drift[item.Tool] = item
			}
			w := cmd.OutOrStdout()
			_, _ = fmt.Fprintln(w, "tool\tsupport\tinstalled\tversion\tconfig\tstate")
			for _, adapter := range adapters.All() {
				supported, reason := adapter.Supported()
				support := "yes"
				state := "not connected"
				if !supported {
					support = "no"
					state = reason
				}
				det := adapter.Detect(home, toolRunner{})
				version := det.Version
				if version == "" {
					version = "-"
				}
				installed := "no"
				if det.Installed {
					installed = "yes"
				}
				if supported {
					if item, ok := drift[adapter.ID()]; ok && item.Drift {
						state = "drift"
					} else if det.Connected || (drift[adapter.ID()].Status == "applied") {
						state = "connected"
					}
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", adapter.ID(), support, installed, version, det.ConfigPath, state)
			}
			return nil
		},
	}
}

func harnessConnectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connect [<tool>]",
		Short: "Plan and apply a tool connection",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runHarnessConnect,
	}
	cmd.Flags().Bool("all", false, "Connect every supported tool")
	cmd.Flags().String("gateway-url", "", "Gateway base URL")
	cmd.Flags().String("labels-mode", "", "static, dynamic, or none")
	cmd.Flags().StringArray("label", nil, "Static label k=v")
	cmd.Flags().String("model", "", "Model id")
	cmd.Flags().Bool("set-default", false, "Make the gateway model the tool default")
	cmd.Flags().Bool("dry-run", false, "Print the diff and do not write files")
	cmd.Flags().Bool("force", false, "Replace an existing helper and continue when an endpoint is missing")
	cmd.Flags().Bool("experimental", false, "Allow continue and aider")
	cmd.Flags().Bool("global-env", false, "Export global OPENAI_* and ANTHROPIC_* from the shell block")
	cmd.Flags().Bool("yes", false, "Apply without a confirmation prompt")
	cmd.Flags().Bool("session", false, "Remember session mode for this tool")
	cmd.Flags().String("session-ttl", "", "Session TTL stored for the tool (for example 8h)")
	return cmd
}

func runHarnessConnect(cmd *cobra.Command, args []string) error {
	home, err := credentialHome()
	if err != nil {
		return err
	}
	ids, err := selectedTools(cmd, args)
	if err != nil {
		return err
	}
	params, err := buildConnectParams(cmd, home)
	if err != nil {
		return err
	}
	force, _ := cmd.Flags().GetBool("force")
	if err := probeTools(cmd.Context(), params.GatewayURL, ids, force); err != nil {
		return err
	}
	var plans []harness.Plan
	w := cmd.OutOrStdout()
	for _, id := range ids {
		adapter, ok := adapters.ByID(id)
		if !ok {
			return fmt.Errorf("unknown tool %s", id)
		}
		if supported, reason := adapter.Supported(); !supported {
			return fmt.Errorf("%s: %s", id, reason)
		}
		plan, err := adapter.Plan(home, params)
		if err != nil {
			return err
		}
		for _, warning := range plan.Warnings {
			_, _ = fmt.Fprintln(w, "warning:", warning)
		}
		for _, change := range plan.Changes {
			_, _ = fmt.Fprint(w, harness.Diff(change.Path, change.Before, change.After))
		}
		if len(plan.Changes) == 0 {
			_, _ = fmt.Fprintln(w, id+": already connected")
		}
		plans = append(plans, plan)
	}
	dry, _ := cmd.Flags().GetBool("dry-run")
	if dry {
		return nil
	}
	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		if err := confirmApply(cmd); err != nil {
			return err
		}
	}
	eng := &harness.Engine{Home: home, Version: version}
	for _, plan := range plans {
		if len(plan.Changes) == 0 {
			continue
		}
		if _, err := eng.Apply(plan); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(w, "check: yb harness doctor %s\nundo: yb harness disconnect %s\n", plan.Tool, plan.Tool)
	}
	if session, _ := cmd.Flags().GetBool("session"); session {
		ttl, _ := cmd.Flags().GetString("session-ttl")
		if err := saveHarnessSession(home, ids, ttl); err != nil {
			return err
		}
	}
	return nil
}

func harnessDisconnectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disconnect [<tool>]",
		Short: "Roll back a tool connection",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := credentialHome()
			if err != nil {
				return err
			}
			ids, err := selectedTools(cmd, args)
			if err != nil {
				return err
			}
			yes, _ := cmd.Flags().GetBool("yes")
			all, _ := cmd.Flags().GetBool("all")
			if !yes {
				if err := confirmApply(cmd); err != nil {
					return err
				}
			}
			eng := &harness.Engine{Home: home}
			w := cmd.OutOrStdout()
			for _, id := range ids {
				adapter, ok := adapters.ByID(id)
				if !ok {
					return fmt.Errorf("unknown tool %s", id)
				}
				report, err := eng.Rollback(id, adapter.Unapply)
				if err != nil {
					if all && strings.Contains(err.Error(), "no applied transaction") {
						continue
					}
					return err
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\n", report.Tool, report.Status)
				for _, file := range report.Files {
					_, _ = fmt.Fprintf(w, "%s\t%s\n", file.Path, file.Action)
				}
			}
			return nil
		},
	}
	cmd.Flags().Bool("all", false, "Disconnect every supported tool")
	cmd.Flags().Bool("yes", false, "Roll back without a confirmation prompt")
	return cmd
}

func harnessStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show harness transactions and drift",
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := credentialHome()
			if err != nil {
				return err
			}
			status, err := (&harness.Engine{Home: home}).Status()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if len(status) == 0 {
				_, _ = fmt.Fprintln(w, "no harness transactions")
				return nil
			}
			for _, item := range status {
				drift := "no"
				if item.Drift {
					drift = "yes"
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\tdrift=%s\n", item.Tool, item.Status, drift)
			}
			return nil
		},
	}
}

func harnessDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor [<tool>]",
		Short: "Check a tool connection without printing the API key",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runHarnessDoctor,
	}
	cmd.Flags().String("gateway-url", "", "Gateway base URL")
	return cmd
}

func runHarnessDoctor(cmd *cobra.Command, args []string) error {
	home, err := credentialHome()
	if err != nil {
		return err
	}
	params, err := buildConnectParams(cmd, home)
	if err != nil {
		return err
	}
	var problems []string
	key, err := lookupAPIKey(cmd.Context(), "default")
	if err != nil || key == "" {
		problems = append(problems, "API key is missing")
	}
	if (cictx.OSEnv{}).Getenv("ANTHROPIC_API_KEY") != "" {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "warning: ANTHROPIC_API_KEY is set and can override the helper")
	}
	ids := supportedIDs()
	if len(args) == 1 {
		ids = []string{args[0]}
	}
	if err := probeTools(cmd.Context(), params.GatewayURL, ids, false); err != nil {
		problems = append(problems, err.Error())
	}
	for _, id := range ids {
		adapter, ok := adapters.ByID(id)
		if !ok {
			problems = append(problems, "unknown tool "+id)
			continue
		}
		if supported, reason := adapter.Supported(); !supported {
			problems = append(problems, id+": "+reason)
			continue
		}
		det := adapter.Detect(home, toolRunner{})
		if det.ConfigPath == "" {
			continue
		}
		if err := configParses(id, det.ConfigPath); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "ok")
	return nil
}

func harnessKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Print the API key for a tool helper",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tool, _ := cmd.Flags().GetString("tool")
			if _, ok := adapters.ByID(tool); !ok {
				return fmt.Errorf("unknown tool %s", tool)
			}
			key, err := harnessKey(cmd, tool)
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), key)
			return err
		},
	}
	cmd.Flags().String("tool", "", "Tool id")
	if err := cmd.MarkFlagRequired("tool"); err != nil {
		panic(err)
	}
	return cmd
}

func selectedTools(cmd *cobra.Command, args []string) ([]string, error) {
	all, _ := cmd.Flags().GetBool("all")
	if all && len(args) > 0 {
		return nil, errors.New("pass either a tool or --all")
	}
	if all {
		return supportedIDs(), nil
	}
	if len(args) != 1 {
		return nil, errors.New("pass a tool or --all")
	}
	return []string{args[0]}, nil
}

func supportedIDs() []string {
	var ids []string
	for _, adapter := range adapters.All() {
		if ok, _ := adapter.Supported(); ok {
			ids = append(ids, adapter.ID())
		}
	}
	return ids
}

func buildConnectParams(cmd *cobra.Command, home string) (adapters.ConnectParams, error) {
	flagURL, _ := cmd.Flags().GetString("gateway-url")
	cfg, err := loadConfig(home)
	if err != nil {
		return adapters.ConnectParams{}, err
	}
	profile := cfg.Profiles["default"]
	base := strings.TrimSpace(flagURL)
	if base == "" {
		base = GatewayURL(profile.GatewayURL)
	}
	if base == "" {
		return adapters.ConnectParams{}, errors.New("gateway url required")
	}
	mode, _ := cmd.Flags().GetString("labels-mode")
	if mode == "" {
		mode = "none"
		if len(profile.Labels) > 0 {
			mode = "static"
		}
	}
	switch mode {
	case "static", "dynamic", "none":
	default:
		return adapters.ConnectParams{}, fmt.Errorf("unknown labels mode %s", mode)
	}
	var static labels.Set
	if mode == "static" {
		static = labels.Set{}
		for key, value := range profile.Labels {
			static[key] = value
		}
	}
	if cmd.Flags().Lookup("label") != nil {
		pairs, _ := cmd.Flags().GetStringArray("label")
		for _, pair := range pairs {
			key, value, ok := strings.Cut(pair, "=")
			if !ok || key == "" {
				return adapters.ConnectParams{}, fmt.Errorf("label must be k=v, got %q", pair)
			}
			if static == nil {
				static = labels.Set{}
			}
			static[key] = value
			if mode == "none" {
				mode = "static"
			}
		}
	}
	model, _ := cmd.Flags().GetString("model")
	setDefault, _ := cmd.Flags().GetBool("set-default")
	experimental, _ := cmd.Flags().GetBool("experimental")
	globalEnv, _ := cmd.Flags().GetBool("global-env")
	force, _ := cmd.Flags().GetBool("force")
	models, err := fetchModels(cmd.Context(), base)
	if err != nil {
		return adapters.ConnectParams{}, err
	}
	return adapters.ConnectParams{
		GatewayURL:   base,
		LabelsMode:   mode,
		StaticLabels: static,
		Model:        model,
		SetDefault:   setDefault,
		Force:        force,
		Experimental: experimental,
		GlobalEnv:    globalEnv,
		Models:       models,
	}, nil
}

func fetchModels(ctx context.Context, base string) ([]string, error) {
	key, err := lookupAPIKey(ctx, "default")
	if err != nil {
		return nil, err
	}
	status, body, err := probeRequest(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/v1/models", key, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, errors.New("шлюз ещё не поддерживает эндпоинт /v1/models (карточки RM-20/RM-25)")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("gateway returned %d", status)
	}
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	var ids []string
	for _, item := range payload.Data {
		if item.ID != "" {
			ids = append(ids, item.ID)
		}
	}
	return ids, nil
}

func probeTools(ctx context.Context, base string, ids []string, force bool) error {
	key, err := lookupAPIKey(ctx, "default")
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	checks := []struct {
		tool string
		path string
	}{}
	if want["codex"] {
		checks = append(checks, struct {
			tool string
			path string
		}{"codex", "/v1/responses"})
	}
	if want["claude-code"] {
		checks = append(checks, struct {
			tool string
			path string
		}{"claude-code", "/v1/messages"})
	}
	for _, check := range checks {
		status, _, err := probeRequest(ctx, http.MethodPost, strings.TrimRight(base, "/")+check.path, key, []byte("{}"))
		if err != nil {
			return err
		}
		if status == http.StatusUnauthorized {
			return errors.New("invalid API key")
		}
		if status == http.StatusNotFound && !force {
			return fmt.Errorf("шлюз ещё не поддерживает эндпоинт %s (карточки RM-20/RM-25)", check.path)
		}
	}
	return nil
}

func probeRequest(ctx context.Context, method, endpoint, key string, body []byte) (int, []byte, error) {
	if ctx == nil {
		return 0, nil, errors.New("nil context")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, payload, nil
}

func confirmApply(cmd *cobra.Command) error {
	in := cmd.InOrStdin()
	file, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return errors.New("not a terminal; pass --yes")
	}
	_, _ = fmt.Fprint(cmd.OutOrStdout(), "Apply these changes? [y/N] ")
	var answer string
	if _, err := fmt.Fscanln(file, &answer); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return nil
	default:
		return errors.New("aborted")
	}
}

func lookupAPIKey(ctx context.Context, name string) (string, error) {
	if ctx == nil {
		return "", errors.New("nil context")
	}
	if key := (cictx.OSEnv{}).Getenv("YABANIN_API_KEY"); key != "" {
		return key, nil
	}
	home, err := credentialHome()
	if err != nil {
		return "", err
	}
	store, err := credentialOpen(home)
	if err != nil {
		return "", err
	}
	return store.Get(ctx, name)
}

func configParses(id, path string) error {
	body, err := os.ReadFile(path) //nolint:gosec // G304: path is the tool config under the user home
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	switch id {
	case "claude-code", "opencode":
		if !json.Valid(body) {
			return fmt.Errorf("%s is not JSON", path)
		}
	case "codex":
		var doc map[string]any
		if err := toml.Unmarshal(body, &doc); err != nil {
			return err
		}
	}
	return nil
}

type toolRunner struct{}

func (toolRunner) Run(ctx context.Context, dir string, _ []byte, name string, args ...string) (string, error) {
	if ctx == nil {
		return "", errors.New("nil context")
	}
	var cmd *exec.Cmd
	switch name {
	case "codex":
		cmd = exec.CommandContext(ctx, "codex", args...) //nolint:gosec // G204: executable is the literal codex binary; args are the adapter's fixed version probe
	default:
		return "", errors.New("no version probe for " + name)
	}
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
