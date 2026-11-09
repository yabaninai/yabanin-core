package trcli

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/reireirei/yabanin/pkg/clientconfig"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/spf13/cobra"
)

var repoPattern = regexp.MustCompile(`^[A-Za-z0-9._/@:-]{1,200}$`)

func clientConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client-config",
		Short: "Print a client configuration that points at the gateway",
		RunE: func(cmd *cobra.Command, _ []string) error {
			text, err := renderClientConfig(cmd)
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), text)
			return err
		},
	}
	cmd.Flags().String("client", "", "codex, claude-code, opencode, continue, cline, or aider")
	cmd.Flags().String("base-url", "", "Gateway base URL")
	cmd.Flags().String("key-env", "YABANIN_API_KEY", "Environment variable that holds the API key")
	cmd.Flags().String("key-mode", "env", "env or helper")
	cmd.Flags().String("model", "", "Model id")
	cmd.Flags().String("autocomplete-model", "", "Autocomplete model id")
	cmd.Flags().String("repo", "", "git.repo label")
	cmd.Flags().StringArray("label", nil, "label k=v (repeatable)")
	cmd.Flags().String("models", "", "Comma-separated model ids for OpenCode")
	return cmd
}

func renderClientConfig(cmd *cobra.Command) (string, error) {
	client, _ := cmd.Flags().GetString("client")
	base, _ := cmd.Flags().GetString("base-url")
	if strings.TrimSpace(base) == "" {
		base, _ = cmd.Flags().GetString("gateway-url")
	}
	if strings.TrimSpace(client) == "" || strings.TrimSpace(base) == "" {
		return "", fmt.Errorf("--client and --base-url are required")
	}
	keyEnv, _ := cmd.Flags().GetString("key-env")
	keyMode, _ := cmd.Flags().GetString("key-mode")
	if keyMode != "env" && keyMode != "helper" {
		return "", fmt.Errorf("--key-mode must be env or helper")
	}
	model, _ := cmd.Flags().GetString("model")
	auto, _ := cmd.Flags().GetString("autocomplete-model")
	repo, _ := cmd.Flags().GetString("repo")
	rawLabels, _ := cmd.Flags().GetStringArray("label")
	modelList, _ := cmd.Flags().GetString("models")
	set, err := parseClientLabels(rawLabels, repo)
	if err != nil {
		return "", err
	}
	params := clientconfig.Params{
		BaseURL:           base,
		KeyEnv:            keyEnv,
		Model:             model,
		AutocompleteModel: auto,
		Labels:            set,
		KeyMode:           keyMode,
		ProviderID:        "yabanin",
	}
	switch client {
	case "codex":
		return clientconfig.Codex(params).RenderTOML(), nil
	case "claude-code":
		settings := clientconfig.ClaudeCode(params)
		if keyMode == "env" {
			return settings.RenderEnv(), nil
		}
		return settings.RenderJSON(), nil
	case "opencode":
		return clientconfig.OpenCode(params, splitModels(modelList)).RenderJSON(), nil
	case "continue":
		return clientconfig.Continue(params).RenderYAML(), nil
	case "cline":
		return clientconfig.Cline(params), nil
	case "aider":
		cfg := clientconfig.Aider(params)
		return cfg.RenderYAML() + cfg.RenderEnv(), nil
	default:
		return "", fmt.Errorf("unknown client %q", client)
	}
}

func parseClientLabels(raw []string, repo string) (labels.Set, error) {
	set := labels.Set{}
	for _, item := range raw {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("label %q must be key=value", item)
		}
		norm, keyOK := labels.NormalizeKey(key)
		if !keyOK {
			return nil, fmt.Errorf("invalid label key %q", key)
		}
		val, reason := labels.NormalizeValue(value)
		if reason != "" {
			return nil, fmt.Errorf("invalid label %s: %s", norm, reason)
		}
		set[norm] = val
	}
	if repo == "" {
		return set, nil
	}
	if !repoPattern.MatchString(repo) {
		return nil, fmt.Errorf("invalid repo %q", repo)
	}
	set["git.repo"] = repo
	return set, nil
}

func splitModels(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
