package trcli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/spf13/cobra"
)

func labelsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "labels",
		Short: "Show client attribution labels",
	}
	cmd.AddCommand(labelsShowCmd(), labelsExplainCmd())
	return cmd
}

func labelsShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print labels for the current directory",
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, _ := cmd.Flags().GetString("format")
			set, _, _, err := collectLabels(cmd)
			if err != nil {
				return err
			}
			text, err := formatLabels(format, set)
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), text)
			return err
		},
	}
	cmd.Flags().String("format", "header", "header, json, env, github, or gitlab")
	addLabelInputs(cmd)
	return cmd
}

func labelsExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Show where each label came from",
		RunE: func(cmd *cobra.Command, _ []string) error {
			set, sources, dropped, err := explainLabels(cmd)
			if err != nil {
				if _, ok := err.(*cictx.ExitError); !ok {
					return err
				}
			}
			var b strings.Builder
			b.WriteString("key | value | source | status\n")
			keys := make([]string, 0, len(set)+len(dropped))
			seen := map[string]bool{}
			for key := range set {
				keys = append(keys, key)
				seen[key] = true
			}
			for _, drop := range dropped {
				if !seen[drop.Key] {
					keys = append(keys, drop.Key)
					seen[drop.Key] = true
				}
			}
			sort.Strings(keys)
			for _, key := range keys {
				if value, ok := set[key]; ok {
					fmt.Fprintf(&b, "%s | %s | %s | ok\n", key, value, sources[key])
					continue
				}
				for _, drop := range dropped {
					if drop.Key == key {
						fmt.Fprintf(&b, "%s |  | %s | dropped:%s\n", key, sources[key], drop.Reason)
					}
				}
			}
			if policyErr := writeServerPolicy(&b, cmd, set); policyErr != nil {
				return policyErr
			}
			_, werr := io.WriteString(cmd.OutOrStdout(), b.String())
			if werr != nil {
				return werr
			}
			return err
		},
	}
	addLabelInputs(cmd)
	return cmd
}

func addLabelInputs(cmd *cobra.Command) {
	cmd.Flags().StringArray("label", nil, "override label k=v (repeatable)")
	cmd.Flags().String("profile", "", "path to .yabanin.yml")
	cmd.Flags().String("dir", ".", "repository directory")
}

func collectLabels(cmd *cobra.Command) (labels.Set, map[string]string, []labels.Dropped, error) {
	set, sources, dropped, missing, profile, err := assembleLabels(cmd)
	if err != nil {
		return nil, nil, nil, err
	}
	if profile != nil && profile.OnMissing == "fail" && len(missing) > 0 {
		return set, sources, dropped, &cictx.ExitError{Code: 3, Missing: missing}
	}
	return set, sources, dropped, nil
}

func explainLabels(cmd *cobra.Command) (labels.Set, map[string]string, []labels.Dropped, error) {
	return collectLabels(cmd)
}

func assembleLabels(cmd *cobra.Command) (labels.Set, map[string]string, []labels.Dropped, []string, *cictx.Profile, error) {
	dir, _ := cmd.Flags().GetString("dir")
	profilePath, _ := cmd.Flags().GetString("profile")
	rawFlags, _ := cmd.Flags().GetStringArray("label")
	flags, err := parseLabelFlags(rawFlags)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	env := cictx.OSEnv{}
	detected, err := cictx.Detect(cmd.Context(), env, cictx.ExecRunner{}, dir)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	found, err := cictx.FindProfile(env, dir, profilePath)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	var profile *cictx.Profile
	if found != "" {
		profile, err = cictx.LoadProfile(found)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}
	view := profile
	if profile != nil && profile.OnMissing == "fail" {
		copied := *profile
		copied.OnMissing = "warn"
		view = &copied
	}
	final, dropped, missing, err := cictx.Build(detected, view, env, flags)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	sources := labelSources(detected, profile, env, flags)
	return final, sources, dropped, missing, profile, nil
}

func labelSources(detected cictx.Context, profile *cictx.Profile, env cictx.Env, flags labels.Set) map[string]string {
	origin := "ci"
	if detected.System == "local" || detected.System == "" {
		origin = "git"
	}
	sources := map[string]string{}
	prev, _, _, _ := cictx.Build(detected, nil, env, nil)
	for key := range prev {
		sources[key] = origin
	}
	if profile == nil && len(flags) == 0 {
		return sources
	}
	if profile != nil {
		staticOnly := *profile
		staticOnly.Labels.FromEnv = nil
		staticOnly.Labels.Extract = nil
		staticOnly.Require = nil
		staticOnly.OnMissing = "warn"
		next, _, _, _ := cictx.Build(detected, &staticOnly, env, nil)
		noteChanged(sources, prev, next, "profile.static")
		prev = next

		envOnly := *profile
		envOnly.Labels.Extract = nil
		envOnly.Require = nil
		envOnly.OnMissing = "warn"
		next, _, _, _ = cictx.Build(detected, &envOnly, env, nil)
		noteChanged(sources, prev, next, "profile.env")
		prev = next

		full := *profile
		full.Require = nil
		full.OnMissing = "warn"
		next, _, _, _ = cictx.Build(detected, &full, env, nil)
		noteChanged(sources, prev, next, "profile.extract")
		prev = next
	}
	next, _, _, _ := cictx.Build(detected, profile, env, flags)
	noteChanged(sources, prev, next, "flag")
	if _, ok := sources["ci.actor"]; ok && profile != nil && profile.Labels.IncludeActor {
		sources["ci.actor"] = "ci"
	}
	return sources
}

func noteChanged(sources map[string]string, prev, next labels.Set, source string) {
	for key, value := range next {
		if prev[key] != value {
			sources[key] = source
		}
	}
}

func parseLabelFlags(raw []string) (labels.Set, error) {
	set := labels.Set{}
	for _, item := range raw {
		key, value, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("label %q must be key=value", item)
		}
		set[key] = value
	}
	return set, nil
}

func formatLabels(format string, set labels.Set) (string, error) {
	encoded := labels.Encode(set)
	switch format {
	case "", "header":
		return encoded + "\n", nil
	case "json":
		body, err := json.Marshal(map[string]string(set))
		if err != nil {
			return "", err
		}
		return string(body) + "\n", nil
	case "env":
		return "export YABANIN_LABELS=" + shellQuote(encoded) + "\n", nil
	case "github", "gitlab":
		return "YABANIN_LABELS=" + encoded + "\n", nil
	default:
		return "", fmt.Errorf("unknown format %q", format)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func writeServerPolicy(b *strings.Builder, cmd *cobra.Command, set labels.Set) error {
	base, _ := cmd.Flags().GetString("base-url")
	key, _ := cmd.Flags().GetString("api-key")
	if base == "" {
		base = cictx.OSEnv{}.Getenv("YABANIN_GATEWAY_URL")
	}
	if key == "" {
		key = cictx.OSEnv{}.Getenv("YABANIN_API_KEY")
	}
	if base == "" || key == "" {
		return nil
	}
	status, body, err := getLabelPolicy(cmd.Context(), base, key)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		b.WriteString("server policy unknown (gateway without AT-15)\n")
		return nil
	}
	if status != http.StatusOK {
		return fmt.Errorf("label policy: HTTP %d", status)
	}
	var policy labels.Policy
	if err := json.Unmarshal(body, &policy); err != nil {
		return err
	}
	compiled, err := policy.Compile()
	if err != nil {
		return err
	}
	resolved := labels.Resolve(compiled, []labels.Source{{Name: "request", Labels: set}}, nil)
	b.WriteString("server keeps:\n")
	keys := make([]string, 0, len(resolved.Labels))
	for key := range resolved.Labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(b, "%s | %s | server | ok\n", key, resolved.Labels[key])
	}
	for _, drop := range resolved.Dropped {
		fmt.Fprintf(b, "%s |  | server | dropped:%s\n", drop.Key, drop.Reason)
	}
	return nil
}

func getLabelPolicy(ctx context.Context, base, apiKey string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	endpoint := strings.TrimRight(base, "/") + "/v1/yabanin/label-policy"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}
