package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/clientconfig"
	"github.com/reireirei/yabanin/pkg/harness"
)

type claudeAdapter struct{}

func (claudeAdapter) ID() string { return "claude-code" }

func (claudeAdapter) Supported() (bool, string) { return true, "" }

func (claudeAdapter) Detect(home string, _ cictx.Runner) Detection {
	path := filepath.Join(home, ".claude", "settings.json")
	body, _ := readOrEmpty(path)
	return Detection{ConfigPath: path, Installed: body != nil, Connected: bytes.Contains(body, []byte("yb harness key --tool claude-code"))}
}

func (claudeAdapter) Plan(home string, p ConnectParams) (harness.Plan, error) {
	path := filepath.Join(home, ".claude", "settings.json")
	before, err := readOrEmpty(path)
	if err != nil {
		return harness.Plan{}, err
	}
	doc := map[string]any{}
	if len(bytes.TrimSpace(before)) > 0 {
		if !json.Valid(before) {
			return harness.Plan{}, fmt.Errorf("claude settings are not JSON")
		}
		if err := json.Unmarshal(before, &doc); err != nil {
			return harness.Plan{}, err
		}
	}
	warnings := []string{}
	prev := map[string]any{}
	var paths []string
	if existing, ok := doc["apiKeyHelper"].(string); ok && existing != "" && existing != "yb harness key --tool claude-code" && !p.Force {
		return harness.Plan{}, fmt.Errorf("claude-code already has apiKeyHelper; pass --force")
	}
	env, _ := doc["env"].(map[string]any)
	if env == nil {
		env = map[string]any{}
		doc["env"] = env
	}
	for _, key := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"} {
		if value, ok := env[key]; ok {
			track(prev, &paths, "env."+key, value, true)
			delete(env, key)
			warnings = append(warnings, key+" removed so it does not override the helper")
		}
	}
	settings := clientconfig.ClaudeCode(clientconfig.Params{
		BaseURL: p.GatewayURL, KeyMode: "helper", Labels: staticLabels(p),
	})
	setTracked(env, prev, &paths, "ANTHROPIC_BASE_URL", strings.TrimRight(p.GatewayURL, "/"))
	setTracked(env, prev, &paths, "CLAUDE_CODE_GATEWAY_HINT_HEADERS", "1")
	if p.LabelsMode == "static" && settings.CustomHeaders != "" {
		old, existed := env["ANTHROPIC_CUSTOM_HEADERS"].(string)
		switch {
		case existed && (old == settings.CustomHeaders || strings.Contains(old, settings.CustomHeaders)):
		case existed:
			track(prev, &paths, "env.ANTHROPIC_CUSTOM_HEADERS", old, true)
			env["ANTHROPIC_CUSTOM_HEADERS"] = old + "\n" + settings.CustomHeaders
		default:
			track(prev, &paths, "env.ANTHROPIC_CUSTOM_HEADERS", nil, false)
			env["ANTHROPIC_CUSTOM_HEADERS"] = settings.CustomHeaders
		}
	}
	oldHelper, helperExisted := doc["apiKeyHelper"]
	doc["apiKeyHelper"] = settings.APIKeyHelper
	track(prev, &paths, "apiKeyHelper", oldHelper, helperExisted)
	after, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return harness.Plan{}, err
	}
	after = append(after, '\n')
	if bytes.Equal(before, after) {
		return harness.Plan{Tool: "claude-code"}, nil
	}
	return harness.Plan{Tool: "claude-code", Warnings: warnings, Changes: []harness.Change{{
		Path: path, Kind: kindOf(before), Before: before, After: after,
		Managed: harness.Managed{JSONPaths: paths, PrevValues: prev},
		Validate: func(body []byte) error {
			if !json.Valid(body) {
				return fmt.Errorf("claude settings are not JSON")
			}
			return nil
		},
	}}}, nil
}

func (claudeAdapter) Unapply(_ string, current []byte, m harness.Managed) ([]byte, error) {
	if len(bytes.TrimSpace(current)) == 0 {
		return current, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(current, &doc); err != nil {
		return nil, err
	}
	for _, drop := range m.JSONPaths {
		prev, ok := m.PrevValues[drop]
		harness.RestorePath(doc, drop, prev, ok)
	}
	if env, ok := doc["env"].(map[string]any); ok && len(env) == 0 {
		delete(doc, "env")
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func track(prev map[string]any, paths *[]string, key string, old any, existed bool) {
	*paths = append(*paths, key)
	if existed {
		prev[key] = old
	}
}

func setTracked(env map[string]any, prev map[string]any, paths *[]string, key, value string) {
	old, existed := env[key]
	env[key] = value
	track(prev, paths, "env."+key, old, existed)
}

func staticLabels(p ConnectParams) map[string]string {
	if p.LabelsMode != "static" {
		return nil
	}
	return p.StaticLabels
}
