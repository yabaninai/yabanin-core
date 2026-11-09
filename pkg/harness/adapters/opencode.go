package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/clientconfig"
	"github.com/reireirei/yabanin/pkg/harness"
)

type opencodeAdapter struct{}

func (opencodeAdapter) ID() string { return "opencode" }

func (opencodeAdapter) Supported() (bool, string) { return true, "" }

func (opencodeAdapter) Detect(home string, _ cictx.Runner) Detection {
	path := filepath.Join(home, ".config", "opencode", "opencode.json")
	body, _ := readOrEmpty(path)
	return Detection{ConfigPath: path, Installed: body != nil, Connected: bytes.Contains(body, []byte(`"yabanin"`))}
}

func (opencodeAdapter) Plan(home string, p ConnectParams) (harness.Plan, error) {
	dir := filepath.Join(home, ".config", "opencode")
	jsonc := filepath.Join(dir, "opencode.jsonc")
	if _, err := os.Stat(jsonc); err == nil {
		if _, jsonErr := os.Stat(filepath.Join(dir, "opencode.json")); jsonErr != nil {
			return harness.Plan{}, fmt.Errorf("opencode.jsonc cannot be edited automatically\n%s", manualOpenCode(p))
		}
	}
	path := filepath.Join(dir, "opencode.json")
	before, err := readOrEmpty(path)
	if err != nil {
		return harness.Plan{}, err
	}
	if len(bytes.TrimSpace(before)) > 0 && !json.Valid(before) {
		return harness.Plan{}, fmt.Errorf("opencode.json is not strict JSON\n%s", manualOpenCode(p))
	}
	doc := map[string]any{}
	if len(bytes.TrimSpace(before)) > 0 {
		if err := json.Unmarshal(before, &doc); err != nil {
			return harness.Plan{}, err
		}
	}
	provider := clientconfig.OpenCode(clientconfig.Params{
		BaseURL: p.GatewayURL, Model: p.Model, Labels: staticLabels(p), KeyMode: "env",
	}, p.Models)
	raw, err := json.Marshal(provider)
	if err != nil {
		return harness.Plan{}, err
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return harness.Plan{}, err
	}
	providers, _ := doc["provider"].(map[string]any)
	if providers == nil {
		providers = map[string]any{}
	}
	prev := map[string]any{}
	paths := []string{"provider.yabanin"}
	if old, existed := providers["yabanin"]; existed {
		prev["provider.yabanin"] = old
	}
	providers["yabanin"] = asMap
	doc["provider"] = providers
	if p.SetDefault && p.Model != "" {
		if old, existed := doc["model"]; existed {
			prev["model"] = old
		}
		paths = append(paths, "model")
		doc["model"] = "yabanin/" + p.Model
	}
	after, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return harness.Plan{}, err
	}
	after = append(after, '\n')
	plan := harness.Plan{Tool: "opencode"}
	if !bytes.Equal(before, after) {
		plan.Changes = append(plan.Changes, harness.Change{
			Path: path, Kind: kindOf(before), Before: before, After: after,
			Managed: harness.Managed{JSONPaths: paths, PrevValues: prev},
			Validate: func(body []byte) error {
				if !json.Valid(body) {
					return fmt.Errorf("opencode.json is not JSON")
				}
				return nil
			},
		})
	}
	shellPlan, err := (shellAdapter{}).planWithKey(home, p, true)
	if err != nil {
		return harness.Plan{}, err
	}
	plan.Changes = append(plan.Changes, shellPlan.Changes...)
	plan.Warnings = append(plan.Warnings, shellPlan.Warnings...)
	return plan, nil
}

func (opencodeAdapter) Unapply(path string, current []byte, m harness.Managed) ([]byte, error) {
	if bytes.Contains(current, []byte("yabanin:shell:")) {
		return (shellAdapter{}).Unapply(path, current, m)
	}
	var doc map[string]any
	if err := json.Unmarshal(current, &doc); err != nil {
		return nil, err
	}
	drops := m.JSONPaths
	if len(drops) == 0 {
		drops = []string{"provider.yabanin"}
	}
	for _, drop := range drops {
		prev, ok := m.PrevValues[drop]
		harness.RestorePath(doc, drop, prev, ok)
	}
	if providers, ok := doc["provider"].(map[string]any); ok && len(providers) == 0 {
		delete(doc, "provider")
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func manualOpenCode(p ConnectParams) string {
	return clientconfig.OpenCode(clientconfig.Params{BaseURL: p.GatewayURL, Model: p.Model, KeyMode: "env"}, p.Models).RenderJSON()
}
