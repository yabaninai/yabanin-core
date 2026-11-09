package adapters

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/clientconfig"
	"github.com/reireirei/yabanin/pkg/harness"
)

type continueAdapter struct{}

func (continueAdapter) ID() string { return "continue" }

func (continueAdapter) Supported() (bool, string) { return true, "" }

func (continueAdapter) Detect(home string, _ cictx.Runner) Detection {
	path := filepath.Join(home, ".continue", "config.yaml")
	body, _ := readOrEmpty(path)
	return Detection{ConfigPath: path, Installed: body != nil, Connected: bytes.Contains(body, []byte("yabanin:continue:"))}
}

func (continueAdapter) Plan(home string, p ConnectParams) (harness.Plan, error) {
	if !p.Experimental {
		return harness.Plan{}, fmt.Errorf("continue is experimental; pass --experimental and verify with the tool's current docs")
	}
	path := filepath.Join(home, ".continue", "config.yaml")
	plan, err := textPlan("continue", "models", path, clientconfig.Continue(clientconfig.Params{
		BaseURL: p.GatewayURL, Model: p.Model,
		Labels: staticLabels(p), KeyMode: "env",
	}).RenderYAML())
	if err != nil {
		return harness.Plan{}, err
	}
	plan.Warnings = append(plan.Warnings, "verify with the tool's current docs")
	return plan, nil
}

func (continueAdapter) Unapply(_ string, current []byte, m harness.Managed) ([]byte, error) {
	return harness.RemoveManagedBlocks(current, m.Blocks), nil
}

func textPlan(tool, block, path, body string) (harness.Plan, error) {
	before, err := readOrEmpty(path)
	if err != nil {
		return harness.Plan{}, err
	}
	stripped := harness.RemoveManagedBlocks(before, []string{tool + ":" + block})
	after := append(bytes.TrimRight(stripped, "\n"), []byte("\n"+wrapBlock(tool, block, body))...)
	if len(bytes.TrimSpace(stripped)) == 0 {
		after = []byte(wrapBlock(tool, block, body))
	}
	if bytes.Equal(before, after) {
		return harness.Plan{Tool: tool}, nil
	}
	return harness.Plan{Tool: tool, Changes: []harness.Change{{
		Path: path, Kind: kindOf(before), Before: before, After: after,
		Managed: harness.Managed{Blocks: []string{tool + ":" + block}},
	}}}, nil
}
