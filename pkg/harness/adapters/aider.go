package adapters

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/clientconfig"
	"github.com/reireirei/yabanin/pkg/harness"
)

type aiderAdapter struct{}

func (aiderAdapter) ID() string { return "aider" }

func (aiderAdapter) Supported() (bool, string) { return true, "" }

func (aiderAdapter) Detect(home string, _ cictx.Runner) Detection {
	path := filepath.Join(home, ".aider.conf.yml")
	body, _ := readOrEmpty(path)
	return Detection{ConfigPath: path, Installed: body != nil, Connected: bytes.Contains(body, []byte("yabanin:aider:"))}
}

func (aiderAdapter) Plan(home string, p ConnectParams) (harness.Plan, error) {
	if !p.Experimental {
		return harness.Plan{}, fmt.Errorf("aider is experimental; pass --experimental and verify with the tool's current docs")
	}
	cfg := clientconfig.Aider(clientconfig.Params{BaseURL: p.GatewayURL, Model: p.Model, KeyMode: "helper"})
	path := filepath.Join(home, ".aider.conf.yml")
	plan, err := textPlan("aider", "config", path, cfg.RenderYAML())
	if err != nil {
		return harness.Plan{}, err
	}
	script := shellScript(p, false, fish(shellPath(home)))
	keyLine := strings.TrimSpace(cfg.RenderEnv())
	if fish(shellPath(home)) {
		keyLine = "set -gx AIDER_OPENAI_API_KEY (yb harness key --tool aider)"
	}
	if script != "" {
		script += "\n" + keyLine
	} else {
		script = keyLine
	}
	shell, err := (shellAdapter{}).planWithScript(home, script)
	if err != nil {
		return harness.Plan{}, err
	}
	plan.Changes = append(plan.Changes, shell.Changes...)
	plan.Warnings = append(plan.Warnings, "verify with the tool's current docs")
	return plan, nil
}

func (aiderAdapter) Unapply(path string, current []byte, m harness.Managed) ([]byte, error) {
	if bytes.Contains(current, []byte("yabanin:shell:")) {
		return (shellAdapter{}).Unapply(path, current, m)
	}
	return harness.RemoveManagedBlocks(current, m.Blocks), nil
}
