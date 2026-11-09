package adapters

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/harness"
	"github.com/reireirei/yabanin/pkg/labels"
)

type shellAdapter struct{}

func (shellAdapter) ID() string { return "shell" }

func (shellAdapter) Supported() (bool, string) { return true, "" }

func (shellAdapter) Detect(home string, _ cictx.Runner) Detection {
	path := shellPath(home)
	body, _ := readOrEmpty(path)
	return Detection{ConfigPath: path, Installed: true, Connected: strings.Contains(string(body), "yabanin:shell:")}
}

func (s shellAdapter) Plan(home string, p ConnectParams) (harness.Plan, error) {
	return s.planWithKey(home, p, true)
}

func (s shellAdapter) planWithKey(home string, p ConnectParams, includeKey bool) (harness.Plan, error) {
	return s.planWithScript(home, shellScript(p, includeKey, fish(shellPath(home))))
}

func (shellAdapter) planWithScript(home string, script string) (harness.Plan, error) {
	return textPlan("shell", "env", shellPath(home), script)
}

func (shellAdapter) Unapply(_ string, current []byte, m harness.Managed) ([]byte, error) {
	return harness.RemoveManagedBlocks(current, m.Blocks), nil
}

func shellPath(home string) string {
	switch filepath.Base(os.Getenv("SHELL")) {
	case "bash":
		return filepath.Join(home, ".bashrc")
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish")
	default:
		return filepath.Join(home, ".zshrc")
	}
}

func fish(path string) bool { return strings.HasSuffix(path, "config.fish") }

func shellScript(p ConnectParams, includeKey, fish bool) string {
	var lines []string
	add := func(name, value string) {
		if fish {
			lines = append(lines, "set -gx "+name+" "+value)
			return
		}
		lines = append(lines, "export "+name+"="+value)
	}
	add("YABANIN_GATEWAY_URL", quoteShell(p.GatewayURL, fish))
	if includeKey && !fish {
		lines = append(lines, `export YABANIN_API_KEY="$(yb key print 2>/dev/null)"`)
	}
	if includeKey && fish {
		lines = append(lines, `set -gx YABANIN_API_KEY (yb key print 2>/dev/null)`)
	}
	if p.LabelsMode == "static" && len(p.StaticLabels) > 0 {
		add("YABANIN_LABELS", quoteShell(labels.Encode(p.StaticLabels), fish))
	}
	if p.GlobalEnv {
		add("OPENAI_BASE_URL", quoteShell(withV1(p.GatewayURL), fish))
		add("ANTHROPIC_BASE_URL", quoteShell(stringsTrim(p.GatewayURL), fish))
	}
	return strings.Join(lines, "\n")
}

func quoteShell(value string, fish bool) string {
	if fish {
		return "'" + strings.ReplaceAll(value, "'", `\'`) + "'"
	}
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func stringsTrim(value string) string { return strings.TrimRight(value, "/") }
