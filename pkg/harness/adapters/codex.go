package adapters

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/clientconfig"
	"github.com/reireirei/yabanin/pkg/harness"
)

type codexAdapter struct{}

func (codexAdapter) ID() string { return "codex" }

func (codexAdapter) Supported() (bool, string) { return true, "" }

func (codexAdapter) Detect(home string, run cictx.Runner) Detection {
	path := codexConfigPath(home)
	body, _ := readOrEmpty(path)
	det := Detection{ConfigPath: path, Installed: body != nil || pathExists(filepath.Dir(path)), Connected: bytes.Contains(body, []byte("yabanin:codex:"))}
	if run != nil {
		if out, err := run.Run(context.Background(), home, nil, "codex", "--version"); err == nil {
			det.Installed = true
			det.Version = strings.TrimSpace(out)
		}
	}
	return det
}

func (codexAdapter) Plan(home string, p ConnectParams) (harness.Plan, error) {
	path := codexConfigPath(home)
	before, err := readOrEmpty(path)
	if err != nil {
		return harness.Plan{}, err
	}
	stripped := harness.RemoveManagedBlocks(before, []string{"codex:top", "codex:provider"})
	if bytes.Contains(stripped, []byte("[model_providers.yabanin]")) {
		return harness.Plan{}, fmt.Errorf("codex already has [model_providers.yabanin] outside a managed block; pass --provider-id")
	}
	commented, disabled := commentTopLevel(string(stripped), p.Model != "")
	cfg := clientconfig.Codex(clientconfig.Params{
		BaseURL: p.GatewayURL, Model: p.Model, KeyMode: "helper", ProviderID: "yabanin",
	})
	full := cfg.RenderTOML()
	top, table := splitTOML(full)
	after := wrapBlock("codex", "top", top) + strings.TrimLeft(commented, "\n")
	if !strings.HasSuffix(after, "\n") {
		after += "\n"
	}
	after += wrapBlock("codex", "provider", table)
	if bytes.Equal(before, []byte(after)) {
		return harness.Plan{Tool: "codex"}, nil
	}
	base := withV1(p.GatewayURL)
	return harness.Plan{Tool: "codex", Changes: []harness.Change{{
		Path: path, Kind: kindOf(before), Before: before, After: []byte(after),
		Managed:  harness.Managed{Blocks: []string{"codex:top", "codex:provider"}, CommentedLines: disabled},
		Validate: validateCodex(base),
	}}}, nil
}

func (codexAdapter) Unapply(_ string, current []byte, m harness.Managed) ([]byte, error) {
	out := harness.RemoveManagedBlocks(current, m.Blocks)
	out = harness.RestoreDisabled(out, m.CommentedLines)
	return out, nil
}

func codexConfigPath(home string) string {
	if env := os.Getenv("CODEX_HOME"); env != "" {
		return filepath.Join(env, "config.toml")
	}
	return filepath.Join(home, ".codex", "config.toml")
}

func commentTopLevel(content string, commentModel bool) (string, []string) {
	lines := strings.Split(content, "\n")
	var disabled []string
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") {
			break
		}
		if isTopKey(trim, "model_provider") || (commentModel && isTopKey(trim, "model")) {
			disabled = append(disabled, line)
			lines[i] = "# yabanin-disabled: " + line
		}
	}
	return strings.Join(lines, "\n"), disabled
}

func isTopKey(line, key string) bool {
	if strings.HasPrefix(line, "#") {
		return false
	}
	field, _, ok := strings.Cut(line, "=")
	return ok && strings.TrimSpace(field) == key
}

func splitTOML(full string) (top, table string) {
	if i := strings.Index(full, "\n["); i >= 0 {
		return strings.TrimSpace(full[:i]), strings.TrimSpace(full[i+1:])
	}
	return strings.TrimSpace(full), ""
}

func validateCodex(base string) func([]byte) error {
	return func(body []byte) error {
		var doc map[string]any
		if err := toml.Unmarshal(body, &doc); err != nil {
			return err
		}
		providers, _ := doc["model_providers"].(map[string]any)
		block, _ := providers["yabanin"].(map[string]any)
		got, _ := block["base_url"].(string)
		if got != base {
			return fmt.Errorf("codex base_url %q, want %q", got, base)
		}
		return nil
	}
}

func withV1(base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.HasSuffix(base, "/v1") {
		return base
	}
	return base + "/v1"
}

func kindOf(before []byte) harness.ChangeKind {
	if before == nil {
		return harness.KindCreate
	}
	return harness.KindEdit
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
