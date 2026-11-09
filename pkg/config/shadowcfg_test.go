package config

import (
	"os"
	"strings"
	"testing"
)

func TestShadowEnvSurvivesYAMLMerge(t *testing.T) {
	_ = os.Setenv("YABANIN_SHADOW_ENABLED", "true")
	_ = os.Setenv("YABANIN_SHADOW_MODEL", "gpt-4o")
	defer func() { _ = os.Unsetenv("YABANIN_SHADOW_ENABLED") }()
	defer func() { _ = os.Unsetenv("YABANIN_SHADOW_MODEL") }()

	// minimal yaml like the real config.yaml (no shadow key)
	f, _ := os.CreateTemp(t.TempDir(), "cfg*.yaml")
	_, _ = f.WriteString("gateway:\n  listen_address: \":8082\"\n  log_level: \"info\"\n")
	_ = f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Gateway.Shadow.Enabled {
		t.Errorf("Shadow.Enabled = false after YAML merge; env value clobbered")
	}
	if cfg.Gateway.Shadow.Model != "gpt-4o" {
		t.Errorf("Shadow.Model = %q, want gpt-4o", cfg.Gateway.Shadow.Model)
	}
	// also: yaml that DOES set shadow must win
	f2, _ := os.CreateTemp(t.TempDir(), "cfg2*.yaml")
	_, _ = f2.WriteString("gateway:\n  shadow:\n    enabled: false\n    model: \"other\"\n")
	_ = f2.Close()
	cfg2, _ := Load(f2.Name())
	if cfg2.Gateway.Shadow.Model != "other" {
		t.Errorf("yaml should override: got %q", cfg2.Gateway.Shadow.Model)
	}
	_ = strings.TrimSpace
}
