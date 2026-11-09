package trcli

import (
	"strings"
	"testing"
)

func TestClientConfigRepoAndModes(t *testing.T) {
	dirArgs := []string{"client-config", "--client", "codex", "--base-url", "https://gw.example", "--model", "gpt"}
	got, err := runTr(t, append(dirArgs, "--key-mode", "helper")...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `wire_api = "responses"`) || !strings.Contains(got, `command = "yb"`) || strings.Contains(got, "sk-") {
		t.Fatalf("%s", got)
	}
	if _, err := runTr(t, append(dirArgs, "--repo", "bad repo")...); err == nil {
		t.Fatal("expected invalid repo")
	}
	withRepo, err := runTr(t, append(dirArgs, "--repo", "group/proj", "--key-mode", "env")...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(withRepo, `env_key = "YABANIN_API_KEY"`) {
		t.Fatalf("%s", withRepo)
	}
}
