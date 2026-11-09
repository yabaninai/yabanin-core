package trcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvaluateCLI(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pairs.json")
	if err := os.WriteFile(file, []byte(`[{"id":"one","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"ok","output":{}}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := RootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"evaluate", file})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"meets_threshold": true`) {
		t.Fatal("CLI omitted verdict")
	}
}

// A05: the CLI surfaces the evaluator's error contract — a duplicate-ID or
// empty-corpus dataset fails with the evaluator's message, not a panic or a
// silent empty report.
func TestEvaluateCLI_ErrorContract(t *testing.T) {
	write := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("duplicate id", func(t *testing.T) {
		file := write("dup.json", `[{"id":"x","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}},{"id":"x","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"missing"}}]`)
		cmd := RootCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"evaluate", file})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("expected duplicate-id error, got %v", err)
		}
	})

	t.Run("empty corpus", func(t *testing.T) {
		file := write("empty.json", `[]`)
		cmd := RootCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"evaluate", file})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "at least 1 case") {
			t.Fatalf("expected empty-corpus error, got %v", err)
		}
	})

	t.Run("invalid threshold", func(t *testing.T) {
		file := write("ok.json", `[{"id":"one","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"ok","output":{}}}]`)
		cmd := RootCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"evaluate", file, "--min-pass-rate", "1.5"})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "between 0 and 1") {
			t.Fatalf("expected threshold error, got %v", err)
		}
	})
}

func TestAuditRejectsUnwiredSemanticMode(t *testing.T) {
	cmd := RootCommand()
	cmd.SetArgs([]string{"audit", "does-not-exist.jsonl", "--cache-mode", "semantic"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "no embedder is configured") {
		t.Fatal("semantic mode must fail before ingest")
	}
}
