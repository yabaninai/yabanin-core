package trcli

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/agenteval/datasets"
)

func runDataset(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := RootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"dataset"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

func TestDatasetCommandRoundtrip(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.jsonl")
	if err := os.WriteFile(source, []byte(`{"schema_version":1,"dataset_id":"demo","id":"@formula","payload":{"text":"hello"}}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"jsonl", "csv"} {
		first := filepath.Join(dir, format+"-revision.json")
		second := filepath.Join(dir, format+"-second.json")
		exported := filepath.Join(dir, "export."+format)
		if _, err := runDataset(t, "import", "--format", "jsonl", "--input", source, "--output", first); err != nil {
			t.Fatal(err)
		}
		if _, err := runDataset(t, "export", "--format", format, "--input", first, "--output", exported); err != nil {
			t.Fatal(err)
		}
		if format == "csv" {
			data, err := os.ReadFile(exported) //nolint:gosec // G304: exported is under t.TempDir.
			if err != nil {
				t.Fatal(err)
			}
			reader := csv.NewReader(bytes.NewReader(data))
			if _, err := reader.Read(); err != nil {
				t.Fatal(err)
			}
			record, err := reader.Read()
			if err != nil {
				t.Fatal(err)
			}
			if record[2] != "'@formula" {
				t.Fatalf("CLI-exported sample ID cell = %q, want %q", record[2], "'@formula")
			}
		}
		if _, err := runDataset(t, "import", "--format", format, "--input", exported, "--output", second); err != nil {
			t.Fatal(err)
		}
		one, err := os.ReadFile(first) //nolint:gosec // G304: first is under t.TempDir.
		if err != nil {
			t.Fatal(err)
		}
		two, err := os.ReadFile(second) //nolint:gosec // G304: second is under t.TempDir.
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(one, two) {
			t.Fatal("canonical repeated import changed bytes")
		}
		_, digest1, err := datasets.ReadRevision(bytes.NewReader(one))
		if err != nil {
			t.Fatal(err)
		}
		_, digest2, err := datasets.ReadRevision(bytes.NewReader(two))
		if err != nil {
			t.Fatal(err)
		}
		if digest1 != digest2 {
			t.Fatal("revision digest changed")
		}
		if _, err := runDataset(t, "import", "--format", "jsonl", "--input", source, "--output", first); err == nil {
			t.Fatal("existing file overwritten")
		}
		preserved, err := os.ReadFile(first) //nolint:gosec // G304: first is under t.TempDir.
		if err != nil || !bytes.Equal(preserved, one) {
			t.Fatal("existing destination modified")
		}
	}
}

func TestDatasetPreviewAndFailure(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "bad.jsonl")
	output := filepath.Join(dir, "must-not-exist")
	if err := os.WriteFile(source, []byte("{secret-payload}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runDataset(t, "import", "--format", "jsonl", "--input", source, "--output", output, "--preview")
	if err == nil || !strings.Contains(out, `"row":1`) || strings.Contains(out, "secret-payload") {
		t.Fatalf("unsafe/wrong diagnostic: %s %v", out, err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("preview wrote output")
	}
	if _, err := runDataset(t, "import", "--format", "jsonl", "--input", source, "--output", output); err == nil {
		t.Fatal("malformed import accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("failed import wrote output")
	}
	row := map[string]any{"schema_version": 1, "dataset_id": "demo", "id": "a", "payload": map[string]any{}}
	data, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	out, err = runDataset(t, "import", "--format", "jsonl", "--input", source, "--preview")
	if err != nil || !strings.Contains(out, "samples=1 errors=0") {
		t.Fatalf("valid preview: %s %v", out, err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("valid preview wrote output")
	}
}

func TestDatasetCSVPreviewPhysicalLine(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "multiline.csv")
	output := filepath.Join(dir, "must-not-exist.json")
	contents := "schema_version,dataset_id,sample_id,payload_json\n" +
		"1,demo,first,\"{\n\"\"text\"\":\"\"multiline-private-value\"\"\n}\"\n" +
		"1,demo,broken,{},synthetic-private-marker\n"
	if err := os.WriteFile(input, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	out, err := runDataset(t, "import", "--format", "csv", "--input", input, "--output", output, "--preview")
	want := `[{"row":5,"code":"malformed_row"}]` + "\n"
	if err == nil || !strings.HasPrefix(out, want) || strings.Contains(out, "private") {
		t.Fatalf("CSV preview = %q, err %v; want only bounded physical-row diagnostic %q", out, err, want)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("preview created destination: stat error %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".dataset-") {
			t.Fatalf("preview left temporary output %q", entry.Name())
		}
	}
}

func TestDatasetCommandOversizeAndCSVBoundary(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output")
	for _, format := range []string{"jsonl", "csv"} {
		if err := os.WriteFile(input, []byte(strings.Repeat("x", (8<<20)+1)), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := runDataset(t, "import", "--format", format, "--input", input, "--output", output); err == nil {
			t.Fatal("oversized CLI input accepted")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("oversized import wrote output")
		}
	}
	csv := "schema_version,dataset_id,sample_id,payload_json,org_id\n1,demo,a,{},foreign\n"
	if err := os.WriteFile(input, []byte(csv), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runDataset(t, "import", "--format", "csv", "--input", input, "--preview")
	if err == nil || !strings.Contains(out, "invalid_header") || strings.Contains(out, "foreign") {
		t.Fatalf("CSV boundary: %s %v", out, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatal("failed commands left output or temporary artifacts")
	}
}

func TestCreateDatasetOutputCleanupFailureAfterPublish(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "complete-output.json")
	want := []byte("complete dataset output\n")
	var staged string
	err := createDatasetOutputWithCleanup(destination, want, func(path string) error {
		staged = path
		return errors.New("injected staging cleanup failure")
	})
	if err != nil {
		t.Fatalf("published output returned error: %v", err)
	}
	if staged == "" {
		t.Fatal("staging cleanup was not attempted")
	}
	t.Cleanup(func() { _ = os.Remove(staged) })
	got, err := os.ReadFile(destination) //nolint:gosec // G304: destination is under t.TempDir.
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("published output = %q, %v; want complete bytes", got, err)
	}
}

func TestCreateDatasetOutputFailsBeforePublishWhenParentIsMissing(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "missing-parent")
	destination := filepath.Join(parent, "complete-output.json")
	err := createDatasetOutput(destination, []byte("complete dataset output\n"))
	if err == nil || err.Error() != "cannot create dataset output" {
		t.Fatalf("create failure = %v, want bounded create error", err)
	}
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Fatalf("failed prepublish create left parent path: %v", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed prepublish create published a destination: %v", err)
	}
}
