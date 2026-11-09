package apiformat

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestChatToResponses_Goldens(t *testing.T) {
	matches, err := filepath.Glob("testdata/chat_to_responses_*.in.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 3 {
		t.Fatalf("goldens %d, want 3", len(matches))
	}
	opts := ResponsesOptions{
		IDGen: func(prefix string) string { return prefix + "fixed" },
		Now:   func() time.Time { return time.Unix(1700000000, 0) },
	}
	for _, inPath := range matches {
		name := inPath[len("testdata/") : len(inPath)-len(".in.json")]
		t.Run(name, func(t *testing.T) {
			in, err := os.ReadFile(inPath) //nolint:gosec // G304: path is filepath.Glob of testdata, not user input
			if err != nil {
				t.Fatal(err)
			}
			outPath := inPath[:len(inPath)-len(".in.json")] + ".out.json"
			want, err := os.ReadFile(outPath) //nolint:gosec // G304: path is filepath.Glob of testdata, not user input
			if err != nil {
				t.Fatal(err)
			}
			got, convErr := ChatToResponses(in, metaForGolden(name), opts)
			if convErr != nil {
				t.Fatal(convErr)
			}
			if !jsonEqual(got, want) {
				t.Fatalf("mismatch\ngot  %s\nwant %s", got, bytes.TrimSpace(want))
			}
		})
	}
}

func metaForGolden(name string) ResponsesMeta {
	if name == "chat_to_responses_tools" {
		return ResponsesMeta{CustomToolNames: map[string]bool{"apply_patch": true}}
	}
	return ResponsesMeta{}
}

func TestChatToResponses_NoChoices(t *testing.T) {
	_, err := ChatToResponses([]byte(`{"choices":[]}`), ResponsesMeta{}, ResponsesOptions{})
	if !errors.Is(err, ErrNoChoices) {
		t.Fatalf("got %v", err)
	}
	if _, err := ChatToResponses([]byte(`not-json`), ResponsesMeta{}, ResponsesOptions{}); err == nil {
		t.Fatal("expected invalid json error")
	}
	raw, err := ChatToResponses([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"","type":"function","function":{"name":"n","arguments":""}},{"id":"c","type":"function","function":{"name":"custom","arguments":"not-json"}}]},"finish_reason":"stop"}]}`),
		ResponsesMeta{CustomToolNames: map[string]bool{"custom": true}},
		ResponsesOptions{IDGen: func(prefix string) string { return prefix + "x" }})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Usage struct {
			Total int64 `json:"total_tokens"`
		} `json:"usage"`
		Output []struct {
			Type      string `json:"type"`
			CallID    string `json:"call_id"`
			Arguments string `json:"arguments"`
			Input     string `json:"input"`
		} `json:"output"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Usage.Total != 0 || len(doc.Output) != 2 {
		t.Fatalf("%+v", doc)
	}
	if doc.Output[0].CallID != "call_x" || doc.Output[0].Arguments != "{}" {
		t.Fatalf("function %#v", doc.Output[0])
	}
	if doc.Output[1].Input != "not-json" {
		t.Fatalf("custom %#v", doc.Output[1])
	}
}

func TestChatToResponses_ContentFilterAndDefaults(t *testing.T) {
	body := []byte(`{"model":"","choices":[{"message":{"role":"assistant","content":"x","refusal":"nope"},"finish_reason":"content_filter"}]}`)
	opts := ResponsesOptions{
		IDGen: func(prefix string) string { return prefix + "id" },
		Now:   func() time.Time { return time.Unix(42, 0) },
	}
	raw, err := ChatToResponses(body, ResponsesMeta{RequestedModel: "fallback-model"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Model      string          `json:"model"`
		CreatedAt  int64           `json:"created_at"`
		Status     string          `json:"status"`
		Incomplete json.RawMessage `json:"incomplete_details"`
		Output     []struct {
			Type    string `json:"type"`
			Content []struct {
				Type    string `json:"type"`
				Text    string `json:"text"`
				Refusal string `json:"refusal"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Model != "fallback-model" || doc.CreatedAt != 42 || doc.Status != "incomplete" {
		t.Fatalf("%+v", doc)
	}
	if string(doc.Incomplete) != `{"reason":"content_filter"}` {
		t.Fatalf("incomplete %s", doc.Incomplete)
	}
	if len(doc.Output) != 1 || len(doc.Output[0].Content) != 2 {
		t.Fatalf("output %#v", doc.Output)
	}
}
