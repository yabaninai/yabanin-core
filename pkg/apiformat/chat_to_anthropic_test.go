package apiformat

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestChatToAnthropic_Goldens(t *testing.T) {
	matches, err := filepath.Glob("testdata/chat_to_anthropic_*.in.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("goldens %d, want 2", len(matches))
	}
	opts := AnthropicOptions{IDGen: func(prefix string) string { return prefix + "fixed" }}
	meta := AnthropicMeta{RequestedModel: "claude-test"}
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
			got, convErr := ChatToAnthropic(in, meta, opts)
			if convErr != nil {
				t.Fatal(convErr)
			}
			if !jsonEqual(got, want) {
				t.Fatalf("mismatch\ngot  %s\nwant %s", got, bytes.TrimSpace(want))
			}
		})
	}
}

func TestChatToAnthropic_InvalidArgumentsEmptyInput(t *testing.T) {
	raw, err := ChatToAnthropic([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"","type":"function","function":{"name":"bash","arguments":"not-json"}}]},"finish_reason":"stop"}]}`),
		AnthropicMeta{RequestedModel: "m"},
		AnthropicOptions{IDGen: func(prefix string) string { return prefix + "fixed" }})
	if err != nil {
		t.Fatal(err)
	}
	var doc AnthropicResponse
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.StopReason != "tool_use" || len(doc.Content) != 1 {
		t.Fatalf("%+v", doc)
	}
	block := doc.Content[0]
	if block.Type != "tool_use" || block.ID != "toolu_fixed" || string(block.Input) != "{}" {
		t.Fatalf("%+v", block)
	}
}

func TestChatToAnthropic_StopAndEmpty(t *testing.T) {
	opts := AnthropicOptions{IDGen: func(prefix string) string { return prefix + "fixed" }}
	length, err := ChatToAnthropic([]byte(`{"choices":[{"message":{"content":"x"},"finish_reason":"length"}]}`), AnthropicMeta{RequestedModel: "m"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc AnthropicResponse
	if err := json.Unmarshal(length, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.StopReason != "max_tokens" {
		t.Fatalf("stop %s", doc.StopReason)
	}
	filtered, err := ChatToAnthropic([]byte(`{"choices":[{"message":{"content":null},"finish_reason":"content_filter"}]}`), AnthropicMeta{RequestedModel: "m"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(filtered, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.StopReason != "refusal" || len(doc.Content) != 0 {
		t.Fatalf("%+v", doc)
	}
	over, err := ChatToAnthropic([]byte(`{"choices":[{"message":{"content":""},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":5}}}`), AnthropicMeta{RequestedModel: "m"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(over, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Usage.InputTokens != 0 || doc.Usage.CacheReadInputTokens != 5 {
		t.Fatalf("usage %+v", doc.Usage)
	}
	if _, err := ChatToAnthropic([]byte(`{"choices":[]}`), AnthropicMeta{}, AnthropicOptions{}); !errors.Is(err, ErrNoChoices) {
		t.Fatalf("got %v", err)
	}
	if _, err := ChatToAnthropic([]byte(`not-json`), AnthropicMeta{}, AnthropicOptions{}); err == nil {
		t.Fatal("expected invalid json")
	}
}
