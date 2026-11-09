package apiformat

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAnthropicToChat_Goldens(t *testing.T) {
	matches, err := filepath.Glob("testdata/anthropic_*.in.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no anthropic goldens")
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
			got, _, ferr := AnthropicToChat(in)
			var probe map[string]json.RawMessage
			if json.Unmarshal(want, &probe) == nil {
				if _, ok := probe["status"]; ok {
					if ferr == nil {
						t.Fatalf("expected error, got %s", got)
					}
					var exp FormatError
					if err := json.Unmarshal(want, &exp); err != nil {
						t.Fatal(err)
					}
					if ferr.Status != exp.Status || ferr.Type != exp.Type || ferr.Code != exp.Code || ferr.Message != exp.Message {
						t.Fatalf("error %+v, want %+v", ferr, exp)
					}
					return
				}
			}
			if ferr != nil {
				t.Fatalf("unexpected error: %+v", ferr)
			}
			if !jsonEqual(got, want) {
				t.Fatalf("chat JSON mismatch\ngot  %s\nwant %s", got, bytes.TrimSpace(want))
			}
		})
	}
}

func TestAnthropicToChat_ToolChoice(t *testing.T) {
	cases := []struct {
		choice string
		want   string
	}{
		{`{"type":"auto"}`, `"auto"`},
		{`{"type":"any"}`, `"required"`},
		{`{"type":"none"}`, `"none"`},
		{`{"type":"tool","name":"bash"}`, `{"type":"function","function":{"name":"bash"}}`},
	}
	for _, tc := range cases {
		body := []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"Hi"}],"tool_choice":` + tc.choice + `}`)
		got, _, ferr := AnthropicToChat(body)
		if ferr != nil {
			t.Fatal(ferr)
		}
		var chat ChatRequest
		if err := json.Unmarshal(got, &chat); err != nil {
			t.Fatal(err)
		}
		if string(chat.ToolChoice) != tc.want {
			t.Fatalf("choice %s got %s", tc.choice, chat.ToolChoice)
		}
	}
}

func TestAnthropicToChat_DisableParallel(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"Hi"}],"tool_choice":{"type":"auto","disable_parallel_tool_use":true}}`)
	got, _, ferr := AnthropicToChat(body)
	if ferr != nil {
		t.Fatal(ferr)
	}
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	if chat.ParallelToolCalls == nil || *chat.ParallelToolCalls {
		t.Fatalf("parallel %#v", chat.ParallelToolCalls)
	}
}

func TestAnthropicToChat_ServerToolDropped(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"web_search_20250305","name":"web_search"},{"name":"local","input_schema":null}]}`)
	_, meta, ferr := AnthropicToChat(body)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if !containsDrop(meta.Dropped, "tool:web_search_20250305") {
		t.Fatalf("dropped %#v", meta.Dropped)
	}
	got, _, _ := AnthropicToChat(body)
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	if len(chat.Tools) != 1 || string(chat.Tools[0].Function.Parameters) != `{"type":"object","properties":{}}` {
		t.Fatalf("tools %#v", chat.Tools)
	}
}

func TestAnthropicToChat_DocumentPlaceholder(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"x"}}]}]}`)
	got, meta, ferr := AnthropicToChat(body)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if !containsDrop(meta.Dropped, "document") {
		t.Fatalf("dropped %#v", meta.Dropped)
	}
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	var text string
	if err := json.Unmarshal(chat.Messages[0].Content, &text); err != nil {
		t.Fatal(err)
	}
	if text != "[document omitted: not supported on this route]" {
		t.Fatalf("content %q", text)
	}
}

func TestAnthropicToChat_SystemRoleBecomesPrefixedUser(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"Hi"},{"role":"system","content":"secret"},{"role":"user","content":"Go"}]}`)
	got, _, ferr := AnthropicToChat(body)
	if ferr != nil {
		t.Fatal(ferr)
	}
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	if len(chat.Messages) != 3 || chat.Messages[1].Role != "user" {
		t.Fatalf("messages %#v", chat.Messages)
	}
	var text string
	if err := json.Unmarshal(chat.Messages[1].Content, &text); err != nil {
		t.Fatal(err)
	}
	if text != "[system]\nsecret" {
		t.Fatalf("content %q", text)
	}
}

func TestAnthropicToChat_MoreBranches(t *testing.T) {
	body := []byte(`{
		"model":"m","max_tokens":8,"stream":true,"temperature":0.2,"top_p":0.9,"top_k":5,
		"system":[{"type":"text","text":"A"},{"type":"text","text":"B"}],
		"stop_sequences":["a","b","c","d","e"],
		"thinking":{"type":"adaptive"},
		"output_config":{"effort":"low"},
		"metadata":{"user_id":"u1"},
		"messages":[
			{"role":"system","content":[{"type":"text","text":"lead"}]},
			{"role":"user","content":[
				{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"no"},{"type":"image","source":{"type":"url","url":"http://x"}}],"is_error":true},
				{"type":"image","source":{"type":"url","url":"http://img"}},
				{"type":"image","source":{"type":"file"}},
				{"type":"document","source":{"type":"text","data":"doc"}},
				{"type":"mystery"}
			]},
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"x"},
				{"type":"text","text":"ab"},
				{"type":"text","text":"c"},
				{"type":"tool_use","id":"t2","name":"f","input":null},
				{"type":"server_tool_use","id":"s","name":"web"}
			]},
			{"role":"tool"}
		],
		"tools":[{"type":"custom","name":"f","description":"d","strict":true}]
	}`)
	got, meta, ferr := AnthropicToChat(body)
	if ferr != nil {
		t.Fatal(ferr)
	}
	for _, name := range []string{"stop_sequences_over_4", "top_k", "output_config", "image_source", "block:mystery", "block:server_tool_use", "role:tool"} {
		if !containsDrop(meta.Dropped, name) {
			t.Fatalf("missing %s in %#v", name, meta.Dropped)
		}
	}
	if containsDrop(meta.Dropped, "thinking") {
		t.Fatal("adaptive thinking must be silent")
	}
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	if !chat.Stream || chat.StreamOptions == nil || !chat.StreamOptions.IncludeUsage {
		t.Fatalf("stream %#v", chat.StreamOptions)
	}
	if chat.User != "u1" || len(chat.Stop) != 4 {
		t.Fatalf("user %q stops %#v", chat.User, chat.Stop)
	}
	if chat.Messages[0].Role != "system" {
		t.Fatalf("leading %#v", chat.Messages[0])
	}
	var lead string
	if err := json.Unmarshal(chat.Messages[0].Content, &lead); err != nil || lead != "A\n\nB\n\nlead" {
		t.Fatalf("system %q", lead)
	}
	if chat.Messages[1].Role != "tool" {
		t.Fatalf("tool first %#v", chat.Messages[1])
	}
	var toolText string
	_ = json.Unmarshal(chat.Messages[1].Content, &toolText)
	if toolText != "ERROR: no\n[image omitted]" {
		t.Fatalf("tool text %q", toolText)
	}
	var assistant string
	_ = json.Unmarshal(chat.Messages[3].Content, &assistant)
	if assistant != "abc" || len(chat.Messages[3].ToolCalls) != 1 || chat.Messages[3].ToolCalls[0].Function.Arguments != "{}" {
		t.Fatalf("assistant %#v", chat.Messages[3])
	}
	if len(chat.Tools) != 1 || chat.Tools[0].Function.Strict == nil || !*chat.Tools[0].Function.Strict {
		t.Fatalf("tools %#v", chat.Tools)
	}

	_, enabled, ferr := AnthropicToChat([]byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"Hi"}],"thinking":{"type":"enabled"}}`))
	if ferr != nil || !containsDrop(enabled.Dropped, "thinking") {
		t.Fatalf("enabled %#v %v", enabled.Dropped, ferr)
	}
	if _, _, ferr := AnthropicToChat([]byte(`[]`)); ferr == nil || ferr.Code != "invalid_json" {
		t.Fatalf("json %v", ferr)
	}
	if _, _, ferr := AnthropicToChat([]byte(`{"max_tokens":1,"messages":[{"role":"user","content":"Hi"}]}`)); ferr == nil || ferr.Message != "model: Field required" {
		t.Fatalf("model %v", ferr)
	}
	if _, _, ferr := AnthropicToChat([]byte(`{"model":"m","max_tokens":1,"messages":[]}`)); ferr == nil || ferr.Message != "messages: at least one message is required" {
		t.Fatalf("messages %v", ferr)
	}
}

func containsDrop(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}
