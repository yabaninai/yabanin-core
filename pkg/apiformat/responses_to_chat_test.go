package apiformat

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestResponsesToChat_Goldens(t *testing.T) {
	matches, err := filepath.Glob("testdata/responses_*.in.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no responses goldens")
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
			got, _, ferr := ResponsesToChat(in)
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

func TestResponsesToChat_GroupsFunctionCalls(t *testing.T) {
	body := []byte(`{
	  "model":"m",
	  "input":[
	    {"type":"function_call","call_id":"c1","name":"a","arguments":""},
	    {"type":"function_call","call_id":"c2","name":"b","arguments":"{\"x\":1}"},
	    {"type":"function_call_output","call_id":"c1","output":"ok"},
	    {"type":"function_call","call_id":"c3","name":"c","arguments":"{}"}
	  ]
	}`)
	got, _, ferr := ResponsesToChat(body)
	if ferr != nil {
		t.Fatal(ferr)
	}
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	if len(chat.Messages) != 3 {
		t.Fatalf("messages %#v", chat.Messages)
	}
	if chat.Messages[0].Role != "assistant" || len(chat.Messages[0].ToolCalls) != 2 {
		t.Fatalf("first %#v", chat.Messages[0])
	}
	if chat.Messages[0].ToolCalls[0].Function.Arguments != "{}" {
		t.Fatalf("empty arguments %#v", chat.Messages[0].ToolCalls[0])
	}
	if chat.Messages[1].Role != "tool" {
		t.Fatalf("tool %#v", chat.Messages[1])
	}
	if chat.Messages[2].Role != "assistant" || len(chat.Messages[2].ToolCalls) != 1 || chat.Messages[2].ToolCalls[0].ID != "c3" {
		t.Fatalf("new assistant %#v", chat.Messages[2])
	}
}

func TestResponsesToChat_DeveloperAndMidSystem(t *testing.T) {
	body := []byte(`{
	  "model":"m",
	  "instructions":"Inst",
	  "input":[
	    {"role":"developer","content":"Dev"},
	    {"role":"user","content":"Hi"},
	    {"role":"developer","content":"Later"}
	  ]
	}`)
	got, _, ferr := ResponsesToChat(body)
	if ferr != nil {
		t.Fatal(ferr)
	}
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	if len(chat.Messages) != 3 {
		t.Fatalf("%#v", chat.Messages)
	}
	var system, later string
	_ = json.Unmarshal(chat.Messages[0].Content, &system)
	_ = json.Unmarshal(chat.Messages[2].Content, &later)
	if chat.Messages[0].Role != "system" || system != "Inst\n\nDev" {
		t.Fatalf("system %q", system)
	}
	if chat.Messages[2].Role != "user" || later != "[system]\nLater" {
		t.Fatalf("later role %s content %q", chat.Messages[2].Role, later)
	}
}

func TestResponsesToChat_CustomToolAndWebSearch(t *testing.T) {
	body := []byte(`{
	  "model":"m",
	  "input":"go",
	  "tools":[
	    {"type":"custom","name":"apply_patch","description":"Patch","format":{"type":"grammar","syntax":"lark","definition":"start: WORD"}},
	    {"type":"web_search"}
	  ]
	}`)
	got, meta, ferr := ResponsesToChat(body)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if !meta.CustomToolNames["apply_patch"] {
		t.Fatalf("custom names %#v", meta.CustomToolNames)
	}
	if len(meta.Dropped) != 1 || meta.Dropped[0] != "tool:web_search" {
		t.Fatalf("dropped %#v", meta.Dropped)
	}
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	if len(chat.Tools) != 1 || chat.Tools[0].Function.Name != "apply_patch" {
		t.Fatalf("tools %#v", chat.Tools)
	}
	var params struct {
		Properties struct {
			Input struct {
				Description string `json:"description"`
			} `json:"input"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(chat.Tools[0].Function.Parameters, &params); err != nil {
		t.Fatal(err)
	}
	if params.Properties.Input.Description != "Raw input for this tool.\n\nThe input MUST match this lark grammar:\nstart: WORD" {
		t.Fatalf("desc %q", params.Properties.Input.Description)
	}
}

func TestResponsesToChat_RejectsAndEcho(t *testing.T) {
	cases := []struct {
		name string
		body string
		code string
	}{
		{"missing model", `{"input":"hi"}`, "missing_model"},
		{"empty input", `{"model":"m"}`, "empty_input"},
		{"conversation", `{"model":"m","input":"hi","conversation":{"id":"c"}}`, "conversation_not_supported"},
		{"background", `{"model":"m","input":"hi","background":true}`, "background_not_supported"},
		{"prompt", `{"model":"m","input":"hi","prompt":{"id":"p"}}`, "prompt_templates_not_supported"},
		{"file id", `{"model":"m","input":[{"role":"user","content":[{"type":"input_image","file_id":"f"}]}]}`, "input_image_file_id_not_supported"},
		{"file", `{"model":"m","input":[{"role":"user","content":[{"type":"input_file","file_id":"f"}]}]}`, "input_file_not_supported"},
		{"audio", `{"model":"m","input":[{"role":"user","content":[{"type":"input_audio"}]}]}`, "input_audio_not_supported"},
		{"item ref", `{"model":"m","input":[{"type":"item_reference","id":"x"}]}`, "item_reference_not_supported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, ferr := ResponsesToChat([]byte(tc.body))
			if ferr == nil || ferr.Status != 400 || ferr.Code != tc.code {
				t.Fatalf("got %+v", ferr)
			}
		})
	}

	got, meta, ferr := ResponsesToChat([]byte(`{
	  "model":"m","input":"hi","stream":true,"temperature":0.2,"safety_identifier":"sid",
	  "text":{"format":{"type":"json_object"},"verbosity":"low"},
	  "reasoning":{"effort":"low","summary":"auto"},
	  "tool_choice":{"type":"function","name":"read"},
	  "prompt_cache_key":"sess","extra_field":1
	}`))
	if ferr != nil {
		t.Fatal(ferr)
	}
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	if !chat.Stream || chat.StreamOptions == nil || !chat.StreamOptions.IncludeUsage {
		t.Fatalf("stream %#v", chat.StreamOptions)
	}
	if chat.User != "sid" || meta.PromptCacheKey != "sess" || meta.Echo.User != "sid" {
		t.Fatalf("user %q key %q", chat.User, meta.PromptCacheKey)
	}
	if string(chat.ResponseFormat) != `{"type":"json_object"}` {
		t.Fatalf("format %s", chat.ResponseFormat)
	}
	if string(chat.ToolChoice) == "" || !jsonEqual(chat.ToolChoice, []byte(`{"type":"function","function":{"name":"read"}}`)) {
		t.Fatalf("choice %s", chat.ToolChoice)
	}
	found := map[string]bool{}
	for _, name := range meta.Dropped {
		found[name] = true
	}
	if !found["text.verbosity"] || !found["reasoning"] || !found["extra_field"] {
		t.Fatalf("dropped %#v", meta.Dropped)
	}
}

// TestResponsesToChat_EmptyPreviousResponseIDAccepted pins the stateless
// boundary of the continuation refusal (I60/D1): only a NON-empty
// previous_response_id is an unsupported-capability error. The empty string
// and an explicit null — the shapes a client sends when it echoes the field
// unset — must proceed through the normal translation and pass the endpoint
// probe, never 400.
func TestResponsesToChat_EmptyPreviousResponseIDAccepted(t *testing.T) {
	for _, body := range []string{
		`{"model":"m","input":"hi","previous_response_id":""}`,
		`{"model":"m","input":"hi","previous_response_id":null}`,
	} {
		got, _, ferr := ResponsesToChat([]byte(body))
		if ferr != nil {
			t.Fatalf("%s: unexpected rejection %+v", body, ferr)
		}
		var chat ChatRequest
		if err := json.Unmarshal(got, &chat); err != nil {
			t.Fatal(err)
		}
		if len(chat.Messages) == 0 || chat.Messages[len(chat.Messages)-1].Role != "user" {
			t.Fatalf("%s: translated messages %#v", body, chat.Messages)
		}
	}
	for _, probe := range []string{
		`{"previous_response_id":""}`,
		`{"previous_response_id":null}`,
	} {
		if ferr := RejectPreviousResponseID([]byte(probe)); ferr != nil {
			t.Fatalf("%s: endpoint probe must accept an unset id, got %+v", probe, ferr)
		}
	}
}

// TestRejectPreviousResponseID_IDShapes pins the stateless boundary at the
// endpoint probe for every JSON shape previous_response_id can arrive in:
// only an unset field (absent, null, empty string, empty container) passes.
// Any non-empty value is the unsupported-continuation error — including
// non-string shapes and ids that are not conversation response ids at all
// (approval-operation ids, tool-call ids, reasoning item ids). The gateway
// must never treat such a value as ignorable metadata or as a key to
// restore history: the client gets the same explicit 400 either way.
func TestRejectPreviousResponseID_IDShapes(t *testing.T) {
	refused := []struct {
		name string
		raw  string
	}{
		{"response id", `{"previous_response_id":"resp_9d2f31"}`},
		{"approval operation id", `{"previous_response_id":"op_7c1e55a0"}`},
		{"task operation id", `{"previous_response_id":"task_42"}`},
		{"tool call id", `{"previous_response_id":"call_0519"}`},
		{"custom tool call item id", `{"previous_response_id":"ctc_0a1b2c"}`},
		{"reasoning item id", `{"previous_response_id":"rs_9d2f31c0ffee"}`},
		{"number", `{"previous_response_id":123}`},
		{"boolean", `{"previous_response_id":true}`},
		{"object", `{"previous_response_id":{"id":"op_1"}}`},
		{"array", `{"previous_response_id":["resp_9d2f31"]}`},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			ferr := RejectPreviousResponseID([]byte(tc.raw))
			if ferr == nil {
				t.Fatalf("%s must be refused, probe accepted it", tc.raw)
			}
			if ferr != ErrPreviousResponseID {
				t.Fatalf("refusal must be the uniform error, got %+v", ferr)
			}
		})
	}
	for _, raw := range []string{
		`{}`,
		`{"previous_response_id":null}`,
		`{"previous_response_id":""}`,
		`{"previous_response_id":{}}`,
		`{"previous_response_id":[]}`,
	} {
		if ferr := RejectPreviousResponseID([]byte(raw)); ferr != nil {
			t.Fatalf("%s must pass the unset boundary, got %+v", raw, ferr)
		}
	}
	if ferr := RejectPreviousResponseID([]byte(`not-json`)); ferr != nil {
		t.Fatalf("non-JSON body is not this probe's error: %+v", ferr)
	}
}

// TestResponsesToChat_StatelessItemsResend verifies the response-item
// surface of the stateless contract with the shapes a real Codex client
// resends in input[]: the whole conversation rides the array every turn and
// the translation reconstructs it from content only. Reasoning items (with
// their item ids and opaque encrypted payloads) are skipped entirely —
// their ids must never leak into the chat request, because nothing in the
// translated turn may depend on server-side item identity (no false
// history restoration). Message/function item ids ride the same rule;
// tool call ids are content and are preserved.
func TestResponsesToChat_StatelessItemsResend(t *testing.T) {
	body := []byte(`{
	  "model":"gpt-5-codex",
	  "instructions":"You are Codex.",
	  "input":[
	    {"type":"message","role":"user","content":[{"type":"input_text","text":"Patch hello.txt"}]},
	    {"type":"reasoning","id":"rs_9d2f31c0ffee","summary":[{"type":"summary_text","text":"weighed patch scope"}],"encrypted_content":"ENC-7f3a"},
	    {"type":"custom_tool_call","id":"ctc_0a1b2c","call_id":"call_0519","name":"apply_patch","input":"*** Begin Patch"},
	    {"type":"custom_tool_call_output","call_id":"call_0519","output":"done"},
	    {"type":"message","id":"msg_555a","role":"assistant","content":[{"type":"output_text","text":"interim"}]},
	    {"type":"unknown_future_item","id":"zz_1"},
	    {"type":"message","role":"user","content":"now finish it"}
	  ],
	  "tools":[{"type":"custom","name":"apply_patch","description":"Patch"}],
	  "store":false
	}`)
	got, meta, ferr := ResponsesToChat(body)
	if ferr != nil {
		t.Fatal(ferr)
	}
	for _, forbidden := range []string{"rs_9d2f31c0ffee", "ENC-7f3a", "ctc_0a1b2c", "msg_555a", "zz_1", " weighed patch scope"} {
		if bytes.Contains(got, []byte(forbidden)) {
			t.Fatalf("translated chat request leaked item identity %q:\n%s", forbidden, got)
		}
	}
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	want := []struct{ role string }{
		{"system"}, {"user"}, {"assistant"}, {"tool"}, {"assistant"}, {"user"},
	}
	if len(chat.Messages) != len(want) {
		t.Fatalf("messages %#v", chat.Messages)
	}
	for i, w := range want {
		if chat.Messages[i].Role != w.role {
			t.Fatalf("message %d role %s, want %s (%#v)", i, chat.Messages[i].Role, w.role, chat.Messages[i])
		}
	}
	if chat.Messages[0].Content == nil || !bytes.Contains(chat.Messages[0].Content, []byte("You are Codex.")) {
		t.Fatalf("instructions not carried as the system message: %s", chat.Messages[0].Content)
	}
	call := chat.Messages[2].ToolCalls[0]
	if call.ID != "call_0519" || call.Function.Name != "apply_patch" {
		t.Fatalf("tool call identity not preserved: %#v", call)
	}
	if chat.Messages[3].ToolCallID != "call_0519" {
		t.Fatalf("tool output pairing lost: %#v", chat.Messages[3])
	}
	var interim, final string
	_ = json.Unmarshal(chat.Messages[4].Content, &interim)
	_ = json.Unmarshal(chat.Messages[5].Content, &final)
	if interim != "interim" || final != "now finish it" {
		t.Fatalf("assistant/user text lost: %q %q", interim, final)
	}
	dropped := map[string]bool{}
	for _, name := range meta.Dropped {
		dropped[name] = true
	}
	if !dropped["input:unknown_future_item"] {
		t.Fatalf("unknown item type must be disclosed, dropped %#v", meta.Dropped)
	}
	if !meta.CustomToolNames["apply_patch"] {
		t.Fatalf("custom tool not registered: %#v", meta.CustomToolNames)
	}
}

func TestResponsesToChat_MoreBranches(t *testing.T) {
	if _, _, ferr := ResponsesToChat([]byte(`not-json`)); ferr == nil || ferr.Code != "invalid_json" {
		t.Fatalf("%+v", ferr)
	}
	got, meta, ferr := ResponsesToChat([]byte(`{
	  "model":"m",
	  "user":"alice",
	  "safety_identifier":"ignored",
	  "parallel_tool_calls":false,
	  "max_output_tokens":16,
	  "top_p":0.5,
	  "tool_choice":"none",
	  "input":[
	    {"role":"assistant","content":"plain"},
	    {"role":"assistant","content":[{"type":"refusal","refusal":"no"}]},
	    {"type":"custom_tool_call","call_id":"c","name":"apply_patch","input":"diff"},
	    {"type":"custom_tool_call_output","call_id":"c","output":[{"type":"output_text","text":"ok"},{"type":"image","image_url":"x"}]},
	    {"role":"user","content":[{"type":"input_image","image_url":{"url":"https://example.com/b.png","detail":"high"}}]},
	    {"type":"web_search_call"}
	  ],
	  "tools":[{"type":"function","name":"bare"}],
	  "text":{"format":{"type":"json_schema","name":"Answer","schema":{"type":"object"},"strict":true,"description":"d"}},
	  "extra":true,
	  "also":1
	}`))
	if ferr != nil {
		t.Fatal(ferr)
	}
	var chat ChatRequest
	if err := json.Unmarshal(got, &chat); err != nil {
		t.Fatal(err)
	}
	if chat.User != "alice" || chat.MaxTokens == nil || *chat.MaxTokens != 16 || chat.TopP == nil {
		t.Fatalf("scalars %+v", chat)
	}
	if !bytes.Contains(chat.ResponseFormat, []byte(`"json_schema"`)) {
		t.Fatalf("format %s", chat.ResponseFormat)
	}
	if string(chat.ToolChoice) != `"none"` {
		t.Fatalf("choice %s", chat.ToolChoice)
	}
	if len(chat.Tools) != 1 || string(chat.Tools[0].Function.Parameters) == "" {
		t.Fatalf("bare tool %#v", chat.Tools)
	}
	found := false
	for _, name := range meta.Dropped {
		if name == "tool_output_non_text" || name == "input:web_search_call" {
			found = true
		}
	}
	if !found {
		t.Fatalf("dropped %#v", meta.Dropped)
	}

	weird, meta, ferr := ResponsesToChat([]byte(`{"model":"m","input":"hi","tool_choice":{"type":"other"},"input_shape":1}`))
	if ferr != nil {
		t.Fatal(ferr)
	}
	var chat2 ChatRequest
	if err := json.Unmarshal(weird, &chat2); err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(chat2.ToolChoice, []byte(`"auto"`)) {
		t.Fatalf("choice %s dropped %#v", chat2.ToolChoice, meta.Dropped)
	}

	long := stringsRepeat("x", 9000)
	body := `{"model":"m","input":"hi","tools":[{"type":"custom","name":"g","description":"d","format":{"type":"grammar","syntax":"lark","definition":"` + long + `"}}]}`
	_, _, ferr = ResponsesToChat([]byte(body))
	if ferr != nil {
		t.Fatal(ferr)
	}
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func jsonEqual(a, b []byte) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	ab, _ := json.Marshal(left)
	bb, _ := json.Marshal(right)
	return bytes.Equal(ab, bb)
}
