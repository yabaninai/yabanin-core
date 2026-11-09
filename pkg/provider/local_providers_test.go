package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFactory_VLLMOllamaTGI(t *testing.T) {
	for _, name := range []string{"vllm", "ollama", "tgi"} {
		p, err := New(name)
		if err != nil {
			t.Fatalf("New(%s): %v", name, err)
		}
		if p.Name() != name {
			t.Errorf("expected name %s, got %s", name, p.Name())
		}
	}
}

func TestFactory_UnknownStillErrors(t *testing.T) {
	if _, err := New("bogus"); err == nil {
		t.Error("expected error for bogus provider")
	}
}

func TestFactory_LlamaCPP(t *testing.T) {
	p, err := New("llamacpp")
	if err != nil {
		t.Fatalf("New(llamacpp): %v", err)
	}
	if p.Name() != "llamacpp" {
		t.Errorf("expected name llamacpp, got %s", p.Name())
	}
	if p.Path(false) != "/v1/chat/completions" {
		t.Errorf("unexpected non-stream path %s", p.Path(false))
	}
}

func TestVLLM_ParseUsage_FullShape(t *testing.T) {
	body := `{"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}`
	u := (VLLM{}).ParseUsage([]byte(body))
	if u.PromptTokens != 10 || u.CompletionTokens != 20 || u.TotalTokens != 30 {
		t.Errorf("unexpected usage: %+v", u)
	}
}

func TestVLLM_ParseUsage_MissingReturnsZero(t *testing.T) {
	u := (VLLM{}).ParseUsage([]byte(`{"choices":[]}`))
	if u.PromptTokens != 0 || u.TotalTokens != 0 {
		t.Errorf("expected zero usage, got %+v", u)
	}
}

func TestOllama_ParseUsage(t *testing.T) {
	body := `{"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}`
	u := (Ollama{}).ParseUsage([]byte(body))
	if u.TotalTokens != 12 {
		t.Errorf("expected 12, got %d", u.TotalTokens)
	}
}

func TestTGI_TranslateRequest_ChatToGenerate(t *testing.T) {
	in := []byte(`{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":16,"temperature":0.5}`)

	// TranslateRequest is identity: translation is stream-dependent and lives
	// in PrepareRequest (W-PROV). A translate-time conversion double-translated
	// the non-stream body (empty prompt) and corrupted the streaming shim.
	id, err := (TGI{}).TranslateRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(id) != string(in) {
		t.Fatalf("TranslateRequest must be identity, got %s", id)
	}

	req, err := (TGI{}).PrepareRequest(context.Background(), "http://tgi", "/generate", in, "", false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	inputs, _ := got["inputs"].(string)
	if inputs == "" {
		t.Error("expected non-empty inputs")
	}
	params, _ := got["parameters"].(map[string]interface{})
	if params == nil {
		t.Fatal("expected parameters map")
	}
	if params["max_new_tokens"] != float64(16) {
		t.Errorf("max_new_tokens=%v", params["max_new_tokens"])
	}

	// Streaming goes to the OpenAI-compat shim: the OpenAI body must pass
	// through untouched (no TGI inputs payload on this path).
	req, err = (TGI{}).PrepareRequest(context.Background(), "http://tgi", "/v1/chat/completions", in, "", true)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(in) {
		t.Fatalf("stream body must be the OpenAI body verbatim, got %s", body)
	}
}

func TestTGI_TranslateResponse_WrapsGeneratedText(t *testing.T) {
	providerBody := []byte(`{"generated_text":"hello there"}`)
	out, err := (TGI{}).TranslateResponse(providerBody)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Choices) != 1 || r.Choices[0].Message.Content != "hello there" {
		t.Errorf("unexpected response shape: %s", out)
	}
}

// TestFactory_LocalNearMissNamesRefused pins the packet failure scenario
// "unknown capability" at the factory boundary (contract §5 row 1): near-
// miss spellings of the local adapter names must be refused with the
// canonical `unknown provider %q` text and a nil adapter — never silently
// mapped to the OpenAI/cloud adapter (a silent fallback would send a local
// prompt to cloud with the wrong schema, credentials and billing).
func TestFactory_LocalNearMissNamesRefused(t *testing.T) {
	for _, name := range []string{
		"llama-cpp", // contract example 2's exact admin typo
		"llama.cpp",
		"llama_cpp",
		"vLLM", // the factory is exact-match: case variants are unknown
		"VLLM",
		"Ollama",
		"tgi-server",
		"openai_compatible",
	} {
		p, err := New(name)
		require.Error(t, err, "near-miss local name %q must be refused", name)
		require.Nil(t, p, "refusal must not yield a fallback adapter for %q", name)
		assert.Equal(t, fmt.Sprintf("unknown provider %q", name), err.Error(),
			"refusal text must be canonical so request-time degradation (chat.go) is diagnosable")
	}
}
