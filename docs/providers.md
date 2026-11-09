# Provider Integration Guide

## Overview

Yabanin abstracts upstream LLM APIs behind the `provider.Provider` interface (`pkg/provider/provider.go`). The interface has six methods:

| Method | Purpose |
|---|---|
| `Name()` | Canonical identifier (`"openai"`, `"anthropic"`, `"openai-compat"`) |
| `Path(stream bool)` | HTTP endpoint path (`/v1/chat/completions` or `/v1/messages`) |
| `PrepareRequest(ctx, baseURL, path, body, apiKey, stream)` | Sets URL, headers (Auth, version, beta), content-type |
| `TranslateRequest(openaiBody)` | OpenAI JSON → provider-native schema |
| `TranslateResponse(providerBody)` | Provider-native JSON → OpenAI ChatCompletion shape |
| `ParseUsage(respBody)` | Extracts prompt/completion/cache tokens |

Streaming uses the separate `StreamHandler` interface in
`pkg/provider/stream.go`; its factory selects translation or passthrough.
It is not a seventh method on `Provider`.

The adapter factory (`pkg/provider/factory.go`) resolves provider names at runtime via `New(name)`. The upstream pool (`pkg/upstream/pool.go`) creates one `*Client` per `(provider, URL)` pair, each carrying its own adapter.

### Z.AI GLM Coding Plan (`zai-coding`)

OpenAI-compatible Coding Plan adapter pinned to `https://api.z.ai/api/coding/paas/v4`. Enable with `YABANIN_ZAI_CODING_ENABLED=true`. Register models such as `glm-5.3` with `provider: zai-coding`; `upstream_url` is ignored so quota cannot leak to a PAYG or arbitrary host. Feature flag is off by default. OpenCode example: <a href="/examples/opencode.json">examples/opencode.json</a>.

---

## Adding a new provider

1. **Create the adapter** — `pkg/provider/<name>.go` implementing `Provider` with all 6 methods.
2. **Register in factory** — add a case in `New(name)` → returns your adapter.
3. **Update DB constraint** — run a migration adding the new type to `chk_provider`.
4. **Check registration surfaces** — the model CRUD carries a `provider` field, but supported-name validation and UI provider options may also need updates. Check model and BYOK validation as well as the adapter factory.
5. **Write tests** — TranslateRequest, TranslateResponse, ParseUsage, StreamHandler for every event type.
6. **Integration test** — end-to-end via `pkg/testutil/mock<name>` (see below).
7. **Add pricing** — extend `pkg/pricing/pricing.go` table with `"provider:model"` keys.

---

## Translation patterns

### System message handling

| Provider | System location |
|---|---|
| OpenAI | Inside `messages[]` as `{role:"system", content:"..."}` |
| Anthropic | Top-level `system` field (string or array with cache_control) |
| Gemini | `systemInstruction: {parts:[...]}` in request body |

### Tool format

| Provider | Schema field | Function declaration |
|---|---|---|
| OpenAI | `parameters` (JSON Schema) | `function` inside `tools[]` |
| Anthropic | `input_schema` (JSON Schema) | `input_schema` + `name`/`description` in `tools[]` |
| Gemini | N/A | `functionDeclarations[]` in contents |

### Streaming event mapping

| Provider | Native Event | OpenAI chunk equivalent |
|---|---|---|
| Anthropic | `message_start` | `{choices:[{delta:{role:"assistant", content:""}}]}` |
| Anthropic | `content_block_delta` (text) | `{choices:[{delta:{content:"..."}}]}` |
| Anthropic | `message_stop` | `data: [DONE]\n\n` |
| Anthropic | `error` | error event with message |

---

## Testing checklist for new provider

- [ ] **TranslateRequest** covers: system, multi-turn conversation, tool use, structured content, cache_control blocks
- [ ] **TranslateResponse**: single choice, multi-choice (if supported), usage section
- [ ] **ParseUsage**: prompt_tokens, completion_tokens, total, cache_read, cache_creation — all accounted
- [ ] **StreamHandler**: every native event type translated to OpenAI SSE chunks + `[DONE]` termination
- [ ] **Integration test** with mock server (`pkg/testutil/mock<name>`) — end-to-end 200 response through gateway
- [ ] **Integration error mapping**: 4xx errors → proper OpenAI error shape with `error.message` and `error.type`
- [ ] **Health probe**: the provider's `/health` or `/v1/models` endpoint is a valid health-check target
- [ ] **Pricing table** updated in `pkg/pricing/pricing.go` with current per-million-token rates

---

## Mock server pattern

Use `pkg/testutil/mockopenai` or `pkg/testutil/mockanthropic` for integration tests:

The following adapter test performs an actual HTTP request against the mock.
It tests request preparation and authentication, not the gateway's routing,
SSRF, retries or organization isolation; those need gateway-level tests.

```go
package provider_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/testutil/mockopenai"
)

func TestOpenAIRequestExample(t *testing.T) {
	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK,
		`{"id":"test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}]}`)
	server := httptest.NewServer(mock)
	defer server.Close()

	adapter, err := provider.New("openai")
	if err != nil {
		t.Fatal(err)
	}
	request, err := adapter.PrepareRequest(context.Background(), server.URL,
		adapter.Path(false),
		[]byte(`{"model":"test-model","messages":[{"role":"user","content":"ping"}]}`),
		"test-provider-key", false)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	requests := mock.Requests()
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
	if requests[0].Header.Get("Authorization") != "Bearer test-provider-key" {
		t.Fatal("unexpected authorization scheme or credential")
	}
}
```

For retries, configure `FailFirstN(2, 429, "rate limited")` before sending
requests through the retrying client. The mock itself does not retry.
For streaming, use `SetStreamMode(true)` and a body with real newline
characters, valid JSON chunks and a terminal `[DONE]` event.

The same pattern applies to `mockanthropic` — use `MessagesJSON()` or `MessagesJSONWithCache()` for response bodies.

---

## Prompt caching

For providers that support prompt caching (Anthropic):
- The adapter detects `"cache_control"` keys in message content blocks
- When present, the `anthropic-beta: prompt-caching-2024-07-31` header is automatically added by `PrepareRequest`
- Cache tokens are parsed in `ParseUsage` and billed separately via `ComputeCost` in `pkg/pricing/`
