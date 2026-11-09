package provider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// N03-P06-T04 — prompt-cache usage parsing and hint honesty.
//
// The gateway's transparency surface (X-Yabanin-Prompt-Cache) and billing are
// only honest when every adapter parses back exactly the cache-read usage its
// provider reports, and no adapter advertises a caching hint it does not
// implement. These tests pin both halves across the adapter matrix.

func TestOpenAIParseUsage_CacheReadSources(t *testing.T) {
	body := func(details, legacy string) []byte {
		usage := `{"prompt_tokens":1000,"completion_tokens":10,"total_tokens":1010`
		if details != "" {
			usage += `,"prompt_tokens_details":{"cached_tokens":` + details + `}`
		}
		if legacy != "" {
			usage += `,"prompt_cache_hit_tokens":` + legacy
		}
		usage += `}`
		return []byte(`{"id":"x","usage":` + usage + `}`)
	}

	t.Run("cached_tokens parsed", func(t *testing.T) {
		u := openAIParseUsage(body("400", ""))
		assert.Equal(t, int64(1000), u.PromptTokens)
		assert.Equal(t, int64(400), u.CacheReadTokens)
		assert.Equal(t, UsageSourceProvider, u.Source)
	})

	t.Run("legacy deepseek prompt_cache_hit_tokens fallback", func(t *testing.T) {
		u := openAIParseUsage(body("", "250"))
		assert.Equal(t, int64(250), u.CacheReadTokens, "legacy DeepSeek field must reach billing when prompt_tokens_details is absent")
		assert.Equal(t, UsageSourceProvider, u.Source)
	})

	t.Run("both present — details wins, no double count", func(t *testing.T) {
		u := openAIParseUsage(body("400", "250"))
		assert.Equal(t, int64(400), u.CacheReadTokens,
			"when a provider reports both fields they are the same value; details must win")
	})

	t.Run("legacy zero does not override", func(t *testing.T) {
		u := openAIParseUsage(body("", "0"))
		assert.Equal(t, int64(0), u.CacheReadTokens)
		assert.Equal(t, UsageSourceProvider, u.Source)
	})

	t.Run("no cache fields at all", func(t *testing.T) {
		u := openAIParseUsage(body("", ""))
		assert.Equal(t, int64(0), u.CacheReadTokens)
		assert.Equal(t, int64(1000), u.PromptTokens)
		assert.Equal(t, UsageSourceProvider, u.Source)
	})

	t.Run("missing usage object", func(t *testing.T) {
		u := openAIParseUsage([]byte(`{"id":"x","choices":[]}`))
		assert.Equal(t, UsageSourceNone, u.Source)
		assert.Zero(t, u.PromptTokens)
		assert.Zero(t, u.CacheReadTokens)
	})
}

// TestOpenAICompatAdapters_ParseCachedTokens walks every adapter the factory
// can build (anthropic has its own usage shape) and requires the cached-token
// fields to survive ParseUsage. A new OpenAI-compat adapter with a
// hand-rolled minimal parser will fail here until it delegates to
// openAIParseUsage — that is the point.
func TestOpenAICompatAdapters_ParseCachedTokens(t *testing.T) {
	names := []string{
		"", "openai", "openai-compat", "sakana", "sarvam", "krutrim", "naver",
		"falcon", "jais", "mistral", "yandex", "sber", "vllm", "ollama",
		"tgi", "llamacpp", "zai-coding", "azure-openai",
	}
	resp := []byte(`{"id":"x","choices":[],"usage":{"prompt_tokens":8000,` +
		`"completion_tokens":50,"total_tokens":8050,` +
		`"prompt_tokens_details":{"cached_tokens":2000}}}`)

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			p, err := New(name)
			require.NoError(t, err)
			u := p.ParseUsage(resp)
			assert.Equal(t, int64(8000), u.PromptTokens)
			assert.Equal(t, int64(50), u.CompletionTokens)
			assert.Equal(t, int64(2000), u.CacheReadTokens,
				"%s must parse prompt_tokens_details.cached_tokens", p.Name())
			assert.Equal(t, UsageSourceProvider, u.Source)
		})
	}
}

// TestProviderAdapters_NeverFabricateCacheHints pins the hint half of T04:
// only the anthropic adapter, whose provider implements explicit prompt
// caching, may set a cache-hint header, and only when the body actually
// carries cache_control markers. No adapter may invent markers for a body
// that has none.
//
// Header matrix excludes sber and azure-openai: their PrepareRequest dials a
// live oauth/Entra endpoint to mint a token, so they cannot be built without
// network. Neither sets cache headers by inspection (sber.go, azure_openai.go
// — Bearer auth only), and their request construction has no body-dependent
// branches.
func TestProviderAdapters_NeverFabricateCacheHints(t *testing.T) {
	names := []string{
		"", "openai", "openai-compat", "anthropic", "sakana", "sarvam",
		"krutrim", "naver", "falcon", "jais", "mistral", "yandex",
		"vllm", "ollama", "tgi", "llamacpp", "zai-coding",
	}
	hintedBody := []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`)
	plainBody := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			p, err := New(name)
			require.NoError(t, err)
			isAnthropic := p.Name() == "anthropic"

			t.Run("unhinted body gains no markers", func(t *testing.T) {
				out, err := p.TranslateRequest(plainBody)
				require.NoError(t, err)
				assert.NotContains(t, string(out), "cache_control",
					"%s must not fabricate cache_control for an unhinted body", p.Name())
			})

			t.Run("headers", func(t *testing.T) {
				// Most adapters pass bodies through unchanged, so the hinted
				// body proves headers stay clean even when markers are
				// present. tgi validates string-content bodies and cannot
				// represent markers at all — its hint surface is inert by
				// construction, so the plain body suffices there.
				body := hintedBody
				if p.Name() == "tgi" {
					body = plainBody
				}
				// yandex ("<iam>|<folder>") and naver ("<clova>|<apigw>")
				// validate their composite credential shape before building
				// the request; any well-formed dummy pair passes validation.
				credFor := func(provider string) string {
					switch provider {
					case "yandex":
						return "dummy-iam|dummy-folder"
					case "naver":
						return "dummy-clova|dummy-apigw"
					default:
						return "dummy"
					}
				}
				req, err := p.PrepareRequest(context.Background(), "http://up.test", p.Path(false), body, credFor(p.Name()), false)
				require.NoError(t, err)
				for key, vals := range req.Header {
					for _, v := range vals {
						mention := strings.Contains(strings.ToLower(key), "cache") ||
							strings.Contains(strings.ToLower(v), "prompt-caching")
						if isAnthropic {
							if mention {
								assert.Equal(t, "Anthropic-Beta", key)
								assert.Equal(t, "prompt-caching-2024-07-31", v)
							}
							continue
						}
						assert.False(t, mention,
							"%s must not advertise a cache hint it does not implement: %s: %s", p.Name(), key, v)
					}
				}
				if isAnthropic {
					assert.Equal(t, "prompt-caching-2024-07-31", req.Header.Get("Anthropic-Beta"),
						"anthropic adapter sets the caching beta header for a hinted body")
				}
			})
		})
	}
}

// TestOpenAIParseUsage_UnmarshalSafety guards against malformed bodies.
func TestOpenAIParseUsage_UnmarshalSafety(t *testing.T) {
	assert.NotPanics(t, func() { _ = openAIParseUsage([]byte(`not json`)) })
	var u Usage
	_ = json.Unmarshal([]byte(`{}`), &u)
	assert.Zero(t, u.CacheReadTokens)
}

// TestOpenAIParseUsage_MalformedCacheFields_NoFabricatedCredit (N03-P06-T05)
// pins the defensive half of the savings promise: a provider replying with a
// wrong JSON type in a cache field must yield zero cache-read tokens — no
// panic, no fabricated credit, and the known token fields still parse.
func TestOpenAIParseUsage_MalformedCacheFields_NoFabricatedCredit(t *testing.T) {
	t.Run("string cached_tokens", func(t *testing.T) {
		u := openAIParseUsage([]byte(`{"id":"x","usage":{"prompt_tokens":1000,"completion_tokens":10,` +
			`"total_tokens":1010,"prompt_tokens_details":{"cached_tokens":"most of it"}}}`))
		assert.Zero(t, u.CacheReadTokens, "a wrong-typed cached_tokens must not fabricate a credit")
		assert.Equal(t, int64(1000), u.PromptTokens, "known fields must still parse")
		assert.Equal(t, UsageSourceProvider, u.Source)
	})
	t.Run("string legacy prompt_cache_hit_tokens", func(t *testing.T) {
		u := openAIParseUsage([]byte(`{"id":"x","usage":{"prompt_tokens":1000,"completion_tokens":10,` +
			`"total_tokens":1010,"prompt_cache_hit_tokens":"lots"}}`))
		assert.Zero(t, u.CacheReadTokens)
		assert.Equal(t, int64(1000), u.PromptTokens)
		assert.Equal(t, UsageSourceProvider, u.Source)
	})
	t.Run("array prompt_tokens_details", func(t *testing.T) {
		u := openAIParseUsage([]byte(`{"id":"x","usage":{"prompt_tokens":1000,"completion_tokens":10,` +
			`"total_tokens":1010,"prompt_tokens_details":[]}}`))
		assert.Zero(t, u.CacheReadTokens)
		assert.Equal(t, int64(1000), u.PromptTokens)
	})
}
