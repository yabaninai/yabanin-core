package embeddings

// N03-P04-T03: multilingual domain and context qualifier separation.
//
// These tests pin the qualifier primitives the semantic cache leans on:
// ScriptQualifier must be deterministic and must separate the major writing
// systems (a ru↔en near-duplicate pair must classify differently, or the
// cache-level guarantee below has no foundation); the prefix and space
// builders must be identity functions on an empty tag so qualifier-blind
// embedders keep the exact N03-P04-T02 behavior; the HTTP client's static
// ContextQualifier must change the space version while an empty one keeps
// the T02 format byte-identical.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScriptQualifier_DeterministicAndDiscriminating(t *testing.T) {
	en := "What is the deadline for filing the quarterly report submitted on 2025-03-31?"
	ru := "Какой срок подачи квартального отчёта, отправленного 31.03.2025?"
	ja := "四半期報告の締め切りはいつですか"
	ko := "분기 보고서 마감일이 언제인지 알려주세요"
	ar := "ما هو الموعد النهائي لتقديم التقرير الفصلي؟"

	testCases := []struct {
		name string
		text string
		want string
	}{
		{"empty", "", "none"},
		{"digits and punctuation only", "2025-03-31!!! ... 42?", "none"},
		{"english", en, "latn"},
		{"russian", ru, "cyrl"},
		{"japanese (kana-dominant sentence)", ja, "kana"},
		{"han-dominant japanese", "四半期報告書", "hani"},
		{"korean", ko, "hang"},
		{"arabic", ar, "arab"},
		{"mixed tie", "Привет museum", "mix"},
		{"dominant script wins with latin noise", ru + " org: 8f14e45f (ref)", "cyrl"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScriptQualifier(tc.text)
			assert.Equal(t, tc.want, got)
			// Determinism: same bytes, same answer, always.
			for i := 0; i < 3; i++ {
				assert.Equal(t, got, ScriptQualifier(tc.text))
			}
		})
	}

	// The card's core negative: a ru↔en near-duplicate PAIR must land in
	// different qualifiers, whatever the embedder later claims about vector
	// similarity.
	assert.NotEqual(t, ScriptQualifier(en), ScriptQualifier(ru),
		"cross-language near-duplicates must not share a qualifier space")
}

func TestQualifierInputPrefix_EmptyTagIsIdentity(t *testing.T) {
	assert.Empty(t, QualifierInputPrefix(""), "an empty tag must not change the input bytes (pre-T03 behavior)")
	assert.Equal(t, "[q:cyrl] prompt", QualifierInputPrefix("cyrl")+"prompt")
}

func TestQualifiedSpaceVersion_EmptyTagPreservesBase(t *testing.T) {
	// Empty tag must be the exact identity function: qualifier-blind
	// embedders and pre-T03 entries keep their T02 space version.
	assert.Equal(t, "emb1:abcd1234", QualifiedSpaceVersion("emb1:abcd1234", ""))
	assert.Equal(t, "emb1:abcd1234|q:latn", QualifiedSpaceVersion("emb1:abcd1234", "latn"))
	assert.Equal(t, "emb1:abcd1234|q:cyrl", QualifiedSpaceVersion("emb1:abcd1234", "cyrl"))
	assert.NotEqual(t,
		QualifiedSpaceVersion("emb1:abcd1234", "latn"),
		QualifiedSpaceVersion("emb1:abcd1234", "cyrl"),
		"different qualifiers must never resolve to the same space")
}

// qualifierRoundTrip is the cache-side contract in miniature: the same text
// qualified twice yields the same input and space; different texts (ru vs en)
// yield different spaces.
func TestQualifier_ComposedSpaceAndPrefixContract(t *testing.T) {
	base := "emb1:deadbeef"
	for _, text := range []string{"hello world", "Привет мир", "こんにちは世界"} {
		tag := ScriptQualifier(text)
		input1 := QualifierInputPrefix(tag) + text
		input2 := QualifierInputPrefix(ScriptQualifier(text)) + text
		assert.Equal(t, input1, input2, "input construction must be deterministic")
		assert.Equal(t,
			QualifiedSpaceVersion(base, tag),
			QualifiedSpaceVersion(base, ScriptQualifier(text)),
			"space construction must be deterministic")
		assert.True(t, strings.HasPrefix(input1, "[q:"), "qualified input must carry the qualifier prefix")
	}
}

func TestHTTPClient_InputQualifierTag_Gating(t *testing.T) {
	ru := "Какой срок подачи квартального отчёта?"

	// Disabled (default): qualifier-blind — the exact pre-T03 behavior.
	off := NewHTTPClient(Config{BaseURL: "http://embedder:8000", Model: "BAAI/bge-small-en-v1.5"})
	assert.Empty(t, off.InputQualifierTag(ru))
	assert.Empty(t, off.InputQualifierTag("hello"))

	// Enabled: script tag, deterministic per input.
	on := NewHTTPClient(Config{BaseURL: "http://embedder:8000", Model: "BAAI/bge-small-en-v1.5", QualifyScripts: true})
	assert.Equal(t, "cyrl", on.InputQualifierTag(ru))
	assert.Equal(t, "latn", on.InputQualifierTag("hello world"))
	ruTag := on.InputQualifierTag(ru)
	assert.Equal(t, "cyrl", ruTag, "repeated derivation of the same input must stay stable")

	// Domain-bound: same script, different context domain — still distinct.
	domain := NewHTTPClient(Config{BaseURL: "http://embedder:8000", Model: "BAAI/bge-small-en-v1.5", QualifyScripts: true, ContextQualifier: "support-billing"})
	assert.Equal(t, "cyrl;d:support-billing", domain.InputQualifierTag(ru))
	assert.NotEqual(t, on.InputQualifierTag(ru), domain.InputQualifierTag(ru))

	// Interface satisfaction for both configurations (the cache uses one
	// type assertion).
	var _ InputQualifier = off
	var _ InputQualifier = domain
}

func TestHTTPClient_SpaceVersion_ContextQualifierParticipation(t *testing.T) {
	baseCfg := Config{BaseURL: "http://embedder:8000", Model: "BAAI/bge-small-en-v1.5"}

	// Empty ContextQualifier keeps the exact N03-P04-T02 identity: same
	// inputs as a T02-era config must resolve to the same version.
	t02 := NewHTTPClient(baseCfg)
	empty := NewHTTPClient(Config{BaseURL: baseCfg.BaseURL, Model: baseCfg.Model, ContextQualifier: ""})
	require.Equal(t, t02.SpaceVersion(), empty.SpaceVersion())
	assert.True(t, strings.HasPrefix(t02.SpaceVersion(), "emb1:"), "version must stay namespaced")

	// A different context domain is a different space.
	billing := NewHTTPClient(Config{BaseURL: baseCfg.BaseURL, Model: baseCfg.Model, ContextQualifier: "support-billing"})
	assert.NotEqual(t, t02.SpaceVersion(), billing.SpaceVersion())

	legal := NewHTTPClient(Config{BaseURL: baseCfg.BaseURL, Model: baseCfg.Model, ContextQualifier: "support-legal"})
	assert.NotEqual(t, billing.SpaceVersion(), legal.SpaceVersion(),
		"two context domains of the same model must not share one space")

	// QualifyScripts alone (per-input qualifiers) must NOT change the static
	// space version — the per-input tag enters identity per prompt, not per
	// client.
	scripts := NewHTTPClient(Config{BaseURL: baseCfg.BaseURL, Model: baseCfg.Model, QualifyScripts: true})
	assert.Equal(t, t02.SpaceVersion(), scripts.SpaceVersion())
}

// TestHTTPClient_QualifiedEmbedStillSendsPrefix proves the qualifier prefix
// reaches the embedding service as part of the input when the caller builds
// the input through QualifierInputPrefix (the cache contract), and that a
// qualifier-blind config sends the input unchanged.
func TestHTTPClient_QualifiedEmbedStillSendsPrefix(t *testing.T) {
	var gotInput string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req EmbeddingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		gotInput, _ = req.Input.(string)
		resp := EmbeddingResponse{
			Data:  []EmbeddingData{{Index: 0, Embedding: []float32{1}, Object: "embedding"}},
			Model: req.Model,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	prompt := "Какой срок подачи отчёта?"
	on := NewHTTPClient(Config{BaseURL: srv.URL, Model: "m", QualifyScripts: true})
	_, err := on.Embed(context.Background(), QualifierInputPrefix("cyrl")+prompt)
	require.NoError(t, err)
	assert.Equal(t, "[q:cyrl] "+prompt, gotInput, "the qualifier prefix must reach the embedder as part of the input")

	off := NewHTTPClient(Config{BaseURL: srv.URL, Model: "m"})
	_, err = off.Embed(context.Background(), prompt)
	require.NoError(t, err)
	assert.Equal(t, prompt, gotInput, "qualifier-blind config must send the input unchanged")
}
