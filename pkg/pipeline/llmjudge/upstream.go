package llmjudge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// Transport defaults for judge calls. The policy's per-step timeout still
// bounds the whole step; these bound the HTTP hop itself.
const (
	// DefaultJudgeTimeout bounds one judge HTTP round trip when neither the
	// resolved model nor the client sets a timeout.
	DefaultJudgeTimeout = 30 * time.Second
	// maxErrorBody and maxResponseBody cap how much of an upstream answer is
	// read (judge verdicts are small; error pages must not eat memory).
	maxErrorBody    = 8 << 10
	maxResponseBody = 4 << 20
)

// Target is the resolved endpoint of a judge model — the subset of
// resolver.ModelInfo the judge transport needs.
type Target struct {
	// Model is the canonical model name sent upstream (after any registry
	// alias/indirection resolution).
	Model string
	// Provider selects the upstream adapter ("openai", "anthropic", ...);
	// empty means the pool default (openai-compatible).
	Provider string
	// UpstreamURL is the model's upstream base URL (sovereign/on-prem
	// endpoints are first-class here).
	UpstreamURL string
	// Timeout, when non-zero, overrides DefaultJudgeTimeout for this model.
	Timeout time.Duration
}

// ModelResolver resolves a raw policy model reference — including
// "$(sovereign-classifier)" style indirections — into a Target. The gateway
// implements this over its normal resolver path (model registry →
// resolver.ModelInfo), so judge calls see exactly the endpoints, aliases and
// failover semantics the rest of the gateway sees. A ref without an
// indirection may be served as a literal model name.
type ModelResolver interface {
	ResolveJudgeModel(ctx context.Context, ref string) (Target, error)
}

// ModelResolverFunc adapts a function to ModelResolver.
type ModelResolverFunc func(ctx context.Context, ref string) (Target, error)

// ResolveJudgeModel implements ModelResolver.
func (f ModelResolverFunc) ResolveJudgeModel(ctx context.Context, ref string) (Target, error) {
	return f(ctx, ref)
}

// KeyResolver supplies the upstream credential for one judge call. Its
// contract mirrors the gateway's resolveUpstreamKey priority chain (org BYOK
// → per-model key → global default) so the judge uses the same credential
// mechanism as every other call — WITHOUT routing through the gateway
// struct. Implementations must never log key material; an implementation may
// return "" (public/on-prem endpoints).
type KeyResolver interface {
	ResolveJudgeKey(ctx context.Context, orgID string, target Target) (key string, err error)
}

// KeyResolverFunc adapts a function to KeyResolver.
type KeyResolverFunc func(ctx context.Context, orgID string, target Target) (string, error)

// ResolveJudgeKey implements KeyResolver.
func (f KeyResolverFunc) ResolveJudgeKey(ctx context.Context, orgID string, target Target) (string, error) {
	return f(ctx, orgID, target)
}

// DirectModelResolver is the registry-free ModelResolver for dev mode and
// tests: every reference without an indirection is treated as a literal
// model name served by one fixed upstream. "$(name)" refs are errors —
// silently sending an unresolved indirection upstream would leak policy
// internals to a provider.
type DirectModelResolver struct {
	// URL is the upstream base URL ("" → pool default).
	URL string
	// Provider selects the adapter ("" → openai-compatible).
	Provider string
}

// ResolveJudgeModel implements ModelResolver.
func (r DirectModelResolver) ResolveJudgeModel(_ context.Context, ref string) (Target, error) {
	if strings.HasPrefix(ref, "$(") {
		return Target{}, fmt.Errorf("model ref %q: indirection needs a registry-backed ModelResolver", ref)
	}
	return Target{Model: ref, Provider: r.Provider, UpstreamURL: r.URL}, nil
}

// UpstreamJudgeClient is the packaged JudgeClient: it routes judge
// chat.completions through upstream.Pool — the same HTTP machinery the
// gateway uses for client traffic (per-provider adapters, SSRF allow-list,
// mTLS, request-id propagation). Credentials come exclusively from the
// injected KeyResolver; the client itself never touches stores or config.
type UpstreamJudgeClient struct {
	pool   *upstream.Pool
	models ModelResolver
	keys   KeyResolver
}

// NewUpstreamJudgeClient builds the adapter. models and keys may be nil for
// plain openai-compatible, key-less endpoints (local models); a nil pool
// makes the client unusable.
func NewUpstreamJudgeClient(pool *upstream.Pool, models ModelResolver, keys KeyResolver) *UpstreamJudgeClient {
	return &UpstreamJudgeClient{pool: pool, models: models, keys: keys}
}

// JudgeChat implements JudgeClient. It refuses unmarked requests: the judge
// marker (IsJudgeMeta) is the recursion-exclusion contract and must survive
// every hop — the client is the last line of defense before the wire.
func (c *UpstreamJudgeClient) JudgeChat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	if !IsJudgeMeta(req.Meta) {
		return ChatResponse{}, fmt.Errorf("judge call refused: meta lacks the %s=%s marker (recursion-exclusion contract, see package doc)", MetaLabelJudge, JudgeLabelValue)
	}
	ref := req.ModelRef
	if c.models != nil {
		target, err := c.models.ResolveJudgeModel(ctx, ref)
		if err != nil {
			return ChatResponse{}, fmt.Errorf("judge model resolve: %w", err)
		}
		return c.call(ctx, req, target)
	}
	// No resolver wired: serve the ref literally through the pool default
	// (dev/test shape; DirectModelResolver semantics without the struct).
	return c.call(ctx, req, Target{Model: ref})
}

// call performs one translated chat.completions round trip against the
// pooled upstream client for target.
func (c *UpstreamJudgeClient) call(ctx context.Context, req ChatRequest, target Target) (ChatResponse, error) {
	key := ""
	if c.keys != nil {
		var err error
		key, err = c.keys.ResolveJudgeKey(ctx, req.Meta.Org, target)
		if err != nil {
			return ChatResponse{}, fmt.Errorf("judge key resolve: %w", err)
		}
	}

	cl, err := c.pool.Get(target.UpstreamURL, target.Provider)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("judge upstream client: %w", err)
	}
	prov := cl.Adapter()

	body, err := json.Marshal(buildChatBody(req, target.Model))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("judge request encode: %w", err)
	}
	native, err := prov.TranslateRequest(body)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("judge request translate: %w", err)
	}

	extra := http.Header{}
	extra.Set(JudgeHeader, JudgeLabelValue)

	timeout := target.Timeout
	if timeout <= 0 {
		timeout = DefaultJudgeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := cl.Do(ctx, prov.Path(false), native, key, false, extra)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("judge upstream call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		upErr := upstream.Error{Status: resp.StatusCode, Body: string(errBody)}
		return ChatResponse{}, fmt.Errorf("judge upstream status %d: %s", resp.StatusCode, upErr.Error())
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("judge upstream read: %w", err)
	}
	translated, err := prov.TranslateResponse(respBody)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("judge upstream translate response: %w", err)
	}
	content, err := choiceContent(translated)
	if err != nil {
		return ChatResponse{}, err
	}
	return ChatResponse{Content: content, Model: target.Model}, nil
}

// chatBody is the openai chat.completions payload sent to the judge model.
type chatBody struct {
	Model          string             `json:"model"`
	Messages       []pipeline.Message `json:"messages"`
	Temperature    float64            `json:"temperature"`
	MaxTokens      int                `json:"max_tokens,omitempty"`
	ResponseFormat *responseFormat    `json:"response_format,omitempty"`
}

type responseFormat struct {
	Type string `json:"type"`
}

// buildChatBody maps a ChatRequest onto the openai chat.completions payload
// sent to the judge model.
func buildChatBody(req ChatRequest, model string) chatBody {
	b := chatBody{
		Model:       model,
		Messages:    req.Messages,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
	}
	if req.ResponseJSON {
		b.ResponseFormat = &responseFormat{Type: "json_object"}
	}
	return b
}

// choiceContent extracts choices[0].message.content from an
// openai-shaped completion.
func choiceContent(body []byte) (string, error) {
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("judge upstream response parse: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("judge upstream response has no choices")
	}
	return resp.Choices[0].Message.Content, nil
}
