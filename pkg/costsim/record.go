// Package audit is an offline cost/savings analyzer. It ingests a customer's own
// LLM request logs (exported from any gateway or this one), computes what they
// actually spent, and estimates what semantic caching plus tier-routing would
// have saved on their traffic. It is intentionally dependency-light: the default
// path makes no network calls and does not require Postgres/Redis/an embedder.
//
// The analyzer is honest by construction: it reports only what the input data
// supports, labels every derived figure as measured or estimated, and emits
// explicit caveats where a projection is conditional (cache equivalence, routing
// acceptability). See docs/audit.md.
package audit

import (
	"strings"
	"time"
)

// CharsPerToken is the heuristic token estimate when real counts are absent.
// It mirrors estimateContextTokens in pkg/gateway/request_parse.go (one constant,
// not two). The report discloses the share of rows whose counts were estimated
// with this value.
const CharsPerToken = 4

// Record is the canonical in-memory row produced from any supported input
// format. Timestamp zero value means "unparseable/absent"; the analyzer treats
// all-zero-timestamp input as unordered and the simulation falls back to input
// order (documented in the report, not silent).
type Record struct {
	Timestamp        time.Time // zero value allowed
	Model            string
	Provider         string // inferred if absent
	Prompt           string // concatenated message content; may be empty
	PromptHash       string // filled by the analyzer, not the parser
	PromptTokens     int
	CompletionTokens int
	TokensEstimated  bool // true when counts were derived from text length
	MaxTokens        int  // 0 = not set by caller
	Temperature      float64
	TemperatureSet   bool
	StatusCode       int // 0 = unknown
	DurationMS       int // 0 = unknown
}

// EstimateTokens derives a token count from text length using CharsPerToken.
// An empty string yields 0. Callers must also set Record.TokensEstimated so the
// report can disclose the estimation share.
func EstimateTokens(text string) int {
	if text == "" {
		return 0
	}
	return len(text) / CharsPerToken
}

// providerPrefixes maps model-name prefixes to a provider. Order matters for
// first-match: more specific prefixes are checked before generic ones. An
// unmatched model yields "" (unknown), never a guess.
var providerPrefixes = []struct {
	prefix string
	prov   string
}{
	// OpenAI
	{"gpt-", "openai"},
	{"o1", "openai"},
	{"o3", "openai"},
	// Anthropic
	{"claude-", "anthropic"},
	// Google
	{"gemini-", "google"},
	// Open weights (self-hostable / non-frontier)
	{"llama", "openweights"},
	{"qwen", "openweights"},
	{"mistral", "openweights"},
	{"deepseek", "openweights"},
}

// InferProvider returns the provider implied by a model name, or "" when the
// model is unknown. A whole-file override (the --provider flag) is applied by
// the caller, not here, so this stays a pure function of the model string.
func InferProvider(model string) string {
	if model == "" {
		return ""
	}
	for _, p := range providerPrefixes {
		if strings.HasPrefix(model, p.prefix) {
			return p.prov
		}
	}
	return ""
}
