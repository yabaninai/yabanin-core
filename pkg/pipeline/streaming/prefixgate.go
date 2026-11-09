package streaming

import (
	"context"
	"errors"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/reireirei/yabanin/pkg/apierrors"
	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Prefix buffer defaults (plan §2.2 п.5: 64 tokens / 500ms; both are policy
// parameters layered over these config defaults).
const (
	// DefaultPrefixTokens is the token budget of the hold-back buffer.
	DefaultPrefixTokens = 64
	// DefaultPrefixDelay bounds how long the first byte may be held.
	DefaultPrefixDelay = 500 * time.Millisecond
)

// Policy parameter keys that override the prefix defaults (see
// ParsePrefixParams).
const (
	ParamPrefixTokens  = "prefix_tokens"
	ParamPrefixDelayMS = "prefix_delay_ms"
)

// approxTokenCount approximates the token count of one delta (~4 runes per
// token — the standard BPE heuristic; CJK tokenizes denser, which errs
// toward flushing earlier, the safe direction for a guardrail buffer).
// Override TokenCounter when an org requires tokenizer-exact counts.
func approxTokenCount(s string) int {
	n := utf8.RuneCountInString(s)
	if n == 0 {
		return 0
	}
	return (n + 3) / 4
}

// PrefixConfig configures one PrefixGate.
type PrefixConfig struct {
	// MaxTokens flushes the buffer once this many tokens accumulated.
	// <= 0 disables the token threshold (delay alone bounds the hold).
	MaxTokens int
	// MaxDelay flushes at first-delta + MaxDelay even when the token budget
	// is not full. <= 0 disables the delay threshold (tokens alone bound
	// the hold).
	MaxDelay time.Duration
	// TokenCounter counts the tokens of one delta; nil → approxTokenCount.
	TokenCounter func(string) int
	// Runner executes the prefix policies (hook stream_prefix) over the
	// buffered payload. Required for Flush.
	Runner Runner
	// Meta travels to the policies (routing identity; the engine deep-clones
	// it per run).
	Meta *pipeline.RequestMeta
	// Endpoint names the gateway surface ("chat", "messages", ...).
	Endpoint string
}

// PrefixDecision is the state of the prefix stage.
type PrefixDecision string

// Prefix stage decisions.
const (
	// PrefixHold: still buffering — no policy has run yet.
	PrefixHold PrefixDecision = "hold"
	// PrefixRelease: policies passed the buffer; forward Text (possibly the
	// mutated text) and switch the stream to passthrough.
	PrefixRelease PrefixDecision = "release"
	// PrefixAbort: policies denied the buffer; terminate the stream with
	// AbortFrame before any buffered byte reaches the client.
	PrefixAbort PrefixDecision = "abort"
)

// PrefixOutcome is the fixed result of the prefix policy run.
type PrefixOutcome struct {
	// Decision: release (forward Text) or abort (terminate with AbortFrame).
	Decision PrefixDecision
	// Text is the buffer to forward when Decision is release: the original
	// buffer, or the mutated text when an enforce policy changed it
	// (Result.Mutated). Empty on abort — denied content never leaves.
	Text string
	// Result is the full engine result (findings, trace, verdict) for the
	// decision-log (OP-9) and the gateway metrics (OP-8).
	Result *pipeline.Result
	// Err carries an infrastructure failure (dead ctx, missing runner).
	// Non-nil implies Decision == abort (fail-closed).
	Err error
}

// PrefixGate buffers the stream prefix until the token or delay threshold
// fires, then runs the prefix policies once and fixes the stage decision
// (release | abort). See the package doc for the lifecycle.
//
// The gate does not own timers or I/O: the middleware drives it — Ingest
// per upstream delta, ShouldFlush after each ingest, Deadline for the
// select loop while waiting for upstream bytes, and one final Flush at
// end-of-stream (a short stream may end while still buffering). Not
// goroutine-safe: one gate per stream.
type PrefixGate struct {
	cfg    PrefixConfig
	buf    []byte
	tokens int
	first  time.Time // arrival of the first non-empty delta
	done   bool
	out    PrefixOutcome
}

// NewPrefixGate returns a gate with defaults applied for unset config
// fields (DefaultPrefixTokens / DefaultPrefixDelay / approxTokenCount).
func NewPrefixGate(cfg PrefixConfig) *PrefixGate {
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = DefaultPrefixTokens
	}
	if cfg.MaxDelay == 0 {
		cfg.MaxDelay = DefaultPrefixDelay
	}
	if cfg.TokenCounter == nil {
		cfg.TokenCounter = approxTokenCount
	}
	return &PrefixGate{cfg: cfg}
}

// Ingest appends one decoded text delta to the buffer. After the gate has
// decided (see Flushed), Ingest is a no-op — the caller switches to
// passthrough.
func (g *PrefixGate) Ingest(delta string) {
	if g.done || delta == "" {
		return
	}
	if g.first.IsZero() {
		g.first = time.Now()
	}
	g.buf = append(g.buf, delta...)
	g.tokens += g.cfg.TokenCounter(delta)
}

// Buffered returns the buffered prefix text and its approximate token count
// (telemetry / decision-log support).
func (g *PrefixGate) Buffered() (string, int) {
	return string(g.buf), g.tokens
}

// Flushed reports whether Flush already ran (the stage decision is fixed).
func (g *PrefixGate) Flushed() bool { return g.done }

// ShouldFlush reports whether a threshold fired at time now: the token
// budget is full, or the delay since the first delta elapsed. A flushed
// gate never needs another flush.
func (g *PrefixGate) ShouldFlush(now time.Time) bool {
	if g.done {
		return false
	}
	if g.cfg.MaxTokens > 0 && g.tokens >= g.cfg.MaxTokens {
		return true
	}
	if g.cfg.MaxDelay > 0 && !g.first.IsZero() && now.Sub(g.first) >= g.cfg.MaxDelay {
		return true
	}
	return false
}

// Deadline returns when the hold expires (first delta + MaxDelay) and
// whether one is armed — the middleware can select on it while waiting for
// upstream bytes instead of polling.
func (g *PrefixGate) Deadline() (time.Time, bool) {
	if g.done || g.cfg.MaxDelay <= 0 || g.first.IsZero() {
		return time.Time{}, false
	}
	return g.first.Add(g.cfg.MaxDelay), true
}

// Flush runs the prefix policies over the buffered payload and returns the
// stage outcome. It is idempotent: the first call fixes the decision, every
// later call returns the cached outcome.
//
// A cancelled caller context fail-closes: Decision abort with Err set.
// Unverified content is never forwarded, and a dead ctx must not be mapped
// to "allow" by the engine's skip semantics.
func (g *PrefixGate) Flush(ctx context.Context) PrefixOutcome {
	if g.done {
		return g.out
	}
	g.done = true
	text := string(g.buf)
	g.buf = nil
	g.out = g.run(ctx, text)
	return g.out
}

// run executes the policies over one buffer snapshot and maps the engine
// result to the stage outcome.
func (g *PrefixGate) run(ctx context.Context, text string) PrefixOutcome {
	if err := ctx.Err(); err != nil {
		return PrefixOutcome{Decision: PrefixAbort, Err: err}
	}
	if g.cfg.Runner == nil {
		return PrefixOutcome{Decision: PrefixAbort, Err: errNilRunner}
	}
	res := g.cfg.Runner.Run(ctx, &pipeline.Payload{
		Kind:     pipeline.KindStreamPrefix,
		Endpoint: g.cfg.Endpoint,
		Body:     []byte(text),
		Meta:     g.cfg.Meta,
	})
	if res == nil {
		return PrefixOutcome{Decision: PrefixAbort, Err: errors.New("streaming: prefix policy run returned no result")}
	}
	if res.Verdict == pipeline.ActionDeny {
		return PrefixOutcome{Decision: PrefixAbort, Result: res}
	}
	out := PrefixOutcome{Decision: PrefixRelease, Text: text, Result: res}
	if res.Mutated != nil {
		out.Text = payloadText(res.Mutated)
	}
	return out
}

// sseDone is the SSE stream terminator every client contract relies on.
var sseDone = []byte("data: [DONE]\n\n")

// AbortFrame renders the canonical SSE termination of a policy-aborted
// stream: the OpenAI error envelope riding a data line, followed by the
// "data: [DONE]\n\n" terminator — the same wire contract as the gateway's
// writeSSEError, so every client sees a closed stream, never a half-open
// one. The [DONE] terminator is unconditional.
func AbortFrame(message string) []byte {
	frame := apierrors.SSEErrorFrame(&apierrors.E{
		Type:    apierrors.TypeAPI,
		Code:    "policy_aborted",
		Message: message,
	})
	out := make([]byte, 0, len(frame)+len(sseDone))
	out = append(out, frame...)
	return append(out, sseDone...)
}

// ParsePrefixParams resolves the policy parameters of the prefix buffer
// over the config defaults (plan §2.2 п.5: both thresholds are policy
// parameters). Recognized keys: prefix_tokens (int), prefix_delay_ms (int).
// Unset or nil keys yield the defaults; other keys in the map are ignored
// (the middleware owns param selection). Malformed values are errors so a
// policy typo cannot silently change the buffer shape.
func ParsePrefixParams(params map[string]any) (tokens int, delay time.Duration, err error) {
	tokens, err = paramInt(params, ParamPrefixTokens, DefaultPrefixTokens)
	if err != nil {
		return 0, 0, err
	}
	ms, err := paramInt(params, ParamPrefixDelayMS, int(DefaultPrefixDelay/time.Millisecond))
	if err != nil {
		return 0, 0, err
	}
	if tokens < 0 {
		return 0, 0, errors.New("streaming: params." + ParamPrefixTokens + ": must be >= 0")
	}
	if ms < 0 {
		return 0, 0, errors.New("streaming: params." + ParamPrefixDelayMS + ": must be >= 0")
	}
	return tokens, time.Duration(ms) * time.Millisecond, nil
}

// paramInt resolves an int param with a default; accepts int, int64,
// float64 (integral) and string forms (YAML decodes scalars as int, JSON as
// float64).
func paramInt(params map[string]any, key string, def int) (int, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return def, nil
	}
	switch v := raw.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		if v != float64(int(v)) {
			return 0, errors.New("streaming: params." + key + ": must be an integer")
		}
		return int(v), nil
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, errors.New("streaming: params." + key + ": must be an integer")
		}
		return n, nil
	default:
		return 0, errors.New("streaming: params." + key + ": must be an integer")
	}
}
