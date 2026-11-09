// Package provider — streaming handlers.
//
// StreamHandler implementations read an upstream SSE response and write
// OpenAI-compatible chunks to the client. OpenAI/compat upstreams pass through
// verbatim; Anthropic events are translated in real time via the
// AnthropicStreamTranslator (P3.13a).
//
// Retry and fallback (P3.13b/c) operate only at the connection-setup phase —
// once a 200 response is received and the handler is invoked, the stream is
// committed and the handler drains it directly to the client without buffering.
package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// StreamHandler drains an upstream SSE response into an OpenAI-compatible
// client response. Implementations must:
//
//   - Flush after every write so chunks reach the client immediately
//     (streaming contract: time-to-first-token must be ~network RTT).
//   - Return Usage parsed from the stream when available.
//   - Honour ctx cancellation: when ctx is cancelled, stop reading from
//     resp.Body and return ctx.Err().
//
// Mid-stream errors (malformed events, upstream disconnect) are surfaced as
// the returned error; the caller is responsible for emitting a terminal SSE
// error event + [DONE] since partial data has already been flushed.
//
// Saw-terminal contract (H3, audit extra §R-1): a stream that ends at EOF
// without its provider terminal event ([DONE] line, anthropic message_stop,
// bedrock metadata) must return an error wrapping ErrStreamIncomplete —
// even when the handler synthesizes a client-facing [DONE] to keep the
// OpenAI wire contract. The gateway uses the error to refuse caching the
// truncated prefix and to report the run as failed instead of completed.
type StreamHandler interface {
	// HandleStream reads resp.Body to EOF, writing translated chunks to w.
	// Returns the parsed Usage (zeros when the provider doesn't report it)
	// and any error encountered after at least one successful write.
	HandleStream(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, resp *http.Response) (Usage, error)
}

// ErrStreamIncomplete marks a stream that reached EOF without its provider
// terminal event. Handlers wrap it (fmt.Errorf %w) so callers can match it
// with errors.Is; the gateway treats any drain error — this one included —
// as "incomplete": no cache write, request.failed accounting.
var ErrStreamIncomplete = errors.New("upstream stream ended without its terminal event")

// StreamOptions tunes StreamHandler construction (RM-03). The zero value
// preserves the pre-RM-03 behaviour exactly.
type StreamOptions struct {
	// SuppressUsageOnlyChunk drops the trailing `choices: []` + usage chunk
	// the gateway requested on the client's behalf via
	// stream_options.include_usage. The chunk is still parsed for Usage —
	// only the client-facing bytes are suppressed.
	SuppressUsageOnlyChunk bool
	// RequestBytes is the upstream request body length. When a stream ends
	// without provider usage, prompt tokens are estimated as ceil(RequestBytes/4).
	RequestBytes int
}

// NewStreamHandler returns the appropriate handler for the given provider.
// "anthropic" and "bedrock" get translating handlers; all others (including
// "openai" and "openai-compat") get the identity passthrough.
func NewStreamHandler(providerName, model string) StreamHandler {
	return NewStreamHandlerWithOptions(providerName, model, StreamOptions{})
}

// NewStreamHandlerWithOptions is NewStreamHandler with RM-03 stream options.
func NewStreamHandlerWithOptions(providerName, model string, opts StreamOptions) StreamHandler {
	if providerName == "anthropic" {
		return &anthropicStreamHandler{model: model, emitUsage: !opts.SuppressUsageOnlyChunk}
	}
	if providerName == "vertex" {
		// N08-P03-T02: Gemini SSE ≠ OpenAI chunks; the translating handler
		// ships with N08-P03-T03. Fail closed instead of a foreign-schema
		// passthrough (I51) — see vertex_stream.go.
		return vertexStreamTerminator{}
	}
	if providerName == "bedrock" {
		// N08-P02: Bedrock ConverseStream is binary AWS eventstream, never
		// SSE — identity passthrough would leak foreign frames to the client.
		return &bedrockStreamHandler{model: model, emitUsage: !opts.SuppressUsageOnlyChunk}
	}
	return &openAIStreamHandler{
		suppressUsageOnlyChunk: opts.SuppressUsageOnlyChunk,
		requestBytes:           opts.RequestBytes,
	}
}

// maxStreamLineBytes bounds a single SSE line. Chunks for text generation are
// small (<4 KB) but tool-call args can reach hundreds of KB. 1 MiB is the same
// bound used by the plan in P3_multi_provider.md.
const maxStreamLineBytes = 1 << 20 // 1 MiB

// openAIStreamHandler is the identity handler for OpenAI and any
// OpenAI-compatible upstream. It passes bytes through unchanged and parses
// usage from the final chunk (the only chunk that carries a usage field).
type openAIStreamHandler struct {
	// suppressUsageOnlyChunk (RM-03): when the gateway injected
	// stream_options.include_usage on the client's behalf, upstreams answer
	// with a trailing `choices: []` + usage chunk the client never asked
	// for. Set via NewStreamHandlerWithOptions to drop that chunk from the
	// client bytes while still parsing its usage.
	suppressUsageOnlyChunk bool
	requestBytes           int
}

func (h *openAIStreamHandler) HandleStream(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, resp *http.Response) (Usage, error) {
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), maxStreamLineBytes)

	// sseTerm is the per-line suffix we write. SSE framing: each line is
	// terminated by LF; frame separators are an additional empty line (LF).
	// Writing each scanned line followed by a single LF reproduces the
	// original stream byte-for-byte, including blank-line frame separators
	// (which the scanner yields as zero-length lines).
	const sseTerm = "\n"

	var usage Usage
	var completionBytes int
	lastLineEmpty := true
	sawDone := false   // H3: did the upstream carry its [DONE] terminal event?
	skipBlank := false // a suppressed usage-only chunk also eats its frame separator
	for scanner.Scan() {
		// Surface client-disconnect / ctx cancellation promptly. The next
		// resp.Body.Read would eventually error, but this avoids one more
		// upstream round-trip when the client is already gone.
		if err := ctx.Err(); err != nil {
			return usage, err
		}

		line := scanner.Bytes()
		lastLineEmpty = len(line) == 0
		if isDoneDataLine(line) {
			sawDone = true
		}

		// RM-03: the gateway-requested usage-only chunk. Parse its usage,
		// write nothing, and swallow the blank separator that follows so
		// the client sees a well-formed stream.
		if h.suppressUsageOnlyChunk && isUsageOnlyChunk(line) {
			usage = parseOpenAIChunkUsage(line, usage)
			skipBlank = true
			continue
		}
		if skipBlank {
			skipBlank = false
			if len(line) == 0 {
				continue
			}
			// Malformed upstream: next line isn't a separator — write it.
		}

		// IMPORTANT: scanner.Bytes() aliases the scanner's internal buffer.
		// We must not pass it through append() (which would mutate the
		// buffer and corrupt subsequent tokens) — write the line and the
		// terminator as separate calls instead.
		if _, err := w.Write(line); err != nil {
			return usage, fmt.Errorf("stream write failed: %w", err)
		}
		if _, err := io.WriteString(w, sseTerm); err != nil {
			return usage, fmt.Errorf("stream write failed: %w", err)
		}
		flusher.Flush()

		completionBytes += streamDeltaBytes(line)
		usage = parseOpenAIChunkUsage(line, usage)
	}

	if err := scanner.Err(); err != nil {
		// The request was accepted and the prefix was consumed upstream, so
		// the drain-failure cost is the estimate over what actually streamed
		// (contract §8.2), not zero.
		if usage.Source == "" {
			usage = estimatedStreamUsage(h.requestBytes, completionBytes)
		}
		return usage, fmt.Errorf("stream read failed: %w", err)
	}
	// Some compatible providers end with "data: [DONE]" and omit the
	// event's empty separator line. Complete that final frame so downstream
	// SSE filters can wait for full events without swallowing the terminator.
	if !lastLineEmpty {
		if _, err := io.WriteString(w, sseTerm); err != nil {
			return usage, fmt.Errorf("stream write failed: %w", err)
		}
		flusher.Flush()
	}
	if usage.Source == "" {
		usage = estimatedStreamUsage(h.requestBytes, completionBytes)
	}
	// H3 (saw-terminal contract): EOF without [DONE] means the upstream cut
	// the stream mid-flight (load balancer timeout, crash, network tear).
	// The prefix may look complete but no terminal event was seen — report
	// the run as incomplete so the gateway never caches it and never
	// accounts it as a completed request. The bytes already flushed stay
	// as-is; the gateway's drain-failure path owns the client-facing
	// error frame + [DONE].
	if !sawDone {
		return usage, fmt.Errorf("openai stream ended without [DONE] terminator: %w", ErrStreamIncomplete)
	}
	return usage, nil
}

// isDoneDataLine reports whether an SSE line is the OpenAI [DONE] terminator.
// Both "data: [DONE]" and the no-space "data:[DONE]" spelling (seen on some
// compatible upstreams) count; a [DONE]-shaped payload on any other prefix
// does not.
func isDoneDataLine(line []byte) bool {
	if startsWith(line, "data: ") {
		return equal(line[len("data: "):], []byte("[DONE]"))
	}
	if startsWith(line, "data:") {
		return equal(line[len("data:"):], []byte("[DONE]"))
	}
	return false
}

// isUsageOnlyChunk reports whether an SSE data line is the final
// usage-bearing chunk OpenAI-compatible upstreams emit when asked for
// include_usage: empty choices array plus a non-null usage object.
func isUsageOnlyChunk(line []byte) bool {
	const prefix = "data: "
	if !startsWith(line, prefix) {
		return false
	}
	payload := line[len(prefix):]
	if equal(payload, []byte("[DONE]")) {
		return false
	}
	var chunk struct {
		Choices []json.RawMessage `json:"choices"`
		Usage   json.RawMessage   `json:"usage"`
	}
	if err := json.Unmarshal(payload, &chunk); err != nil {
		return false
	}
	return len(chunk.Choices) == 0 && len(chunk.Usage) > 0 && !equal(chunk.Usage, []byte("null"))
}

// parseOpenAIChunkUsage updates usage in-place when the line is a data: line
// carrying a top-level usage object (only the final chunk in OpenAI streams).
// Errors are silently ignored — malformed lines fall through to passthrough.
func parseOpenAIChunkUsage(line []byte, prev Usage) Usage {
	const prefix = "data: "
	if !startsWith(line, prefix) {
		return prev
	}
	payload := line[len(prefix):]
	if equal(payload, []byte("[DONE]")) {
		return prev
	}
	var chunk struct {
		Usage *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
			// RM-03: OpenAI-compatible upstreams report cached prompt tokens
			// in prompt_tokens_details.cached_tokens; DeepSeek instead uses
			// the top-level-in-usage prompt_cache_hit_tokens. Both feed
			// CacheReadTokens so streaming cache hits are priced correctly.
			PromptTokensDetails *struct {
				CachedTokens int64 `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
			PromptCacheHitTokens int64 `json:"prompt_cache_hit_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(payload, &chunk); err != nil {
		return prev
	}
	if chunk.Usage == nil {
		return prev
	}
	out := Usage{
		PromptTokens:     chunk.Usage.PromptTokens,
		CompletionTokens: chunk.Usage.CompletionTokens,
		TotalTokens:      chunk.Usage.TotalTokens,
		Source:           UsageSourceProvider,
	}
	if chunk.Usage.PromptTokensDetails != nil {
		out.CacheReadTokens = chunk.Usage.PromptTokensDetails.CachedTokens
	} else if chunk.Usage.PromptCacheHitTokens > 0 {
		out.CacheReadTokens = chunk.Usage.PromptCacheHitTokens
	}
	return out
}

func streamDeltaBytes(line []byte) int {
	const prefix = "data: "
	if !startsWith(line, prefix) || equal(line[len(prefix):], []byte("[DONE]")) {
		return 0
	}
	var chunk struct {
		Choices []struct {
			Text  string `json:"text"`
			Delta struct {
				Content   json.RawMessage `json:"content"`
				ToolCalls []struct {
					Function struct {
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(line[len(prefix):], &chunk); err != nil {
		return 0
	}
	n := 0
	for _, choice := range chunk.Choices {
		n += len(choice.Text)
		if len(choice.Delta.Content) > 0 && string(choice.Delta.Content) != "null" {
			var text string
			if err := json.Unmarshal(choice.Delta.Content, &text); err == nil {
				n += len(text)
			}
		}
		for _, call := range choice.Delta.ToolCalls {
			n += len(call.Function.Arguments)
		}
	}
	return n
}

func estimatedStreamUsage(requestBytes, completionBytes int) Usage {
	prompt := ceilDiv4(requestBytes)
	completion := ceilDiv4(completionBytes)
	return Usage{
		PromptTokens:     prompt,
		CompletionTokens: completion,
		TotalTokens:      prompt + completion,
		Source:           UsageSourceEstimated,
	}
}

func ceilDiv4(n int) int64 {
	if n <= 0 {
		return 0
	}
	return int64((n + 3) / 4)
}

// anthropicStreamHandler translates Anthropic SSE events to OpenAI
// chat.completion.chunk frames in real time.
type anthropicStreamHandler struct {
	model     string
	emitUsage bool
}

func (h *anthropicStreamHandler) HandleStream(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, resp *http.Response) (usage Usage, err error) {
	// PromptTokens holds raw Anthropic input_tokens until return. Cache
	// fields are merged in as they arrive; canonical prompt is applied once.
	defer func() {
		usage = canonicalAnthropicStreamUsage(usage)
	}()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), maxStreamLineBytes)

	tr := NewAnthropicStreamTranslator(h.model)
	tr.SetEmitUsage(h.emitUsage)
	var pendingEventType string // Anthropic SSE: "event: X\n data: Y"

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return usage, err
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			// Blank line is the frame separator; the event/data pair for this
			// frame is complete. Reset pending event type.
			pendingEventType = ""
			continue
		}

		// Anthropic SSE format: "event: message_start\ndata: {...}\n\n"
		// Scanner reads one line at a time, so we accumulate the event type
		// then translate when we hit the data: line.
		if startsWith(line, "event: ") {
			pendingEventType = string(line[len("event: "):])
			continue
		}
		if startsWith(line, "id:") || startsWith(line, ":") {
			// Ignore ids and comments — not used by Anthropic Messages API.
			continue
		}

		if !startsWith(line, "data: ") {
			// Unexpected line format — skip silently rather than fail the stream.
			continue
		}
		payload := string(line[len("data: "):])
		if payload == "[DONE]" {
			// Anthropic doesn't send [DONE] but be defensive: terminate cleanly.
			if err := writeDone(w, flusher); err != nil {
				return usage, err
			}
			return usage, nil
		}

		// message_start carries input and cache usage; message_delta carries
		// the final output count (and cache fields when the upstream repeats
		// them). The translator ignores both for token accounting.
		switch pendingEventType {
		case "message_start":
			usage = mergeUsage(usage, parseAnthropicMessageStartUsage([]byte(payload)))
		case "message_delta":
			usage = mergeUsage(usage, parseAnthropicMessageDeltaUsage([]byte(payload)))
		}

		chunk, done, terr := tr.Translate(pendingEventType, payload)
		if terr != nil {
			// Don't abort the whole stream on one bad event — log via returned
			// error only if no chunks were flushed yet. For now skip silently;
			// callers can't easily distinguish recoverable vs fatal anyway.
			return usage, fmt.Errorf("translate anthropic event %q: %w", pendingEventType, terr)
		}
		if chunk != "" {
			if _, err := fmt.Fprintf(w, "data: %s\n\n", chunk); err != nil {
				return usage, fmt.Errorf("stream write failed: %w", err)
			}
			flusher.Flush()
		}
		if done {
			if err := writeDone(w, flusher); err != nil {
				return usage, err
			}
			return usage, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return usage, fmt.Errorf("stream read failed: %w", err)
	}

	// Stream ended without an explicit message_stop — the upstream truncated
	// the run (H3 saw-terminal contract). Emit [DONE] so OpenAI clients
	// terminate cleanly (the client already saw stream frames; a dangling
	// stream is worse than a synthesized terminator), but report the run as
	// incomplete: the gateway must not cache the prefix and must not account
	// it as a completed request.
	if err := writeDone(w, flusher); err != nil {
		return usage, err
	}
	return usage, fmt.Errorf("anthropic stream ended without message_stop: %w", ErrStreamIncomplete)
}

// parseAnthropicMessageDeltaUsage extracts usage from a message_delta event.
// Anthropic emits both cumulative input_tokens and the running output_tokens
// count here. Returns zero Usage on malformed payload.
func parseAnthropicMessageStartUsage(payload []byte) Usage {
	var ms struct {
		Message struct {
			Usage anthropicRawUsage `json:"usage"`
		} `json:"message"`
	}
	if err := json.Unmarshal(payload, &ms); err != nil {
		return Usage{}
	}
	return anthropicRawToUsage(ms.Message.Usage)
}

func parseAnthropicMessageDeltaUsage(payload []byte) Usage {
	var md struct {
		Usage anthropicRawUsage `json:"usage"`
	}
	if err := json.Unmarshal(payload, &md); err != nil {
		return Usage{}
	}
	return anthropicRawToUsage(md.Usage)
}

// anthropicRawUsage is the provider's native usage object. input_tokens does
// not include cache read or cache creation.
type anthropicRawUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
}

// anthropicRawToUsage keeps PromptTokens as raw input_tokens. Call
// canonicalAnthropicStreamUsage once, after the stream is fully merged.
func anthropicRawToUsage(raw anthropicRawUsage) Usage {
	return Usage{
		PromptTokens:        raw.InputTokens,
		CompletionTokens:    raw.OutputTokens,
		TotalTokens:         raw.InputTokens + raw.OutputTokens,
		CacheReadTokens:     raw.CacheReadInputTokens,
		CacheCreationTokens: raw.CacheCreationInputTokens,
		Source:              UsageSourceProvider,
	}
}

// canonicalAnthropicStreamUsage folds cache tokens into PromptTokens.
// PromptTokens must still be the raw input_tokens count.
func canonicalAnthropicStreamUsage(u Usage) Usage {
	u.PromptTokens += u.CacheReadTokens + u.CacheCreationTokens
	u.TotalTokens = u.PromptTokens + u.CompletionTokens
	if u.Source == "" {
		u.Source = UsageSourceNone
	}
	return u
}

// mergeUsage prefers non-zero fields from incoming. Anthropic streams send
// input usage on message_start and output usage on message_delta, so a
// partial update must not wipe cache fields already recorded.
func mergeUsage(prev, next Usage) Usage {
	out := prev
	if next.PromptTokens != 0 {
		out.PromptTokens = next.PromptTokens
	}
	if next.CompletionTokens != 0 {
		out.CompletionTokens = next.CompletionTokens
	}
	if next.TotalTokens != 0 {
		out.TotalTokens = next.TotalTokens
	}
	if next.CacheReadTokens != 0 {
		out.CacheReadTokens = next.CacheReadTokens
	}
	if next.CacheCreationTokens != 0 {
		out.CacheCreationTokens = next.CacheCreationTokens
	}
	if next.Source != "" {
		out.Source = next.Source
	}
	return out
}

// writeDone emits the OpenAI stream terminator. Returns the underlying write
// error so the caller can stop cleanly on client disconnect.
func writeDone(w http.ResponseWriter, flusher http.Flusher) error {
	if _, err := w.Write([]byte("data: [DONE]\n\n")); err != nil {
		return errors.New("write [DONE] failed: " + err.Error())
	}
	flusher.Flush()
	return nil
}

// startsWith is a bytes-aware strings.HasPrefix — avoids allocating a string
// for every line in the hot path.
func startsWith(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// equal reports whether two byte slices are equal. Equivalent to bytes.Equal
// but inlined to avoid the package import in the hot path.
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
