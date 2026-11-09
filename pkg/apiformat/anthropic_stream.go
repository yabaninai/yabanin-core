package apiformat

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	anthModeOpen = iota
	anthModeError
	anthModeStream
	anthModeJSON
)

// AnthropicStreamWriter turns a chat completion written by the gateway into
// either an Anthropic SSE stream or a single Messages JSON body.
type AnthropicStreamWriter struct {
	dst  http.ResponseWriter
	meta AnthropicMeta
	opts AnthropicOptions

	mu     sync.Mutex
	header http.Header
	mode   int
	status int
	buf    bytes.Buffer

	msgID        string
	model        string
	nextIndex    int
	textOpen     bool
	textIdx      int
	calls        []*anthCall
	byIdx        map[int]*anthCall
	finishReason string
	usage        *ChatUsage
	failed       bool
	finished     bool
	parser       SSEParser
	stopKeep     chan struct{}
	keepWG       sync.WaitGroup
	keepOnce     sync.Once
	lastWrite    time.Time
}

type anthCall struct {
	id   string
	name string
	args strings.Builder
}

// NewAnthropicWriter wraps dst. The caller must invoke Finish after the
// inner chat handler returns.
func NewAnthropicWriter(dst http.ResponseWriter, meta AnthropicMeta, opts AnthropicOptions) *AnthropicStreamWriter {
	return &AnthropicStreamWriter{
		dst:      dst,
		meta:     meta,
		opts:     opts,
		header:   make(http.Header),
		byIdx:    map[int]*anthCall{},
		stopKeep: make(chan struct{}),
	}
}

// Header returns the header map the inner chat handler fills before WriteHeader.
func (s *AnthropicStreamWriter) Header() http.Header { return s.header }

// WriteHeader records a non-200 as a buffered JSON error, or starts the
// Anthropic SSE stream when the chat handler chose text/event-stream.
func (s *AnthropicStreamWriter) WriteHeader(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode != anthModeOpen {
		return
	}
	s.status = code
	if code != http.StatusOK {
		s.mode = anthModeError
		return
	}
	if strings.Contains(s.header.Get("Content-Type"), "text/event-stream") || s.meta.Stream {
		s.startStreamLocked()
		return
	}
	s.mode = anthModeJSON
}

// Write accepts chat SSE or a buffered JSON body, depending on WriteHeader.
func (s *AnthropicStreamWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode == anthModeOpen {
		s.status = http.StatusOK
		if strings.Contains(s.header.Get("Content-Type"), "text/event-stream") || s.meta.Stream {
			s.startStreamLocked()
		} else {
			s.mode = anthModeJSON
		}
	}
	switch s.mode {
	case anthModeError, anthModeJSON:
		_, _ = s.buf.Write(p)
	case anthModeStream:
		s.feedLocked(p)
	}
	return len(p), nil
}

// Flush flushes the downstream writer once the Anthropic stream has started.
func (s *AnthropicStreamWriter) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode == anthModeStream {
		if f, ok := s.dst.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// Finish completes the translation. It is safe to call once.
func (s *AnthropicStreamWriter) Finish() {
	s.mu.Lock()
	switch s.mode {
	case anthModeOpen:
		if s.meta.Stream {
			s.startStreamLocked()
			s.finalizeLocked()
			s.forwardTrailersLocked()
		}
	case anthModeStream:
		for _, ev := range s.parser.Flush() {
			s.handleEventLocked(ev)
		}
		s.finalizeLocked()
		s.forwardTrailersLocked()
	case anthModeJSON:
		s.finishJSONLocked()
	case anthModeError:
		s.finishErrorLocked()
	}
	s.stopKeepaliveLocked()
	s.mu.Unlock()
	s.keepWG.Wait()
}

func (s *AnthropicStreamWriter) startStreamLocked() {
	if s.mode == anthModeStream {
		return
	}
	s.mode = anthModeStream
	s.status = http.StatusOK
	if s.opts.IDGen == nil {
		s.opts.IDGen = NewID
	}
	s.msgID = s.opts.IDGen("msg_")
	s.model = s.meta.RequestedModel
	s.copyPassthroughLocked()
	dst := s.dst.Header()
	dst.Set("Content-Type", "text/event-stream")
	dst.Set("Cache-Control", "no-cache")
	dst.Set("X-Accel-Buffering", "no")
	s.dst.WriteHeader(http.StatusOK)
	s.emitLocked("message_start", messageStart{
		Type: "message_start",
		Message: anthMessage{
			ID:           s.msgID,
			Type:         "message",
			Role:         "assistant",
			Model:        s.model,
			Content:      []struct{}{},
			StopReason:   nil,
			StopSequence: nil,
			Usage:        anthStartUsage{},
		},
	})
	s.lastWrite = time.Now()
	s.startKeepaliveLocked()
}

type messageStart struct {
	Type    string      `json:"type"`
	Message anthMessage `json:"message"`
}

type anthMessage struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Role         string         `json:"role"`
	Model        string         `json:"model"`
	Content      []struct{}     `json:"content"`
	StopReason   *string        `json:"stop_reason"`
	StopSequence *string        `json:"stop_sequence"`
	Usage        anthStartUsage `json:"usage"`
}

type anthStartUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

func (s *AnthropicStreamWriter) startKeepaliveLocked() {
	interval := s.opts.KeepAlive
	if interval == 0 {
		interval = 15 * time.Second
	}
	if interval < 0 {
		return
	}
	tick := 5 * time.Second
	if interval < tick {
		tick = interval
	}
	ticker := time.NewTicker(tick)
	s.keepWG.Add(1)
	go func() {
		defer ticker.Stop()
		defer s.keepWG.Done()
		for {
			select {
			case <-s.stopKeep:
				return
			case now := <-ticker.C:
				s.mu.Lock()
				if s.finished || s.failed || s.mode != anthModeStream {
					s.mu.Unlock()
					return
				}
				if now.Sub(s.lastWrite) >= interval {
					s.emitRawLocked("ping", []byte(`{"type":"ping"}`))
				}
				s.mu.Unlock()
			}
		}
	}()
}

func (s *AnthropicStreamWriter) stopKeepaliveLocked() {
	s.keepOnce.Do(func() { close(s.stopKeep) })
}

func (s *AnthropicStreamWriter) feedLocked(p []byte) {
	if s.failed || s.finished {
		return
	}
	for _, ev := range s.parser.Feed(p) {
		s.handleEventLocked(ev)
	}
}

func (s *AnthropicStreamWriter) handleEventLocked(ev SSEEvent) {
	if s.failed || s.finished {
		return
	}
	data := strings.TrimSpace(ev.Data)
	if data == "" {
		return
	}
	if data == "[DONE]" {
		s.finalizeLocked()
		return
	}
	var chunk ChatChunk
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return
	}
	if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
		s.emitStreamErrorLocked(data)
		return
	}
	if chunk.Usage != nil {
		s.usage = chunk.Usage
	}
	if s.model == "" && chunk.Model != "" {
		s.model = chunk.Model
	}
	if len(chunk.Choices) == 0 {
		return
	}
	choice := chunk.Choices[0]
	if choice.Index != 0 {
		return
	}
	if choice.Delta.Content != nil && *choice.Delta.Content != "" {
		s.appendTextLocked(*choice.Delta.Content)
	}
	for _, call := range choice.Delta.ToolCalls {
		s.appendCallLocked(call)
	}
	if choice.FinishReason != nil && *choice.FinishReason != "" {
		s.finishReason = *choice.FinishReason
	}
}

func (s *AnthropicStreamWriter) appendTextLocked(delta string) {
	if !s.textOpen {
		s.textIdx = s.nextIndex
		s.nextIndex++
		s.textOpen = true
		s.emitLocked("content_block_start", blockStart{
			Type:  "content_block_start",
			Index: s.textIdx,
			Block: textBlock{Type: "text", Text: ""},
		})
	}
	s.emitLocked("content_block_delta", blockDelta{
		Type:  "content_block_delta",
		Index: s.textIdx,
		Delta: textDelta{Type: "text_delta", Text: delta},
	})
}

func (s *AnthropicStreamWriter) appendCallLocked(call ChunkToolCall) {
	got := s.byIdx[call.Index]
	if got == nil {
		got = &anthCall{}
		s.byIdx[call.Index] = got
		s.calls = append(s.calls, got)
	}
	if got.id == "" && call.ID != "" {
		got.id = call.ID
	}
	if got.name == "" && call.Function.Name != "" {
		got.name = call.Function.Name
	}
	if call.Function.Arguments != "" {
		got.args.WriteString(call.Function.Arguments)
	}
}

func (s *AnthropicStreamWriter) finalizeLocked() {
	if s.finished || s.failed || s.mode != anthModeStream {
		return
	}
	s.closeTextBlockLocked()
	for _, call := range s.calls {
		s.finishCallLocked(call)
	}
	usage := anthropicUsage(s.usage)
	s.emitLocked("message_delta", messageDelta{
		Type: "message_delta",
		Delta: anthStop{
			StopReason:   chatFinishToAnthropicStop(s.finishReason, len(s.calls) > 0),
			StopSequence: nil,
		},
		Usage: usage,
	})
	s.emitLocked("message_stop", messageStop{Type: "message_stop"})
	s.finished = true
	s.stopKeepaliveLocked()
}

func (s *AnthropicStreamWriter) finishCallLocked(call *anthCall) {
	idx := s.nextIndex
	s.nextIndex++
	id := call.id
	if id == "" {
		id = s.opts.IDGen("toolu_")
	}
	args := string(anthropicToolInput(call.args.String()))
	s.emitLocked("content_block_start", blockStart{
		Type:  "content_block_start",
		Index: idx,
		Block: toolUseBlock{Type: "tool_use", ID: id, Name: call.name, Input: json.RawMessage(`{}`)},
	})
	s.emitLocked("content_block_delta", blockDelta{
		Type:  "content_block_delta",
		Index: idx,
		Delta: inputDelta{Type: "input_json_delta", Partial: args},
	})
	s.emitLocked("content_block_stop", blockStop{Type: "content_block_stop", Index: idx})
}

// closeTextBlockLocked ends the open text block, if any. tool_use blocks are
// emitted atomically in finishCallLocked, so the text block is the only block
// that can be open mid-stream.
func (s *AnthropicStreamWriter) closeTextBlockLocked() {
	if !s.textOpen {
		return
	}
	s.emitLocked("content_block_stop", blockStop{Type: "content_block_stop", Index: s.textIdx})
	s.textOpen = false
}

func (s *AnthropicStreamWriter) emitStreamErrorLocked(data string) {
	if s.failed || s.finished {
		return
	}
	// Close any open content block before the terminal error so
	// Claude Code renders the partial text instead of wedging on an
	// unterminated block. Buffered (never announced) tool calls stay dropped.
	s.closeTextBlockLocked()
	s.failed = true
	var probe struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	_ = json.Unmarshal([]byte(data), &probe)
	body, _ := ToAnthropicError(openAITypeStatus(probe.Error.Type), []byte(data))
	s.emitRawLocked("error", body)
	s.finished = true
	s.stopKeepaliveLocked()
}

func openAITypeStatus(typ string) int {
	switch typ {
	case "server_error", "api_error":
		return http.StatusInternalServerError
	case "service_unavailable_error":
		return http.StatusServiceUnavailable
	case "authentication_error":
		return http.StatusUnauthorized
	case "permission_denied_error":
		return http.StatusForbidden
	case "rate_limit_exceeded":
		return http.StatusTooManyRequests
	case "not_found_error":
		return http.StatusNotFound
	default:
		return http.StatusBadRequest
	}
}

type blockStart struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Block any    `json:"content_block"`
}

type textBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolUseBlock struct {
	Type  string          `json:"type"`
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

type blockDelta struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta any    `json:"delta"`
}

type textDelta struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type inputDelta struct {
	Type    string `json:"type"`
	Partial string `json:"partial_json"`
}

type blockStop struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

type messageDelta struct {
	Type  string         `json:"type"`
	Delta anthStop       `json:"delta"`
	Usage AnthropicUsage `json:"usage"`
}

type anthStop struct {
	StopReason   string  `json:"stop_reason"`
	StopSequence *string `json:"stop_sequence"`
}

type messageStop struct {
	Type string `json:"type"`
}

func (s *AnthropicStreamWriter) emitLocked(event string, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	s.emitRawLocked(event, raw)
}

func (s *AnthropicStreamWriter) emitRawLocked(event string, raw []byte) {
	var buf bytes.Buffer
	buf.WriteString("event: ")
	buf.WriteString(event)
	buf.WriteByte('\n')
	buf.WriteString("data: ")
	buf.Write(raw)
	buf.WriteString("\n\n")
	_, _ = s.dst.Write(buf.Bytes())
	if f, ok := s.dst.(http.Flusher); ok {
		f.Flush()
	}
	s.lastWrite = time.Now()
}

func (s *AnthropicStreamWriter) finishJSONLocked() {
	if s.finished {
		return
	}
	s.finished = true
	out, err := ChatToAnthropic(s.buf.Bytes(), s.meta, s.opts)
	if err != nil {
		body, hdr := ToAnthropicError(http.StatusBadGateway, []byte(`{"error":{"message":"upstream returned no choices","type":"server_error"}}`))
		s.writeFinalLocked(http.StatusBadGateway, hdr, body)
		return
	}
	s.writeFinalLocked(http.StatusOK, nil, out)
}

func (s *AnthropicStreamWriter) finishErrorLocked() {
	if s.finished {
		return
	}
	s.finished = true
	body := s.buf.Bytes()
	code := s.status
	if code == 0 {
		code = http.StatusBadRequest
	}
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte(`{"type":"error"`)) {
		s.writeFinalLocked(code, nil, body)
		return
	}
	converted, hdr := ToAnthropicError(code, body)
	s.writeFinalLocked(code, hdr, converted)
}

func (s *AnthropicStreamWriter) writeFinalLocked(code int, extra http.Header, body []byte) {
	s.copyPassthroughLocked()
	dst := s.dst.Header()
	for key, values := range extra {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	dst.Set("Content-Type", "application/json")
	s.dst.WriteHeader(code)
	_, _ = s.dst.Write(body)
}

func (s *AnthropicStreamWriter) copyPassthroughLocked() {
	dst := s.dst.Header()
	for key, values := range s.header {
		if !passthroughHeaderKey(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// passthroughHeaderKey reports whether a private-map key belongs to the
// passthrough allowlist copied to the client writer.
func passthroughHeaderKey(key string) bool {
	return strings.HasPrefix(key, "X-Yabanin-") ||
		strings.HasPrefix(key, "X-Cache") ||
		strings.HasPrefix(key, "X-Residency-")
}

// forwardTrailersLocked delivers header entries the inner chat pipeline wrote
// after the Anthropic SSE stream opened. startStreamLocked copied the
// pre-commit passthrough set and committed the 200, so later entries land
// only in the private map. The pipeline's late writer is the prompt-cache
// outcome (pkg/gateway.setPromptCacheTrailer) carried as an
// http.TrailerPrefix key: the client ResponseWriter accepts trailer keys
// after WriteHeader and emits them at the end of the chunked body — the same
// channel the native /v1/messages relay uses. Late non-trailer passthrough
// headers are attempted too, skipping keys already delivered at stream start;
// on the live server post-commit regular header writes are dropped, on
// recording test writers they stay visible. No SSE event byte changes.
func (s *AnthropicStreamWriter) forwardTrailersLocked() {
	dst := s.dst.Header()
	for key, values := range s.header {
		if !strings.HasPrefix(key, http.TrailerPrefix) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	for key, values := range s.header {
		if !passthroughHeaderKey(key) || dst.Values(key) != nil {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
