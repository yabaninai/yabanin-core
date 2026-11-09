package apiformat

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/metrics"
)

const (
	respModeOpen = iota
	respModeError
	respModeStream
	respModeJSON
)

// ResponsesStreamWriter turns a chat completion written by the gateway into
// either a Responses SSE stream or a single Responses JSON body.
type ResponsesStreamWriter struct {
	dst  http.ResponseWriter
	meta ResponsesMeta
	opts ResponsesOptions

	mu     sync.Mutex
	header http.Header
	mode   int
	status int
	buf    bytes.Buffer

	seq          int
	respID       string
	created      int64
	model        string
	text         *respText
	calls        []*respCall
	byIdx        map[int]*respCall
	nextOutIdx   int
	finishReason string
	usage        *ChatUsage
	output       []json.RawMessage
	failed       bool
	finished     bool
	parser       SSEParser
	stopKeep     chan struct{}
	keepWG       sync.WaitGroup
	keepOnce     sync.Once
	lastWrite    time.Time
}

type respText struct {
	id     string
	outIdx int
	b      strings.Builder
}

type respCall struct {
	callID string
	name   string
	args   strings.Builder
}

// NewResponsesWriter wraps dst. The caller must invoke Finish after the
// inner chat handler returns.
func NewResponsesWriter(dst http.ResponseWriter, meta ResponsesMeta, opts ResponsesOptions) *ResponsesStreamWriter {
	return &ResponsesStreamWriter{
		dst:      dst,
		meta:     meta,
		opts:     opts,
		header:   make(http.Header),
		byIdx:    map[int]*respCall{},
		stopKeep: make(chan struct{}),
	}
}

// Header returns the header map the inner chat handler fills before WriteHeader.
func (s *ResponsesStreamWriter) Header() http.Header { return s.header }

// WriteHeader records a non-200 as a buffered JSON error, or starts the
// Responses SSE stream when the chat handler chose text/event-stream.
func (s *ResponsesStreamWriter) WriteHeader(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode != respModeOpen {
		return
	}
	s.status = code
	if code != http.StatusOK {
		s.mode = respModeError
		return
	}
	if strings.Contains(s.header.Get("Content-Type"), "text/event-stream") || s.meta.Stream {
		s.startStreamLocked()
		return
	}
	s.mode = respModeJSON
}

func (s *ResponsesStreamWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode == respModeOpen {
		s.status = http.StatusOK
		if strings.Contains(s.header.Get("Content-Type"), "text/event-stream") || s.meta.Stream {
			s.startStreamLocked()
		} else {
			s.mode = respModeJSON
		}
	}
	switch s.mode {
	case respModeError, respModeJSON:
		_, _ = s.buf.Write(p)
	case respModeStream:
		s.feedLocked(p)
	}
	return len(p), nil
}

// Flush flushes the downstream writer once the Responses stream has started.
func (s *ResponsesStreamWriter) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode == respModeStream {
		if f, ok := s.dst.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// Finish completes the translation. It is safe to call once.
func (s *ResponsesStreamWriter) Finish() {
	s.mu.Lock()
	switch s.mode {
	case respModeOpen:
		if s.meta.Stream {
			s.startStreamLocked()
			s.finalizeLocked()
		}
	case respModeStream:
		for _, ev := range s.parser.Flush() {
			s.handleEventLocked(ev)
		}
		s.finalizeLocked()
	case respModeJSON:
		s.finishJSONLocked()
	case respModeError:
		s.finishErrorLocked()
	}
	s.stopKeepaliveLocked()
	s.mu.Unlock()
	s.keepWG.Wait()
}

func (s *ResponsesStreamWriter) startStreamLocked() {
	if s.mode == respModeStream {
		return
	}
	s.mode = respModeStream
	s.status = http.StatusOK
	if s.opts.IDGen == nil {
		s.opts.IDGen = NewID
	}
	if s.opts.Now == nil {
		s.opts.Now = time.Now
	}
	s.respID = s.opts.IDGen("resp_")
	s.created = s.opts.Now().Unix()
	s.model = s.meta.RequestedModel
	dst := s.dst.Header()
	for key, values := range s.header {
		if strings.HasPrefix(key, "X-Yabanin-") || strings.HasPrefix(key, "X-Cache") || strings.HasPrefix(key, "X-Residency-") {
			for _, value := range values {
				dst.Add(key, value)
			}
		}
	}
	dst.Set("Content-Type", "text/event-stream")
	dst.Set("Cache-Control", "no-cache")
	dst.Set("X-Accel-Buffering", "no")
	s.dst.WriteHeader(http.StatusOK)
	s.emitLocked("response.created", map[string]any{"response": s.snapshotLocked("in_progress", nil)})
	s.emitLocked("response.in_progress", map[string]any{"response": s.snapshotLocked("in_progress", nil)})
	s.lastWrite = time.Now()
	s.startKeepaliveLocked()
}

func (s *ResponsesStreamWriter) startKeepaliveLocked() {
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
			case <-ticker.C:
				s.mu.Lock()
				if s.finished || s.mode != respModeStream {
					s.mu.Unlock()
					return
				}
				if time.Since(s.lastWrite) >= interval {
					_, _ = io.WriteString(s.dst, ": keepalive\n\n")
					if f, ok := s.dst.(http.Flusher); ok {
						f.Flush()
					}
					s.lastWrite = time.Now()
				}
				s.mu.Unlock()
			}
		}
	}()
}

func (s *ResponsesStreamWriter) stopKeepaliveLocked() {
	s.keepOnce.Do(func() { close(s.stopKeep) })
}

func (s *ResponsesStreamWriter) feedLocked(p []byte) {
	if s.failed || s.finished {
		return
	}
	for _, ev := range s.parser.Feed(p) {
		s.handleEventLocked(ev)
	}
}

func (s *ResponsesStreamWriter) handleEventLocked(ev SSEEvent) {
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
		metrics.SilentFailure("apiformat_stream_parse", "chunk_decode")
		return
	}
	if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
		code, msg := gatewayError(chunk.Error)
		s.emitFailedLocked(code, msg)
		return
	}
	if chunk.Usage != nil {
		s.usage = chunk.Usage
	}
	if chunk.Model != "" {
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

func (s *ResponsesStreamWriter) appendTextLocked(delta string) {
	if s.text == nil {
		s.text = &respText{id: s.opts.IDGen("msg_"), outIdx: s.nextOutIdx}
		s.nextOutIdx++
		s.emitLocked("response.output_item.added", map[string]any{
			"output_index": s.text.outIdx,
			"item": map[string]any{
				"type": "message", "id": s.text.id, "status": "in_progress", "role": "assistant", "content": []any{},
			},
		})
		s.emitLocked("response.content_part.added", map[string]any{
			"item_id": s.text.id, "output_index": s.text.outIdx, "content_index": 0,
			"part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}},
		})
	}
	s.text.b.WriteString(delta)
	s.emitLocked("response.output_text.delta", map[string]any{
		"item_id": s.text.id, "output_index": s.text.outIdx, "content_index": 0, "delta": delta, "logprobs": []any{},
	})
}

func (s *ResponsesStreamWriter) appendCallLocked(call ChunkToolCall) {
	got := s.byIdx[call.Index]
	if got == nil {
		got = &respCall{}
		s.byIdx[call.Index] = got
		s.calls = append(s.calls, got)
	}
	if got.callID == "" && call.ID != "" {
		got.callID = call.ID
	}
	if got.name == "" && call.Function.Name != "" {
		got.name = call.Function.Name
	}
	if call.Function.Arguments != "" {
		got.args.WriteString(call.Function.Arguments)
	}
}

func (s *ResponsesStreamWriter) finalizeLocked() {
	if s.finished || s.failed || s.mode != respModeStream {
		return
	}
	if s.text != nil {
		full := s.text.b.String()
		s.emitLocked("response.output_text.done", map[string]any{
			"item_id": s.text.id, "output_index": s.text.outIdx, "content_index": 0, "text": full, "logprobs": []any{},
		})
		part := map[string]any{"type": "output_text", "text": full, "annotations": []any{}}
		s.emitLocked("response.content_part.done", map[string]any{
			"item_id": s.text.id, "output_index": s.text.outIdx, "content_index": 0, "part": part,
		})
		item := map[string]any{
			"type": "message", "id": s.text.id, "status": "completed", "role": "assistant",
			"content": []any{part},
		}
		s.emitLocked("response.output_item.done", map[string]any{"output_index": s.text.outIdx, "item": item})
		s.output = append(s.output, mustObject(item))
	}
	for _, call := range s.calls {
		s.finishCallLocked(call)
	}
	status := "completed"
	event := "response.completed"
	var incomplete json.RawMessage = []byte("null")
	if s.finishReason == "length" {
		status = "incomplete"
		event = "response.incomplete"
		incomplete = json.RawMessage(`{"reason":"max_output_tokens"}`)
	}
	s.emitLocked(event, map[string]any{"response": s.snapshotLocked(status, incomplete)})
	s.finished = true
	s.stopKeepaliveLocked()
}

func (s *ResponsesStreamWriter) finishCallLocked(call *respCall) {
	idx := s.nextOutIdx
	s.nextOutIdx++
	callID := call.callID
	if callID == "" {
		callID = s.opts.IDGen("call_")
	}
	args := call.args.String()
	if args == "" {
		args = "{}"
	}
	if s.meta.CustomToolNames[call.name] {
		input := customToolInput(args)
		itemID := s.opts.IDGen("ctc_")
		added := map[string]any{"type": "custom_tool_call", "id": itemID, "call_id": callID, "name": call.name, "input": ""}
		s.emitLocked("response.output_item.added", map[string]any{"output_index": idx, "item": added})
		s.emitLocked("response.custom_tool_call_input.delta", map[string]any{"item_id": itemID, "output_index": idx, "delta": input})
		s.emitLocked("response.custom_tool_call_input.done", map[string]any{"item_id": itemID, "output_index": idx, "input": input})
		done := map[string]any{"type": "custom_tool_call", "id": itemID, "call_id": callID, "name": call.name, "input": input}
		s.emitLocked("response.output_item.done", map[string]any{"output_index": idx, "item": done})
		s.output = append(s.output, mustObject(done))
		return
	}
	itemID := s.opts.IDGen("fc_")
	added := map[string]any{"type": "function_call", "id": itemID, "call_id": callID, "name": call.name, "arguments": "", "status": "in_progress"}
	s.emitLocked("response.output_item.added", map[string]any{"output_index": idx, "item": added})
	s.emitLocked("response.function_call_arguments.delta", map[string]any{"item_id": itemID, "output_index": idx, "delta": args})
	s.emitLocked("response.function_call_arguments.done", map[string]any{"item_id": itemID, "output_index": idx, "arguments": args})
	done := map[string]any{"type": "function_call", "id": itemID, "call_id": callID, "name": call.name, "arguments": args, "status": "completed"}
	s.emitLocked("response.output_item.done", map[string]any{"output_index": idx, "item": done})
	s.output = append(s.output, mustObject(done))
}

func (s *ResponsesStreamWriter) emitFailedLocked(code, message string) {
	if s.failed || s.finished {
		return
	}
	s.failed = true
	resp := s.snapshotLocked("failed", json.RawMessage("null"))
	resp["error"] = map[string]any{"code": code, "message": message}
	s.emitLocked("response.failed", map[string]any{"response": resp})
	s.finished = true
	s.stopKeepaliveLocked()
}

func (s *ResponsesStreamWriter) snapshotLocked(status string, incomplete json.RawMessage) map[string]any {
	if incomplete == nil {
		incomplete = json.RawMessage("null")
	}
	output := s.output
	if output == nil {
		output = []json.RawMessage{}
	}
	parallel := true
	if s.meta.Echo.ParallelToolCalls != nil {
		parallel = *s.meta.Echo.ParallelToolCalls
	}
	temperature := 1.0
	if s.meta.Echo.Temperature != nil {
		temperature = *s.meta.Echo.Temperature
	}
	topP := 1.0
	if s.meta.Echo.TopP != nil {
		topP = *s.meta.Echo.TopP
	}
	model := s.model
	if model == "" {
		model = s.meta.RequestedModel
	}
	return map[string]any{
		"id":                   s.respID,
		"object":               "response",
		"created_at":           s.created,
		"status":               status,
		"error":                json.RawMessage("null"),
		"incomplete_details":   incomplete,
		"instructions":         orRaw(s.meta.Echo.Instructions, "null"),
		"max_output_tokens":    maxOutput(s.meta.Echo.MaxOutputTokens),
		"model":                model,
		"output":               output,
		"parallel_tool_calls":  parallel,
		"previous_response_id": json.RawMessage("null"),
		"reasoning":            orRaw(s.meta.Echo.Reasoning, `{"effort":null,"summary":null}`),
		"store":                false,
		"temperature":          temperature,
		"text":                 orRaw(s.meta.Echo.Text, `{"format":{"type":"text"}}`),
		"tool_choice":          orRaw(s.meta.Echo.ToolChoice, `"auto"`),
		"tools":                orRaw(s.meta.Echo.Tools, "[]"),
		"top_p":                topP,
		"truncation":           "disabled",
		"usage":                responsesUsage(s.usage),
		"user":                 userRaw(s.meta.Echo.User),
		"metadata":             orRaw(s.meta.Echo.Metadata, "{}"),
	}
}

func (s *ResponsesStreamWriter) emitLocked(event string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["type"] = event
	fields["sequence_number"] = s.seq
	s.seq++
	payload, err := json.Marshal(fields)
	if err != nil {
		return
	}
	var buf bytes.Buffer
	buf.WriteString("event: ")
	buf.WriteString(event)
	buf.WriteByte('\n')
	buf.WriteString("data: ")
	buf.Write(payload)
	buf.WriteString("\n\n")
	_, _ = s.dst.Write(buf.Bytes())
	if f, ok := s.dst.(http.Flusher); ok {
		f.Flush()
	}
	s.lastWrite = time.Now()
}

func (s *ResponsesStreamWriter) finishJSONLocked() {
	if s.finished {
		return
	}
	s.finished = true
	out, err := ChatToResponses(s.buf.Bytes(), s.meta, s.opts)
	if err != nil {
		s.dst.Header().Set("Content-Type", "application/json")
		s.dst.WriteHeader(http.StatusBadGateway)
		_, _ = s.dst.Write([]byte(`{"error":{"message":"upstream returned no choices","type":"server_error","param":null,"code":"server_error"}}`))
		return
	}
	s.dst.Header().Set("Content-Type", "application/json")
	if s.status == 0 {
		s.status = http.StatusOK
	}
	s.dst.WriteHeader(s.status)
	_, _ = s.dst.Write(out)
}

func (s *ResponsesStreamWriter) finishErrorLocked() {
	if s.finished {
		return
	}
	s.finished = true
	body := normalizeResponsesError(s.buf.Bytes())
	s.dst.Header().Set("Content-Type", "application/json")
	code := s.status
	if code == 0 {
		code = http.StatusBadRequest
	}
	s.dst.WriteHeader(code)
	_, _ = s.dst.Write(body)
}

func normalizeResponsesError(body []byte) []byte {
	var env struct {
		Error struct {
			Message string  `json:"message"`
			Type    string  `json:"type"`
			Param   *string `json:"param"`
			Code    *string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) != nil || (env.Error.Message == "" && env.Error.Type == "") {
		return body
	}
	out := map[string]any{
		"error": map[string]any{
			"message": env.Error.Message,
			"type":    env.Error.Type,
			"param":   nil,
			"code":    env.Error.Code,
		},
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return body
	}
	return encoded
}

func gatewayError(raw json.RawMessage) (string, string) {
	var errBody struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	}
	if json.Unmarshal(raw, &errBody) != nil {
		return "server_error", "upstream error"
	}
	code := errBody.Code
	if code == "" {
		code = errBody.Type
	}
	if code == "" {
		code = "server_error"
	}
	if errBody.Message == "" {
		errBody.Message = "upstream error"
	}
	return code, errBody.Message
}

func mustObject(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
