// slowmock: duration-tunable OpenAI-dialect mock upstream for the N12-P04
// long-response load profiles (card N12-P04-T03; T01 inventory gap G3).
//
// The stock deploy/mock-provider answers instantly, so no profile in the
// repo can exercise the contract's long-response arithmetic (§15 line 131:
// 30 s answers ~600 steady / ~3000 peak; a separate 120 s profile at 20 RPS
// ~2400 in flight). slowmock closes that gap: each request carries a
// per-request duration via a prompt marker,
//
//	[delay=30s] write a deterministic sentence
//	[delay=120s] write a deterministic sentence
//
// and slowmock spreads the response over that window on REAL wall-clock
// (streaming: delta frames evenly across the window, first frame ~immediate,
// terminal stop frame with usage at the end; non-streaming: sleep, then one
// JSON body). Requests without a marker use the MOCK_DELAY_MS default (0 =
// instant, matching mock-provider semantics).
//
// Honesty rules (packet negative criteria): there is no time acceleration —
// the delay is a sleep on the serving goroutine, and the profile's k6
// thresholds (dropped_iterations, completion floor) turn any generator or
// stack shortfall into a loud failure instead of a hidden rate degradation.
//
// Deliberately stdlib-only and module-isolated from the root go.mod: this is
// test tooling, not a product dependency (same isolation as
// scripts/loadtest/{matched,gatewayoverhead}).
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// delayMarker matches a leading "[delay=Ns]" request marker. Only the FIRST
// occurrence counts; later text is treated as the prompt body.
var delayMarker = regexp.MustCompile(`\[delay=(\d+(?:\.\d+)?)(ms|s|m)\]`)

// maxDelay caps any single response window. A typo'd marker must not be able
// to hold a VU forever; the contract's longest profile is 120 s.
const maxDelay = 10 * time.Minute

// chunkCadence is the target interval between SSE delta frames. The frames
// act as natural heartbeats for long windows; the count is derived from the
// delay and clamped so tiny delays still stream a handful of frames.
const chunkCadence = 750 * time.Millisecond

const minChunks = 4
const maxChunks = 4096

// ChatCompletionRequest matches OpenAI's /v1/chat/completions (the subset
// the gateway forwards).
type ChatCompletionRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream,omitempty"`
}

// ContentPart represents a single content part in multimodal OpenAI format.
type ContentPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Message is a single chat message; Content is a string or a content-part
// array (same dialect as deploy/mock-provider).
type Message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

// StringContent extracts the text of Content regardless of its shape.
func (m Message) StringContent() string {
	switch v := m.Content.(type) {
	case string:
		return v
	case []interface{}:
		var sb strings.Builder
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				if t, ok := m["type"].(string); ok && t == "text" {
					if text, ok := m["text"].(string); ok {
						sb.WriteString(text)
						sb.WriteString(" ")
					}
				}
			}
		}
		return sb.String()
	}
	return ""
}

// Usage contains token usage information.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// lastUserText returns the text of the last user message ("" if none).
func lastUserText(req ChatCompletionRequest) string {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			return req.Messages[i].StringContent()
		}
	}
	return ""
}

// parseDelay extracts the response window from the prompt marker, falling
// back to def. The value is clamped to [0, maxDelay].
func parseDelay(text string, def time.Duration) time.Duration {
	m := delayMarker.FindStringSubmatch(text)
	if m == nil {
		return def
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil || n < 0 {
		return def
	}
	switch m[2] {
	case "ms":
		n = n / 1000
	case "m":
		n = n * 60
	}
	d := time.Duration(n * float64(time.Second))
	if d > maxDelay {
		d = maxDelay
	}
	return d
}

// stripMarker removes every delay marker from the text so control syntax
// never leaks into canned responses or usage counts.
func stripMarker(text string) string {
	return strings.TrimSpace(delayMarker.ReplaceAllString(text, ""))
}

// response builds the deterministic canned reply (plain requests).
func response(req ChatCompletionRequest, text string) map[string]any {
	clean := stripMarker(text)
	return map[string]any{
		"id":      "chatcmpl-slowmock",
		"object":  "chat.completion",
		"created": 1720000000,
		"model":   req.Model,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": "Slow mock response to: " + clean},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{
			"prompt_tokens":     len(clean),
			"completion_tokens": 16,
			"total_tokens":      len(clean) + 16,
		},
	}
}

// chunkCount derives the number of delta frames for a window.
func chunkCount(delay time.Duration) int {
	if delay <= 0 {
		return minChunks
	}
	n := int(delay / chunkCadence)
	if n < minChunks {
		n = minChunks
	}
	if n > maxChunks {
		n = maxChunks
	}
	return n
}

// streamInterval is the gap between delta frames for a window.
func streamInterval(delay time.Duration, chunks int) time.Duration {
	if chunks <= 1 || delay <= 0 {
		return 0
	}
	return delay / time.Duration(chunks)
}

// writeJSON answers non-streaming requests: hold the window, then emit the
// full body at once.
func writeJSON(w http.ResponseWriter, req ChatCompletionRequest, delay time.Duration) {
	if delay > 0 {
		time.Sleep(delay)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response(req, lastUserText(req)))
}

// writeSSE answers streaming requests: delta frames spread across the whole
// window (first frame ~immediately — the shape a real streaming LLM has),
// a terminal stop frame with usage, then [DONE]. Every frame is flushed so
// intermediaries (the gateway) pipe bytes through as they arrive.
func writeSSE(w http.ResponseWriter, req ChatCompletionRequest, delay time.Duration) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	text := lastUserText(req)
	chunks := chunkCount(delay)
	interval := streamInterval(delay, chunks)
	for i := 0; i < chunks; i++ {
		if i > 0 && interval > 0 {
			time.Sleep(interval)
		}
		fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-slowmock\",\"object\":\"chat.completion.chunk\",\"created\":1720000000,\"model\":%q,\"choices\":[{\"index\":0,\"delta\":{\"content\":\" tok%d\"},\"finish_reason\":null}]}\n\n", req.Model, i)
		flusher.Flush()
	}
	// The stop frame lands at (chunks × interval) ≈ the full window, so a
	// streamed response genuinely takes `delay` wall-clock end to end.
	if interval > 0 {
		time.Sleep(interval)
	}
	fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-slowmock\",\"object\":\"chat.completion.chunk\",\"created\":1720000000,\"model\":%q,\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":%d,\"completion_tokens\":16,\"total_tokens\":%d}}\n\n", req.Model, len(text), len(text)+16)
	flusher.Flush()
	fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func main() {
	port := os.Getenv("MOCK_SLOWMOCK_PORT")
	if port == "" {
		port = "8081"
	}
	defDelay := time.Duration(0)
	if raw := os.Getenv("MOCK_DELAY_MS"); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms >= 0 {
			defDelay = time.Duration(ms) * time.Millisecond
		} else {
			log.Printf("invalid MOCK_DELAY_MS %q — default delay disabled", raw)
		}
	}

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":           "ok",
			"goroutines":       runtime.NumGoroutine(), // in-flight holds are visible in probes
			"default_delay_ms": defDelay.Milliseconds(),
		})
	})

	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req ChatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}
		delay := parseDelay(lastUserText(req), defDelay)
		if req.Stream {
			writeSSE(w, req, delay)
			return
		}
		writeJSON(w, req, delay)
	})

	// Long holds must survive client disconnects: a sleeping goroutine whose
	// peer vanished still finishes its window and exits (bounded by maxDelay),
	// so no unbounded goroutine growth is possible even under churn.
	addr := ":" + port
	log.Printf("slowmock listening on %s (default delay %s, max %s)", addr, defDelay, maxDelay)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
