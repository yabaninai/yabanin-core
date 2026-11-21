//go:build integration

package accounting

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fixtureReply mirrors the fixed usage the fixture reports for every served
// completion. The refusal/recovery oracles count arrivals and dispatches,
// not token math, but the fixed values keep charge-consistency checks
// meaningful when a usage row is present.
const (
	fixturePromptTokens     = 7
	fixtureCompletionTokens = 3
	fixtureAssistantContent = "fixture reply"

	// fixtureMicroUSDCost is the independently computed micro-USD cost of
	// one fixture completion under the harness's operator-installed rates
	// (2.0/6.0 per M): 7*2 + 3*6 = 32. With the harness's explicit
	// zero-markup resale provisioning, the wallet debit equals this value
	// (signed negative), not a marked-up retail price.
	fixtureMicroUSDCost = 7*2 + 3*6

	// fixtureEmbedDims is the vector dimension of fixture embeddings
	// replies. The value is arbitrary but fixed: the family controls
	// assert protocol shape, not vector semantics.
	fixtureEmbedDims = 8
)

// fixtureBody is the superset request probe the fixture decodes for every
// route. Fields beyond the chat trio feed the non-chat dispatch families
// (embeddings input, native Responses input/stream).
type fixtureBody struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Input    any    `json:"input"`
	Prompt   string `json:"prompt"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

// fixtureRecord is one ledger entry. Arrival entries are written for every
// request that reaches the provider over the wire — including unauthorized
// ones — so any provider contact (first attempt, retry or fallback hop) is
// observable.
type fixtureRecord struct {
	RequestID string    `json:"request_id"`
	Path      string    `json:"path"`
	AuthOK    bool      `json:"auth_ok"`
	At        time.Time `json:"at"`
}

// fixtureTotals is a whole-ledger snapshot. Window assertions are expressed
// as deltas between snapshots so provider contact is detected regardless of
// which request id the gateway actually forwarded — a gateway that drops or
// rewrites the correlation id still increases the totals.
type fixtureTotals struct {
	arrivals   int
	dispatches int
	receipts   int
}

// fixture is a controllable openai-compat chat-completions provider. It
// keeps three ledgers (arrivals, dispatches, receipts) as in-memory state
// mirrored to JSONL evidence files, and can hold the response of selected
// request IDs until released, which places a request durably past the
// provider's dispatch barrier while the client is still waiting.
type fixture struct {
	t         *testing.T
	listen    string
	token     string
	ledgerDir string

	mu         sync.Mutex
	arrivals   []fixtureRecord
	dispatches []fixtureRecord
	receipts   []fixtureRecord
	hold       map[string]chan struct{}
	writeErr   error

	srv *http.Server
}

// startFixture brings the provider up on a loopback port and returns it
// ready to serve. The evidence ledger directory lives under the stand's
// run-owned temp tree (outside every Git worktree).
func startFixture(t *testing.T, runDir string, token string) *fixture {
	t.Helper()
	f := &fixture{
		t:         t,
		token:     token,
		ledgerDir: filepath.Join(runDir, "fixture-ledgers"),
		hold:      map[string]chan struct{}{},
	}
	if err := os.MkdirAll(f.ledgerDir, 0o750); err != nil {
		t.Fatalf("harness: fixture ledger dir: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("harness: fixture listen: %v", err)
	}
	f.listen = ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", f.serve)
	f.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	done := make(chan struct{})
	go func() {
		close(done)
		_ = f.srv.Serve(ln)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("harness: fixture server did not start")
	}
	t.Logf("harness: fixture provider listening on http://%s", f.listen)
	return f
}

// baseURL is the upstream base URL the seeded model must point at.
func (f *fixture) baseURL() string {
	return "http://" + f.listen
}

// stop shuts the fixture listener down.
func (f *fixture) stop() {
	_ = f.srv.Close()
}

// serve implements the provider contract. Ledger order encodes the
// acceptance-relevant facts:
//
//   - arrivals: the instant the request reached the provider, before any
//     authentication decision. Any provider contact lands here.
//   - dispatches: after bearer authentication succeeded and the body was
//     accepted — the request is irrevocably dispatched from this point.
//   - receipts: after the response bytes were written back successfully.
func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	rid := r.Header.Get("X-Request-ID")
	if rid == "" {
		rid = "(no-request-id)"
	}
	authOK := r.Header.Get("Authorization") == "Bearer "+f.token
	f.append("arrivals", fixtureRecord{RequestID: rid, Path: r.URL.Path, AuthOK: authOK})
	if !authOK {
		// Provider was contacted but refused: still an arrival, never a
		// dispatch. 401 mirrors upstream behavior.
		http.Error(w, "invalid api key", http.StatusUnauthorized)
		return
	}

	var body fixtureBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.Model == "" {
		http.Error(w, "model is required", http.StatusBadRequest)
		return
	}

	f.append("dispatches", fixtureRecord{RequestID: rid, Path: r.URL.Path, AuthOK: true})

	// Hold barrier: place this request durably past dispatch with the
	// response withheld until release.
	if ch := f.holdChan(rid); ch != nil {
		<-ch
	}

	f.serveAccepted(w, r.URL.Path, rid, body)
}

func (f *fixture) serveAccepted(w http.ResponseWriter, path, rid string, body fixtureBody) {
	switch path {
	case "/v1/embeddings":
		f.serveEmbeddings(w, rid, body.Model, path)
	case "/v1/responses":
		if body.Stream {
			f.serveResponsesStream(w, rid, body.Model, path)
			return
		}
		f.serveResponsesJSON(w, rid, body.Model, path)
	case "/v1/completions":
		f.serveCompletionsJSON(w, rid, body.Model, path)
	case "/v1/moderations":
		f.serveModerationsJSON(w, rid, body.Model, path)
	case "/v1/rerank":
		f.serveRerankJSON(w, rid, body.Model, path)
	case "/v1/images/generations":
		f.serveImagesJSON(w, rid, body.Model, path)
	case "/v1/realtime":
		f.serveRealtimeStream(w, rid, body.Model, path)
	default:
		f.serveChat(w, rid, path, body)
	}
}

func (f *fixture) serveChat(w http.ResponseWriter, rid, path string, body fixtureBody) {
	if body.Stream {
		f.serveStream(w, rid, body.Model, path)
		return
	}
	f.serveChatJSON(w, rid, body.Model, path)
}

// serveChatJSON delivers the buffered chat-completions reply.
func (f *fixture) serveChatJSON(w http.ResponseWriter, rid, model, path string) {
	resp := map[string]any{
		"id":      "chatcmpl-fixture-" + rid,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": fixtureAssistantContent},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{
			"prompt_tokens":     fixturePromptTokens,
			"completion_tokens": fixtureCompletionTokens,
			"total_tokens":      fixturePromptTokens + fixtureCompletionTokens,
		},
	}
	payload, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(payload); err != nil {
		// Client is gone (e.g. killed gateway). The dispatch stands, the
		// receipt does not.
		f.t.Logf("fixture: response write failed for %s (client gone): %v", rid, err)
		return
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// serveEmbeddings delivers a protocol-valid openai-compat embeddings
// reply: a list object whose data entries carry fixed-dimension vectors,
// with the known input-token usage. Embeddings have no generated output,
// mirroring the product's out_cap=0 reservation bound for the family.
func (f *fixture) serveEmbeddings(w http.ResponseWriter, rid, model, path string) {
	vec := make([]float64, fixtureEmbedDims)
	for i := range vec {
		vec[i] = float64(i) / 10
	}
	resp := map[string]any{
		"object": "list",
		"model":  model,
		"data": []map[string]any{
			{"object": "embedding", "index": 0, "embedding": vec},
			{"object": "embedding", "index": 1, "embedding": vec},
		},
		"usage": map[string]any{
			"prompt_tokens": fixturePromptTokens,
			"total_tokens":  fixturePromptTokens,
		},
	}
	payload, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(payload); err != nil {
		f.t.Logf("fixture: embeddings write failed for %s (client gone): %v", rid, err)
		return
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// serveResponsesJSON delivers a protocol-valid native Responses reply:
// one completed response object with a message output item carrying the
// fixture text, and the known input/output token usage at the top level.
func (f *fixture) serveResponsesJSON(w http.ResponseWriter, rid, model, path string) {
	resp := map[string]any{
		"id":         "resp-fixture-" + rid,
		"object":     "response",
		"created_at": time.Now().Unix(),
		"status":     "completed",
		"model":      model,
		"output": []map[string]any{{
			"type": "message",
			"id":   "msg-fixture-" + rid,
			"role": "assistant",
			"content": []map[string]any{{
				"type":        "output_text",
				"text":        fixtureAssistantContent,
				"annotations": []any{},
			}},
		}},
		"usage": map[string]any{
			"input_tokens":  fixturePromptTokens,
			"output_tokens": fixtureCompletionTokens,
		},
	}
	payload, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(payload); err != nil {
		f.t.Logf("fixture: responses write failed for %s (client gone): %v", rid, err)
		return
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// serveResponsesStream delivers the native Responses family as SSE: a
// response.created event (input-token prefix usage, so a mid-stream break
// still bills the prefix), one output_text delta, and the terminal
// response.completed event carrying the full known usage. The stream ends
// after the terminal event — the Responses protocol has no [DONE]
// sentinel — so a clean EOF is the expected drain end. The receipt ledger
// entry is appended only after every frame was written successfully,
// keeping the ledgers comparable across families and delivery modes.
func (f *fixture) serveResponsesStream(w http.ResponseWriter, rid, model, path string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	frames := []string{
		responsesFrame("response.created", map[string]any{
			"type": "response.created",
			"response": map[string]any{
				"id": "resp-fixture-" + rid, "object": "response", "status": "in_progress", "model": model,
				"usage": map[string]any{"input_tokens": fixturePromptTokens, "output_tokens": 0},
			},
		}),
		responsesFrame("response.output_text.delta", map[string]any{
			"type":  "response.output_text.delta",
			"delta": fixtureAssistantContent,
		}),
		responsesFrame("response.completed", map[string]any{
			"type": "response.completed",
			"response": map[string]any{
				"id": "resp-fixture-" + rid, "object": "response", "status": "completed", "model": model,
				"usage": map[string]any{"input_tokens": fixturePromptTokens, "output_tokens": fixtureCompletionTokens},
			},
		}),
	}
	for _, frame := range frames {
		if _, err := w.Write([]byte(frame)); err != nil {
			f.t.Logf("fixture: responses stream write failed for %s (client gone): %v", rid, err)
			return
		}
		flusher.Flush()
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// responsesFrame encodes one named SSE event from a JSON payload.
func responsesFrame(event string, payload any) string {
	data, _ := json.Marshal(payload)
	return "event: " + event + "\ndata: " + string(data) + "\n\n"
}

// fixtureImageB64 is the deterministic base64 payload returned for image
// generations: 16 opaque bytes. The accounting contract only needs a
// non-empty decodable payload plus the known usage block.
var fixtureImageB64 = func() string {
	raw := []byte("fixture-image-bytes")
	return base64.StdEncoding.EncodeToString(raw)
}()

// serveImagesJSON delivers a protocol-valid images-generation reply: a
// created stamp, one b64_json datum and the known token usage block
// (images_endpoint.go parses exactly this shape; unpriced replies fall
// back to per-image catalog rates, which the fixture avoids by always
// carrying usage).
func (f *fixture) serveImagesJSON(w http.ResponseWriter, rid, model, path string) {
	resp := map[string]any{
		"created": time.Now().Unix(),
		"data": []map[string]any{
			{"b64_json": fixtureImageB64},
		},
		"usage": map[string]any{
			"input_tokens":  fixturePromptTokens,
			"output_tokens": fixtureCompletionTokens,
			"total_tokens":  fixturePromptTokens + fixtureCompletionTokens,
		},
	}
	payload, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(payload); err != nil {
		f.t.Logf("fixture: images write failed for %s (client gone): %v", rid, err)
		return
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// serveRealtimeStream delivers a protocol-valid realtime SSE session:
// response.created, one output_text.delta and the terminal response.done
// whose NESTED response.usage carries the known input/output tokens —
// the exact branch realtimeUsageFromEvent parses for realtime sessions.
// No [DONE] sentinel: the gateway relays the session byte-honestly.
func (f *fixture) serveRealtimeStream(w http.ResponseWriter, rid, model, path string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	frames := []string{
		responsesFrame("response.created", map[string]any{
			"type":     "response.created",
			"response": map[string]any{"id": "resp-rt-fixture-" + rid, "status": "in_progress"},
		}),
		responsesFrame("response.output_text.delta", map[string]any{
			"type":  "response.output_text.delta",
			"delta": fixtureAssistantContent,
		}),
		responsesFrame("response.done", map[string]any{
			"type": "response.done",
			"response": map[string]any{
				"id": "resp-rt-fixture-" + rid, "status": "completed",
				"usage": map[string]any{"input_tokens": fixturePromptTokens, "output_tokens": fixtureCompletionTokens},
			},
		}),
	}
	for _, frame := range frames {
		if _, err := w.Write([]byte(frame)); err != nil {
			f.t.Logf("fixture: realtime stream write failed for %s (client gone): %v", rid, err)
			return
		}
		flusher.Flush()
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// serveCompletionsJSON delivers a protocol-valid legacy text-completion
// reply with the known usage.
func (f *fixture) serveCompletionsJSON(w http.ResponseWriter, rid, model, path string) {
	resp := map[string]any{
		"id":      "cmpl-fixture-" + rid,
		"object":  "text_completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]any{{
			"index":         0,
			"text":          fixtureAssistantContent,
			"finish_reason": "stop",
		}},
		"usage": map[string]any{
			"prompt_tokens":     fixturePromptTokens,
			"completion_tokens": fixtureCompletionTokens,
			"total_tokens":      fixturePromptTokens + fixtureCompletionTokens,
		},
	}
	payload, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(payload); err != nil {
		f.t.Logf("fixture: completions write failed for %s (client gone): %v", rid, err)
		return
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// serveModerationsJSON delivers a protocol-valid moderations reply: one
// unflagged result per input with the known input-token usage.
func (f *fixture) serveModerationsJSON(w http.ResponseWriter, rid, model, path string) {
	resp := map[string]any{
		"id":    "mod-fixture-" + rid,
		"model": model,
		"results": []map[string]any{
			{"index": 0, "flagged": false, "categories": map[string]bool{}, "category_scores": map[string]float64{}},
			{"index": 1, "flagged": false, "categories": map[string]bool{}, "category_scores": map[string]float64{}},
		},
		"usage": map[string]any{
			"prompt_tokens": fixturePromptTokens,
			"total_tokens":  fixturePromptTokens,
		},
	}
	payload, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(payload); err != nil {
		f.t.Logf("fixture: moderations write failed for %s (client gone): %v", rid, err)
		return
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// serveRerankJSON delivers a protocol-valid rerank reply: relevance
// scores plus the known input-token usage (rerank has no generated
// output).
func (f *fixture) serveRerankJSON(w http.ResponseWriter, rid, model, path string) {
	resp := map[string]any{
		"id":    "rr-fixture-" + rid,
		"model": model,
		"results": []map[string]any{
			{"index": 0, "relevance_score": 0.98},
			{"index": 1, "relevance_score": 0.42},
		},
		"usage": map[string]any{
			"prompt_tokens": fixturePromptTokens,
			"total_tokens":  fixturePromptTokens,
		},
	}
	payload, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(payload); err != nil {
		f.t.Logf("fixture: rerank write failed for %s (client gone): %v", rid, err)
		return
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// serveStream delivers the same fixed completion as server-sent-events
// chunks, mirroring an openai-compat streaming response: a role frame, the
// content frame, a terminal chunk carrying the usage object, then the
// [DONE] sentinel. The receipt ledger entry is appended only after every
// frame has been written successfully, exactly like the buffered path —
// the ledgers remain comparable across delivery modes.
func (f *fixture) serveStream(w http.ResponseWriter, rid, model, path string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	frames := []string{
		streamFrame(map[string]any{"id": "chatcmpl-fixture-" + rid, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model,
			"choices": []map[string]any{{"index": 0, "delta": map[string]any{"role": "assistant"}, "finish_reason": nil}}}),
		streamFrame(map[string]any{"id": "chatcmpl-fixture-" + rid, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model,
			"choices": []map[string]any{{"index": 0, "delta": map[string]any{"content": fixtureAssistantContent}, "finish_reason": nil}}}),
		streamFrame(map[string]any{"id": "chatcmpl-fixture-" + rid, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model,
			"choices": []map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
			"usage": map[string]any{
				"prompt_tokens":     fixturePromptTokens,
				"completion_tokens": fixtureCompletionTokens,
				"total_tokens":      fixturePromptTokens + fixtureCompletionTokens,
			}}),
		"data: [DONE]\n\n",
	}
	for _, frame := range frames {
		if _, err := w.Write([]byte(frame)); err != nil {
			f.t.Logf("fixture: stream write failed for %s (client gone): %v", rid, err)
			return
		}
		flusher.Flush()
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// streamFrame encodes one SSE data frame from a JSON payload.
func streamFrame(payload any) string {
	data, _ := json.Marshal(payload)
	return "data: " + string(data) + "\n\n"
}

// holdChan returns the release channel when the request is held.
func (f *fixture) holdChan(rid string) <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ch, ok := f.hold[rid]; ok {
		return ch
	}
	return nil
}

// Hold arms the hold barrier for rid. The provider will accept and record
// the dispatch, then withhold the response until ReleaseAll.
func (f *fixture) Hold(rid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.hold[rid]; !ok {
		f.hold[rid] = make(chan struct{})
	}
}

// ReleaseAll releases every held response.
func (f *fixture) ReleaseAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for rid, ch := range f.hold {
		close(ch)
		delete(f.hold, rid)
	}
}

// Snapshot captures whole-ledger totals. Deltas between snapshots are the
// provider-contact oracle for fault windows.
func (f *fixture) Snapshot() fixtureTotals {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fixtureTotals{
		arrivals:   len(f.arrivals),
		dispatches: len(f.dispatches),
		receipts:   len(f.receipts),
	}
}

// Since returns the whole-ledger growth since the snapshot.
func (f *fixture) Since(s fixtureTotals) fixtureTotals {
	now := f.Snapshot()
	return fixtureTotals{
		arrivals:   now.arrivals - s.arrivals,
		dispatches: now.dispatches - s.dispatches,
		receipts:   now.receipts - s.receipts,
	}
}

// Counts returns the ledger counts for one request id. Used for identity
// checks (which request was dispatched); window-level contact detection
// uses Snapshot/Since totals instead.
func (f *fixture) Counts(rid string) (arrivals, dispatches, receipts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := func(recs []fixtureRecord) int {
		n := 0
		for _, r := range recs {
			if r.RequestID == rid {
				n++
			}
		}
		return n
	}
	return count(f.arrivals), count(f.dispatches), count(f.receipts)
}

// ArrivalPaths returns the upstream paths every arrival ledger entry
// recorded for rid, in order. Family controls use it to prove WHICH
// upstream protocol served the request (e.g. native /v1/responses vs the
// chat-adapted translation), not merely that contact happened.
func (f *fixture) ArrivalPaths(rid string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var paths []string
	for _, r := range f.arrivals {
		if r.RequestID == rid {
			paths = append(paths, r.Path)
		}
	}
	return paths
}

// WaitForDispatch blocks until rid has a dispatch ledger entry or the
// deadline passes. It reports whether the barrier was reached.
func (f *fixture) WaitForDispatch(rid string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, dispatches, _ := f.Counts(rid); dispatches > 0 {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// VerifyEvidence fails the test when any retained-evidence write failed or
// the on-disk ledger mirrors diverge from the in-memory oracle state. The
// oracle must never report success from state whose evidence was not
// actually retained.
func (f *fixture) VerifyEvidence() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		f.t.Fatalf("harness: fixture evidence write failed earlier: %v", f.writeErr)
	}
	for name, want := range map[string]int{
		"arrivals":   len(f.arrivals),
		"dispatches": len(f.dispatches),
		"receipts":   len(f.receipts),
	} {
		data, err := os.ReadFile(filepath.Join(f.ledgerDir, name+".jsonl"))
		if err != nil {
			f.t.Fatalf("harness: fixture evidence %s unreadable: %v", name, err)
		}
		got := 0
		for _, line := range data {
			if line == '\n' {
				got++
			}
		}
		if got != want {
			f.t.Fatalf("harness: fixture evidence %s has %d entries, oracle state has %d", name, got, want)
		}
	}
}

// append records one ledger entry in memory and mirrors it to the JSONL
// evidence file. A failed evidence write poisons the oracle and is reported
// by VerifyEvidence.
func (f *fixture) append(name string, rec fixtureRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch name {
	case "arrivals":
		f.arrivals = append(f.arrivals, rec)
	case "dispatches":
		f.dispatches = append(f.dispatches, rec)
	case "receipts":
		f.receipts = append(f.receipts, rec)
	default:
		panic(fmt.Sprintf("fixture: unknown ledger %q", name))
	}
	line, err := json.Marshal(rec)
	if err != nil {
		if f.writeErr == nil {
			f.writeErr = fmt.Errorf("ledger %s encode: %w", name, err)
		}
		return
	}
	path := filepath.Join(f.ledgerDir, name+".jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		if f.writeErr == nil {
			f.writeErr = fmt.Errorf("ledger %s file: %w", name, err)
		}
		return
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil && f.writeErr == nil {
		f.writeErr = fmt.Errorf("ledger %s write: %w", name, err)
	}
}
