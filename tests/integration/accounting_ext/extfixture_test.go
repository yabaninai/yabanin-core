//go:build integration

// Package accountingext holds the CURRENT (non-frozen) independent
// black-box acceptance cases for invocation-aware mandatory accounting.
// It extends the frozen baseline tree (tests/integration/accounting) with:
// streamed (SSE) response modes, a second tenant org, loggerd stop/start,
// 0028-bound admission-state oracles (text org binding, resolve_reason
// contract literals) and signed wallet-delta assertions
// (pkg/credits Deduct stores amount_micro_usd as -amount for usage rows).
//
// Contract sources bound here:
//   - migrations/0028_request_invocations.up.sql (candidate lane)
//   - consumer contract record 2026-11-21-preview2-accounting-consumer.md
//     (grace default 15m; 'unresolved' + 'grace_elapsed_no_terminal_facts';
//     'reconciled' + 'event_delivered'; never back to dispatch)
package accountingext

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	extPromptTokens     = 7
	extCompletionTokens = 3
	// 7*2.0/M + 3*6.0/M = 32 micro-USD at the acceptance pricing.
	extCostMicroUSD = int64(32)
)

// chatRequest is the body the gateway accepts and the fixture answers.
type chatRequest struct {
	Model    string        `json:"model"`
	Stream   bool          `json:"stream,omitempty"`
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatChunk / chatResponse: minimal shapes the fixture emits.
type chatChunk struct {
	Choices []struct {
		Delta struct {
			Role    string `json:"role,omitempty"`
			Content string `json:"content,omitempty"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason,omitempty"`
	} `json:"choices"`
	Usage *chatUsage `json:"usage,omitempty"`
}

type chatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage chatUsage `json:"usage"`
}

// fixtureEvidence is the deterministic accounting evidence per rid.
type fixtureEvidence struct {
	Streamed         bool
	PromptTokens     int
	CompletionTokens int
}

// providerFixture is an in-memory controllable paid provider: a whole ledger
// of arrivals/dispatches/receipts keyed by correlation id, a Hold gate that
// blocks response delivery until released, and two response encodings.
type providerFixture struct {
	t   *testing.T
	srv *httptest.Server

	mu         sync.Mutex
	arrivals   map[string]int
	dispatches map[string]int
	receipts   map[string]int
	evidence   map[string]fixtureEvidence
	held       map[string]chan struct{}
	nextArr    int // total arrivals across rids (ordering aid)
	nextDisp   int
	nextRecv   int
}

func newProviderFixture(t *testing.T) *providerFixture {
	t.Helper()
	f := &providerFixture{
		t:          t,
		arrivals:   map[string]int{},
		dispatches: map[string]int{},
		receipts:   map[string]int{},
		evidence:   map[string]fixtureEvidence{},
		held:       map[string]chan struct{}{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", f.handleChat)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *providerFixture) URL() string { return f.srv.URL }

func (f *providerFixture) handleChat(w http.ResponseWriter, r *http.Request) {
	rid := r.Header.Get("X-Request-ID")
	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Messages) == 0 {
		http.Error(w, "malformed fixture request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.arrivals[rid]++
	f.nextArr++
	gate, isHeld := f.held[rid]
	f.mu.Unlock()
	if isHeld {
		select {
		case <-gate:
		case <-r.Context().Done():
			return // client abandoned before dispatch; nothing dispatched
		}
	}
	f.mu.Lock()
	f.dispatches[rid]++
	f.nextDisp++
	f.evidence[rid] = fixtureEvidence{
		Streamed:         req.Stream,
		PromptTokens:     extPromptTokens,
		CompletionTokens: extCompletionTokens,
	}
	f.mu.Unlock()

	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		fl, _ := w.(http.Flusher)
		writeChunk := func(c chatChunk) {
			b, _ := json.Marshal(c)
			fmt.Fprintf(w, "data: %s\n\n", b)
			if fl != nil {
				fl.Flush()
			}
		}
		var role chatChunk
		role.Choices = append(role.Choices, struct {
			Delta struct {
				Role    string `json:"role,omitempty"`
				Content string `json:"content,omitempty"`
			} `json:"delta"`
			FinishReason string `json:"finish_reason,omitempty"`
		}{})
		role.Choices[0].Delta.Role = "assistant"
		writeChunk(role)

		var content chatChunk
		content.Choices = append(content.Choices, struct {
			Delta struct {
				Role    string `json:"role,omitempty"`
				Content string `json:"content,omitempty"`
			} `json:"delta"`
			FinishReason string `json:"finish_reason,omitempty"`
		}{})
		content.Choices[0].Delta.Content = "Hi"
		writeChunk(content)

		var done chatChunk
		done.Choices = append(done.Choices, struct {
			Delta struct {
				Role    string `json:"role,omitempty"`
				Content string `json:"content,omitempty"`
			} `json:"delta"`
			FinishReason string `json:"finish_reason,omitempty"`
		}{})
		done.Choices[0].FinishReason = "stop"
		done.Usage = &chatUsage{PromptTokens: extPromptTokens, CompletionTokens: extCompletionTokens}
		writeChunk(done)

		fmt.Fprint(w, "data: [DONE]\n\n")
		if fl != nil {
			fl.Flush()
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
		var resp chatResponse
		resp.Choices = append(resp.Choices, struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		}{})
		resp.Choices[0].Message.Role = "assistant"
		resp.Choices[0].Message.Content = "Hi"
		resp.Choices[0].FinishReason = "stop"
		resp.Usage = chatUsage{PromptTokens: extPromptTokens, CompletionTokens: extCompletionTokens}
		_ = json.NewEncoder(w).Encode(resp)
	}

	f.mu.Lock()
	f.receipts[rid]++
	f.nextRecv++
	f.mu.Unlock()
}

// Hold blocks response delivery for rid until ReleaseAll. If the request is
// never released, the client sees a hang and the provider call never counts
// as dispatched (the gate sits before the dispatch ledger write).
func (f *providerFixture) Hold(rid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.held[rid]; !ok {
		f.held[rid] = make(chan struct{})
	}
}

func (f *providerFixture) ReleaseAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for rid, gate := range f.held {
		close(gate)
		delete(f.held, rid)
	}
}

// WaitForDispatch blocks until rid has been dispatched at least once.
func (f *providerFixture) WaitForDispatch(rid string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := f.dispatches[rid]
		f.mu.Unlock()
		if n >= 1 {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// LedgerSnapshot is a whole-ledger instant for delta reasoning.
type LedgerSnapshot struct {
	Arrivals   map[string]int
	Dispatches map[string]int
	Receipts   map[string]int
	TotalArr   int
	TotalDisp  int
	TotalRecv  int
}

func (f *providerFixture) Snapshot() LedgerSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := LedgerSnapshot{
		Arrivals:   map[string]int{},
		Dispatches: map[string]int{},
		Receipts:   map[string]int{},
		TotalArr:   f.nextArr,
		TotalDisp:  f.nextDisp,
		TotalRecv:  f.nextRecv,
	}
	for k, v := range f.arrivals {
		s.Arrivals[k] = v
	}
	for k, v := range f.dispatches {
		s.Dispatches[k] = v
	}
	for k, v := range f.receipts {
		s.Receipts[k] = v
	}
	return s
}

// Since returns whole-ledger deltas between two snapshots.
func (f *providerFixture) Since(before LedgerSnapshot) (dArr, dDisp, dRecv int) {
	cur := f.Snapshot()
	return cur.TotalArr - before.TotalArr, cur.TotalDisp - before.TotalDisp, cur.TotalRecv - before.TotalRecv
}

// Counts returns per-rid ledger counts.
func (f *providerFixture) Counts(rid string) (arr, disp, recv int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.arrivals[rid], f.dispatches[rid], f.receipts[rid]
}

// VerifyEvidence asserts the fixture's own accounting for rid is coherent.
func (f *providerFixture) VerifyEvidence(t *testing.T, rid string, wantStreamed bool) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	ev, ok := f.evidence[rid]
	if !ok {
		t.Fatalf("fixture evidence: no dispatch recorded for %s", rid)
	}
	if ev.Streamed != wantStreamed {
		t.Fatalf("fixture evidence: rid %s streamed=%v want %v", rid, ev.Streamed, wantStreamed)
	}
	if ev.PromptTokens != extPromptTokens || ev.CompletionTokens != extCompletionTokens {
		t.Fatalf("fixture evidence: rid %s tokens %d/%d want %d/%d",
			rid, ev.PromptTokens, ev.CompletionTokens, extPromptTokens, extCompletionTokens)
	}
}

// stripDataPrefix is a small SSE helper shared with client-side parsing.
func stripDataPrefix(line string) (string, bool) {
	if strings.HasPrefix(line, "data:") {
		return strings.TrimSpace(strings.TrimPrefix(line, "data:")), true
	}
	return "", false
}
