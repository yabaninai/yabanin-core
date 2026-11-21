//go:build integration

package accountingext

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestExtFixtureSelfCheck (unit-level, no Docker, no product binaries):
// proves the fixture's two response encodings, ledger semantics and hold
// gate behave as the acceptance cases assume. Runs directly in CI-cheap
// contexts; the heavy lease is only needed for the stand-level cases.
func TestExtFixtureSelfCheck(t *testing.T) {
	f := newProviderFixture(t)

	post := func(rid string, stream bool) (int, string, *chatUsage) {
		body := chatRequest{
			Model:    "selfcheck",
			Stream:   stream,
			Messages: []chatMessage{{Role: "user", Content: "Say Hi"}},
		}
		raw, _ := json.Marshal(body)
		req, err := http.NewRequest(http.MethodPost, f.URL()+"/v1/chat/completions",
			strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("selfcheck: request build: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-ID", rid)
		if stream {
			req.Header.Set("Accept", "text/event-stream")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req = req.WithContext(ctx)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("selfcheck: do: %v", err)
		}
		defer resp.Body.Close()
		payload, _ := io.ReadAll(resp.Body)
		if !stream {
			var cr chatResponse
			if err := json.Unmarshal(payload, &cr); err != nil || len(cr.Choices) == 0 {
				t.Fatalf("selfcheck: buffered body unparseable: %q", string(payload))
			}
			u := cr.Usage
			return resp.StatusCode, cr.Choices[0].Message.Content, &u
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
			t.Fatalf("selfcheck: streamed Content-Type = %q, want text/event-stream", ct)
		}
		var content strings.Builder
		var usage *chatUsage
		usageChunks := 0
		sawDone := false
		for _, line := range strings.Split(string(payload), "\n") {
			line = strings.TrimSpace(line)
			data, ok := stripDataPrefix(line)
			if !ok {
				continue
			}
			if data == "[DONE]" {
				sawDone = true
				continue
			}
			var c chatChunk
			if err := json.Unmarshal([]byte(data), &c); err != nil {
				t.Fatalf("selfcheck: chunk unparseable: %q", data)
			}
			for _, ch := range c.Choices {
				content.WriteString(ch.Delta.Content)
			}
			if c.Usage != nil {
				usageChunks++
				u := *c.Usage
				usage = &u
			}
		}
		if !sawDone {
			t.Fatalf("selfcheck: stream missing [DONE]: %q", string(payload))
		}
		if usageChunks != 1 {
			t.Fatalf("selfcheck: usage chunks = %d, want exactly 1", usageChunks)
		}
		return resp.StatusCode, content.String(), usage
	}

	for _, tc := range []struct {
		label  string
		stream bool
	}{
		{"buffered", false},
		{"streamed", true},
	} {
		rid := "selfcheck-" + tc.label
		before := f.Snapshot()
		status, content, usage := post(rid, tc.stream)
		if status != http.StatusOK || content != "Hi" {
			t.Fatalf("selfcheck %s: status=%d content=%q", tc.label, status, content)
		}
		if usage == nil || usage.PromptTokens != extPromptTokens || usage.CompletionTokens != extCompletionTokens {
			t.Fatalf("selfcheck %s: usage = %+v, want %d/%d", tc.label, usage, extPromptTokens, extCompletionTokens)
		}
		dArr, dDisp, dRecv := f.Since(before)
		if dArr != 1 || dDisp != 1 || dRecv != 1 {
			t.Fatalf("selfcheck %s: ledger delta = %d/%d/%d, want 1/1/1", tc.label, dArr, dDisp, dRecv)
		}
		f.VerifyEvidence(t, rid, tc.stream)
	}

	// Hold gate: a held request must record the arrival but NOT the dispatch
	// until released.
	rid := "selfcheck-held"
	f.Hold(rid)
	done := make(chan struct{})
	go func() { defer close(done); post(rid, false) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if arr, disp, _ := f.Counts(rid); arr == 1 && disp == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if arr, disp, _ := f.Counts(rid); arr != 1 || disp != 0 {
		t.Fatalf("selfcheck hold: arr/disp = %d/%d, want 1/0 while held", arr, disp)
	}
	f.ReleaseAll()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("selfcheck hold: held request never completed after release")
	}
	if arr, disp, recv := f.Counts(rid); arr != 1 || disp != 1 || recv != 1 {
		t.Fatalf("selfcheck hold: after release arr/disp/recv = %d/%d/%d, want 1/1/1", arr, disp, recv)
	}
}
