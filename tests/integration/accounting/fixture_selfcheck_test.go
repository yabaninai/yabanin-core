//go:build integration

package accounting

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFixtureSelfCheck is the unit-level validation of the acceptance
// oracle itself: it exercises the provider fixture's ledgers, hold
// barrier, evidence files and snapshot/delta math against real HTTP
// round trips, without Docker or the product binary. A detector that has
// not proven itself cannot back an acceptance verdict, so the fixture is
// verified in isolation before any stand-level run.
func TestFixtureSelfCheck(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "yabanin-accounting-fixture", newRunID(t))
	f := startFixture(t, dir, "unit-token")
	t.Cleanup(f.stop)

	// An unauthorized probe still counts as a provider arrival but never
	// becomes a dispatch.
	before := f.Snapshot()
	status, body, err := httpPostJSON(5*time.Second, f.baseURL()+"/v1/chat/completions",
		"wrong-token", "unit-unauth", `{"model":"m","messages":[{"role":"user","content":"x"}]}`)
	if err != nil || status != http.StatusUnauthorized {
		t.Fatalf("fixture self-check: unauthorized probe status=%d err=%v body=%q, want 401", status, err, body)
	}
	if delta := f.Since(before); delta.arrivals != 1 || delta.dispatches != 0 || delta.receipts != 0 {
		t.Fatalf("fixture self-check: unauthorized probe delta arrivals/dispatches/receipts = %d/%d/%d, want 1/0/0",
			delta.arrivals, delta.dispatches, delta.receipts)
	}

	// A held authorized request reaches the dispatch barrier and stays
	// there (client waiting) until released.
	rid := "unit-held"
	f.Hold(rid)
	type reply struct {
		status int
		body   string
		err    error
	}
	done := make(chan reply, 1)
	go func() {
		status, body, err := httpPostJSON(10*time.Second, f.baseURL()+"/v1/chat/completions",
			"unit-token", rid, `{"model":"m","messages":[{"role":"user","content":"x"}]}`)
		done <- reply{status: status, body: body, err: err}
	}()
	if !f.WaitForDispatch(rid, 5*time.Second) {
		t.Fatal("fixture self-check: held request never reached the dispatch barrier")
	}
	select {
	case r := <-done:
		t.Fatalf("fixture self-check: held request completed before release (status=%d err=%v)", r.status, r.err)
	case <-time.After(300 * time.Millisecond):
		// Still held, as designed.
	}
	if a, d, r := f.Counts(rid); a != 1 || d != 1 || r != 0 {
		t.Fatalf("fixture self-check: held request counts arrivals/dispatches/receipts = %d/%d/%d, want 1/1/0", a, d, r)
	}

	// Release completes the round trip with the fixed usage facts.
	f.ReleaseAll()
	select {
	case r := <-done:
		if r.err != nil || r.status != http.StatusOK {
			t.Fatalf("fixture self-check: released request status=%d err=%v", r.status, r.err)
		}
		var env struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(r.body), &env); err != nil {
			t.Fatalf("fixture self-check: response not JSON: %v (%s)", err, r.body)
		}
		if len(env.Choices) != 1 || env.Choices[0].Message.Content != fixtureAssistantContent {
			t.Fatalf("fixture self-check: unexpected choices in %s", r.body)
		}
		if env.Usage.PromptTokens != fixturePromptTokens || env.Usage.CompletionTokens != fixtureCompletionTokens {
			t.Fatalf("fixture self-check: usage %d/%d, want %d/%d",
				env.Usage.PromptTokens, env.Usage.CompletionTokens, fixturePromptTokens, fixtureCompletionTokens)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fixture self-check: released request never completed")
	}
	if a, d, r := f.Counts(rid); a != 1 || d != 1 || r != 1 {
		t.Fatalf("fixture self-check: completed request counts arrivals/dispatches/receipts = %d/%d/%d, want 1/1/1", a, d, r)
	}

	// Snapshot/delta math must be exact across the whole history.
	total := f.Snapshot()
	if total.arrivals != 2 || total.dispatches != 1 || total.receipts != 1 {
		t.Fatalf("fixture self-check: total ledger %d/%d/%d, want 2/1/1", total.arrivals, total.dispatches, total.receipts)
	}
	if delta := f.Since(total); delta.arrivals != 0 || delta.dispatches != 0 || delta.receipts != 0 {
		t.Fatalf("fixture self-check: delta against the current snapshot must be zero, got %d/%d/%d",
			delta.arrivals, delta.dispatches, delta.receipts)
	}

	// Evidence files must mirror the oracle state line for line and be
	// valid records.
	f.VerifyEvidence()
	wantLines := map[string]int{"arrivals": 2, "dispatches": 1, "receipts": 1}
	for name, want := range wantLines {
		data, err := os.ReadFile(filepath.Join(dir, "fixture-ledgers", name+".jsonl"))
		if err != nil {
			t.Fatalf("fixture self-check: evidence %s unreadable: %v", name, err)
		}
		if n := strings.Count(string(data), "\n"); n != want {
			t.Fatalf("fixture self-check: evidence %s has %d lines, want %d", name, n, want)
		}
		var rec fixtureRecord
		if err := json.Unmarshal([]byte(strings.SplitN(string(data), "\n", 2)[0]), &rec); err != nil {
			t.Fatalf("fixture self-check: evidence %s line 1 not a record: %v", name, err)
		}
	}

	// The self-check's evidence directory must not resolve as a Git
	// worktree (same rule as the stand's runtime temp).
	if err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Run(); err == nil {
		t.Fatalf("fixture self-check: temp dir %s unexpectedly resolves as a Git worktree", dir)
	}
	t.Logf("fixture self-check passed (ledgers at %s)", dir)
}
