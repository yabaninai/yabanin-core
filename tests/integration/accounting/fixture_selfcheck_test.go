//go:build integration

package accounting

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, status, body)
	require.Equal(t, fixtureTotals{arrivals: 1}, f.Since(before))

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
	require.True(t, f.WaitForDispatch(rid, 5*time.Second))
	select {
	case r := <-done:
		t.Fatalf("fixture self-check: held request completed before release (status=%d err=%v)", r.status, r.err)
	case <-time.After(300 * time.Millisecond):
		// Still held, as designed.
	}
	a, d, r := f.Counts(rid)
	require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1}, fixtureTotals{a, d, r})

	// Release completes the round trip with the fixed usage facts.
	f.ReleaseAll()
	select {
	case r := <-done:
		require.NoError(t, r.err)
		require.Equal(t, http.StatusOK, r.status, r.body)
		validateChatReply(t, nil, r.body)
	case <-time.After(5 * time.Second):
		t.Fatal("fixture self-check: released request never completed")
	}
	a, d, r = f.Counts(rid)
	require.Equal(t, fixtureTotals{1, 1, 1}, fixtureTotals{a, d, r})

	// The streamed delivery mode must produce the same fixed completion
	// shape and the same ledger semantics (receipt only after the final
	// frame reaches the client), so both modes back comparable verdicts.
	srid := "unit-streamed"
	beforeStream := f.Snapshot()
	status, body, err = httpPostJSON(5*time.Second, f.baseURL()+"/v1/chat/completions",
		"unit-token", srid, `{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, body)
	validateChatSSE(t, nil, body)
	require.Equal(t, fixtureTotals{1, 1, 1}, f.Since(beforeStream))

	total := f.Snapshot()
	require.Equal(t, fixtureTotals{3, 2, 2}, total)
	require.Equal(t, fixtureTotals{}, f.Since(total))
	f.VerifyEvidence()
	for name, ids := range map[string][]string{
		"arrivals": {"unit-unauth", rid, srid}, "dispatches": {rid, srid}, "receipts": {rid, srid},
	} {
		data, err := os.ReadFile(filepath.Join(dir, "fixture-ledgers", name+".jsonl"))
		require.NoError(t, err)
		lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		require.Len(t, lines, len(ids))
		for i, line := range lines {
			var record fixtureRecord
			require.NoError(t, json.Unmarshal([]byte(line), &record))
			require.Equal(t, ids[i], record.RequestID)
			require.Equal(t, ids[i] != "unit-unauth", record.AuthOK)
			require.Equal(t, "/v1/chat/completions", record.Path)
			require.False(t, record.At.IsZero())
		}
	}

	// The self-check's evidence directory must not resolve as a Git
	// worktree (same rule as the stand's runtime temp).
	if err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Run(); err == nil {
		t.Fatalf("fixture self-check: temp dir %s unexpectedly resolves as a Git worktree", dir)
	}
	t.Logf("fixture self-check passed (ledgers at %s)", dir)
}

func TestFixtureHeldPeerDisconnect(t *testing.T) {
	f := startFixture(t, t.TempDir(), "unit-token")
	t.Cleanup(f.stop)
	const rid = "held-cancelled"
	f.Hold(rid)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.baseURL()+"/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer unit-token")
	req.Header.Set("X-Request-ID", rid)
	done := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		done <- err
	}()
	if !f.WaitForDispatch(rid, 5*time.Second) {
		t.Fatal("request never reached the held provider")
	}
	cancel()
	f.waitForHeldDisconnects()
	f.ReleaseAll()
	if err := <-done; err == nil {
		t.Fatal("held request received a response after cancellation")
	}
	if a, d, r := f.Counts(rid); a != 1 || d != 1 || r != 0 {
		t.Fatalf("cancelled request arrivals/dispatches/receipts = %d/%d/%d, want 1/1/0", a, d, r)
	}
	requireHealthyFixtureRetry(t, f, rid)
	f.VerifyEvidence()
}

func requireHealthyFixtureRetry(t *testing.T, f *fixture, rid string) {
	t.Helper()
	// A new invocation with the same correlation must proceed normally after
	// the disconnected one, as in the client-retry recovery scenario.
	status, _, err := httpPostJSON(5*time.Second, f.baseURL()+"/v1/chat/completions", "unit-token", rid, `{"model":"m"}`)
	if err != nil || status != http.StatusOK {
		t.Fatalf("same-correlation control: status=%d err=%v", status, err)
	}
	if a, d, r := f.Counts(rid); a != 2 || d != 2 || r != 1 {
		t.Fatalf("after healthy retry arrivals/dispatches/receipts = %d/%d/%d, want 2/2/1", a, d, r)
	}
}

func TestFixtureLedgerDetectsSameLengthSubstitutions(t *testing.T) {
	first := fixtureRecord{RequestID: "first", Path: "/v1/chat/completions", AuthOK: true, At: time.Unix(1, 0).UTC()}
	second := first
	second.RequestID = "other"
	records := []fixtureRecord{first, second}
	a, err := json.Marshal(first)
	require.NoError(t, err)
	b, err := json.Marshal(second)
	require.NoError(t, err)
	lineA, lineB := string(a)+"\n", string(b)+"\n"
	require.NoError(t, verifyFixtureLedger([]byte(lineA+lineB), records))
	for _, altered := range []string{lineB + lineA, lineA + lineA, lineA, lineA + lineB + lineB, lineA + string(b), lineA + lineB + "x"} {
		require.Error(t, verifyFixtureLedger([]byte(altered), records))
	}
}
