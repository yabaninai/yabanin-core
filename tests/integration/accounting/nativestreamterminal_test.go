//go:build integration

package accounting

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// D1 terminal-ordering proof for BOTH native protocols' streaming paths:
// the client-visible terminal frame may only be relayed after the durable
// terminal usage row committed, and that relay must not depend on the
// upstream connection ending. Two independent levers make the seam
// observable in the real binary:
//
//   - the fixture writes the terminal frame but keeps the upstream
//     connection open (HoldAfterTerminal), so any relay that waits for
//     upstream EOF before committing is exposed;
//   - a gated trigger on request_terminal_facts makes the product's
//     facts INSERT block on an advisory lock the test holds, so the
//     moment the commit happens is externally controllable.
//
// While the commit is blocked: content frames are already delivered to
// the client, the terminal frame is not, and no facts row exists. The
// instant the terminal frame is observed on the client, the facts row
// must already be durable (fail-hard, not eventually: a relay that ships
// the terminal before the commit is exactly the defect under test).

// TestAccountingNativeStreamTerminalOrdering runs the ordering leg for
// the native Anthropic Messages stream and the native Responses stream.
// The responses leg uses the same environment gate the refusal sweep
// uses (YABANIN_RESPONSES_NATIVE_PROVIDERS=openai-compat) so the seeded
// model is served natively on /v1/responses.
func TestAccountingNativeStreamTerminalOrdering(t *testing.T) {
	s := startStandWithGatewayEnv(t, "YABANIN_RESPONSES_NATIVE_PROVIDERS=openai-compat")
	org := s.oracleDB.orgID
	s.assertWalletConfigured(t, org, "native stream ordering pre-control")
	s.controlRequest(t, "native-stream-pre")
	model := s.provisionNativeAnthropicModel(t)
	s.armNativeTerminalHold(t)

	// Harness-level detector control, before any product assertion: the
	// same reader machinery the legs rely on must OBSERVE a terminal
	// frame that is genuinely delivered right after the nonterminal
	// frames — proving the legs' terminal-absent observations are
	// meaningful, not a blind reader. It runs against the fixture's
	// native surface directly with the real credential shape, so it also
	// positively exercises the fixture's per-path credential gate.
	ctlRid := s.reqPrefix + "native-order-detector-ctl"
	ctlPayload := fmt.Sprintf(
		`{"model":%q,"max_tokens":32,"stream":true,"messages":[{"role":"user","content":"detector control"}]}`,
		model)
	ctl, err := openFixtureSSE(t, s, ctlRid, ctlPayload)
	require.NoError(t, err, "detector control: open fixture SSE")
	requireEventually(t, 15*time.Second, 25*time.Millisecond, func() bool {
		return ctl.hasEvent("content_block_delta")
	}, "detector control: nonterminal frames never arrived")
	requireEventually(t, 15*time.Second, 25*time.Millisecond, func() bool {
		return ctl.hasEvent("message_stop")
	}, "detector control: the reader failed to observe a delivered terminal frame — the legs' terminal-absent checks would be vacuous")
	ctlStatus, ctlHdr, ctlBody := ctl.finish(t)
	require.Equal(t, http.StatusOK, ctlStatus, "detector control: status")
	require.Equal(t, "text/event-stream", ctlHdr.Get("Content-Type"), "detector control: content type")
	validateNativeMessageStream(t, s, ctlBody)
	ctlArrivals, ctlDispatches, ctlReceipts := s.fixture.Counts(ctlRid)
	require.EqualValues(t, 1, ctlArrivals, "detector control: fixture arrivals")
	require.EqualValues(t, 1, ctlDispatches, "detector control: fixture dispatches")
	require.EqualValues(t, 1, ctlReceipts, "detector control: fixture receipts")

	anthropic := nativeStreamLeg{
		label: "anthropic /v1/messages",
		path:  "/v1/messages",
		send: func(rid string) (*sseStream, error) {
			payload := fmt.Sprintf(
				`{"model":%q,"max_tokens":32,"stream":true,"messages":[{"role":"user","content":"native terminal ordering probe"}]}`,
				model)
			return openSSE(t, s, s.gatewayURL+"/v1/messages", rid, payload)
		},
		nonterminal: "content_block_delta",
		terminal:    "message_stop",
		final: func(t *testing.T, body string) {
			validateNativeMessageStream(t, s, body)
		},
	}
	responses := nativeStreamLeg{
		label: "responses /v1/responses",
		path:  "/v1/responses",
		send: func(rid string) (*sseStream, error) {
			payload := fmt.Sprintf(`{"model":%q,"input":"native terminal ordering probe","stream":true}`, s.model)
			return openSSE(t, s, s.gatewayURL+"/v1/responses", rid, payload)
		},
		nonterminal: "response.output_text.delta",
		terminal:    "response.completed",
		final: func(t *testing.T, body string) {
			validateResponsesSSE(t, s, body)
		},
	}

	for _, leg := range []nativeStreamLeg{anthropic, responses} {
		runNativeTerminalOrderingLeg(t, s, leg)
	}
	s.controlRequest(t, "native-stream-post")
	s.fixture.VerifyEvidence()
}

// nativeStreamLeg describes one protocol's ordering probe.
type nativeStreamLeg struct {
	label       string
	path        string                               // native dispatch path the request must use
	send        func(rid string) (*sseStream, error) // open the streaming request
	nonterminal string                               // event proving content delivery pre-terminal
	terminal    string                               // protocol terminal event
	final       func(t *testing.T, body string)      // full-body protocol validation
}

// runNativeTerminalOrderingLeg executes one ordering probe: block the
// terminal-facts commit, prove nonterminal delivery without the terminal
// frame or a facts row, release the commit, then require the hard
// terminal-implies-durable ordering and the full settlement.
func runNativeTerminalOrderingLeg(t *testing.T, s *stand, leg nativeStreamLeg) {
	t.Helper()
	org := s.oracleDB.orgID
	rid := s.reqPrefix + "native-order-" + strings.NewReplacer(" ", "-", "/", "-").Replace(leg.label)
	s.gateNativeTerminalHold(t, rid)
	s.fixture.HoldAfterTerminal(rid)
	t.Cleanup(func() { s.fixture.ReleasePostTerminal(rid) })

	// Hold the advisory lock the gated facts INSERT needs: the product's
	// terminal commit blocks inside this leg's window.
	tx, err := s.oracleDB.db.Begin()
	require.NoError(t, err, "%s: begin ordering barrier", leg.label)
	defer tx.Rollback()
	_, err = tx.Exec(`SELECT pg_advisory_xact_lock(1921, 113)`)
	require.NoError(t, err, "%s: take ordering barrier lock", leg.label)

	st, err := leg.send(rid)
	require.NoError(t, err, "%s: open SSE request", leg.label)

	// Content is relayed while the terminal commit is blocked.
	requireEventually(t, 15*time.Second, 25*time.Millisecond, func() bool {
		return st.hasEvent(leg.nonterminal)
	}, "%s: nonterminal frames never reached the client", leg.label)
	require.False(t, st.hasEvent(leg.terminal),
		"%s: the terminal frame was delivered while the terminal-facts write was still blocked", leg.label)

	// The blocked INSERT itself must be observable as a waiting advisory
	// lock request (the gateway is the only writer of terminal facts in
	// this window), proving the ordering was actually exercised.
	waitingWriters := func() int {
		return s.oracleCount(t, `SELECT count(*) FROM pg_locks
			WHERE locktype='advisory' AND classid=1921 AND objid=113 AND NOT granted`)
	}
	requireEventually(t, 15*time.Second, 25*time.Millisecond, func() bool {
		return waitingWriters() >= 1
	}, "%s: the terminal-facts insert never blocked on the ordering barrier — the seam was not exercised", leg.label)

	// Bounded observation while the commit is impossible: every tick
	// re-confirms the writer is still waiting under the held barrier and
	// the client terminal still absent. A premature terminal delivered
	// after the initial sample but before the release cannot slip
	// through here — and the post-release hard check below only catches
	// such a defect if it is observed in time. The window is short by
	// design: the product's blocked facts attempt must survive it and
	// succeed once the barrier is released.
	observeUntil := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(observeUntil) {
		require.GreaterOrEqual(t, waitingWriters(), 1,
			"%s: the ordering barrier lost its waiting writer while the test still holds the lock", leg.label)
		require.False(t, st.hasEvent(leg.terminal),
			"%s: the terminal frame reached the client while the terminal-facts commit was still blocked", leg.label)
		require.Zero(t, s.oracleTerminalFactsCount(t, rid, org),
			"%s: terminal facts committed while the ordering barrier was still held", leg.label)
		time.Sleep(25 * time.Millisecond)
	}

	// Release the barrier: the facts INSERT proceeds.
	require.NoError(t, tx.Commit(), "%s: commit ordering barrier", leg.label)

	// Hard ordering: the instant the terminal frame is visible to the
	// client, the durable row must already exist. This is a fail-hard
	// check by design — polling until both hold would mask exactly the
	// relay-before-commit defect under test.
	requireEventually(t, 30*time.Second, 50*time.Millisecond, func() bool {
		return st.hasEvent(leg.terminal)
	}, "%s: terminal frame never reached the client (is the relay waiting for the upstream connection to end before committing?)", leg.label)
	require.Equal(t, 1, s.oracleTerminalFactsCount(t, rid, org),
		"%s: terminal frame was relayed before the terminal-facts row was durable", leg.label)

	s.fixture.ReleasePostTerminal(rid)
	status, hdr, body := st.finish(t)
	require.Equal(t, http.StatusOK, status, "%s: stream status", leg.label)
	require.Equal(t, "text/event-stream", hdr.Get("Content-Type"), "%s: content type", leg.label)
	leg.final(t, body)
	s.requireNativeSettled(t, leg.label, "terminal ordering", rid, leg.path)
}

// armNativeTerminalHold installs the gated ordering barrier: terminal
// facts INSERTs for gated request ids block on the (1921, 113) advisory
// lock until the test's barrier transaction commits.
func (s *stand) armNativeTerminalHold(t *testing.T) {
	t.Helper()
	s.oracleExec(t, "create native terminal hold selector", `CREATE TABLE acc_native_hold_target (rid text PRIMARY KEY)`)
	s.oracleExec(t, "arm native terminal hold", `
		CREATE FUNCTION acc_native_hold_terminal() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF EXISTS (SELECT 1 FROM acc_native_hold_target WHERE rid=NEW.client_request_id) THEN
				PERFORM pg_advisory_xact_lock(1921, 113);
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER acc_native_hold_terminal BEFORE INSERT ON request_terminal_facts
		FOR EACH ROW EXECUTE FUNCTION acc_native_hold_terminal()`)
	t.Cleanup(func() {
		s.oracleExec(t, "remove native terminal hold", `
			DROP TRIGGER acc_native_hold_terminal ON request_terminal_facts;
			DROP FUNCTION acc_native_hold_terminal();
			DROP TABLE acc_native_hold_target`)
	})
}

// gateNativeTerminalHold targets one request id with the ordering
// barrier.
func (s *stand) gateNativeTerminalHold(t *testing.T, rid string) {
	t.Helper()
	s.oracleExec(t, "gate native terminal hold", `INSERT INTO acc_native_hold_target VALUES ($1)`, rid)
}

// --- incremental SSE reader ---------------------------------------------

// sseStream incrementally reads one gateway SSE response while it is
// produced: ordering assertions must observe frames as they arrive, not
// after EOF. A background reader drains the body; snapshots of the
// complete events are available at any time.
type sseStream struct {
	t      *testing.T
	status int
	hdr    http.Header

	mu      sync.Mutex
	builder strings.Builder
	done    chan struct{}
}

// openSSE starts the streaming request against the gateway (Bearer
// client credentials) and the background reader.
func openSSE(t *testing.T, s *stand, url, rid, payload string) (*sseStream, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", rid)
	req.Header.Set("Accept", "text/event-stream")
	return startSSE(t, req, rid, cancel)
}

// openFixtureSSE starts a streaming request directly against the
// fixture's native Anthropic Messages surface with the native credential
// shape (x-api-key plus pinned anthropic-version).
func openFixtureSSE(t *testing.T, s *stand, rid, payload string) (*sseStream, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.fixture.baseURL()+"/v1/messages", strings.NewReader(payload))
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("x-api-key", s.fixtureTok)
	req.Header.Set("anthropic-version", fixtureAnthropicVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", rid)
	req.Header.Set("Accept", "text/event-stream")
	return startSSE(t, req, rid, cancel)
}

// startSSE executes a prepared streaming request and starts the
// background reader.
func startSSE(t *testing.T, req *http.Request, rid string, cancel context.CancelFunc) (*sseStream, error) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	st := &sseStream{t: t, status: resp.StatusCode, hdr: resp.Header, done: make(chan struct{})}
	go func() {
		defer close(st.done)
		defer resp.Body.Close()
		defer cancel()
		buf := make([]byte, 8192)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				st.mu.Lock()
				st.builder.Write(buf[:n])
				st.mu.Unlock()
			}
			if rerr != nil {
				if !errors.Is(rerr, io.EOF) && req.Context().Err() == nil {
					st.t.Logf("stream read ended for %s: %v", rid, rerr)
				}
				return
			}
		}
	}()
	return st, nil
}

// snapshot returns the raw bytes read so far.
func (st *sseStream) snapshot() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.builder.String()
}

// eventNames parses the event names of the SSE records that are complete
// so far; a trailing partial record is ignored until its terminator
// arrives. Interim assertions must never match against half a frame.
func (st *sseStream) eventNames() []string {
	raw := st.snapshot()
	if idx := strings.LastIndex(raw, "\n\n"); idx >= 0 {
		raw = raw[:idx]
	} else {
		raw = ""
	}
	var names []string
	for _, record := range strings.Split(raw, "\n\n") {
		for _, line := range strings.Split(record, "\n") {
			if strings.HasPrefix(line, "event:") {
				names = append(names, strings.TrimSpace(strings.TrimPrefix(line, "event:")))
			}
		}
	}
	return names
}

// hasEvent reports whether a complete record with this event name has
// been received.
func (st *sseStream) hasEvent(name string) bool {
	for _, n := range st.eventNames() {
		if n == name {
			return true
		}
	}
	return false
}

// finish waits for the body to end and returns the status, headers and
// full body for the final protocol validation.
func (st *sseStream) finish(t *testing.T) (int, http.Header, string) {
	t.Helper()
	select {
	case <-st.done:
	case <-time.After(60 * time.Second):
		t.Fatalf("stream: body never ended")
	}
	return st.status, st.hdr, st.snapshot()
}
