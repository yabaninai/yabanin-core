package cli

// N03-P03-T08 interruption/retry/resume recovery — the gateway relay seam
// (the primitives live in pkg/pipeline/streaming/n03p3t08_recovery_test.go).
// The relay owns the event assembly buffer (sseStreamPolicyWriter) and the
// end-of-stream ordering (finishStream → drain-failure notification), so the
// broken-stream scenarios are pinned here at the wire level:
//
//   - a drain failure while the assembly buffer holds a dangling partial
//     event (the upstream stalled between a data line and its blank
//     separator, the idle watchdog aborted): the termination notification
//     must compose WELL-FORMED events — the dangling partial is never glued
//     to the error frame into one multi-data-line event, and its never-
//     processed bytes never reach the client (they passed no policy stage);
//   - a client cancel mid-stream keeps enforcing on every byte that still
//     traverses the chain (no raw span rides any captured frame) and still
//     terminates well-formed;
//   - the retry after an interrupted delivery reconstructs the control
//     stream byte-for-byte (no duplicates, no losses, fresh pipeline state);
//   - a replayed forbidden prefix re-denies in a fresh request — cancel and
//     retry cannot bypass the future-token check (the packet negative).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
)

// t08StallUpstream serves `first` complete frames, then one HALF event (a
// data line without its blank separator), then goes silent until the gateway
// cancels the stream — the exact stall shape that leaves a dangling partial
// in the relay's assembly buffer when the idle watchdog fires.
func t08StallUpstream(t *testing.T, first []string, halfEvent string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, f := range first {
			if r.Context().Err() != nil {
				return
			}
			_, _ = io.WriteString(w, "data: "+f+"\n\n")
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(20 * time.Millisecond) // let the gateway drain each frame
		}
		if r.Context().Err() != nil {
			return
		}
		_, _ = io.WriteString(w, halfEvent) // dangling: no "\n\n" separator
		if flusher != nil {
			flusher.Flush()
		}
		<-r.Context().Done() // the silent stretch outlasts the idle timeout
	}))
}

// t08Frames splits an SSE body into events and asserts the wire contract the
// recovery scenarios pin: every event is blank-line terminated, carries
// exactly one data line, and its payload is valid JSON or the [DONE]
// sentinel — a glued multi-data-line event or a raw tail fails here.
func t08Frames(t *testing.T, body string) []string {
	t.Helper()
	require.True(t, strings.HasSuffix(body, "\n\n"), "body must end with a terminated event, got %q", body[len(body)-min(len(body), 40):])
	var frames []string
	for _, f := range strings.Split(body, "\n\n") {
		if f == "" {
			continue
		}
		if n := strings.Count(f, "data: "); n != 1 {
			t.Fatalf("event carries %d data lines (glued or partial): %q", n, f)
		}
		payload := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(f), "data: "))
		if payload == "[DONE]" {
			frames = append(frames, payload)
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(payload), &doc); err != nil {
			t.Fatalf("event payload is not valid JSON: %v (%q)", err, payload)
		}
		frames = append(frames, payload)
	}
	return frames
}

func t08CountDone(body string) int { return strings.Count(body, "data: [DONE]\n\n") }

// TestN03P3T08_DrainFailure_PartialEventComposesWellFormedTermination: the
// idle watchdog aborts a stream whose last write stopped between the data
// line and its separator. The dangling partial must be dropped (its bytes
// never passed the policy stages), and the error notification must compose
// well-formed events for the still-connected client.
func TestN03P3T08_DrainFailure_PartialEventComposesWellFormedTermination(t *testing.T) {
	const secret = "super-secret-value"
	const stalledMarker = "t08-never-completed-tail"
	up := t08StallUpstream(t,
		[]string{
			`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
			streamChunkFrame("c1", "prefix "+secret+" delivered"),
		},
		`{"id":"c2","choices":[{"index":0,"delta":{"content":"`+stalledMarker+` `+secret+`"}}]}`+"\n",
	)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamPseudonymizeYAML(secret)), up.URL)
	gw.streamIdleTimeout = 80 * time.Millisecond

	rec := streamPolicyPost(t, gw, streamRequestBody)
	body := rec.body()

	// The delivered prefix frame: suppressed and delivered before the stall.
	assert.Contains(t, body, "{{YPP_1}}", "the prefix frame reached the client mutated")
	assert.Contains(t, body, "prefix {{YPP_1}} delivered", "the delivered text survives except the secret")

	// The dangling partial: dropped, not glued, not emitted raw.
	assert.NotContains(t, body, stalledMarker,
		"the dangling partial event never passed the policy stages — it must not reach the client")

	// The termination composes well-formed events with exactly one [DONE].
	frames := t08Frames(t, body)
	assert.Equal(t, 1, t08CountDone(body), "exactly one [DONE] terminator")
	var errFrames int
	for _, f := range frames {
		if strings.Contains(f, `"error"`) {
			errFrames++
			assert.Contains(t, f, "upstream stream idle timeout")
		}
	}
	assert.Equal(t, 1, errFrames, "exactly one error notification frame")

	// No raw secret anywhere on the recovered wire.
	assert.NotContains(t, body, secret, "the raw secret must never reach the client")
}

// TestN03P3T08_ClientCancel_NoRawLeakAndWellFormedTermination — axis D: the
// client leaves mid-stream; every byte still traversing the chain keeps
// being enforced (no raw span rides any captured frame), and the stream
// still terminates well-formed.
func TestN03P3T08_ClientCancel_NoRawLeakAndWellFormedTermination(t *testing.T) {
	const secret = "super-secret-value"
	up := newStreamPolicyUpstream(t, 15*time.Millisecond,
		streamChunkFrame("c1", "first "+secret+" frame"),
		streamChunkFrame("c1", "second "+secret+" frame"),
		streamChunkFrame("c1", "third "+secret+" frame"),
		streamChunkFrame("c1", "fourth "+secret+" frame"),
	)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamPseudonymizeYAML(secret)), up.srv.URL)

	// streamPolicyPostAsync with a cancellable request context.
	gw.res = stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: gw.cfg.Provider, Enabled: true},
	}
	info := rt06TestResolve(gw, "m1")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(streamRequestBody))
	ctx, cancel := context.WithCancel(withReservationGate(r.Context(), &reservationGate{
		plan: &budget.Plan{Mode: budget.ModeOff},
		rsv: &budget.Reservation{OrgID: testOrg, Scopes: []budget.ScopeReserve{
			{Scope: budget.ScopeWallet, Key: testOrg, Bound: 1_000_000},
		}},
	}))
	rec := newSyncRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		gw.serveStream(rec, ctx, info, []byte(streamRequestBody), false,
			"sess", testOrg, "", "task", "req", testLogger(), routingDecision{From: "m1"}, "", 0, "", "", "", false)
	}()

	// Leave once the first frame is on the wire.
	require.Eventually(t, func() bool {
		return strings.Contains(rec.body(), "{{YPP_1}}")
	}, 2*time.Second, 5*time.Millisecond, "the first frame must be delivered before the cancel")
	cancel()
	<-done

	body := rec.body()
	assert.NotContains(t, body, secret, "no raw span may ride any frame, before or after the cancel")
	assert.Equal(t, 1, t08CountDone(body), "exactly one [DONE] after the cancel")
	t08Frames(t, body) // every event well-formed, none glued
	assert.Contains(t, body, `"error"`, "the drain-failure notification is still composed")
}

// TestN03P3T08_RetryAfterInterruption_ReconstructsControlStream — axis B: a
// client retrying after an interrupted delivery gets a byte-identical stream
// (fresh pipeline state, no duplicated replacements, no losses), while the
// interrupted attempt itself never leaked the raw span.
func TestN03P3T08_RetryAfterInterruption_ReconstructsControlStream(t *testing.T) {
	const secret = "super-secret-value"
	frames := []string{
		`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		streamChunkFrame("c1", "the "+secret+" in the prefix"),
		streamChunkFrame("c1", " and again "+secret+" near the end"),
		streamChunkFrame("c1", " final tail"),
	}

	upGood := newStreamPolicyUpstream(t, 5*time.Millisecond, frames...)
	gwControl := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamPseudonymizeYAML(secret)), upGood.srv.URL)
	control := streamPolicyPost(t, gwControl, streamRequestBody).body()

	upStall := t08StallUpstream(t, frames[:2],
		`{"id":"c2","choices":[{"index":0,"delta":{"content":"t08 interrupted tail `+secret+`"}}]}`+"\n")
	gwFail := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamPseudonymizeYAML(secret)), upStall.URL)
	gwFail.streamIdleTimeout = 80 * time.Millisecond
	interrupted := streamPolicyPost(t, gwFail, streamRequestBody).body()

	gwRetry := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamPseudonymizeYAML(secret)), upGood.srv.URL)
	retry := streamPolicyPost(t, gwRetry, streamRequestBody).body()

	// The retry is the control: byte-for-byte, including the single [DONE].
	assert.Equal(t, control, retry, "the retry must reconstruct the uninterrupted stream byte-for-byte")
	assert.Equal(t, 1, t08CountDone(retry))
	assert.Equal(t, 2, strings.Count(retry, "{{YPP_1}}"), "each span occurrence replaced exactly once (2 per full stream)")

	// The interrupted attempt: safe partial delivery, clean termination.
	assert.NotContains(t, interrupted, secret)
	assert.NotContains(t, interrupted, "t08 interrupted tail")
	t08Frames(t, interrupted)
	assert.Equal(t, 1, t08CountDone(interrupted))
}

// TestN03P3T08_DenyReplay_RetryCannotBypass — axis D negative: the retry of
// a denied stream is denied again by the FRESH request's prefix stage — the
// decision is re-evaluated per request, never inherited or bypassed.
func TestN03P3T08_DenyReplay_RetryCannotBypass(t *testing.T) {
	const trigger = "forbidden-phrase"
	up := newStreamPolicyUpstream(t, 10*time.Millisecond,
		`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		streamChunkFrame("c1", "here comes the "+trigger+" and more text to fill the buffer"),
		streamChunkFrame("c1", "tail the client must never see"),
	)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamDenyPrefixYAML(trigger)), up.srv.URL)

	first := streamPolicyPost(t, gw, streamRequestBody).body()
	second := streamPolicyPost(t, gw, streamRequestBody).body()

	for name, body := range map[string]string{"first": first, "retry": second} {
		assert.Contains(t, body, "request blocked by organization policy", "%s: the replayed prefix re-denies", name)
		assert.Equal(t, 1, t08CountDone(body), "%s: one canonical termination", name)
		assert.NotContains(t, body, trigger, "%s: the denied content stays off the wire", name)
		assert.NotContains(t, body, `"content"`, "%s: no content frame passes the prefix gate", name)
		t08Frames(t, body)
	}
	assert.Equal(t, first, second, "the re-decision is deterministic")
}
