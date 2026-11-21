package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// TestReviewPaidChatHTTP is the owner's real-handler binding regression
// (chat JSON): a failed or lost-ACK durable start must refuse with the
// external code history_unavailable BEFORE any provider arrival, and a
// known terminal-write failure after a dispatched call must never surface
// the upstream body as a payable success.
func TestReviewPaidChatHTTP(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store *fakeInvocationStore
		calls int32
	}{
		{"healthy", &fakeInvocationStore{}, 1},
		{"no store", nil, 0},
		// Covers both the explicit failure and the lost-ACK class: the
		// holder treats every start-write error identically (latch +
		// ErrInvocationStoreUnavailable), and the escrow release rides
		// the same single refusal path.
		{"unconfirmed start", &fakeInvocationStore{admitErr: errors.New("database unavailable")}, 0},
		{"terminal write failure", &fakeInvocationStore{factsErr: errors.New("terminal write unavailable")}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(goldenChatUsage))
			}))
			defer server.Close()
			gw := goldenChatGateway(t, server.URL)
			if tc.store != nil {
				gw.invocations = tc.store
			}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(goldenChatBody))
			goldenIdentity(r)
			r.Header.Set("X-Request-ID", "owner-controlled-correlation")
			rec := httptest.NewRecorder()
			gw.chatCompletions(rec, r)
			require.Equal(t, tc.calls, calls.Load())
			if tc.calls == 0 {
				require.Equal(t, 503, rec.Code)
				var body struct {
					Error struct{ Code, Message string }
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
				require.Equal(t, "history_unavailable", body.Error.Code)
				require.Contains(t, body.Error.Message, "the paid call was not sent")
				return
			}
			if tc.store.factsErr != nil {
				require.GreaterOrEqual(t, rec.Code, 400, "client received success after losing known terminal usage: %s", rec.Body.String())
				require.Contains(t, rec.Body.String(), "accounting_commit_failed")
				require.Contains(t, rec.Body.String(), "NOT safe to retry", "post-dispatch failure must state the charge is not safely retryable")
				return
			}
			require.Equal(t, 200, rec.Code)
			require.Len(t, tc.store.admitted, 1)
			require.Len(t, tc.store.facts, 1)
			require.Equal(t, tc.store.admitted[0].InvocationID, tc.store.facts[0].InvocationID)
			require.Equal(t, "100", tc.store.facts[0].Fields["tokens_in"])
		})
	}
}

// TestReviewPaidChatTransientPGRecovery is acceptance leaf 38c441b and the
// physical oracle 29e5434 at the real handler: the first terminal INSERT
// fails AFTER the provider already answered with 7+3 usage — with a
// wrapped PG 40001 serialization error, or the session-kill classes
// pg_terminate_backend actually surfaces (57P01 admin_shutdown, 08xxx
// connection_exception) — and the bounded independent retry recovers the
// SAME invocation (one facts row, one admit, exactly one provider
// arrival) and only then the client succeeds.
func TestReviewPaidChatTransientPGRecovery(t *testing.T) {
	for _, fault := range []error{
		fmt.Errorf("driver: %w", &pgconn.PgError{Code: "40001"}),
		&pgconn.PgError{Code: "57P01"},
		&pgconn.PgError{Code: "08006"},
	} {
		store := &fakeInvocationStore{factsErrs: []error{fault}}
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(goldenChatUsage))
		}))
		defer server.Close()
		gw := goldenChatGateway(t, server.URL)
		gw.invocations = store
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(goldenChatBody))
		goldenIdentity(r)
		rec := httptest.NewRecorder()
		gw.chatCompletions(rec, r)
		require.Equal(t, int32(1), calls.Load(), "recovery must not re-dispatch the provider")
		require.Equal(t, 200, rec.Code, "recovered commit must surface the upstream answer for fault %v", fault)
		require.Equal(t, 2, store.factsCalls, "exactly one transient failure then the recovery write for fault %v", fault)
		require.Len(t, store.facts, 1, "exactly one durable facts row — no double debit")
		require.Len(t, store.admitted, 1)
		require.Equal(t, store.admitted[0].InvocationID, store.facts[0].InvocationID)
	}
}

// TestReviewPaidChatPermanentStorageNo200 pins the other half of the
// retry control: a permanent storage error is NOT retried into a success.
func TestReviewPaidChatPermanentStorageNo200(t *testing.T) {
	store := &fakeInvocationStore{factsErr: &pgconn.PgError{Code: "23505"}}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenChatUsage))
	}))
	defer server.Close()
	gw := goldenChatGateway(t, server.URL)
	gw.invocations = store
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(goldenChatBody))
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	require.Equal(t, int32(1), calls.Load())
	require.Equal(t, 1, store.factsCalls, "permanent classes must not burn retries")
	require.GreaterOrEqual(t, rec.Code, 400)
	require.Contains(t, rec.Body.String(), "accounting_commit_failed")
}

type reviewOrderedStore struct {
	fakeInvocationStore
	started  atomic.Bool
	terminal atomic.Bool
}

func (s *reviewOrderedStore) AdmitInvocation(ctx context.Context, rec admissionRecord) error {
	err := s.fakeInvocationStore.AdmitInvocation(ctx, rec)
	if err == nil {
		s.started.Store(true)
	}
	return err
}

func (s *reviewOrderedStore) RecordTerminalFacts(ctx context.Context, rec terminalFactsRecord) error {
	err := s.fakeInvocationStore.RecordTerminalFacts(ctx, rec)
	if err == nil {
		s.terminal.Store(true)
	}
	return err
}

type reviewResponseOrder struct {
	*httptest.ResponseRecorder
	store       *reviewOrderedStore
	beforeFacts bool
}

func (w *reviewResponseOrder) WriteHeader(status int) {
	if status >= 200 && status < 300 && !w.store.terminal.Load() {
		w.beforeFacts = true
	}
	w.ResponseRecorder.WriteHeader(status)
}

func (w *reviewResponseOrder) Write(body []byte) (int, error) {
	if !w.store.terminal.Load() {
		w.beforeFacts = true
	}
	return w.ResponseRecorder.Write(body)
}

// TestReviewPaidChatSuccessOrdering proves the central binding at the real
// handler: the confirmed durable start precedes the provider arrival, and
// NO client byte precedes the terminal-facts commit.
func TestReviewPaidChatSuccessOrdering(t *testing.T) {
	store := new(reviewOrderedStore)
	var confirmedAtArrival atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		confirmedAtArrival.Store(store.started.Load())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenChatUsage))
	}))
	defer up.Close()
	gw := goldenChatGateway(t, up.URL)
	gw.invocations = store
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(goldenChatBody))
	goldenIdentity(r)
	w := &reviewResponseOrder{ResponseRecorder: httptest.NewRecorder(), store: store}
	gw.chatCompletions(w, r)
	require.Equal(t, 200, w.Code)
	require.True(t, confirmedAtArrival.Load(), "provider saw request before confirmed start")
	require.True(t, store.terminal.Load(), "accounting facts were never committed")
	require.False(t, w.beforeFacts, "client saw success before the scripted store confirmed terminal facts")
}
