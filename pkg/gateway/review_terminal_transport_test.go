package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

type reviewTransportStore struct {
	fakeInvocationStore
	first       error
	afterCommit bool
	attempts    int
}

func (s *reviewTransportStore) RecordTerminalFacts(ctx context.Context, rec terminalFactsRecord) error {
	s.attempts++
	if s.attempts == 1 {
		if s.afterCommit {
			if err := s.fakeInvocationStore.RecordTerminalFacts(ctx, rec); err != nil {
				return err
			}
		}
		return s.first
	}
	return s.fakeInvocationStore.RecordTerminalFacts(ctx, rec)
}

func TestReviewTransportTerminal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault error
		after bool
	}{
		{"serialization", fmt.Errorf("driver: %w", &pgconn.PgError{Code: "40001"}), false},
		{"disconnect_before_commit", io.ErrUnexpectedEOF, false},
		{"disconnect_after_commit", io.ErrUnexpectedEOF, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paid atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paid.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(goldenChatUsage))
			}))
			defer server.Close()
			gw := goldenChatGateway(t, server.URL)
			store := &reviewTransportStore{first: tc.fault, afterCommit: tc.after}
			gw.invocations = store
			req := httptest.NewRequestWithContext(t.Context(), "POST", "/v1/chat/completions", strings.NewReader(goldenChatBody))
			goldenIdentity(req)
			resp := httptest.NewRecorder()
			gw.chatCompletions(resp, req)
			t.Logf("HTTP=%d paid=%d attempts=%d facts=%d", resp.Code, paid.Load(), store.attempts, len(store.facts))
			require.EqualValues(t, 1, paid.Load())
			require.Len(t, store.admitted, 1)
			require.Len(t, store.facts, 1)
			require.Equal(t, store.admitted[0].InvocationID, store.facts[0].InvocationID)
			require.Equal(t, "100", store.facts[0].Fields["tokens_in"])
		})
	}
}
