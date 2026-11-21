package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/require"
)

type shadowAccountingFixture struct {
	mu sync.Mutex
	fakeInvocationStore
}

func (s *shadowAccountingFixture) AdmitInvocation(ctx context.Context, rec admissionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fakeInvocationStore.AdmitInvocation(ctx, rec)
}
func (s *shadowAccountingFixture) RecordTerminalFacts(ctx context.Context, rec terminalFactsRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fakeInvocationStore.RecordTerminalFacts(ctx, rec)
}
func (s *shadowAccountingFixture) VoidInvocation(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fakeInvocationStore.VoidInvocation(ctx, id)
}

func TestShadowAccountingDispatch(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		admitErr, factsErr   error
		wantCalls, wantFacts int
	}{
		{name: "healthy", wantCalls: 1, wantFacts: 1},
		{name: "unconfirmed start", admitErr: errors.New("lost admission acknowledgment")},
		{name: "terminal failure", factsErr: errors.New("storage unavailable"), wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &shadowAccountingFixture{fakeInvocationStore: fakeInvocationStore{admitErr: tc.admitErr, factsErr: tc.factsErr}}
			var calls atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				store.mu.Lock()
				started := len(store.admitted)
				store.mu.Unlock()
				if started != 1 {
					t.Errorf("provider observed %d confirmed starts", started)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(completeResp("gpt-4o"))
			}))
			defer provider.Close()
			gw := shadowTestGateway(t, provider.URL, provider.URL)
			gw.invocations = store
			primary := newInvocationIdentity("org-1", "shared", "session", "", "", "primary")
			ctx, cancel := context.WithCancel(withInvocationIdentity(t.Context(), primary))
			job := gw.buildShadowJob(ctx, nonStreamBody("primary", "prompt"), "primary", "org-1", "team", "session", "shared", gw.log)
			cancel()
			var events []*eventpub.Event
			restore := observeEvent(func(ev *eventpub.Event) {
				if ev.RequestID != "shared" {
					return
				}
				store.mu.Lock()
				defer store.mu.Unlock()
				require.Len(t, store.facts, 1, "published before terminal fact was written")
				events = append(events, ev)
			})
			defer restore()
			gw.shadow.Run(job)
			require.EqualValues(t, tc.wantCalls, calls.Load())
			require.Len(t, store.admitted, tc.wantCalls)
			require.Len(t, store.facts, tc.wantFacts)
			require.Len(t, events, tc.wantFacts)
			if tc.wantFacts == 0 {
				return
			}
			fact := store.facts[0]
			require.NotEqual(t, primary.ID(), fact.InvocationID)
			require.Equal(t, store.admitted[0].InvocationID, fact.InvocationID)
			require.Equal(t, fact.InvocationID, events[0].InvocationID)
			require.Equal(t, "shadow", fact.Kind)
			require.Equal(t, "org-1", fact.OrgID)
			require.Equal(t, "shared", fact.ClientRequestID)
			require.Equal(t, "request.shadow_completed", fact.Fields["event_type"])
			require.Equal(t, "10", fact.Fields["tokens_in"])
			require.Equal(t, "5", fact.Fields["tokens_out"])
		})
	}
}
