package cli

import (
	"errors"
	"testing"

	pub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// TestPreviewOwnerStateEdges pins the Preview2 owner-state edges: a refused
// start latches, a pending void blocks the terminal commit, a foreign-org
// event is rejected, and a divergent local recommit is refused.
func TestPreviewOwnerStateEdges(t *testing.T) {
	t.Run("refused_start_latches", previewRefusedStartLatches)
	t.Run("pending_void_blocks_terminal", previewPendingVoidBlocksTerminal)
	t.Run("wrong_org_rejected", previewWrongOrgRejected)
	t.Run("divergent_local_recommit", previewDivergentLocalRecommit)
}

// previewAdmittedEvent starts a paid chat dispatch and returns the
// invocation, its store and the completed-event template the terminal
// edges mutate.
func previewAdmittedEvent(t *testing.T) (*invocationIdentity, *fakeInvocationStore, *pub.Event) {
	t.Helper()

	id := newTestIdentity()
	store := &fakeInvocationStore{}
	if err := id.beginPaidDispatch(t.Context(), store, invocationKindChat); err != nil {
		t.Fatal(err)
	}
	return id, store, &pub.Event{
		EventType:    "request.completed",
		OrgID:        "org-1",
		InvocationID: id.ID(),
		TS:           1234,
		TokensIn:     7,
		RequestID:    "client-req-1",
	}
}

// previewTerminalCommitRejected pins the shared edge of the admitted
// scenarios: the mutated or replayed terminal must not land.
func previewTerminalCommitRejected(t *testing.T, id *invocationIdentity, store *fakeInvocationStore, ev *pub.Event) {
	t.Helper()

	if err := id.commitInvocationTerminal(t.Context(), store, ev); err == nil {
		t.Fatalf("invalid terminal accepted: %+v", store.facts)
	}
}

func previewRefusedStartLatches(t *testing.T) {
	store := &fakeInvocationStore{}
	store.admitErr = errors.New("commit outcome unknown")
	id := newTestIdentity()
	if err := id.beginPaidDispatch(t.Context(), store, invocationKindChat); err == nil {
		t.Fatal("first start succeeded")
	}
	store.admitErr = nil
	if err := id.beginPaidDispatch(t.Context(), store, invocationKindStream); err == nil {
		t.Fatal("fallback on refused request got dispatch permission")
	}
}

func previewPendingVoidBlocksTerminal(t *testing.T) {
	id, store, ev := previewAdmittedEvent(t)
	store.voidErr = errors.New("temporary")
	if err := id.void(t.Context(), store); err == nil {
		t.Fatal("missing void error")
	}
	previewTerminalCommitRejected(t, id, store, ev)
}

func previewWrongOrgRejected(t *testing.T) {
	id, store, ev := previewAdmittedEvent(t)
	ev.OrgID = "another-org"
	previewTerminalCommitRejected(t, id, store, ev)
}

func previewDivergentLocalRecommit(t *testing.T) {
	id, store, ev := previewAdmittedEvent(t)
	if err := id.commitInvocationTerminal(t.Context(), store, ev); err != nil {
		t.Fatal(err)
	}
	ev.TokensIn = 99
	previewTerminalCommitRejected(t, id, store, ev)
}
