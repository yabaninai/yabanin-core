package cli

// invocation_test.go — negative controls for the durable per-invocation
// accounting lifecycle (owner review, November 21): fail-closed store
// errors (no silent admission, no nil-pool grant), void blocking from the
// attempt with a retriable row-write, the terminal-vs-void race in both
// directions, verbatim projection passthrough (used_org_key included)
// and the event-identity binding of commitInvocationTerminal.

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// fakeInvocationStore scripts the durable seam for isolated tests and
// emulates the production store's equality contract on recommit.
type fakeInvocationStore struct {
	admitErr   error
	voidErr    error
	factsErr   error
	factsErrs  []error // scripted per-call queue (transient 40001 ladders)
	factsCalls int
	admitted   []admissionRecord
	voided     []string
	facts      []terminalFactsRecord
}

func (f *fakeInvocationStore) AdmitInvocation(_ context.Context, rec admissionRecord) error {
	if f.admitErr != nil {
		return f.admitErr
	}
	f.admitted = append(f.admitted, rec)
	return nil
}

func (f *fakeInvocationStore) VoidInvocation(_ context.Context, id string) error {
	if f.voidErr != nil {
		return f.voidErr
	}
	f.voided = append(f.voided, id)
	return nil
}

func (f *fakeInvocationStore) RecordTerminalFacts(_ context.Context, rec terminalFactsRecord) error {
	f.factsCalls++
	if len(f.factsErrs) > 0 {
		err := f.factsErrs[0]
		f.factsErrs = f.factsErrs[1:]
		if err != nil {
			return err
		}
	}
	if f.factsErr != nil {
		return f.factsErr
	}
	for _, prev := range f.facts {
		if prev.InvocationID != rec.InvocationID {
			continue
		}
		if prev.OrgID == rec.OrgID && prev.Kind == rec.Kind && maps.Equal(prev.Fields, rec.Fields) {
			return nil // identical re-commit: idempotent win
		}
		return ErrTerminalFactsDivergent // changed payload: first commit wins
	}
	f.facts = append(f.facts, rec)
	return nil
}

func newTestIdentity() *invocationIdentity {
	return newInvocationIdentity("org-1", "client-req-1", "sess-1", "7", "9", "m")
}

func TestBeginPaidDispatchFailsClosedOnStoreError(t *testing.T) {
	store := &fakeInvocationStore{admitErr: errors.New("db down")}
	h := newTestIdentity()

	err := h.beginPaidDispatch(t.Context(), store, invocationKindChat)
	require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
	require.False(t, h.Admitted(), "a failed admission write must never mark admitted (zero provider arrivals posture)")

	// The refused start LATCHES: the same holder can never grant a
	// fallback dispatch, even after the store recovers — the commit
	// outcome stayed unknown. (Owner review, November 21.)
	store.admitErr = nil
	require.ErrorIs(t, h.beginPaidDispatch(t.Context(), store, invocationKindStream),
		ErrInvocationStoreUnavailable, "fallback hop on a refused start must fail closed")
	require.Empty(t, store.admitted)

	// Only a fresh client invocation — a newly minted identity — retries.
	fresh := newTestIdentity()
	require.NoError(t, fresh.beginPaidDispatch(t.Context(), store, invocationKindStream))
	require.Equal(t, invocationKindStream, fresh.Kind())
	require.Len(t, store.admitted, 1, "first-dispatch kind wins; hops are no-ops")
	require.NoError(t, fresh.beginPaidDispatch(t.Context(), store, invocationKindChat))
	require.Len(t, store.admitted, 1)
}

func TestBeginPaidDispatchRejectsVoidedAndInvalidKind(t *testing.T) {
	store := &fakeInvocationStore{}
	h := newTestIdentity()
	require.NoError(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat))
	require.NoError(t, h.void(t.Context(), store))

	require.ErrorIs(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat), ErrInvocationVoided,
		"dispatch after void is a path-ordering bug, not a silent nil")

	require.Error(t, h.beginPaidDispatch(t.Context(), store, "embeddings"), "kind domain is enforced before any store call")
	require.Len(t, store.admitted, 1)
}

func TestNilPoolStoreFailsClosed(t *testing.T) {
	store := NewPGInvocationStore(nil)
	ctx := t.Context()
	require.ErrorIs(t, store.AdmitInvocation(ctx, admissionRecord{}), ErrInvocationStoreUnavailable)
	require.ErrorIs(t, store.VoidInvocation(ctx, "x"), ErrInvocationStoreUnavailable)
	require.ErrorIs(t, store.RecordTerminalFacts(ctx, terminalFactsRecord{Fields: map[string]string{"a": "b"}}),
		ErrInvocationStoreUnavailable)
}

func TestVoidBlocksDispatchFromAttemptAndIsRetriable(t *testing.T) {
	store := &fakeInvocationStore{}
	h := newTestIdentity()
	require.NoError(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat))

	store.voidErr = errors.New("db down")
	require.ErrorIs(t, h.void(t.Context(), store), ErrInvocationStoreUnavailable)
	require.ErrorIs(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat), ErrInvocationVoided,
		"dispatch is disabled from the void ATTEMPT, even while the row-write is retrying")

	store.voidErr = nil
	require.NoError(t, h.void(t.Context(), store), "the durable void is retriable after the database error")
	require.Equal(t, []string{h.ID()}, store.voided)
}

func TestVoidWithoutAdmissionIsLocalOnly(t *testing.T) {
	store := &fakeInvocationStore{}
	h := newTestIdentity()
	require.NoError(t, h.void(t.Context(), store))
	require.Empty(t, store.voided, "never-admitted identities have no row to void")
	require.ErrorIs(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat), ErrInvocationVoided)
}

func TestTerminalVsVoidRace(t *testing.T) {
	t.Run("terminal facts refused on voided identity", func(t *testing.T) {
		store := &fakeInvocationStore{}
		h := newTestIdentity()
		require.NoError(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat))
		require.NoError(t, h.void(t.Context(), store))
		err := h.recordTerminalFacts(t.Context(), store, map[string]string{"event_type": "request.completed"})
		require.ErrorIs(t, err, ErrInvocationVoided)
		require.Empty(t, store.facts)
	})
	t.Run("void refused after terminal facts committed", func(t *testing.T) {
		store := &fakeInvocationStore{}
		h := newTestIdentity()
		require.NoError(t, h.beginPaidDispatch(t.Context(), store, invocationKindStream))
		require.NoError(t, h.recordTerminalFacts(t.Context(), store, map[string]string{"event_type": "request.completed"}))
		require.ErrorIs(t, h.void(t.Context(), store), ErrInvocationTerminal,
			"facts are authoritative — no void can retract committed usage")
	})
	t.Run("dispatch refused after terminal facts", func(t *testing.T) {
		store := &fakeInvocationStore{}
		h := newTestIdentity()
		require.NoError(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat))
		require.NoError(t, h.recordTerminalFacts(t.Context(), store, map[string]string{"event_type": "request.completed"}))
		require.ErrorIs(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat), ErrInvocationTerminal)
	})
}

func TestRecordTerminalFactsRequiresAdmissionAndFields(t *testing.T) {
	store := &fakeInvocationStore{}
	h := newTestIdentity()
	require.Error(t, h.recordTerminalFacts(t.Context(), store, map[string]string{"event_type": "request.completed"}),
		"terminal facts require the admission row (composite FK)")

	require.NoError(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat))
	require.Error(t, h.recordTerminalFacts(t.Context(), store, map[string]string{}), "an empty projection is a bug, not a charge")
}

func TestRecordTerminalFactsDivergenceSurfaces(t *testing.T) {
	store := &fakeInvocationStore{}
	h := newTestIdentity()
	require.NoError(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat))

	first := map[string]string{"event_type": "request.completed", "tokens_in": "7"}
	require.NoError(t, h.recordTerminalFacts(t.Context(), store, first))

	err := h.recordTerminalFacts(t.Context(), store, map[string]string{"event_type": "request.completed", "tokens_in": "99"})
	require.ErrorIs(t, err, ErrTerminalFactsDivergent,
		"a changed payload must never be silently accepted on recommit")
	require.Len(t, store.facts, 1, "the first commit stays authoritative")

	require.NoError(t, h.recordTerminalFacts(t.Context(), store, first),
		"an identical recommit is an idempotent win")
	require.Len(t, store.facts, 1)
}

func TestCommitInvocationTerminalBindsEventIdentityAndPassesFieldsVerbatim(t *testing.T) {
	store := &fakeInvocationStore{}
	h := newTestIdentity()
	require.NoError(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat))

	wrong := &eventpub.Event{EventType: "request.completed", TS: 1}
	require.Error(t, h.commitInvocationTerminal(t.Context(), store, wrong),
		"the event must carry the admitted identity before the facts commit")

	ev := &eventpub.Event{
		EventType:    "request.completed",
		TS:           1732200000000,
		InvocationID: h.ID(),
		OrgID:        "org-1",
		UsedOrgKey:   true,
		StatusCode:   200,
		TokensIn:     10,
		TokensOut:    20,
		PromptHash:   "ph-1",
		APIKeyID:     "7",
		SessionKeyID: "9",
	}
	require.NoError(t, h.commitInvocationTerminal(t.Context(), store, ev))
	require.Len(t, store.facts, 1)
	facts := store.facts[0]
	require.Equal(t, h.ID(), facts.InvocationID)
	require.Equal(t, invocationKindChat, facts.Kind, "facts kind must equal the admission kind (equality guard)")
	require.Equal(t, "true", facts.Fields["used_org_key"], "the BYOK payer marker passes through verbatim")
	require.Equal(t, "200", facts.Fields["status_code"])
	require.Equal(t, "7", facts.Fields["api_key_id"])

	// Idempotent recommit of the same event is a win; the facts stay singular.
	require.NoError(t, h.commitInvocationTerminal(t.Context(), store, ev))
	require.Len(t, store.facts, 1)

	// A zero TS is rejected by the projection before any store call.
	noTS := &eventpub.Event{EventType: "request.completed", InvocationID: h.ID(), OrgID: "org-1"}
	require.Error(t, h.commitInvocationTerminal(t.Context(), store, noTS))
	require.Len(t, store.facts, 1)
}
