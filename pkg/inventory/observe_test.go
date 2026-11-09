package inventory

// E02-P01 W04-C01: observation-plane behavior — identity mapping, dedup,
// no-downgrade touch semantics, monotone last_seen, tombstone clearing.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func obTime(t *testing.T) (time.Time, time.Time) {
	t.Helper()
	return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 11, 7, 13, 0, 0, 0, time.UTC)
}

func obEvent(ts time.Time) *eventpublisher.Event {
	return &eventpublisher.Event{
		TS:             ts.UnixMilli(),
		RequestID:      "req-1",
		SessionID:      "sess-9",
		AgentID:        "agent-x",
		ModelRequested: "gpt-x",
		ModelUsed:      "gpt-x-mini",
		UpstreamURL:    "https://api.openai.com/v1",
		StatusCode:     200,
	}
}

// TestObserveEventIdentityMapping: the W01 identity table — agent, two
// provider-less models, service; session/task never become kinds; session
// is recorded as observation context inside the agent payload.
func TestObserveEventIdentityMapping(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, _ := obTime(t)

	rep, err := o.ObserveEvent(context.Background(), "org-ob1", obEvent(t1))
	require.NoError(t, err)
	assert.Equal(t, 4, rep.Counts.Created, "%+v", rep.Counts)
	assert.False(t, rep.Deduped)

	agent, ok, err := s.GetAsset(context.Background(), "org-ob1", KindAgent, AgentKey("agent-x"))
	require.NoError(t, err)
	require.True(t, ok, "agent asset must exist")
	assert.Equal(t, SourceObservation, agent.Source)
	assert.Equal(t, ConfidenceLow, agent.Confidence)
	var ao agentObservation
	require.NoError(t, json.Unmarshal(agent.Payload, &ao))
	assert.Equal(t, "sess-9", ao.SessionID, "session is payload context")
	assert.Equal(t, []string{"gpt-x"}, ao.ModelsRequested)
	assert.Equal(t, []string{"gpt-x-mini"}, ao.ModelsUsed)
	assert.True(t, ao.ObservedAt.Equal(t1))

	req, ok, _ := s.GetAsset(context.Background(), "org-ob1", KindModel, observedModelKey("gpt-x"))
	require.True(t, ok)
	var mo modelObservation
	require.NoError(t, json.Unmarshal(req.Payload, &mo))
	assert.False(t, mo.Used)
	assert.Equal(t, "agent-x", mo.AgentID)

	used, ok, _ := s.GetAsset(context.Background(), "org-ob1", KindModel, observedModelKey("gpt-x-mini"))
	require.True(t, ok)
	require.NoError(t, json.Unmarshal(used.Payload, &mo))
	assert.True(t, mo.Used)

	svc, ok, _ := s.GetAsset(context.Background(), "org-ob1", KindService, ServiceKey("https://api.openai.com/v1"))
	require.True(t, ok, "upstream service asset must exist")
	assert.Equal(t, SourceObservation, svc.Source)

	// No session or task asset exists, and no asset of any other kind.
	rows, _, err := s.ListAssets(context.Background(), "org-ob1", ListParams{})
	require.NoError(t, err)
	require.Len(t, rows, 4)
	for _, r := range rows {
		assert.NotEqual(t, "session", string(r.Kind))
		assert.NotEqual(t, "task", string(r.Kind))
	}
}

// TestObserveEventNoAgent: without AgentID the event creates no agent
// asset and touches nothing agent-shaped; the rest of the identity table
// still applies.
func TestObserveEventNoAgent(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, _ := obTime(t)
	ev := obEvent(t1)
	ev.AgentID = ""

	rep, err := o.ObserveEvent(context.Background(), "org-ob2", ev)
	require.NoError(t, err)
	assert.Equal(t, 3, rep.Counts.Created)

	_, ok, err := s.GetAsset(context.Background(), "org-ob2", KindAgent, AgentKey("agent-x"))
	require.NoError(t, err)
	assert.False(t, ok, "no AgentID on the wire ⇒ no agent identity")
}

// TestObserveEventRefusesEmptyOrg: obligation ② — observations are
// org-scoped, an empty org is refused with the shared sentinel.
func TestObserveEventRefusesEmptyOrg(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, _ := obTime(t)

	_, err = o.ObserveEvent(context.Background(), "", obEvent(t1))
	require.ErrorIs(t, err, ErrOrgRequired)
}

// TestObserveEventNilEvent: a nil event is a no-op, not an error.
func TestObserveEventNilEvent(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)

	rep, err := o.ObserveEvent(context.Background(), "org-ob2", nil)
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{}, rep.Counts)
}

// TestObserveEventNoIdentity: an event with context but no identity
// fields touches nothing and errors nothing.
func TestObserveEventNoIdentity(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, _ := obTime(t)

	rep, err := o.ObserveEvent(context.Background(), "org-ob2n", &eventpublisher.Event{
		TS: t1.UnixMilli(), RequestID: "req-ni", SessionID: "sess-1", StatusCode: 500,
	})
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{}, rep.Counts)

	rows, _, err := s.ListAssets(context.Background(), "org-ob2n", ListParams{})
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// TestObserveEventDedup: a replayed delivery of the same org+RequestID is
// collapsed by the observer; the same RequestID in another org and a new
// RequestID in the same org are distinct deliveries.
func TestObserveEventDedup(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, _ := obTime(t)

	rep, err := o.ObserveEvent(context.Background(), "org-ob3", obEvent(t1))
	require.NoError(t, err)
	assert.Equal(t, 4, rep.Counts.Created)

	rep, err = o.ObserveEvent(context.Background(), "org-ob3", obEvent(t1))
	require.NoError(t, err)
	assert.True(t, rep.Deduped)
	assert.Equal(t, ImportCounts{}, rep.Counts, "deduped delivery writes nothing")

	// Same RequestID, different org: a different key space entirely.
	rep, err = o.ObserveEvent(context.Background(), "org-ob3b", obEvent(t1))
	require.NoError(t, err)
	assert.False(t, rep.Deduped)
	assert.Equal(t, 4, rep.Counts.Created)

	// New RequestID in the same org: same identities, touch semantics.
	ev := obEvent(t1.Add(time.Minute))
	ev.RequestID = "req-2"
	rep, err = o.ObserveEvent(context.Background(), "org-ob3", ev)
	require.NoError(t, err)
	assert.False(t, rep.Deduped)
	assert.Equal(t, ImportCounts{Updated: 4}, rep.Counts)
}

// TestObserveEventNoDowngrade: an observation of an identity an import
// already wrote keeps the authoritative payload, source and confidence —
// only last_seen advances.
func TestObserveEventNoDowngrade(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, t2 := obTime(t)

	// Authoritative high-confidence row under the observation key.
	_, err = s.UpsertAssets(context.Background(), []Asset{{
		OrgID: "org-ob4", AssetKey: observedModelKey("gpt-x"), Kind: KindModel,
		Payload: json.RawMessage(`{"registry":{"model_name":"gpt-x"}}`), Source: SourceModelsRegistry,
		Confidence: ConfidenceHigh, FirstSeen: t1, LastSeen: t1,
	}})
	require.NoError(t, err)

	ev := &eventpublisher.Event{TS: t2.UnixMilli(), RequestID: "req-d1", ModelRequested: "gpt-x"}
	rep, err := o.ObserveEvent(context.Background(), "org-ob4", ev)
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Updated: 1}, rep.Counts)

	row, ok, err := s.GetAsset(context.Background(), "org-ob4", KindModel, observedModelKey("gpt-x"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, ConfidenceHigh, row.Confidence, "confidence must not degrade")
	assert.Equal(t, SourceModelsRegistry, row.Source, "source must not be rewritten")
	assert.JSONEq(t, `{"registry":{"model_name":"gpt-x"}}`, string(row.Payload), "payload must stay authoritative")
	assert.True(t, row.LastSeen.Equal(t2), "last_seen must advance")
	assert.True(t, row.FirstSeen.Equal(t1), "first_seen must never move")
}

// TestObserveEventTombstoneCleared: a fresh observation resurrects a
// tombstoned observed identity (existence is the payload).
func TestObserveEventTombstoneCleared(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, t2 := obTime(t)

	_, err = o.ObserveEvent(context.Background(), "org-ob5", obEvent(t1))
	require.NoError(t, err)
	n, err := s.TombstoneAssets(context.Background(), "org-ob5", KindModel,
		t1.Add(time.Minute), []string{observedModelKey("gpt-x")})
	require.NoError(t, err)
	require.Equal(t, 1, n)

	ev := obEvent(t2)
	ev.RequestID = "req-t2"
	rep, err := o.ObserveEvent(context.Background(), "org-ob5", ev)
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Updated: 4}, rep.Counts, "the resurrected row is a touch")

	row, ok, err := s.GetAsset(context.Background(), "org-ob5", KindModel, observedModelKey("gpt-x"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.False(t, row.Tombstone, "observation clears the tombstone")
	assert.True(t, row.LastSeen.Equal(t2))
}

// TestObserveEventOldTimestamp: a late delivery carrying an older TS than
// the stored last_seen moves nothing — the max-semantics are durable in
// SQL, surviving an observer restart (no dedup map).
func TestObserveEventOldTimestamp(t *testing.T) {
	s := newTestStore(t)
	o1, err := NewObserver(s)
	require.NoError(t, err)
	t1, t2 := obTime(t)

	_, err = o1.ObserveEvent(context.Background(), "org-ob6", obEvent(t2))
	require.NoError(t, err)

	// Fresh observer (restart): the dedup map is gone, so the replayed
	// older delivery is processed — and lands as unchanged.
	o2, err := NewObserver(s)
	require.NoError(t, err)
	rep, err := o2.ObserveEvent(context.Background(), "org-ob6", obEvent(t1))
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Unchanged: 4}, rep.Counts)

	row, ok, err := s.GetAsset(context.Background(), "org-ob6", KindModel, observedModelKey("gpt-x"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, row.LastSeen.Equal(t2), "old delivery must not rewind last_seen")
}

// TestObserveEventSameModelOnce: requested and used differing only in
// case fold to ONE model asset that served the request.
func TestObserveEventSameModelOnce(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, _ := obTime(t)
	ev := obEvent(t1)
	ev.ModelUsed = "GPT-X"

	rep, err := o.ObserveEvent(context.Background(), "org-ob7", ev)
	require.NoError(t, err)
	// agent + one model + service = 3
	assert.Equal(t, 3, rep.Counts.Created)

	rows, _, err := s.ListAssets(context.Background(), "org-ob7", ListParams{Kind: KindModel})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	var mo modelObservation
	require.NoError(t, json.Unmarshal(rows[0].Payload, &mo))
	assert.True(t, mo.Used, "the served name is the used identity")
}
