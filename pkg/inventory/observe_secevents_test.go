package inventory

// E02-P01 W04-C02: secevents folding — known-ref identity, unknown-ref
// refusal, unique-suffix tool attribution, cross-org tenant boundary,
// EventID dedup, no-downgrade touches.

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/secevents"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secEv builds one security event through the canonical Decode path.
func secEv(t *testing.T, org, id, agentState, agentVal, toolState, toolVal, occurredAt string) *secevents.Event {
	t.Helper()
	wireJSON := `{
		"schema_version": 1,
		"event_id": "` + id + `",
		"event_type": "tool.deny",
		"org_id": "` + org + `",
		"occurred_at": "` + occurredAt + `",
		"identity": {
			"agent": {"state": "` + agentState + `", "value": "` + agentVal + `"},
			"session": {"value": "sess-42"},
			"task": {"state": "absent"},
			"tool": {"state": "` + toolState + `", "value": "` + toolVal + `"}
		},
		"summary": "policy deny by p1",
		"cost": {"state": "unknown"}
	}`
	e, _, err := secevents.Decode([]byte(wireJSON))
	require.NoError(t, err)
	return &e
}

// TestObserveSecEventsAgentKnown: a known agent ref touches agent:<value>;
// session stays payload context; no session/task kind exists.
func TestObserveSecEventsAgentKnown(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)

	rep, err := o.ObserveSecEvents(context.Background(), "org-sc1",
		[]*secevents.Event{secEv(t, "org-sc1", "sec-1", "known", "agent-7", "absent", "", "2026-11-07T12:00:00Z")})
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Created: 1}, rep.Counts)

	row, ok, err := s.GetAsset(context.Background(), "org-sc1", KindAgent, AgentKey("agent-7"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, SourceObservation, row.Source)
	assert.Equal(t, ConfidenceLow, row.Confidence)
	var so seceventObservation
	require.NoError(t, json.Unmarshal(row.Payload, &so))
	assert.Equal(t, []string{"sec-1"}, so.EventIDs)
	assert.Equal(t, []string{"tool.deny"}, so.EventTypes)
	assert.Equal(t, "sess-42", so.SessionID, "session is payload context")
	assert.True(t, so.ObservedAt.Equal(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)))

	rows, _, err := s.ListAssets(context.Background(), "org-sc1", ListParams{})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.NotEqual(t, "session", string(rows[0].Kind))
}

// TestObserveSecEventsUnknownRefs: unknown refs are a redaction statement,
// not an identity — no asset is created or touched.
func TestObserveSecEventsUnknownRefs(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)

	rep, err := o.ObserveSecEvents(context.Background(), "org-sc2",
		[]*secevents.Event{secEv(t, "org-sc2", "sec-2", "unknown", "", "unknown", "", "2026-11-07T12:00:00Z")})
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{}, rep.Counts)
	assert.False(t, rep.Deduped)

	rows, _, err := s.ListAssets(context.Background(), "org-sc2", ListParams{})
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// TestObserveSecEventsToolAttribution: a known tool ref attributes to the
// org's tool asset by UNIQUE suffix match; zero or ambiguous matches mean
// no attribution (never invented, never re-bound).
func TestObserveSecEventsToolAttribution(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	at := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)

	// org-sc3: one server, tool websearch — unique.
	_, err = s.UpsertAssets(context.Background(), []Asset{
		{OrgID: "org-sc3", AssetKey: MCPToolKey("srv-a", "websearch"), Kind: KindTool,
			Payload: json.RawMessage(`{"name":"websearch"}`), Source: SourceMCPRegistry,
			Confidence: ConfidenceHigh, FirstSeen: at, LastSeen: at},
	})
	require.NoError(t, err)

	rep, err := o.ObserveSecEvents(context.Background(), "org-sc3",
		[]*secevents.Event{secEv(t, "org-sc3", "sec-3", "known", "agent-7", "known", "websearch", "2026-11-07T12:00:00Z")})
	require.NoError(t, err)
	// agent created + the existing (imported) tool touched = 1 created, 1 updated
	assert.Equal(t, ImportCounts{Created: 1, Updated: 1}, rep.Counts)

	tool, ok, err := s.GetAsset(context.Background(), "org-sc3", KindTool, MCPToolKey("srv-a", "websearch"))
	require.NoError(t, err)
	require.True(t, ok, "unique suffix ⇒ attribution")
	assert.Equal(t, ConfidenceHigh, tool.Confidence, "no downgrade")
	assert.True(t, tool.LastSeen.Equal(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)))

	// org-sc4: same tool name on TWO servers — ambiguous.
	_, err = s.UpsertAssets(context.Background(), []Asset{
		{OrgID: "org-sc4", AssetKey: MCPToolKey("srv-a", "websearch"), Kind: KindTool,
			Payload: json.RawMessage(`{"name":"websearch"}`), Source: SourceMCPRegistry,
			Confidence: ConfidenceHigh, FirstSeen: at, LastSeen: at},
		{OrgID: "org-sc4", AssetKey: MCPToolKey("srv-b", "websearch"), Kind: KindTool,
			Payload: json.RawMessage(`{"name":"websearch"}`), Source: SourceMCPRegistry,
			Confidence: ConfidenceHigh, FirstSeen: at, LastSeen: at},
	})
	require.NoError(t, err)

	rep, err = o.ObserveSecEvents(context.Background(), "org-sc4",
		[]*secevents.Event{secEv(t, "org-sc4", "sec-4", "known", "agent-7", "known", "websearch", "2026-11-07T12:00:00Z")})
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Created: 1}, rep.Counts, "ambiguous tool ⇒ agent only")

	// org-sc5: no such tool at all — zero matches.
	rep, err = o.ObserveSecEvents(context.Background(), "org-sc5",
		[]*secevents.Event{secEv(t, "org-sc5", "sec-5", "known", "agent-7", "known", "nosuch", "2026-11-07T12:00:00Z")})
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Created: 1}, rep.Counts, "unknown-to-org tool ⇒ agent only")
}

// TestObserveSecEventsRefusesEmptyOrg: obligation ②.
func TestObserveSecEventsRefusesEmptyOrg(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)

	_, err = o.ObserveSecEvents(context.Background(), "",
		[]*secevents.Event{secEv(t, "org-e", "sec-e", "known", "agent-7", "absent", "", "2026-11-07T12:00:00Z")})
	require.ErrorIs(t, err, ErrOrgRequired)
}

// TestObserveSecEventsCrossOrgSkipped: an event stamped for another org is
// refused and counted — a cross-org fold would be a tenant leak.
func TestObserveSecEventsCrossOrgSkipped(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)

	rep, err := o.ObserveSecEvents(context.Background(), "org-sc6",
		[]*secevents.Event{secEv(t, "org-sc0", "sec-6", "known", "agent-7", "absent", "", "2026-11-07T12:00:00Z")})
	require.NoError(t, err)
	assert.Equal(t, 1, rep.Skipped)
	assert.Equal(t, ImportCounts{}, rep.Counts)

	rows, _, err := s.ListAssets(context.Background(), "org-sc6", ListParams{})
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// TestObserveSecEventsDedup: replayed EventID deliveries collapse; a new
// EventID touches the same identities (last_seen only).
func TestObserveSecEventsDedup(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)

	rep, err := o.ObserveSecEvents(context.Background(), "org-sc7",
		[]*secevents.Event{secEv(t, "org-sc7", "sec-7", "known", "agent-7", "absent", "", "2026-11-07T12:00:00Z")})
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Created: 1}, rep.Counts)

	rep, err = o.ObserveSecEvents(context.Background(), "org-sc7",
		[]*secevents.Event{secEv(t, "org-sc7", "sec-7", "known", "agent-7", "absent", "", "2026-11-07T12:00:00Z")})
	require.NoError(t, err)
	assert.True(t, rep.Deduped)
	assert.Equal(t, ImportCounts{}, rep.Counts)

	rep, err = o.ObserveSecEvents(context.Background(), "org-sc7",
		[]*secevents.Event{secEv(t, "org-sc7", "sec-8", "known", "agent-7", "absent", "", "2026-11-07T13:00:00Z")})
	require.NoError(t, err)
	assert.False(t, rep.Deduped)
	assert.Equal(t, ImportCounts{Updated: 1}, rep.Counts)
}

// TestObserveSecEventsEmptyBatch: nil and empty batches are no-ops.
func TestObserveSecEventsEmptyBatch(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)

	for _, evs := range [][]*secevents.Event{nil, {}} {
		rep, err := o.ObserveSecEvents(context.Background(), "org-sc7", evs)
		require.NoError(t, err)
		assert.Equal(t, &ObserveReport{}, rep)
	}
}

// TestObserveSecEventsNoDowngrade: touching an imported high-confidence
// agent row keeps its payload, source and confidence; only last_seen
// moves.
func TestObserveSecEventsNoDowngrade(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	at := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)

	_, err = s.UpsertAssets(context.Background(), []Asset{
		{OrgID: "org-sc8", AssetKey: AgentKey("agent-7"), Kind: KindAgent,
			Payload: json.RawMessage(`{"registered_by":"admin"}`), Source: SourceMCPRegistry,
			Confidence: ConfidenceHigh, FirstSeen: at, LastSeen: at},
	})
	require.NoError(t, err)

	rep, err := o.ObserveSecEvents(context.Background(), "org-sc8",
		[]*secevents.Event{secEv(t, "org-sc8", "sec-9", "known", "agent-7", "absent", "", "2026-11-07T12:00:00Z")})
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Updated: 1}, rep.Counts)

	row, ok, err := s.GetAsset(context.Background(), "org-sc8", KindAgent, AgentKey("agent-7"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, ConfidenceHigh, row.Confidence)
	assert.Equal(t, SourceMCPRegistry, row.Source)
	assert.JSONEq(t, `{"registered_by":"admin"}`, string(row.Payload))
	assert.True(t, row.LastSeen.Equal(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)))
	assert.True(t, row.FirstSeen.Equal(at))
}

// TestObserveSecEventsToolAttributionBeyondOnePage: W04-C02 review fix —
// resolveToolKey must page through the org's ENTIRE tool set, not just the
// first ListAssets page (MaxPageSize rows). With MaxPageSize+1 tool rows:
// a suffix matching once on page 1 AND once on page 2 must NOT attribute
// to the page-1 twin (the reviewed mis-attribution), while a suffix that
// is unique org-wide but lives only on page 2 MUST still attribute
// (fidelity beyond one page — why the fix is page-exhaust, not fail-closed).
func TestObserveSecEventsToolAttributionBeyondOnePage(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	ctx := context.Background()
	imported := time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)
	eventAt := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)

	// seedTools imports n tool rows for org: server srv-%03d/<name>, row i
	// normally carrying tool name t<i>, overridden per index. Zero-padded
	// server numbers keep (kind, asset_key) sort order == numeric order, so
	// row MaxPageSize is deterministically the FIRST row of page 2.
	seedTools := func(org string, n int, overrides map[int]string) {
		rows := make([]Asset, 0, n)
		for i := 0; i < n; i++ {
			name := "t" + strconv.Itoa(i)
			if ovr, ok := overrides[i]; ok {
				name = ovr
			}
			rows = append(rows, Asset{
				OrgID: org, AssetKey: MCPToolKey(fmt.Sprintf("srv-%03d", i), name), Kind: KindTool,
				Payload: json.RawMessage(`{"imported":true}`), Source: SourceMCPRegistry,
				Confidence: ConfidenceHigh, FirstSeen: imported, LastSeen: imported,
			})
		}
		_, err := s.UpsertAssets(ctx, rows)
		require.NoError(t, err)
	}
	untouched := func(org, server, tool string) { // helper asserts: no attribution landed
		t.Helper()
		row, ok, err := s.GetAsset(ctx, org, KindTool, MCPToolKey(server, tool))
		require.NoError(t, err)
		require.True(t, ok)
		assert.True(t, row.LastSeen.Equal(imported), "%s/%s must keep last_seen %v, got %v",
			server, tool, imported, row.LastSeen)
		assert.JSONEq(t, `{"imported":true}`, string(row.Payload), "%s/%s payload must stay the import's", server, tool)
	}

	// org-sc9 (the reviewed probe): MaxPageSize+1 tool rows, suffix /dupx on
	// srv-000 (page 1) AND srv-500 (page 2) — ambiguous beyond one page.
	n := MaxPageSize + 1
	seedTools("org-sc9", n, map[int]string{0: "dupx", MaxPageSize: "dupx"})
	// Fixture sanity: page 1 is full and a page 2 exists — the boundary is
	// genuinely straddled (guards against silent MaxPageSize drift).
	p1, next, err := s.ListAssets(ctx, "org-sc9", ListParams{Kind: KindTool, IncludeTombstoned: true, Limit: MaxPageSize})
	require.NoError(t, err)
	require.Len(t, p1, MaxPageSize, "first tool page must be full")
	require.NotEmpty(t, next, "a second tool page must exist")

	rep, err := o.ObserveSecEvents(ctx, "org-sc9",
		[]*secevents.Event{secEv(t, "org-sc9", "sec-p1", "known", "agent-7", "known", "dupx", "2026-11-07T09:00:00Z")})
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Created: 1}, rep.Counts,
		"twin on page 2 ⇒ ambiguous org-wide ⇒ agent only, NO tool attribution")
	untouched("org-sc9", "srv-000", "dupx") // the old code touched exactly this page-1 twin
	untouched("org-sc9", fmt.Sprintf("srv-%03d", MaxPageSize), "dupx")

	// org-sc10: MaxPageSize+1 tool rows, suffix /onlypage2 unique org-wide
	// and living ONLY on page 2 (row MaxPageSize) — must still attribute.
	seedTools("org-sc10", n, map[int]string{MaxPageSize: "onlypage2"})

	rep, err = o.ObserveSecEvents(ctx, "org-sc10",
		[]*secevents.Event{secEv(t, "org-sc10", "sec-p2", "known", "agent-7", "known", "onlypage2", "2026-11-07T09:00:00Z")})
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Created: 1, Updated: 1}, rep.Counts,
		"unique suffix beyond page 1 ⇒ attribution preserved (page-exhaust, not fail-closed)")

	row, ok, err := s.GetAsset(ctx, "org-sc10", KindTool, MCPToolKey(fmt.Sprintf("srv-%03d", MaxPageSize), "onlypage2"))
	require.NoError(t, err)
	require.True(t, ok, "unique org-wide suffix on page 2 ⇒ attribution")
	assert.True(t, row.LastSeen.Equal(eventAt), "attribution advances last_seen")
	assert.Equal(t, ConfidenceHigh, row.Confidence, "no downgrade")
	assert.Equal(t, SourceMCPRegistry, row.Source)
	assert.JSONEq(t, `{"imported":true}`, string(row.Payload), "touch never re-binds the payload")
}
