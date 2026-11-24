package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/requestid"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// Each scenario describes facts an operator can observe and the label expected
// on the completed request. An unrelated request is interleaved in every case.
type traceDeliveryScenario struct {
	declared  int
	published int
	drop      bool
	steps     bool
	findings  bool
	want      string
}

var traceDeliveryCases = []traceDeliveryScenario{
	{want: `{"v":1,"c":"unknown"}`},
	{published: 2, want: `{"v":1,"c":"unknown"}`},
	{declared: 2, want: `{"v":1,"c":"absent"}`},
	{declared: 2, published: 1, want: `{"v":1,"c":"unknown"}`},
	{declared: 2, published: 2, want: `{"v":1,"c":"full"}`},
	{declared: 2, published: 3, want: `{"v":1,"c":"full"}`},
	{declared: 2, published: 2, drop: true, want: `{"v":1,"c":"partial","r":["drop:event_publish:publish_failed"]}`},
	{steps: true, findings: true, want: `{"v":1,"c":"partial","r":["truncated:policy_steps","truncated:policy_findings"]}`},
	{drop: true, steps: true, want: `{"v":1,"c":"partial","r":["drop:event_publish:publish_failed","truncated:policy_steps"]}`},
}

// Scale the cohort without changing its expected completeness. Generated
// counts cross small and large declarations and can leave several siblings pending.
func (s traceDeliveryScenario) scaled(extra int) traceDeliveryScenario {
	if s.declared == 0 {
		if s.published > 0 {
			s.published += extra
		}
		return s
	}
	if s.published >= s.declared {
		s.published += extra
	}
	s.declared += extra
	return s
}

func (s traceDeliveryScenario) emit(t *testing.T, id string, before bool) {
	t.Helper()
	if before {
		traceStampDeclare(id, s.declared)
	}
	for range s.published {
		traceStampObservePublished(id)
	}
	traceStampDeclare(id, s.declared)
	traceStampDeclare(id, 0)
	ctx := requestid.NewContext(t.Context(), requestid.ID(id))
	traceStampPolicyTruncation(ctx, s.steps, s.findings)
	if s.drop {
		traceStampObserveDrop(id, "drop:event_publish:publish_failed")
		traceStampObserveDrop(id, "drop:event_publish:publish_failed")
	}
}

func traceDeliveryEvent(t *testing.T, id, label string, scenario traceDeliveryScenario, before bool) *eventpub.Event {
	t.Helper()
	other := traceStampTestID(t, id+"/other")
	traceStampDeclare(other, 1)
	traceStampObservePublished(other)
	scenario.emit(t, id, before)
	caller := map[string]string{"workload": label}
	ev := &eventpub.Event{EventType: "request", RequestID: id, Labels: caller}
	traceStampEvent(ev)
	require.Equal(t, map[string]string{"workload": label}, caller)
	require.Equal(t, label, ev.Labels["workload"])
	require.JSONEq(t, scenario.want, ev.Labels["trace_completeness"])

	adjacent := &eventpub.Event{RequestID: other}
	traceStampEvent(adjacent)
	require.JSONEq(t, `{"v":1,"c":"full"}`, adjacent.Labels["trace_completeness"])
	repeated := &eventpub.Event{RequestID: id}
	traceStampEvent(repeated)
	require.JSONEq(t, `{"v":1,"c":"unknown"}`, repeated.Labels["trace_completeness"])
	return ev
}

func FuzzTraceEventDelivery(f *testing.F) {
	for i := range traceDeliveryCases {
		f.Add(uint8(i), uint32(23+i), i%2 == 0)
	}
	// The two wave-2 guard seeds stay reserved with their baseline
	// arguments: 200 pins the cheap no-op arms, 201 the registry eviction
	// bound. The exact-index dispatch keeps the expensive 201 saturation
	// reachable only through its reserved seed — never a whole range of
	// folded mutations.
	f.Add(uint8(200), uint32(1), false)
	f.Add(uint8(201), uint32(1), false)
	f.Fuzz(func(t *testing.T, index uint8, request uint32, before bool) {
		if index == 200 || index == 201 {
			// Reserved guard indices dispatch explicitly; every other
			// value folds into the fixed scenario table as a legal pick,
			// and the request id, the scaled cohort and the declare order
			// are the genuinely varied inputs.
			traceStampGuardCase(t, int(index))
			return
		}
		s := traceDeliveryCases[int(index)%len(traceDeliveryCases)].scaled(int(request % 31))
		id := traceStampTestID(t, fmt.Sprintf("delivery-%08x", request))
		traceDeliveryEvent(t, id, fmt.Sprintf("team-%x", request), s, before)
	})
}

// TestTraceStampGuardPins pins the wave-3 trace-stamp guard arms the
// request-scoped scenarios cannot reach — the reason-append bound with
// its valid-id drop pin (202) and the bounded-envelope eviction loop
// (203). Guards 200/201 stay pinned through the reserved fuzz seeds in
// FuzzTraceEventDelivery. The guard facts are a fixed table, not a fuzz
// dispatch: mutations must never reach a refusal arm.
func TestTraceStampGuardPins(t *testing.T) {
	for _, index := range []int{202, 203} {
		traceStampGuardCase(t, index)
	}
}

// traceStampGuardCase pins the trace-stamp guard arms (critical-go wave 2):
// empty request ids and reasons outside the closed enum are honest no-ops,
// a context without a request id never marks policy truncation, and the
// bounded registry evicts its oldest slot cyclically when the 4097th
// request registers.
func traceStampGuardCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 200:
		require.Nil(t, traceStampClaim(""))
		traceStampObservePublished("")
		traceStampObserveDrop("", "drop:event_publish:publish_failed")
		traceStampMarkTruncated("", "truncated:policy_steps")
		traceStampMarkTruncated("guard-200", "not-a-reason")
		traceStampDeclare("", 3)
		traceStampDeclare("guard-200", -1)
		traceStampPolicyTruncation(context.Background(), true, true)
		ev := &eventpub.Event{RequestID: "guard-200"}
		traceStampEvent(ev)
		require.JSONEq(t, `{"v":1,"c":"unknown"}`, ev.Labels["trace_completeness"])
	case 201:
		// Fill the registry to its bound, then force one cyclic eviction:
		// the slot about to be overwritten is freed and a claim for it
		// reports absence instead of resurrecting stale evidence.
		var fill []string
		defer func() {
			for _, id := range fill {
				traceStampClaim(id)
			}
		}()
		registrySize := func() int {
			traceStampMu.Lock()
			defer traceStampMu.Unlock()
			return len(traceStampRegistry)
		}
		for registrySize() < traceStampRegistryMax {
			id := fmt.Sprintf("evict-%d", len(fill))
			traceStampStateFor(id)
			fill = append(fill, id)
		}
		traceStampMu.Lock()
		victim := traceStampRing[traceStampRingNext]
		traceStampMu.Unlock()
		traceStampStateFor("evict-newest")
		require.Nil(t, traceStampClaim(victim))
		require.NotNil(t, traceStampClaim("evict-newest"))
	case 202:
		// The reason append is deduplicating and bounded: at the cap the
		// marker is appended once, further reasons are dropped. A valid-id
		// drop is stored per reason in call order (wave-3 explicit pin for
		// the observe-drop path the scenarios only reach via emit).
		one := traceStampAppendUnique(nil, traceStampDropPublishFailed)
		require.Equal(t, []string{traceStampDropPublishFailed}, one)
		require.Len(t, traceStampAppendUnique(one, traceStampDropPublishFailed), 1)
		full := traceStampAppendUnique(
			[]string{traceStampDropBacklogFull, traceStampTruncPolicySteps, traceStampTruncPolicyFindings},
			traceStampDropPublishFailed)
		require.Equal(t, []string{
			traceStampDropBacklogFull, traceStampTruncPolicySteps, traceStampTruncPolicyFindings,
			traceStampReasonsTruncatedCode,
		}, full)
		require.Equal(t, full, traceStampAppendUnique(full, traceStampDropPublishFailed))
		id := traceStampTestID(t, "drop-pin")
		traceStampDeclare(id, 2)
		traceStampObserveDrop(id, traceStampDropPublishFailed)
		traceStampObserveDrop(id, traceStampDropPublishFailed) // dedup: still one reason
		traceStampObserveDrop(id, traceStampDropBacklogFull)
		ev := &eventpub.Event{RequestID: id}
		traceStampEvent(ev)
		require.JSONEq(t, `{"v":1,"c":"partial","r":[`+
			`"drop:event_publish:publish_failed","drop:event_publish:backlog_full"]}`,
			ev.Labels["trace_completeness"])
	case 203:
		// marshalBounded keeps the stamp within the label bound: a natural
		// envelope passes through, the reason-less guard returns the value
		// unchanged, and an oversized reason list degrades oldest-first
		// down to the truncation marker.
		fit := traceCompletenessEnvelope{Version: 1, Completeness: "full",
			Reasons: []string{traceStampDropBacklogFull}}.marshalBounded()
		require.JSONEq(t, `{"v":1,"c":"full","r":["drop:event_publish:backlog_full"]}`, fit)
		guard := traceCompletenessEnvelope{Version: 1,
			Completeness: stringsRepear(200)}.marshalBounded()
		require.Equal(t, `{"v":1,"c":"`+stringsRepear(200)+`"}`, guard)
		reasons := []string{
			stringsRepear(30), stringsRepear(30) + "b", stringsRepear(30) + "c", stringsRepear(30) + "d",
		}
		degraded := traceCompletenessEnvelope{Version: 1, Completeness: stringsRepear(50),
			Reasons: reasons}.marshalBounded()
		require.LessOrEqual(t, len(degraded), labels.MaxValueLen)
		var decoded traceCompletenessEnvelope
		require.NoError(t, json.Unmarshal([]byte(degraded), &decoded))
		require.Equal(t, 1, decoded.Version)
		require.Equal(t, stringsRepear(50), decoded.Completeness)
		require.Equal(t, []string{stringsRepear(30), traceStampReasonsTruncatedCode}, decoded.Reasons)
	default:
		t.Fatalf("unknown trace guard case %d", index)
	}
}

func TestTraceDeliveryRedisStream(t *testing.T) {
	client := testdb.Redis(t)
	stream := "test:trace-delivery:" + t.Name()
	t.Cleanup(func() { require.NoError(t, client.Del(context.Background(), stream).Err()) })
	pub := eventpub.NewRedisPublisher(client, stream)
	var requestIDs []string
	for i, scenario := range traceDeliveryCases {
		id := traceStampTestID(t, fmt.Sprintf("redis-%d", i))
		requestIDs = append(requestIDs, id)
		ev := traceDeliveryEvent(t, id, "history", scenario, true)
		require.NoError(t, pub.Publish(t.Context(), ev))
	}
	rows, err := client.XRange(t.Context(), stream, "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, rows, len(traceDeliveryCases))
	for i, row := range rows {
		require.Equal(t, requestIDs[i], row.Values["request_id"])
		wire, ok := row.Values["labels"].(string)
		require.True(t, ok)
		var tags map[string]string
		require.NoError(t, json.Unmarshal([]byte(wire), &tags))
		require.Equal(t, "history", tags["workload"])
		require.JSONEq(t, traceDeliveryCases[i].want, tags["trace_completeness"])
	}
}
