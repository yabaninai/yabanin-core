package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
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
	f.Fuzz(func(t *testing.T, index uint8, request uint32, before bool) {
		s := traceDeliveryCases[int(index)%len(traceDeliveryCases)].scaled(int(request % 31))
		id := traceStampTestID(t, fmt.Sprintf("delivery-%08x", request))
		traceDeliveryEvent(t, id, fmt.Sprintf("team-%x", request), s, before)
	})
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
