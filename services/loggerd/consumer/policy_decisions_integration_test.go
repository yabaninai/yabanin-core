//go:build integration

package consumer

// «Реальное событие gateway попадает в корректную запись loggerd» proven
// through the ACTUAL consumer entry point — not a direct handler/helper
// call. Every scenario here runs the real pipeline over disposable stands,
//
//	producer (eventpublisher.RedisPublisher.Publish — the real gateway XADD
//	step) → real Redis stream → StreamConsumer.Start (the real XREADGROUP
//	consumer-group loop + PEL reclaim that run.Loggerd wires) → real
//	Postgres request_logs + policy_decisions.
//
// and the dispatch boundary (deliverEvent); this file closes the gap above
// it: the consumer-group loop picks the produced entries up itself, ACKs
// them (the PEL drains), and a bad producer payload never wedges the loop
// (no DLQ, no retry storm) — the negative axis «Array против object;
// mixed-version события» through the SAME boundary. The deny-path
// request.invalid ACK-without-DB-write case stays D1-gated (out of scope).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pePublish runs the REAL producer step (RedisPublisher.Publish — the call
// the gateway publishEvent funnel makes) against the scenario's own stream.
func pePublish(t *testing.T, rdb *redis.Client, stream string, ev *eventpublisher.Event) {
	t.Helper()
	require.NoError(t, eventpublisher.NewRedisPublisher(rdb, stream).Publish(context.Background(), ev),
		"producer XADD must succeed against the disposable redis")
}

// peWaitPELDrained waits until the consumer group's pending list is empty —
// every delivered entry ACKed through the real loop, nothing wedged.
func peWaitPELDrained(t *testing.T, rdb *redis.Client, stream string) {
	t.Helper()
	cppWaitUntil(t, 15*time.Second, "PEL drained on "+stream, func() bool {
		pending, err := rdb.XPendingExt(context.Background(), &redis.XPendingExtArgs{
			Stream: stream, Group: consumerGroup, Start: "-", End: "+", Count: 10,
		}).Result()
		return err == nil && len(pending) == 0
	})
}

// peDLQRowsFor counts DLQ entries whose payload carries any of the given
// request ids (the DLQ stream is shared per disposable redis across suites).
func peDLQRowsFor(t *testing.T, rdb *redis.Client, requestIDs ...string) int {
	t.Helper()
	msgs, err := rdb.XRange(context.Background(), dlqStreamName, "-", "+").Result()
	require.NoError(t, err)
	n := 0
	for _, m := range msgs {
		payload, _ := m.Values["payload"].(string)
		for _, id := range requestIDs {
			if strings.Contains(payload, id) {
				n++
			}
		}
	}
	return n
}

// end-to-end at the production stand shape: a gateway-shaped completed event
// carrying the G2 golden policy array is published by the REAL producer step
// into a real stream, the REAL consumer-group loop (StreamConsumer.Start)
// picks it up itself and lands the documented loggerd record — one
// policy_decisions row per array element readable through
// adminstore.ListPolicyDecisions (the GET /policy-decisions surface) with
// finding evidence stripped, plus the request log — and the entry is ACKed
// (the PEL drains, nothing wedges). The consumer runs under the application
// role (yabanin_app, NOBYPASSRLS, FORCE RLS), so the loop's writes are the
// production RLS posture: they pass only because the writer pins the org GUC.
func TestIntegration_PolicyEvents_GoldenRealLoop_Live(t *testing.T) {
	superPool := testdb.PostgresRegion(t, "e2e")
	appPool := testdb.PostgresApp(t, "e2e")
	rdb := testdb.Redis(t)
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, superPool, "pdec-loop-golden-org")
	stream := "events:r012-05-golden-loop"

	requestID := "req-r012-05-loop-golden"
	pePublish(t, rdb, stream, &eventpublisher.Event{
		EventType:      "request.completed",
		Source:         "gateway",
		RequestID:      requestID,
		OrgID:          orgID,
		ModelRequested: "gpt-4o",
		ModelUsed:      "gpt-4o",
		StatusCode:     200,
		Method:         "POST",
		Policy:         goldenPolicyArray,
	})

	// The real consumer entry point: the XREADGROUP loop run.Loggerd wires.
	stop := cppStartConsumer(t, rdb, appPool, stream, silentLogger(), 0)

	row := cppWaitRow(t, superPool, requestID)
	assert.Equal(t, orgID, row["org_id"], "trusted org identity survives the whole chain")
	assert.Equal(t, "gpt-4o", row["model_used"])

	// The org's own read through the admin surface sees one decision per
	// golden element — written under the app role, read under the app role.
	store := adminstore.New(appPool, silentLogger(), nil)
	rows, total, err := store.ListPolicyDecisions(ctx, orgID,
		adminstore.PolicyDecisionFilters{PageFilter: adminstore.NewPageFilter(1, 50)})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total, "one policy_decisions row per golden array element")
	require.Len(t, rows, 2)

	byPolicy := make(map[string]adminstore.PolicyDecision, len(rows))
	for _, r := range rows {
		byPolicy[r.PolicyID] = r
	}
	shadow, ok := byPolicy["55555555-5555-5555-5555-555555555555"]
	require.True(t, ok, "the shadow decision lands")
	assert.Equal(t, requestID, shadow.RequestID)
	assert.Equal(t, 2, shadow.PolicyVersion)
	assert.Equal(t, "shadow", shadow.Mode)
	assert.Equal(t, "allow", shadow.Verdict)
	assert.Contains(t, string(shadow.Findings), "scan.pii", "findings re-render content-free")

	deny, ok := byPolicy["66666666-6666-6666-6666-666666666666"]
	require.True(t, ok, "the deny decision lands")
	assert.Equal(t, requestID, deny.RequestID)
	assert.Equal(t, "enforce", deny.Mode)
	assert.Equal(t, "deny", deny.Verdict)

	for _, r := range rows {
		assert.NotContains(t, string(r.Findings), "123-456-789", "evidence (content) is stripped")
		assert.NotContains(t, string(r.Findings), "evidence")
	}

	// The delivered entry ACKed through the real loop; nothing hit the DLQ.
	peWaitPELDrained(t, rdb, stream)
	assert.Zero(t, peDLQRowsFor(t, rdb, requestID), "a golden delivery never poisons")

	stop()
}

// TestIntegration_PolicyEvents_FailedRealLoop_Live: policy rides
// request.failed through the SAME real loop — a policy_denied failure keeps
// its verdict trail: the failed request_logs row (raw status, synthetic
// error text) commits with exactly one decision row (enforce/deny), and the
// entry ACKs. No usage rides the event, so the partial-usage reservations
// path stays out of the way (the legacy off behavior).
func TestIntegration_PolicyEvents_FailedRealLoop_Live(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	rdb := testdb.Redis(t)
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, pool, "pdec-loop-failed-org")
	stream := "events:r012-05-failed-loop"

	requestID := "req-r012-05-loop-failed"
	pePublish(t, rdb, stream, &eventpublisher.Event{
		EventType:      "request.failed",
		Source:         "gateway",
		RequestID:      requestID,
		OrgID:          orgID,
		ModelRequested: "gpt-4o",
		StatusCode:     429,
		Method:         "POST",
		Error:          "pipeline denied",
		Policy: `[{"policy_id":"77777777-7777-7777-7777-777777777777","version":1,"mode":"enforce",` +
			`"verdict":"deny","duration_ms":2,"findings":[]}]`,
	})

	stop := cppStartConsumer(t, rdb, pool, stream, silentLogger(), 0)

	row := cppWaitRow(t, pool, requestID)
	assert.Equal(t, float64(429), row["status_code"], "the failed shape keeps the raw status")
	assert.Equal(t, "pipeline denied", row["error"])

	var policyID, mode, verdict string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT policy_id::text, mode, verdict FROM policy_decisions WHERE request_id = $1`, requestID).
		Scan(&policyID, &mode, &verdict))
	assert.Equal(t, "77777777-7777-7777-7777-777777777777", policyID)
	assert.Equal(t, "enforce", mode)
	assert.Equal(t, "deny", verdict)

	peWaitPELDrained(t, rdb, stream)
	assert.Zero(t, peDLQRowsFor(t, rdb, requestID))

	stop()
}

// TestIntegration_PolicyEvents_NegativeShapesRealLoop_Live — the negative
// axis «Array против object; mixed-version события» through the SAME real
// boundary: every unusable `policy` wire shape published by the REAL
// partial rows, the request log still commits, the entry ACKs — and an old
// producer's legacy single-object payload (mixed-version deploy) lands its
// one row through the loop. A bad producer never wedges the real loop: the
// PEL drains and the DLQ stays empty.
func TestIntegration_PolicyEvents_NegativeShapesRealLoop_Live(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	rdb := testdb.Redis(t)
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, pool, "pdec-loop-negative-org")
	stream := "events:r012-05-negative-loop"

	decodeErrorsBefore := policyDecodeErrors.Load()

	type scenario struct {
		requestID string
		policy    string // "" = legacy event without the field
		wantRows  int64
	}
	scenarios := []scenario{
		// Array-vs-object faults (contract (e)).
		{requestID: "req-r012-05-neg-badjson", policy: "{nope", wantRows: 0},
		{requestID: "req-r012-05-neg-nonobjects", policy: `["deny","allow"]`, wantRows: 0},
		{requestID: "req-r012-05-neg-emptyarr", policy: `[]`, wantRows: 0},
		{requestID: "req-r012-05-neg-object", policy: `{"policy_id":"88888888-8888-8888-8888-888888888888",` +
			`"version":5,"mode":"shadow","verdict":"flag","duration_ms":9,"findings":[]}`, wantRows: 1},
		// Partial validity: the one valid decision lands among unusable siblings.
		{requestID: "req-r012-05-neg-mixed", policy: `[{"policy_id":"","mode":"shadow","verdict":"deny"},` +
			`{"policy_id":"11111111-1111-1111-1111-111111111111","version":3,"mode":"shadow",` +
			`"verdict":"mask","duration_ms":7,"findings":[]},` +
			`"{nope",{"policy_id":"p","mode":"kill","verdict":"deny"}]`, wantRows: 1},
		// Mixed-version: a legacy no-policy event skips silently.
		{requestID: "req-r012-05-neg-legacy", policy: "", wantRows: 0},
	}
	for _, sc := range scenarios {
		pePublish(t, rdb, stream, &eventpublisher.Event{
			EventType:      "request.completed",
			Source:         "gateway",
			RequestID:      sc.requestID,
			OrgID:          orgID,
			ModelRequested: "gpt-4o",
			ModelUsed:      "gpt-4o",
			StatusCode:     200,
			Method:         "POST",
			Policy:         sc.policy,
		})
	}

	stop := cppStartConsumer(t, rdb, pool, stream, silentLogger(), 0)

	// Every scenario's request log commits — the delivery never fails.
	cppWaitUntil(t, 20*time.Second, "all negative request_logs rows", func() bool {
		rows := int64(0)
		for _, sc := range scenarios {
			var n int64
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM request_logs WHERE request_id = $1`, sc.requestID).Scan(&n); err != nil {
				return false
			}
			rows += n
		}
		return rows == int64(len(scenarios))
	})

	totalRows := int64(0)
	for _, sc := range scenarios {
		var n int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM policy_decisions WHERE request_id = $1`, sc.requestID).Scan(&n))
		assert.Equal(t, sc.wantRows, n, "policy_decisions rows for %s", sc.requestID)
		totalRows += n
	}
	assert.Equal(t, int64(2), totalRows, "exactly the legacy object and the mixed-validity element land")

	// Every unusable payload/element counted: {nope}=1, non-objects=2,
	// empty array=0, legacy object=0, mixed array=3, absent=0.
	assert.Equal(t, decodeErrorsBefore+6, policyDecodeErrors.Load(),
		"each unusable payload/element counts on its own; usable shapes stay silent")

	// The loop is not wedged: everything ACKed, nothing archived.
	peWaitPELDrained(t, rdb, stream)
	requestIDs := make([]string, len(scenarios))
	for i, sc := range scenarios {
		requestIDs[i] = sc.requestID
	}
	assert.Zero(t, peDLQRowsFor(t, rdb, requestIDs...), "bad policy payloads never poison the loop")

	stop()
}
