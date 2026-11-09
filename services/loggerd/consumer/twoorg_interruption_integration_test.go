//go:build integration

package consumer

// N01-P02 T08 — interruption/retry/resume of the ONE two-org scenario on
// real stands (disposable testdb Postgres + Redis, no mocks for the stores):
// each org's completed event is driven through the real worker boundary and
// the delivery is interrupted at the exact windows a killed loggerd process
// produces, then resumed by a FRESH consumer instance (a restart).
//
//	Pinned exactly-once per org:
//	  - committed-but-unACKed (Redis state lost): the durable event_inbox
//	    claim is the only dedupe authority; the restart replay adds no
//	    second request_logs / tool_calls / policy_decisions / settlement_jobs
//	    row and never re-attributes an org;
//	  - transient Postgres outage (first insert of each org fails): the
//	    failure stays retry-budget work (never archived to the DLQ), the
//	    replay persists exactly one row per org;
//	  - poison retry budget resumes ACROSS a consumer restart: attempts
//	    spent before the crash are not re-granted, the archive happens
//	    exactly once, and a healthy org delivered by the restarted worker
//	    is untouched by the poisoned org's loop.
//
// The interruption windows are modelled deterministically at the exact
// boundary (same harness contract as inbox_live_test.go); every replay runs
// through a fresh StreamConsumer, not a reused one.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// twoOrgIntDLQSize returns the number of entries currently on the shared
// Redis DLQ stream.
func twoOrgIntDLQSize(t *testing.T, rdb redis.Cmdable, ctx context.Context) int {
	t.Helper()
	msgs, err := rdb.XRange(ctx, dlqStreamName, "-", "+").Result()
	require.NoError(t, err, "XRANGE over the DLQ stream")
	return len(msgs)
}

// twoOrgIntCount runs one scalar count query against the real pool.
func twoOrgIntCount(t *testing.T, env *twoOrgJointTest, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, env.pool.QueryRow(env.ctx, query, args...).Scan(&n), "count: %s", query)
	return n
}

// TestTwoOrgInterruption_CommitThenACKLossRestartExactlyOncePerOrg pins the
// acceptance window «рестарт loggerd между commit и ACK» for BOTH orgs of
// the joint scenario: the commit survives, every Redis marker (ACK, seen
// marker, retry state) is lost, and a fresh consumer replays the identical
// stream entries. The durable inbox collapses the replays; each org keeps
// exactly one row everywhere, under its own attribution, with its own
// sentinel only.
func TestTwoOrgInterruption_CommitThenACKLossRestartExactlyOncePerOrg(t *testing.T) {
	env := newTwoOrgJoint(t)
	on := true
	require.NoError(t, env.store.UpdateOrgOriginalRetention(env.ctx, env.orgA, &on))
	require.NoError(t, env.store.UpdateOrgOriginalRetention(env.ctx, env.orgB, &on))

	// Per-org team attribution: the completed delivery also mints a durable
	// settlement intent (team_spend) inside the SAME transaction as the log
	// — a second exactly-once surface the restart must not duplicate.
	valuesA := twoOrgCompletedEvent(env.reqA, env.orgA, env.markerA, twoOrgSessionA, twoOrgToolA, twoOrgPolicyA)
	valuesA["team_id"] = "team-twoorg-int-a"
	valuesB := twoOrgCompletedEvent(env.reqB, env.orgB, env.markerB, twoOrgSessionB, twoOrgToolB, twoOrgPolicyB)
	valuesB["team_id"] = "team-twoorg-int-b"
	msgA := redis.XMessage{ID: "twoorg-int-a-1", Values: valuesA}
	msgB := redis.XMessage{ID: "twoorg-int-b-1", Values: valuesB}

	crashed := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
	crashed.SetOriginalRetentionStore(AdminOriginalRetentionStore{Store: env.store})
	twoOrgDeliver(t, env, crashed, msgA, env.reqA)
	twoOrgDeliver(t, env, crashed, msgB, env.reqB)
	require.Equal(t, 0, twoOrgIntDLQSize(t, env.rdb, env.ctx))

	// Interruption: committed in Postgres, then every Redis marker is lost
	// (process crash plus Redis state loss). Only the durable rows survive.
	require.NoError(t, env.rdb.FlushDB(env.ctx).Err())

	// Restart: a FRESH consumer replays the identical entries.
	restarted := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
	restarted.SetOriginalRetentionStore(AdminOriginalRetentionStore{Store: env.store})
	restarted.handleMessage(env.ctx, msgA)
	restarted.handleMessage(env.ctx, msgB)

	// Exactly-once rows per org, under their own attribution.
	require.EqualValues(t, 2, twoOrgIntCount(t, env,
		"SELECT count(*) FROM request_logs"), "the restart replay must not duplicate any org's row")
	rowA := twoOrgRowJSON(t, env, env.reqA)
	rowB := twoOrgRowJSON(t, env, env.reqB)
	assert.Equal(t, env.orgA, rowA["org_id"], "A's attribution survives the restart unchanged")
	assert.Equal(t, env.orgB, rowB["org_id"], "B's attribution survives the restart unchanged")
	bodyA, err := json.Marshal(rowA)
	require.NoError(t, err)
	bodyB, err := json.Marshal(rowB)
	require.NoError(t, err)
	assert.NotContains(t, string(bodyA), env.markerB, "A's replayed row must never carry B's sentinel")
	assert.NotContains(t, string(bodyB), env.markerA, "B's replayed row must never carry A's sentinel")

	// The durable delivery identities: exactly one claim per stream entry,
	// both under the production (stream, group) identity.
	require.EqualValues(t, 1, twoOrgIntCount(t, env,
		`SELECT count(*) FROM event_inbox WHERE source='events:queue' AND consumer='`+consumerGroup+`' AND event_id='twoorg-int-a-1'`),
		"exactly one durable claim for A's entry")
	require.EqualValues(t, 1, twoOrgIntCount(t, env,
		`SELECT count(*) FROM event_inbox WHERE source='events:queue' AND consumer='`+consumerGroup+`' AND event_id='twoorg-int-b-1'`),
		"exactly one durable claim for B's entry")

	// Tool calls: still one aggregate row per request, per-org attribution.
	require.EqualValues(t, 1, twoOrgIntCount(t, env,
		"SELECT count(*) FROM tool_calls WHERE org_id=$1::uuid AND request_id=$2", env.orgA, env.reqA),
		"A's tool call survives exactly once")
	require.EqualValues(t, 1, twoOrgIntCount(t, env,
		"SELECT count(*) FROM tool_calls WHERE org_id=$1::uuid AND request_id=$2", env.orgB, env.reqB),
		"B's tool call survives exactly once")

	// Policy decisions: one per org after the replay.
	require.EqualValues(t, 1, twoOrgIntCount(t, env,
		"SELECT count(*) FROM policy_decisions WHERE org_id=$1::uuid", env.orgA),
		"A's policy decision survives exactly once")
	require.EqualValues(t, 1, twoOrgIntCount(t, env,
		"SELECT count(*) FROM policy_decisions WHERE org_id=$1::uuid", env.orgB),
		"B's policy decision survives exactly once")

	// Settlement intents: exactly one team_spend row per org, exact amount
	// (0.0125 USD), never doubled by the replay.
	require.EqualValues(t, 1, twoOrgIntCount(t, env,
		`SELECT count(*) FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND charge_kind='`+ChargeKindTeamSpend+`'`, env.orgA, env.reqA),
		"A's settlement intent survives exactly once")
	require.EqualValues(t, 1, twoOrgIntCount(t, env,
		`SELECT count(*) FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND charge_kind='`+ChargeKindTeamSpend+`'`, env.orgB, env.reqB),
		"B's settlement intent survives exactly once")
	var microA, microB int64
	require.NoError(t, env.pool.QueryRow(env.ctx,
		`SELECT amount_micro_usd FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND charge_kind=$3`,
		env.orgA, env.reqA, ChargeKindTeamSpend).Scan(&microA))
	require.NoError(t, env.pool.QueryRow(env.ctx,
		`SELECT amount_micro_usd FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND charge_kind=$3`,
		env.orgB, env.reqB, ChargeKindTeamSpend).Scan(&microB))
	assert.EqualValues(t, 12500, microA, "A's intent keeps the exact event amount")
	assert.EqualValues(t, 12500, microB, "B's intent keeps the exact event amount")

	// Nothing was poisoned by the restart: the DLQ stream stays empty.
	assert.Equal(t, 0, twoOrgIntDLQSize(t, env.rdb, env.ctx),
		"a healthy replay must never archive anything")
}

// TestTwoOrgInterruption_TransientOutageReplayPerOrg pins resume after a
// transient Postgres outage hitting both orgs' first insert: the failed
// attempts stay retry-budget work (no DLQ archive, no partial row, no
// durable claim), and the resumed delivery through a fresh consumer
// persists exactly one fully attributed row per org.
func TestTwoOrgInterruption_TransientOutageReplayPerOrg(t *testing.T) {
	env := newTwoOrgJoint(t)
	on := true
	require.NoError(t, env.store.UpdateOrgOriginalRetention(env.ctx, env.orgA, &on))
	require.NoError(t, env.store.UpdateOrgOriginalRetention(env.ctx, env.orgB, &on))

	flaky := &execFailingDB{inner: NewDBOps(env.pool)}
	flaky.failRequestLogInserts.Store(2) // A's and B's first attempts fail

	crashed := New(NewRedisOps(env.rdb), flaky, "events:queue", silentLogger())
	crashed.SetOriginalRetentionStore(AdminOriginalRetentionStore{Store: env.store})
	crashed.handleMessage(env.ctx, env.deliverA)
	crashed.handleMessage(env.ctx, env.deliverB)

	require.EqualValues(t, 0, twoOrgIntCount(t, env, "SELECT count(*) FROM request_logs"),
		"a failed delivery must not persist a partial row for either org")
	require.EqualValues(t, 0, twoOrgIntCount(t, env, "SELECT count(*) FROM event_inbox"),
		"an aborted delivery must not leave a durable claim")
	assert.Equal(t, 0, twoOrgIntDLQSize(t, env.rdb, env.ctx),
		"a transient outage counts as retry work, never as poison")

	// Resume: the healthy pool delivers both entries exactly once per org.
	restarted := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
	restarted.SetOriginalRetentionStore(AdminOriginalRetentionStore{Store: env.store})
	restarted.handleMessage(env.ctx, env.deliverA)
	restarted.handleMessage(env.ctx, env.deliverB)

	require.EqualValues(t, 2, twoOrgIntCount(t, env, "SELECT count(*) FROM request_logs"),
		"exactly one resumed row per org")
	rowA := twoOrgRowJSON(t, env, env.reqA)
	rowB := twoOrgRowJSON(t, env, env.reqB)
	assert.Equal(t, env.orgA, rowA["org_id"])
	assert.Equal(t, env.orgB, rowB["org_id"])
	bodyA, err := json.Marshal(rowA)
	require.NoError(t, err)
	bodyB, err := json.Marshal(rowB)
	require.NoError(t, err)
	assert.NotContains(t, string(bodyA), env.markerB)
	assert.NotContains(t, string(bodyB), env.markerA)
	require.EqualValues(t, 2, twoOrgIntCount(t, env, "SELECT count(*) FROM event_inbox"),
		"the resumed delivery claims both identities exactly once")
	require.EqualValues(t, 1, twoOrgIntCount(t, env,
		"SELECT count(*) FROM tool_calls WHERE org_id=$1::uuid AND request_id=$2", env.orgA, env.reqA),
		"A's resumed delivery extracts its tool call exactly once")
	assert.Equal(t, 0, twoOrgIntDLQSize(t, env.rdb, env.ctx),
		"recovered deliveries are never archived")
}

// TestTwoOrgInterruption_PoisonBudgetResumesAcrossRestart pins the poison
// retry budget across a consumer restart: attempts spent before the crash
// are resumed, not re-granted — the poison org's event archives exactly
// once on the real DLQ stream right after the restart — while the healthy
// org delivered by the restarted consumer persists normally and never
// touches the poisoned org's envelope.
func TestTwoOrgInterruption_PoisonBudgetResumesAcrossRestart(t *testing.T) {
	env := newTwoOrgJoint(t)
	on := true
	require.NoError(t, env.store.UpdateOrgOriginalRetention(env.ctx, env.orgB, &on))

	poisonOrgA := uuid.NewString() // no organizations row → FK violation in the delivery tx
	reqPoisonA := "req-twoorg-int-poison-a"
	markerPoisonA := "TWOORG-A INT POISON MARKER"
	valuesA := twoOrgCompletedEvent(reqPoisonA, poisonOrgA, markerPoisonA, twoOrgSessionA, twoOrgToolA, twoOrgPolicyA)
	msgA := redis.XMessage{ID: twoOrgDLQEntryA, Values: valuesA}

	// Before the crash: exactly maxRetries attempts — the budget is spent
	// but the poison is NOT archived yet (archive needs count > maxRetries).
	crashed := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
	for i := 0; i < maxRetries; i++ {
		crashed.handleMessage(env.ctx, msgA)
	}
	assert.Equal(t, 0, twoOrgIntDLQSize(t, env.rdb, env.ctx),
		"at exactly maxRetries attempts the poison is still retrying, not archived")
	require.EqualValues(t, 0, twoOrgIntCount(t, env,
		"SELECT count(*) FROM request_logs WHERE request_id=$1", reqPoisonA),
		"a poison event never persists a row")

	// Restart: a fresh consumer instance continues the SAME budget — the
	// very next attempt crosses it and archives exactly once.
	restarted := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
	restarted.handleMessage(env.ctx, msgA)
	require.Equal(t, 1, twoOrgIntDLQSize(t, env.rdb, env.ctx),
		"the resumed budget archives the poison exactly once")

	// The restarted consumer serves the healthy org normally.
	restarted.handleMessage(env.ctx, env.deliverB)
	rowB := twoOrgRowJSON(t, env, env.reqB)
	require.Equal(t, env.orgB, rowB["org_id"], "the healthy org is untouched by A's poison loop")

	// A's archived envelope keeps its own identity and its own captures
	// only; B's identity and sentinel never leak into it.
	fields, envPoison := twoOrgFindDLQEnvelope(t, env.rdb, reqPoisonA)
	assert.Equal(t, poisonOrgA, envPoison.Values["org_id"], "the poison envelope keeps its own org identity")
	assert.Equal(t, reqPoisonA, envPoison.Values["request_id"])
	assert.Equal(t, twoOrgDLQEntryA, envPoison.EntryID)
	assert.EqualValues(t, maxRetries+1, envPoison.RetryCount,
		"the restart resumed the budget, it did not reset it")
	payload, _ := fields["payload"].(string)
	assert.Contains(t, payload, markerPoisonA, "the legacy archive keeps the poisoned org's own captures for replay")
	assert.NotContains(t, payload, env.markerB, "A's envelope must never carry B's sentinel")
	assert.NotContains(t, payload, env.reqB, "A's envelope must never carry B's request id")

	// B's healthy event never reached the DLQ.
	assert.EqualValues(t, 0, twoOrgIntCount(t, env,
		"SELECT count(*) FROM request_logs WHERE request_id=$1", reqPoisonA),
		"the archived poison stays non-persisted")
}
