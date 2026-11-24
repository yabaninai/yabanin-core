package consumer

// Live cross-org session scope controls (review of 1bb4d94): the sessions
// RLS posture is region isolation only, so tenant safety must be observable
// in the committed rows, not assumed from policies. Every control delivers
// real events through the full consumer and observes:
//
//   - committed request_logs rows with a non-NULL session_id,
//   - one distinct stable sessions registry row per org (same raw id),
//   - independent wallet attribution (each org debited exactly its own
//     request, never the sibling org's).
//
// Expected registry ids are read back from SQL after delivery
// (sscopeRegistryID) — the production mapping never supplies an expected
// database identity here. The legacy pre-0032 mapping id in the
// preservation control is a fixed literal (frozen nsRequestLogs namespace,
// uuid5("6f9d2c1e-8b47-4a9b-9d3a-5e2f7c4b1a00", "ses_sscope-preexisting")).
//
// The deliveries use the legacy completed shape unless stated otherwise (no
// invocation binding), so charging goes through the resale-deduction
// settlement path exactly like the AF-05 live battery; the session registry
// is the system under test.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
)

var (
	sscopeOrgA = "5c09e000-0000-4000-8000-00000000000a"
	sscopeOrgB = "5c09e000-0000-4000-8000-00000000000b"
	// A valid client-supplied UUID: the shape whose verbatim mapping made
	// two orgs sharing one id collide on the sessions primary key.
	sscopeSharedUUID = "3f9d5c2a-7b1e-4c8f-9a2d-6e4b8a1c0d3f"
	sscopeSharedSes  = "ses_sscope-shared"
	// The pre-0032 GLOBAL registry mapping of sscopePreexistingSes — the
	// literal row id a pre-upgrade row carries (uuid5 under the frozen
	// namespace over the raw id only, no org). Explicit on purpose: the
	// physical control pins recorded history, it does not recompute it.
	sscopePreexistingSes = "ses_sscope-preexisting"
	sscopeLegacyRowID    = "76135538-dd0e-5b23-b107-af5b23bf01f5"
)

func newSessionScopeLiveEnv(t *testing.T) (context.Context, *pgxpool.Pool, *StreamConsumer) {
	t.Helper()
	ctx, pool, rdb := newInboxLiveEnv(t)
	for _, org := range []string{sscopeOrgA, sscopeOrgB} {
		// The slug is globally unique: derive it from the org id so the
		// two orgs never collide and reruns hit the (id) DO NOTHING.
		_, err := pool.Exec(ctx, `
			INSERT INTO organizations (id, name, slug)
			VALUES ($1, $2, $2)
			ON CONFLICT (id) DO NOTHING`, org, "sscope-"+org[len(org)-4:])
		require.NoError(t, err, "seed org")
		// Reset THIS org's wallet and ledger only (A05 ownership model:
		// never drop the shared tables other suites are using).
		_, err = pool.Exec(ctx, `
			INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd)
			VALUES ($1, 0, 0)
			ON CONFLICT (org_id) DO UPDATE SET balance_cents = 0, remainder_micro_usd = 0`, org)
		require.NoError(t, err, "reset wallet")
		_, err = pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, org)
		require.NoError(t, err, "clear ledger")

		// The declared starting wallet is observed, not assumed.
		var balanceCents, remainder int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id = $1`, org,
		).Scan(&balanceCents, &remainder))
		require.Zero(t, balanceCents, "declared starting wallet of %s", org)
		require.Zero(t, remainder, "declared starting µ remainder of %s", org)
	}
	wallet := credits.NewStoreWithConfig(pool, silentLogger(), credits.Config{GracePeriodCents: -1_000_000})
	c := NewWithCreditStore(NewRedisOps(rdb), NewDBOps(pool), "events:sscope", silentLogger(), wallet)
	return ctx, pool, c
}

// sscopeDeliver delivers one legacy completed request with a cost through
// the live consumer. Request ids embed a run nonce so repeated suites never
// hit the durable inbox of a previous run; entryID is returned so a control
// can replay the exact inbox entry.
func sscopeDeliver(t *testing.T, ctx context.Context, c *StreamConsumer, org, session, requestID, cost string) string {
	t.Helper()
	entryID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), requestID)
	msg := redis.XMessage{ID: entryID, Values: map[string]interface{}{
		"event_type": "request.completed", "source": "gateway-live",
		"request_id": requestID, "org_id": org, "session_id": session,
		"model_requested": "gpt-4", "model_used": "gpt-4",
		"status_code": "200", "tokens_in": "100", "tokens_out": "20",
		"estimated_cost_usd": cost,
	}}
	require.NoError(t, c.processMessage(ctx, msg), "deliver %s", requestID)
	return entryID
}

// sscopeRegistryID reads the committed registry row of one (org, raw) pair.
func sscopeRegistryID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org, raw string) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT id FROM sessions WHERE org_id = $1 AND client_session = $2`, org, raw).Scan(&id),
		"exactly one registry row for (%s, %s)", org, raw)
	return id
}

// sscopeRequestSession observes the committed request_logs row: the session
// reference must be present (never NULL — no silent loss of attribution)
// and point at the registry row id the database actually committed.
func sscopeRequestSession(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org, requestID string) {
	t.Helper()
	var raw string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT client_session FROM sessions s
		JOIN request_logs r ON r.session_id = s.id
		WHERE r.org_id = $1 AND r.request_id = $2`, org, requestID).Scan(&raw),
		"exactly one committed request_logs row for %s referencing an existing registry row", requestID)
	assert.NotEmpty(t, raw, "session_id must be committed, never NULL")
}

// sscopeSettleAndWallet settles the resale-deduction queue of one org and
// returns the exact wallet total in µUSD. Wallet semantics (pkg/credits):
// the sub-cent remainder is a positive accrued residue that LOWERS the
// effective balance, so the exact total is balance_cents*10_000 − remainder
// (1 cent = 10_000 µUSD; at zero cents after a $0.004 charge this is −4000).
func sscopeSettleAndWallet(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org string) int64 {
	t.Helper()
	worker := NewSettlementWorker(pool, credits.NewStoreWithConfig(pool, silentLogger(), credits.Config{GracePeriodCents: -1_000_000}), nil, silentLogger()).WithConfig(liveSettlementConfig())
	drainSettlementQueue(ctx, t, worker, pool, org, ChargeKindResaleDeduction)
	var balanceCents, remainder int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id = $1`, org,
	).Scan(&balanceCents, &remainder))
	return balanceCents*10_000 - remainder
}

// sscopeRequestID mints a fresh request id for this run.
func sscopeRequestID(label string) string {
	return fmt.Sprintf("sscope-%s-%d", label, time.Now().UnixNano())
}

// Cross-org shared valid UUID: both orgs commit their request rows against
// two DISTINCT committed registry rows, each org keeps exactly one stable
// row per raw id, and the wallet debits stay strictly per-org. A repeat
// delivery of the same (org, session) pair resolves onto the same committed
// row and a duplicate inbox entry replays without a second charge.
func TestSessionScopeLive_SharedClientUUIDStaysPerOrg(t *testing.T) {
	ctx, pool, c := newSessionScopeLiveEnv(t)

	reqA1 := sscopeRequestID("a1")
	reqB := sscopeRequestID("b")
	sscopeDeliver(t, ctx, c, sscopeOrgA, sscopeSharedUUID, reqA1, "0.004")
	sscopeDeliver(t, ctx, c, sscopeOrgB, sscopeSharedUUID, reqB, "0.007")

	// The expected identities come from the committed rows, then the
	// request_logs references are compared against them.
	idA := sscopeRegistryID(t, ctx, pool, sscopeOrgA, sscopeSharedUUID)
	idB := sscopeRegistryID(t, ctx, pool, sscopeOrgB, sscopeSharedUUID)
	require.NotEqual(t, idA, idB, "the two orgs must own distinct committed registry rows for the same client UUID")
	var sameOwner int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE id = $1 AND org_id = $2`, idB, sscopeOrgA).Scan(&sameOwner))
	assert.Zero(t, sameOwner, "org B's committed row must not resolve under org A")

	sscopeRequestSession(t, ctx, pool, sscopeOrgA, reqA1)
	sscopeRequestSession(t, ctx, pool, sscopeOrgB, reqB)

	// Stability: a second request of org A with the SAME client UUID
	// resolves onto the SAME committed registry row — one row per org,
	// never a new identity per request.
	reqA2 := sscopeRequestID("a2")
	sscopeDeliver(t, ctx, c, sscopeOrgA, sscopeSharedUUID, reqA2, "0.001")
	idA2 := sscopeRegistryID(t, ctx, pool, sscopeOrgA, sscopeSharedUUID)
	assert.Equal(t, idA, idA2, "repeat deliveries must reuse org A's committed registry row")
	var orgARows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE org_id = $1 AND client_session = $2`,
		sscopeOrgA, sscopeSharedUUID).Scan(&orgARows))
	assert.Equal(t, int64(1), orgARows, "exactly one registry row per (org, raw id)")

	// Independent wallet attribution: org A is debited exactly its own
	// $0.005 (two requests), org B exactly its own $0.007, and neither
	// ledger carries the sibling org's request.
	walletA := sscopeSettleAndWallet(t, ctx, pool, sscopeOrgA)
	walletB := sscopeSettleAndWallet(t, ctx, pool, sscopeOrgB)
	assert.Equal(t, int64(-5_000), walletA, "org A debited exactly $0.005 in µUSD")
	assert.Equal(t, int64(-7_000), walletB, "org B debited exactly $0.007 in µUSD")
	for _, pair := range [][2]string{{sscopeOrgA, reqB}, {sscopeOrgB, reqA1}, {sscopeOrgB, reqA2}} {
		var foreign int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND request_id = $2`,
			pair[0], pair[1]).Scan(&foreign))
		assert.Zero(t, foreign, "no cross-org ledger entry for %s under %s", pair[1], pair[0])
	}

	// Duplicate replay of the settled inbox entry: the durable inbox dedups,
	// the registry row count is unchanged and the wallet does not move again.
	msg := redis.XMessage{ID: fmt.Sprintf("%d-%s", time.Now().UnixNano(), reqA1), Values: map[string]interface{}{
		"event_type": "request.completed", "source": "gateway-live",
		"request_id": reqA1, "org_id": sscopeOrgA, "session_id": sscopeSharedUUID,
		"model_requested": "gpt-4", "model_used": "gpt-4",
		"status_code": "200", "tokens_in": "100", "tokens_out": "20",
		"estimated_cost_usd": "0.004",
	}}
	require.NoError(t, c.processMessage(ctx, msg))
	walletA2 := sscopeSettleAndWallet(t, ctx, pool, sscopeOrgA)
	assert.Equal(t, walletA, walletA2, "the duplicate delivery must not recharge org A")
}

// Non-UUID control: the OpenCode-style ses_... shape stays per-org too —
// the two orgs get distinct committed rows and committed request references.
func TestSessionScopeLive_SharedNonUUIDStaysPerOrg(t *testing.T) {
	ctx, pool, c := newSessionScopeLiveEnv(t)

	reqA := sscopeRequestID("n1")
	reqB := sscopeRequestID("n2")
	sscopeDeliver(t, ctx, c, sscopeOrgA, sscopeSharedSes, reqA, "0.003")
	sscopeDeliver(t, ctx, c, sscopeOrgB, sscopeSharedSes, reqB, "0.002")

	idA := sscopeRegistryID(t, ctx, pool, sscopeOrgA, sscopeSharedSes)
	idB := sscopeRegistryID(t, ctx, pool, sscopeOrgB, sscopeSharedSes)
	require.NotEqual(t, idA, idB, "the non-UUID shape is org-scoped exactly like the UUID shape")

	sscopeRequestSession(t, ctx, pool, sscopeOrgA, reqA)
	sscopeRequestSession(t, ctx, pool, sscopeOrgB, reqB)

	assert.Equal(t, int64(-3_000), sscopeSettleAndWallet(t, ctx, pool, sscopeOrgA))
	assert.Equal(t, int64(-2_000), sscopeSettleAndWallet(t, ctx, pool, sscopeOrgB))
}

// Same-tenant preservation: a registry row written by the pre-0032 mapping
// keeps its recorded row id (the explicit literal below) when the same org
// delivers again — the (org_id, client_session) arbiter returns the
// preexisting row, so stored request_logs references never move. A different
// org with the same raw id still mints its own committed row and cannot
// touch the preserved one.
func TestSessionScopeLive_PreexistingSameTenantRowKeepsID(t *testing.T) {
	ctx, pool, c := newSessionScopeLiveEnv(t)

	_, err := pool.Exec(ctx, `
		INSERT INTO sessions (id, org_id, client_session)
		VALUES ($1, $2, $3)
		ON CONFLICT (id) DO NOTHING`, sscopeLegacyRowID, sscopeOrgA, sscopePreexistingSes)
	require.NoError(t, err, "seed the pre-0032 registry row")

	reqA := sscopeRequestID("p1")
	sscopeDeliver(t, ctx, c, sscopeOrgA, sscopePreexistingSes, reqA, "0.001")
	sscopeRequestSession(t, ctx, pool, sscopeOrgA, reqA)

	var orgARows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE org_id = $1 AND client_session = $2`,
		sscopeOrgA, sscopePreexistingSes).Scan(&orgARows))
	assert.Equal(t, int64(1), orgARows, "the same-tenant delivery must reuse the preexisting row, not mint a derived twin")
	assert.Equal(t, sscopeLegacyRowID, sscopeRegistryID(t, ctx, pool, sscopeOrgA, sscopePreexistingSes),
		"the preserved row keeps its recorded pre-0032 id")

	// The sibling org still cannot resolve onto the preserved row.
	reqB := sscopeRequestID("p2")
	sscopeDeliver(t, ctx, c, sscopeOrgB, sscopePreexistingSes, reqB, "0.001")
	idB := sscopeRegistryID(t, ctx, pool, sscopeOrgB, sscopePreexistingSes)
	require.NotEqual(t, sscopeLegacyRowID, idB)
	sscopeRequestSession(t, ctx, pool, sscopeOrgB, reqB)

	var preserved int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE id = $1 AND org_id = $2`,
		sscopeLegacyRowID, sscopeOrgA).Scan(&preserved))
	assert.Equal(t, int64(1), preserved, "org B's delivery must leave org A's preserved row untouched")
}

// sscopeShadowEvent builds a shadow-mirror delivery whose identity fields
// and terminal facts derive from ONE producer event (the suite's fixture
// recipe), so the stored facts match the wire by construction.
func sscopeShadowEvent(org, requestID, invocationID, session, policyJSON string) (redis.XMessage, []byte) {
	ev := eventpublisher.Event{
		OrgID:            org,
		RequestID:        requestID,
		InvocationID:     invocationID,
		SessionID:        session,
		EventType:        "request.shadow_completed",
		TS:               1732212000000,
		ModelRequested:   "gpt-4",
		ModelUsed:        "gpt-4",
		StatusCode:       200,
		TokensIn:         12,
		TokensOut:        34,
		EstimatedCostUSD: 0.004, // real quote — the shadow must still never bill it
		ResaleCostUSD:    0.004,
		CostStatus:       "priced",
	}
	facts, err := ev.TerminalAccountingFields()
	if err != nil {
		panic(err)
	}
	factsBytes, err := json.Marshal(facts)
	if err != nil {
		panic(err)
	}
	wire := make(map[string]interface{}, len(facts)+2)
	for key, value := range facts {
		if value != "" {
			wire[key] = value
		}
	}
	wire["policy"] = policyJSON
	return redis.XMessage{ID: fmt.Sprintf("%d-%s", time.Now().UnixNano(), requestID), Values: wire}, factsBytes
}

// Recovery-first shadow policy decision with a positive primary control:
// the shadow mirror is delivered BEFORE the primary. Both decision rows must
// land (invocation-bound identity — 0034), each request row references the
// org's committed registry row, the mirror bills nothing while the primary
// charges exactly its own quote, and the ledger names the primary
// invocation. The pre-B9 probe (org_id, request_id) would have suppressed
// whichever decision arrived second.
func TestSessionScopeLive_RecoveryFirstMirrorDecisionAndPrimaryCharge(t *testing.T) {
	ctx, pool, c := newSessionScopeLiveEnv(t)
	org := sscopeOrgA
	session := "ses_sscope-policy"
	requestID := sscopeRequestID("mir")
	invMirror := "7c1e2a30-0000-4000-8000-00000000a001"
	invPrimary := "7c1e2a30-0000-4000-8000-00000000a002"

	mirrorPolicy := `{"policy_id":"7c1e2a30-0000-4000-8000-00000000b001","version":1,"mode":"shadow","verdict":"allow","duration_ms":2,"findings":[]}`
	primaryPolicy := `{"policy_id":"7c1e2a30-0000-4000-8000-00000000b001","version":1,"mode":"enforce","verdict":"allow","duration_ms":5,"findings":[]}`

	seedAdmission := func(invocation, kind string, factsBytes []byte) {
		_, err := pool.Exec(ctx, `
			INSERT INTO request_admissions (invocation_id, org_id, kind, client_request_id, session_id, model_requested, state)
			VALUES ($1, $2, $3, $4, $5, 'gpt-4', 'admitted')
			ON CONFLICT (invocation_id) DO NOTHING`, invocation, org, kind, requestID, session)
		require.NoError(t, err, "seed admission %s", kind)
		_, err = pool.Exec(ctx, `
			INSERT INTO request_terminal_facts (invocation_id, org_id, kind, client_request_id, event)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (invocation_id) DO NOTHING`, invocation, org, kind, requestID, factsBytes)
		require.NoError(t, err, "seed facts %s", kind)
	}

	// Recovery-first ordering: the mirror's gateway fixtures exist and the
	// mirror delivery lands BEFORE anything of the primary.
	mirrorMsg, mirrorFacts := sscopeShadowEvent(org, requestID, invMirror, session, mirrorPolicy)
	seedAdmission(invMirror, "shadow", mirrorFacts)
	require.NoError(t, c.processMessage(ctx, mirrorMsg), "deliver the shadow mirror first")

	// The mirror decision is already durable before the primary exists.
	var mirrorRows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM policy_decisions WHERE org_id=$1 AND request_id=$2 AND invocation_id=$3`,
		org, requestID, invMirror).Scan(&mirrorRows))
	require.Equal(t, int64(1), mirrorRows, "the mirror decision commits without the primary")

	// Now the primary arrives with a real quote: the positive control.
	primaryEvent := eventpublisher.Event{
		OrgID: org, RequestID: requestID, InvocationID: invPrimary,
		SessionID: session, EventType: "request.completed", TS: 1732212000001,
		ModelRequested: "gpt-4", ModelUsed: "gpt-4",
		StatusCode: 200, TokensIn: 12, TokensOut: 34,
		EstimatedCostUSD: 0.004, ResaleCostUSD: 0.004, CostStatus: "priced",
	}
	primaryFacts, err := primaryEvent.TerminalAccountingFields()
	require.NoError(t, err, "build primary facts")
	primaryFactsBytes, err := json.Marshal(primaryFacts)
	require.NoError(t, err)
	seedAdmission(invPrimary, "chat", primaryFactsBytes)
	primaryWire := make(map[string]interface{}, len(primaryFacts)+2)
	for key, value := range primaryFacts {
		if value != "" {
			primaryWire[key] = value
		}
	}
	primaryWire["session_id"] = session
	primaryWire["policy"] = primaryPolicy
	primaryMsg := redis.XMessage{ID: fmt.Sprintf("%d-%s", time.Now().UnixNano(), requestID), Values: primaryWire}
	require.NoError(t, c.processMessage(ctx, primaryMsg), "deliver the primary")

	// Both decision rows exist with distinct invocation identity.
	var decisions int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM policy_decisions WHERE org_id=$1 AND request_id=$2`, org, requestID).Scan(&decisions))
	assert.Equal(t, int64(2), decisions, "mirror and primary decisions both land — neither is suppressed")
	for _, inv := range []string{invMirror, invPrimary} {
		var rows int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM policy_decisions WHERE org_id=$1 AND request_id=$2 AND invocation_id=$3`,
			org, requestID, inv).Scan(&rows))
		assert.Equal(t, int64(1), rows, "exactly one decision row for invocation %s", inv)
	}

	// Both committed request rows (mirror and primary share the client
	// request id; their rows are invocation-distinct) reference the org's
	// committed registry row.
	idSes := sscopeRegistryID(t, ctx, pool, org, session)
	var logRows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM request_logs WHERE org_id=$1 AND request_id=$2 AND session_id=$3`,
		org, requestID, idSes).Scan(&logRows))
	assert.Equal(t, int64(2), logRows,
		"both mirror and primary request rows reference the committed registry row (non-NULL session_id)")

	// Positive primary control with zero mirror billing: exactly one
	// charge intent across every charge kind, bound to the primary
	// invocation, and the wallet debited exactly $0.004.
	var intents int64
	var intentInv *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*), min(invocation_id::text) FROM settlement_jobs
		 WHERE org_id=$1 AND request_id=$2`,
		org, requestID).Scan(&intents, &intentInv))
	assert.Equal(t, int64(1), intents, "only the primary creates a charge intent — the shadow mirror bills nothing")
	require.NotNil(t, intentInv, "the intent binds its invocation identity")
	assert.Equal(t, invPrimary, *intentInv, "the charge intent names the primary invocation")
	assert.Equal(t, int64(-4_000), sscopeSettleAndWallet(t, ctx, pool, org),
		"the wallet moves exactly the primary's $0.004 — the mirror bills nothing")

	var ledgerInv string
	var ledgerRows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*), min(invocation_id::text) FROM credit_transactions WHERE org_id=$1 AND request_id=$2`,
		org, requestID).Scan(&ledgerRows, &ledgerInv))
	assert.Equal(t, int64(1), ledgerRows, "exactly one ledger transaction for the request")
	assert.Equal(t, invPrimary, ledgerInv, "the ledger names the primary invocation, never the mirror")
}
