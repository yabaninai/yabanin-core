package adminstore

// audit (write/read, 0019 snapshot chain + durable outbox), cas (every
// preconditioned mutation family), credits (wallet reads, the grace floor,
// reserved/remainder columns of 0018/0023), budgets (team/agent budgets, the
// team_spend_monthly exact-micro projection of 0021), spend alerts and the
// settlement projections (settlement_jobs 0017/0020, budget_allowances +
// session_spend + allowance_id of 0023), plus the readable admin methods.
// harness: contract() fails on any *pgconn.PgError or rows-iteration
// failure; filter matrices cover every optional sort/page combination and
// the empty answers. Deliberate CHECK-violation probes use rejectPg: the
// constraint must fire, so the rejected write is the expected contract, not
// a breach.
//
// The 03a fixture lacks spend projections, settlement rows and v2 audit
// entries, so seedMoneyAuditExtension adds the domain rows on top of
// seedContractFixture — the harness file stays untouched. The DeductMicro
// wallet ledger itself lives in pkg/credits and the reservation/settlement
// pinned at the schema level and through the adminstore reads.

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// seedMoneyAuditExtension extends the shared 03a fixture with the money &
// journal domain rows the harness cannot know about: a team_spend_monthly
// row carrying the exact 0021 micro accumulator, one settlement_jobs row per
// 0020 lifecycle status (the pending one linked to a 0023 budget_allowances
// escrow), a session_spend row, an agent_spend_daily row with the
// 0020/0023 micro columns and a sub-cent credit_transactions entry (0018).
// Cleanup removes exactly the rows the harness teardown cannot reach;
// org-scoped credit_transactions rows cascade through the fixture cleanup.
func seedMoneyAuditExtension(t *testing.T, pool *pgxpool.Pool, fx *contractFixture) {
	t.Helper()
	ctx := context.Background()
	period := time.Now().UTC().Format("2006-01")

	// 0021: exact team-month spend next to the rounded spend_usd projection.
	_, err := pool.Exec(ctx, `
		INSERT INTO team_spend_monthly (team_id, period, spend_usd, request_count,
			spend_micro_usd, reserved_micro_usd)
		VALUES ($1::uuid, $2, 0.010000, 3, 12345, 2000)`,
		fx.TeamA1, period)
	require.NoError(t, err, "seed team_spend_monthly")

	// 0023: one wallet escrow the pending settlement job points at.
	var allowanceID int64
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, period, org_id,
			granted_micro_usd, returned_micro_usd, status, lease_until)
		VALUES ($1, 'wallet', $2::uuid, '', $2::uuid, 100000, 0, 'active', now() + interval '1 hour')
		RETURNING id`,
		fx.Token+"-replica", fx.OrgA).Scan(&allowanceID), "seed budget_allowances")

	// 0017/0018/0020/0023: one settlement job per lifecycle status; the
	// processing row holds a lease, the pending row links the escrow.
	jobs := []struct {
		kind, status string
		lease        bool
		allowance    bool
	}{
		{"credit_charge", "pending", false, true},
		{"agent_budget", "processing", true, false},
		{"credit_charge", "retry", false, false},
		{"agent_budget", "settled", false, false},
		{"credit_charge", "requires_attention", false, false},
	}
	for i, j := range jobs {
		reqID := fmt.Sprintf("%s-sj-%d", fx.Token, i)
		_, err := pool.Exec(ctx, `
			INSERT INTO settlement_jobs (org_id, request_id, charge_kind, amount_cents,
				amount_micro_usd, status, attempts, payload, lease_until, allowance_id)
			VALUES ($1, $2, $3, 1, 12345, $4, $5,
				'{"settled_key":"imp03d"}'::jsonb,
				CASE WHEN $6 THEN now() + interval '5 minutes' END,
				CASE WHEN $7 THEN $8::bigint END)`,
			fx.OrgA, reqID, j.kind, j.status, i, j.lease, j.allowance, allowanceID)
		require.NoError(t, err, "seed settlement_jobs %s", j.status)
	}

	// 0023: session-key spend/reserve area.
	_, err = pool.Exec(ctx, `
		INSERT INTO session_spend (session_key_id, spent_micro_usd, reserved_micro_usd)
		VALUES ($1::uuid, 7777, 1000)`, fx.SessionKeyA)
	require.NoError(t, err, "seed session_spend")

	// 0020/0023: agent-day exact accumulator plus its reserve.
	_, err = pool.Exec(ctx, `
		INSERT INTO agent_spend_daily (agent_id, day, cost_cents, cost_micro_usd,
			tokens_in, tokens_out, reserved_micro_usd)
		VALUES ($1::uuid, current_date, 0, 9876, 100, 50, 111)`, fx.AgentKeyA)
	require.NoError(t, err, "seed agent_spend_daily")

	// 0018: a sub-cent ledger charge — cents round to 0, the signed micro
	// amount keeps the exact residue (negative = charge).
	_, err = pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type,
			request_id, amount_micro_usd)
		VALUES ($1, 0, 4988, 'usage', $2, -500)`, fx.OrgA, fx.Token+"-micro-1")
	require.NoError(t, err, "seed credit_transactions micro row")

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("money audit extension cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM settlement_jobs WHERE request_id LIKE $1`, fx.Token+"%")
		cleanup(`DELETE FROM budget_allowances WHERE replica_id = $1`, fx.Token+"-replica")
		cleanup(`DELETE FROM session_spend WHERE session_key_id::text = $1`, fx.SessionKeyA)
		cleanup(`DELETE FROM agent_spend_daily WHERE agent_id::text = $1`, fx.AgentKeyA)
		cleanup(`DELETE FROM team_spend_monthly WHERE team_id::text = ANY($1)`,
			[]string{fx.TeamA1, fx.TeamA2, fx.TeamB1})
		cleanup(`DELETE FROM team_budgets WHERE team_id::text = ANY($1)`,
			[]string{fx.TeamA2, fx.TeamB1})
		cleanup(`DELETE FROM api_key_model_whitelist WHERE model_name LIKE $1`, fx.Token+"%")
		cleanup(`DELETE FROM team_model_whitelist WHERE model_name LIKE $1`, fx.Token+"%")
	})
}

// rejectPg asserts that Postgres rejects the write through a constraint —
// the expected contract answer for CHECK/unique probes. A silent acceptance
// (nil error) fails the test.
func rejectPg(t *testing.T, name string, fn func(ctx context.Context) error) {
	t.Helper()
	err := fn(context.Background())
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "%s: Postgres must reject this write via a constraint", name)
}

// TestSQLContractMoney_Audit covers the journal write/read contract:
// InsertAuditLog (hash_version 1), InsertAuditLogEntry with snapshots/reason
// (hash_version 2, the 0019 chain linking every row onto the committed
// predecessor), ListAuditLogEntries over every allowlisted sort column in
// both directions across pages plus the default page size, the outbox
// enqueue idempotency, the drain delivery, the failed-delivery backoff row
// and its redelivery.
func TestSQLContractMoney_Audit(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()

	// v1 legacy append: no snapshots, hash_version 1.
	v1ID := fx.Token + "-v1"
	contract(t, "InsertAuditLog", func(ctx context.Context) error {
		return store.InsertAuditLog(ctx, v1ID, "seed.contract.v1",
			"organization/"+fx.OrgA, "{}", "seed-admin", "seed", "127.0.0.1")
	})

	// v2 append with the full sanitized snapshot set (0019 columns).
	v2ID := fx.Token + "-v2"
	contract(t, "InsertAuditLogEntry", func(ctx context.Context) error {
		return store.InsertAuditLogEntry(ctx, AuditLogEntryRecord{
			ID: v2ID, Action: "seed.contract.v2", Resource: "organization/" + fx.OrgA,
			Details: `{"changed":"grace_floor"}`, AdminID: "seed-admin", AdminName: "seed",
			IPAddress: "127.0.0.1", CreatedAt: time.Now().UTC(),
			Before: `{"grace_floor_cents":null}`, After: `{"grace_floor_cents":-500}`,
			Reason: "owner request IMP-03d",
		})
	})

	// The 0019 chain contract: every appended row carries the previous
	// row's hash, and the snapshot row is hash_version 2 while the plain
	// row stays v1 (the explicit payload version — no silent formula drift).
	contract(t, "audit.chain-and-versions", func(ctx context.Context) error {
		rows, err := pool.Query(ctx, `
			SELECT id, hash_version, prev_hash, row_hash,
			       COALESCE(before_snapshot, ''), COALESCE(after_snapshot, ''), reason
			FROM admin_audit_logs WHERE id = ANY($1) ORDER BY seq`, []string{v1ID, v2ID})
		if err != nil {
			return err
		}
		type row struct {
			id      string
			version int
			prev    string
			hash    string
			before  string
			after   string
			reason  string
		}
		var got []row
		if err := contractRows(rows, func(rows pgx.Rows) error {
			var r row
			if err := rows.Scan(&r.id, &r.version, &r.prev, &r.hash, &r.before, &r.after, &r.reason); err != nil {
				return err
			}
			got = append(got, r)
			return nil
		}); err != nil {
			return err
		}
		if len(got) != 2 {
			t.Errorf("audit rows: got %d, want 2", len(got))
			return nil
		}
		if got[0].version != 1 || got[1].version != 2 {
			t.Errorf("hash versions: v1 row %d, v2 row %d, want 1 and 2", got[0].version, got[1].version)
		}
		if got[1].prev != got[0].hash {
			t.Errorf("chain fork: row %q prev_hash %q != predecessor row_hash %q", got[1].id, got[1].prev, got[0].hash)
		}
		if got[1].before == "" || got[1].after == "" || got[1].reason == "" {
			t.Errorf("snapshot row lost its 0019 payload: %+v", got[1])
		}
		return nil
	})

	// The read contract: every allowlisted sort column in both directions,
	// page 1 and 2, and the default page size — the full optional-filter
	// matrix (AuditLogQuery has no content filters by design).
	for _, col := range []string{"", "id", "action", "resource", "admin_id", "admin_name", "ip_address", "timestamp"} {
		for _, desc := range []bool{false, true} {
			for _, page := range []int{1, 2} {
				name := fmt.Sprintf("ListAuditLogEntries/sort=%s/desc=%t/page=%d", col, desc, page)
				q := AuditLogQuery{Sort: col, Desc: desc, Page: page, PageSize: 10}
				contract(t, name, func(ctx context.Context) error {
					entries, total, _, err := store.ListAuditLogEntries(ctx, q)
					if err != nil {
						return err
					}
					if int64(page) > (total+9)/10 && len(entries) != 0 {
						t.Errorf("%s: page %d over total %d must be empty, got %d rows", name, page, total, len(entries))
					}
					if total < 2 {
						t.Errorf("%s: total %d misses the seeded rows", name, total)
					}
					return nil
				})
			}
		}
	}
	contract(t, "ListAuditLogEntries/default-page", func(ctx context.Context) error {
		_, _, _, err := store.ListAuditLogEntries(ctx, AuditLogQuery{})
		return err
	})
	// An unknown sort column is a validation answer, not SQL.
	_, _, _, err := store.ListAuditLogEntries(ctx, AuditLogQuery{Sort: "secret_hash"})
	require.Error(t, err, "unsupported audit sort column must be rejected without SQL")

	// Outbox: durable intent, idempotent per id.
	outID := fx.Token + "-outbox-1"
	contract(t, "EnqueueAuditOutbox", func(ctx context.Context) error {
		if err := store.EnqueueAuditOutbox(ctx, AuditLogEntryRecord{ID: outID, Action: "seed.outbox"}); err != nil {
			return err
		}
		return store.EnqueueAuditOutbox(ctx, AuditLogEntryRecord{ID: outID, Action: "seed.outbox"})
	})

	// First drain delivers the due intent into the journal and deletes it.
	contract(t, "DrainAuditOutbox/deliver", func(ctx context.Context) error {
		delivered, err := store.DrainAuditOutbox(ctx, 50)
		if err != nil {
			return err
		}
		if delivered < 1 {
			t.Errorf("DrainAuditOutbox: expected the enqueued intent delivered, got %d", delivered)
		}
		return nil
	})
	var journalCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE id = $1`, outID).Scan(&journalCount))
	require.Equal(t, 1, journalCount, "delivered outbox intent must be journaled")
	var outboxCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_outbox WHERE id = $1`, outID).Scan(&outboxCount))
	require.Equal(t, 0, outboxCount, "delivered intent must leave the outbox")

	// A replay whose entry id already exists in the journal is proof of a
	// prior durable delivery (the committed append whose outbox delete was
	// lost, or a concurrent instance's delivery of the same due row):
	// strict dedup (N10-P04-T04) consumes the intent as delivered — the
	// journal keeps exactly one copy and no eternal retry row is created.
	require.NoError(t, store.EnqueueAuditOutbox(ctx, AuditLogEntryRecord{ID: v1ID, Action: "seed.outbox.collide"}))
	contract(t, "DrainAuditOutbox/dedup-replay", func(ctx context.Context) error {
		delivered, err := store.DrainAuditOutbox(ctx, 50)
		if err != nil {
			return err
		}
		if delivered < 1 {
			t.Errorf("DrainAuditOutbox: expected the replayed intent consumed as delivered, got %d", delivered)
		}
		return nil
	})
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE id = $1`, v1ID).Scan(&journalCount))
	require.Equal(t, 1, journalCount, "the replay must not duplicate the journaled entry")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_outbox WHERE id = $1`, v1ID).Scan(&outboxCount))
	require.Equal(t, 0, outboxCount, "the deduped replay must leave the outbox (no backoff row)")

	// A delivery that truly cannot succeed (undecodable payload) must
	// land in the backoff row — attempts bumped, error recorded, row kept.
	badID := fx.Token + "-bad-payload"
	_, err = pool.Exec(ctx,
		`INSERT INTO admin_audit_outbox (id, payload) VALUES ($1, '{"id":123}'::jsonb)`, badID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_audit_outbox WHERE id = $1`, badID)
	})
	contract(t, "DrainAuditOutbox/failure-backoff", func(ctx context.Context) error {
		_, err := store.DrainAuditOutbox(ctx, 50)
		return err
	})
	var attempts int
	var lastError *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT attempts, last_error FROM admin_audit_outbox WHERE id = $1`, badID).Scan(&attempts, &lastError))
	require.Equal(t, 1, attempts, "the failed delivery must bump attempts")
	require.NotNil(t, lastError, "the failed delivery must record last_error")

	// Redelivery after a TRANSIENT failure (outage ends, backoff clears)
	// is covered by TestAuditOutboxStatus_GapsDeadLettersAndRecovery with
	// a real injected append failure; under strict dedup a pkey collision
	// can no longer produce a backoff row, so the old colliding-redelivery
	// contract is obsolete.

	// The limit window: two intents, drain(1) delivers one and keeps one.
	first, second := fx.Token+"-limit-a", fx.Token+"-limit-b"
	require.NoError(t, store.EnqueueAuditOutbox(ctx, AuditLogEntryRecord{ID: first, Action: "seed.limit"}))
	require.NoError(t, store.EnqueueAuditOutbox(ctx, AuditLogEntryRecord{ID: second, Action: "seed.limit"}))
	contract(t, "DrainAuditOutbox/limit-1", func(ctx context.Context) error {
		delivered, err := store.DrainAuditOutbox(ctx, 1)
		if err != nil {
			return err
		}
		if delivered != 1 {
			t.Errorf("DrainAuditOutbox(limit=1): delivered %d, want exactly 1", delivered)
		}
		return nil
	})
	contract(t, "DrainAuditOutbox/limit-rest", func(ctx context.Context) error {
		_, err := store.DrainAuditOutbox(ctx, 50)
		return err
	})
}

// TestSQLContractMoney_CAS covers every preconditioned mutation family
// (AF-09): unconditional (nil expect), matching precondition, mismatched
// precondition (ErrPreconditionFailed + the current state, mutation NOT
// applied) and the vanished row (ErrNotFound). The plain team/agent budget
// CRUD and the whitelist reads the CAS fallbacks use are covered in
// TestSQLContractMoney_Budgets.
func TestSQLContractMoney_CAS(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()
	missing := "00000000-0000-0000-0000-0000000000dd"
	tTrue := true

	// --- api_keys.active ---
	got, err := store.UpdateAPIKeyActivePreconditioned(ctx, fx.APIKeyA, false, &tTrue)
	require.NoError(t, err, "matching precondition must apply")
	require.NotNil(t, got)
	require.False(t, *got, "the new value must be returned")
	got, err = store.UpdateAPIKeyActivePreconditioned(ctx, fx.APIKeyA, true, &tTrue)
	require.ErrorIs(t, err, ErrPreconditionFailed, "stale precondition must conflict")
	require.NotNil(t, got)
	require.False(t, *got, "mismatch must return the unchanged current state")
	got, err = store.UpdateAPIKeyActivePreconditioned(ctx, fx.APIKeyA, true, nil)
	require.NoError(t, err, "nil expect is unconditional")
	require.True(t, *got)
	_, err = store.UpdateAPIKeyActivePreconditioned(ctx, missing, true, nil)
	require.ErrorIs(t, err, ErrNotFound, "vanished key is 404, not a conflict")

	// --- routing_rules.enabled ---
	var ruleID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id::text FROM routing_rules WHERE org_id::text = $1 LIMIT 1`, fx.OrgA).Scan(&ruleID))
	got, err = store.UpdateRoutingRuleEnabledPreconditioned(ctx, ruleID, false, &tTrue)
	require.NoError(t, err)
	require.False(t, *got)
	got, err = store.UpdateRoutingRuleEnabledPreconditioned(ctx, ruleID, true, &tTrue)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.False(t, *got)
	got, err = store.UpdateRoutingRuleEnabledPreconditioned(ctx, ruleID, true, nil)
	require.NoError(t, err)
	require.True(t, *got, "fixture rule must be re-enabled")
	_, err = store.UpdateRoutingRuleEnabledPreconditioned(ctx, missing, true, nil)
	require.ErrorIs(t, err, ErrNotFound)

	// --- api_keys label surface ---
	base := APIKeyLabelsState{Labels: map[string]string{"env": "prod"}, LabelsLocked: true, CanMintSessions: true}
	gotState, err := store.UpdateAPIKeyLabelsPreconditioned(ctx, fx.APIKeyA,
		base.Labels, base.LabelsLocked, base.CanMintSessions, false, nil)
	require.NoError(t, err, "nil expect establishes the baseline state")
	require.Equal(t, base.LabelsLocked, gotState.LabelsLocked)
	gotState, err = store.UpdateAPIKeyLabelsPreconditioned(ctx, fx.APIKeyA,
		map[string]string{"env": "dev"}, false, false, true, &base)
	require.NoError(t, err, "matching label precondition must apply")
	require.Equal(t, map[string]string{"env": "dev"}, gotState.Labels)
	gotState, err = store.UpdateAPIKeyLabelsPreconditioned(ctx, fx.APIKeyA,
		map[string]string{"env": "qa"}, true, false, false, &base)
	require.ErrorIs(t, err, ErrPreconditionFailed, "stale label state must conflict")
	require.Equal(t, map[string]string{"env": "dev"}, gotState.Labels,
		"mismatch must return the current labels, not the attempted ones")
	// jsonb comparison is order-independent: the same map must still match
	// against a freshly built expectation.
	_, err = store.UpdateAPIKeyLabelsPreconditioned(ctx, fx.APIKeyA,
		map[string]string{"env": "dev"}, false, false, true,
		&APIKeyLabelsState{Labels: map[string]string{"env": "dev"}, CanReadUsage: true})
	require.NoError(t, err, "order-independent jsonb equality must match")
	_, err = store.UpdateAPIKeyLabelsPreconditioned(ctx, missing,
		map[string]string{"a": "b"}, false, false, false, nil)
	require.ErrorIs(t, err, ErrNotFound)

	// --- team budgets: absent/match/mismatch on a team without a row ---
	tb, err := store.UpsertTeamBudgetPreconditioned(ctx, fx.TeamA2, 50, false,
		&TeamBudgetExpectation{Absent: true})
	require.NoError(t, err, "absent precondition on a fresh team must insert")
	require.InDelta(t, 50.0, tb.MonthlyLimitUSD, 1e-9)
	tb, err = store.UpsertTeamBudgetPreconditioned(ctx, fx.TeamA2, 75, true,
		&TeamBudgetExpectation{Absent: true})
	require.ErrorIs(t, err, ErrPreconditionFailed, "absent precondition over a live row must conflict")
	require.NotNil(t, tb)
	require.InDelta(t, 50.0, tb.MonthlyLimitUSD, 1e-9, "conflict must not apply the write")
	_, err = store.UpsertTeamBudgetPreconditioned(ctx, fx.TeamA2, 75, true,
		&TeamBudgetExpectation{MonthlyLimitUSD: 50, HardLimit: false})
	require.NoError(t, err, "matching stored state must apply")
	_, err = store.UpsertTeamBudgetPreconditioned(ctx, fx.TeamA2, 75, true,
		&TeamBudgetExpectation{MonthlyLimitUSD: 50, HardLimit: false})
	require.ErrorIs(t, err, ErrPreconditionFailed, "the expectation is consumed by the apply")
	tb, err = store.UpsertTeamBudgetPreconditioned(ctx, fx.TeamA2, 80, false, nil)
	require.NoError(t, err, "nil expect is unconditional")
	require.InDelta(t, 80.0, tb.MonthlyLimitUSD, 1e-9)

	deleted, current, err := store.DeleteTeamBudgetPreconditioned(ctx, fx.TeamA2,
		TeamBudgetExpectation{MonthlyLimitUSD: 999})
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.False(t, deleted)
	require.NotNil(t, current, "mismatch must carry the live row")
	require.InDelta(t, 80.0, current.MonthlyLimitUSD, 1e-9)
	deleted, _, err = store.DeleteTeamBudgetPreconditioned(ctx, fx.TeamA2,
		TeamBudgetExpectation{MonthlyLimitUSD: 80, HardLimit: false})
	require.NoError(t, err)
	require.True(t, deleted)
	deleted, current, err = store.DeleteTeamBudgetPreconditioned(ctx, fx.TeamA2,
		TeamBudgetExpectation{MonthlyLimitUSD: 80})
	require.ErrorIs(t, err, ErrPreconditionFailed, "deleting a vanished row is the lost-record mismatch")
	require.False(t, deleted)
	require.Nil(t, current, "no row to carry")

	// --- agent budgets: the fixture holds daily_limit_cents = 500 ---
	_, err = store.UpsertAgentBudgetPreconditioned(ctx, fx.AgentKeyA, 0, nil)
	require.Error(t, err, "non-positive limits are rejected before SQL")
	_, err = store.UpsertAgentBudgetPreconditioned(ctx, fx.AgentKeyA, 999,
		&AgentBudgetExpectation{DailyLimitCents: 123})
	require.ErrorIs(t, err, ErrPreconditionFailed, "wrong expectation must conflict")
	b, err := store.GetAgentBudget(ctx, fx.AgentKeyA)
	require.NoError(t, err)
	require.Equal(t, int64(500), b.DailyLimitCents, "conflict must not apply")
	b, err = store.UpsertAgentBudgetPreconditioned(ctx, fx.AgentKeyA, 750,
		&AgentBudgetExpectation{DailyLimitCents: 500})
	require.NoError(t, err)
	require.Equal(t, int64(750), b.DailyLimitCents)
	deleted, currentB, err := store.DeleteAgentBudgetPreconditioned(ctx, fx.AgentKeyA, 123)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.False(t, deleted)
	require.NotNil(t, currentB)
	require.Equal(t, int64(750), currentB.DailyLimitCents)
	deleted, _, err = store.DeleteAgentBudgetPreconditioned(ctx, fx.AgentKeyA, 750)
	require.NoError(t, err)
	require.True(t, deleted)
	b, err = store.UpsertAgentBudget(ctx, fx.AgentKeyA, 500)
	require.NoError(t, err, "the fixture budget must be restored")
	require.Equal(t, int64(500), b.DailyLimitCents)

	// --- key whitelist CAS ---
	wlModel := fx.Token + "-wl-key"
	w, err := store.AddKeyWhitelistPreconditioned(ctx, fx.APIKeyA, wlModel, true)
	require.NoError(t, err, "restore-over-absent must insert")
	require.True(t, w.Allowed)
	w, err = store.AddKeyWhitelistPreconditioned(ctx, fx.APIKeyA, wlModel, false)
	require.ErrorIs(t, err, ErrPreconditionFailed, "re-add over a live entry must conflict")
	require.NotNil(t, w)
	require.True(t, w.Allowed, "conflict carries the current entry unchanged")
	deleted, w, err = store.DeleteKeyWhitelistPreconditioned(ctx, fx.APIKeyA, wlModel, false)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.False(t, deleted)
	require.True(t, w.Allowed)
	deleted, _, err = store.DeleteKeyWhitelistPreconditioned(ctx, fx.APIKeyA, wlModel, true)
	require.NoError(t, err)
	require.True(t, deleted)
	deleted, w, err = store.DeleteKeyWhitelistPreconditioned(ctx, fx.APIKeyA, wlModel, true)
	require.ErrorIs(t, err, ErrPreconditionFailed, "second delete: the entry is gone")
	require.False(t, deleted)
	require.Nil(t, w, "no entry to carry")
	entry, exists, err := store.GetKeyWhitelistEntry(ctx, fx.APIKeyA, wlModel)
	require.NoError(t, err)
	require.False(t, exists)
	require.Nil(t, entry)

	// --- team whitelist CAS ---
	teamModel := fx.Token + "-wl-team"
	w, err = store.AddTeamWhitelistPreconditioned(ctx, fx.TeamA2, teamModel, true)
	require.NoError(t, err)
	require.True(t, w.Allowed)
	_, err = store.AddTeamWhitelistPreconditioned(ctx, fx.TeamA2, teamModel, false)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	_, w, err = store.DeleteTeamWhitelistPreconditioned(ctx, fx.TeamA2, teamModel, false)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.True(t, w.Allowed)
	deleted, _, err = store.DeleteTeamWhitelistPreconditioned(ctx, fx.TeamA2, teamModel, true)
	require.NoError(t, err)
	require.True(t, deleted)
	entry, exists, err = store.GetTeamWhitelistEntry(ctx, fx.TeamA2, teamModel)
	require.NoError(t, err)
	require.False(t, exists)
	require.Nil(t, entry)
}

// TestSQLContractMoney_Wallet covers the wallet-side settings and the
// fractional/reserved column contract: GetOrgBudgetSettings (wallet present,
// wallet absent, unknown and non-UUID orgs), UpdateOrgGraceFloor (set 0, set
// negative, clear, create-on-demand, unknown org), UpdateOrgReservationsMode
// (off/shadow/enforce round-trip, invalid mode without SQL), the output cap,
// and the 0018/0023 org_credits columns: the sub-cent remainder and the
// escrow reserve hold their exact durable values, and the CHECK bounds
// (remainder < 10000, reserve >= 0, grace <= 0) are enforced by the database.
func TestSQLContractMoney_Wallet(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()
	missing := "00000000-0000-0000-0000-0000000000dd"

	// CreateOrganization must leave a zero wallet behind (single-transaction
	// org + wallet insert).
	created, err := store.CreateOrganization(ctx, fx.Token+"-org-c", fx.Token+"-org-c")
	require.NoError(t, err)
	var balance int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, created.ID).Scan(&balance))
	require.Equal(t, int64(0), balance, "a fresh wallet starts at zero cents")

	// An org without a wallet row: the settings LEFT JOIN answers a nil
	// floor, and setting one creates the wallet on demand.
	_, err = pool.Exec(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2)`,
		fx.Token+"-org-d", fx.Token+"-org-d")
	require.NoError(t, err)
	var orgD string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id::text FROM organizations WHERE slug = $1`, fx.Token+"-org-d").Scan(&orgD))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM org_credits WHERE org_id = ANY($1)`, []string{created.ID, orgD})
		_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id::text = ANY($1)`, []string{created.ID, orgD})
	})
	settings, err := store.GetOrgBudgetSettings(ctx, orgD)
	require.NoError(t, err)
	require.Nil(t, settings.GraceFloorCents, "a missing wallet row reads as the platform default")

	// Settings block for org A: mode defaults to off, floor NULL.
	settings, err = store.GetOrgBudgetSettings(ctx, fx.OrgA)
	require.NoError(t, err)
	require.Equal(t, ReservationsOff, settings.ReservationsMode)
	require.Nil(t, settings.GraceFloorCents)
	require.Nil(t, settings.DefaultOutputCapTokens)

	// Grace floor: explicit 0 is a distinct valid value, negative floors are
	// stored verbatim, nil clears, and the floor is visible through both
	// the settings and the org reads.
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, fx.OrgA, nil))
	zero := int64(0)
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, fx.OrgA, &zero))
	settings, err = store.GetOrgBudgetSettings(ctx, fx.OrgA)
	require.NoError(t, err)
	require.NotNil(t, settings.GraceFloorCents)
	require.Equal(t, int64(0), *settings.GraceFloorCents, "explicit 0 must survive (AF-01 zero preserved)")
	minus := int64(-12345)
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, fx.OrgA, &minus))
	org, err := store.GetOrganizationByID(ctx, fx.OrgA)
	require.NoError(t, err)
	require.NotNil(t, org.GraceFloorCents)
	require.Equal(t, minus, *org.GraceFloorCents, "the org read joins the wallet floor")
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, orgD, &minus),
		"the floor must create the wallet row on demand")
	settings, err = store.GetOrgBudgetSettings(ctx, orgD)
	require.NoError(t, err)
	require.NotNil(t, settings.GraceFloorCents)
	require.Equal(t, minus, *settings.GraceFloorCents)
	var walletBalance int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, orgD).Scan(&walletBalance))
	require.Equal(t, int64(0), walletBalance, "the on-demand wallet starts at zero")
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, fx.OrgA, nil), "clear back to the platform default")
	require.Error(t, store.UpdateOrgGraceFloor(ctx, missing, &minus), "unknown org is an error")

	// Reservations mode round-trip through every §9 value.
	for _, mode := range []string{ReservationsShadow, ReservationsEnforce, ReservationsOff} {
		require.NoError(t, store.UpdateOrgReservationsMode(ctx, fx.OrgA, mode))
		settings, err = store.GetOrgBudgetSettings(ctx, fx.OrgA)
		require.NoError(t, err)
		require.Equal(t, mode, settings.ReservationsMode)
	}
	require.Error(t, store.UpdateOrgReservationsMode(ctx, fx.OrgA, "turbo"),
		"an invalid mode must be rejected without SQL")
	require.Error(t, store.UpdateOrgReservationsMode(ctx, missing, ReservationsOff))

	// Output cap: set, read, clear; zero is invalid before SQL.
	capTokens := int64(4096)
	require.NoError(t, store.UpdateOrgDefaultOutputCap(ctx, fx.OrgA, &capTokens))
	settings, err = store.GetOrgBudgetSettings(ctx, fx.OrgA)
	require.NoError(t, err)
	require.NotNil(t, settings.DefaultOutputCapTokens)
	require.Equal(t, capTokens, *settings.DefaultOutputCapTokens)
	require.NoError(t, store.UpdateOrgDefaultOutputCap(ctx, fx.OrgA, nil))
	require.Error(t, store.UpdateOrgDefaultOutputCap(ctx, fx.OrgA, &zero))
	require.Error(t, store.UpdateOrgDefaultOutputCap(ctx, missing, &capTokens))

	// Non-UUID org ids answer not-found instead of leaking a cast error.
	_, err = store.GetOrgBudgetSettings(ctx, "not-a-uuid")
	require.ErrorIs(t, err, ErrNotFound)

	// 0023 wallet columns hold exact durable values.
	_, err = pool.Exec(ctx, `
		UPDATE org_credits SET remainder_micro_usd = 9999, reserved_micro_usd = 5000
		WHERE org_id::text = $1`, fx.OrgA)
	require.NoError(t, err)
	var remainder, reserved int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT remainder_micro_usd, reserved_micro_usd FROM org_credits WHERE org_id::text = $1`,
		fx.OrgA).Scan(&remainder, &reserved))
	require.Equal(t, int64(9999), remainder, "the sub-cent residue must be durable, not collapsed")
	require.Equal(t, int64(5000), reserved, "the escrow reserve must be durable")

	// CHECK bounds are the database's last line of defense.
	rejectPg(t, "org_credits.remainder_micro_usd ceiling", func(ctx context.Context) error {
		_, err := pool.Exec(ctx,
			`UPDATE org_credits SET remainder_micro_usd = 10000 WHERE org_id::text = $1`, fx.OrgA)
		return err
	})
	rejectPg(t, "org_credits.reserved_micro_usd floor", func(ctx context.Context) error {
		_, err := pool.Exec(ctx,
			`UPDATE org_credits SET reserved_micro_usd = -1 WHERE org_id::text = $1`, fx.OrgA)
		return err
	})
	rejectPg(t, "org_credits.grace_floor_cents ceiling", func(ctx context.Context) error {
		_, err := pool.Exec(ctx,
			`UPDATE org_credits SET grace_floor_cents = 1 WHERE org_id::text = $1`, fx.OrgA)
		return err
	})
}

// TestSQLContractMoney_Budgets covers the plain budget CRUD and the exact
// team-month projection: GetTeamSpendSummary and ListTeamBudgetsByOrg read
// the seeded 0021 row (rounded spend_usd for the admin surface while the
// exact spend_micro_usd/reserved_micro_usd accumulators stay untouched —
// sub-cent spend is never collapsed to the rounded zero), the agent budget
// lifecycle, and the org/no-row/unknown answers.
func TestSQLContractMoney_Budgets(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedMoneyAuditExtension(t, pool, fx)
	ctx := context.Background()
	period := time.Now().UTC().Format("2006-01")

	summary, err := store.GetTeamSpendSummary(ctx, fx.TeamA1)
	require.NoError(t, err)
	require.Equal(t, period, summary.Period)
	require.InDelta(t, 0.01, summary.SpendUSD, 1e-9, "the rounded admin projection must read back")
	require.Equal(t, int64(3), summary.RequestCount)
	require.InDelta(t, 100.0, summary.MonthlyLimitUSD, 1e-9, "the fixture budget must join")
	require.True(t, summary.HardLimit)
	// The exact 0021 accumulators are read-only for this store method: the
	// admin read must not rewrite them (spend micro stays exact, not the
	// rounded cents).
	var micro, reservedMicro int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT spend_micro_usd, reserved_micro_usd FROM team_spend_monthly
		WHERE team_id::text = $1 AND period = $2`, fx.TeamA1, period).Scan(&micro, &reservedMicro))
	require.Equal(t, int64(12345), micro, "the exact micro accumulator must survive the admin read")
	require.Equal(t, int64(2000), reservedMicro, "the team-month reserve must survive the admin read")

	// A team with neither spend nor budget answers the zero summary. The
	// hard-limit default is the fail-closed contract (an unconfigured team
	// is denied by the enforcer; the SQL's own COALESCE(hard_limit, true)
	summary, err = store.GetTeamSpendSummary(ctx, fx.TeamA2)
	require.NoError(t, err)
	require.Equal(t, period, summary.Period)
	require.InDelta(t, 0.0, summary.SpendUSD, 1e-9)
	require.Equal(t, int64(0), summary.RequestCount)
	require.InDelta(t, 0.0, summary.MonthlyLimitUSD, 1e-9)
	require.True(t, summary.HardLimit,
		"an absent budget row is fail-closed: the summary must not present a soft limit")

	// Org-scoped listing: org A carries the budgeted team, org B has none,
	// an unknown org sees nothing.
	summaries, err := store.ListTeamBudgetsByOrg(ctx, fx.OrgA)
	require.NoError(t, err)
	require.Len(t, summaries, 1, "org A carries exactly the TeamA1 budget")
	require.Equal(t, fx.TeamA1, summaries[0].TeamID)
	require.InDelta(t, 0.01, summaries[0].SpendUSD, 1e-9)
	summaries, err = store.ListTeamBudgetsByOrg(ctx, fx.OrgB)
	require.NoError(t, err)
	require.Empty(t, summaries, "org B has no budgets")
	summaries, err = store.ListTeamBudgetsByOrg(ctx, "00000000-0000-0000-0000-0000000000dd")
	require.NoError(t, err)
	require.Empty(t, summaries)

	// Plain team budget CRUD on a fresh team.
	_, err = store.GetTeamBudget(ctx, fx.TeamA2)
	require.Error(t, err, "a missing budget is a business not-found")
	require.NoError(t, store.UpsertTeamBudget(ctx, fx.TeamA2, 42.5, true))
	tb, err := store.GetTeamBudget(ctx, fx.TeamA2)
	require.NoError(t, err)
	require.InDelta(t, 42.5, tb.MonthlyLimitUSD, 1e-9)
	require.True(t, tb.HardLimit)
	require.NoError(t, store.UpsertTeamBudget(ctx, fx.TeamA2, 43.5, false), "upsert updates")
	tb, err = store.GetTeamBudget(ctx, fx.TeamA2)
	require.NoError(t, err)
	require.False(t, tb.HardLimit)
	require.NoError(t, store.DeleteTeamBudget(ctx, fx.TeamA2))
	_, err = store.GetTeamBudget(ctx, fx.TeamA2)
	require.Error(t, err)

	// Agent budget lifecycle (the fixture budget is restored at the end).
	b, err := store.GetAgentBudget(ctx, fx.AgentKeyA)
	require.NoError(t, err)
	require.Equal(t, int64(500), b.DailyLimitCents)
	_, err = store.GetAgentBudget(ctx, "00000000-0000-0000-0000-0000000000dd")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = store.UpsertAgentBudget(ctx, fx.AgentKeyA, 0)
	require.Error(t, err, "non-positive limits are rejected before SQL")
	b, err = store.UpsertAgentBudget(ctx, fx.AgentKeyA, 700)
	require.NoError(t, err)
	require.Equal(t, int64(700), b.DailyLimitCents)
	require.NoError(t, store.DeleteAgentBudget(ctx, fx.AgentKeyA))
	require.ErrorIs(t, store.DeleteAgentBudget(ctx, fx.AgentKeyA), ErrNotFound,
		"a second delete reports not-found")
	b, err = store.UpsertAgentBudget(ctx, fx.AgentKeyA, 500)
	require.NoError(t, err, "the fixture budget must be restored")
	require.Equal(t, int64(500), b.DailyLimitCents)
}

// TestSQLContractMoney_SpendAlerts covers the spend-alert surface:
// GetOrgSpendAlertSettings (configured, unconfigured, unknown org), the
// SpendToday window semantics (shadow mirrors excluded, unknown-price rows
// count as unpriced zero and are never silently re-priced), the settings
// update round-trip, the alert-org listing scope and the throttling
// timestamp write.
func TestSQLContractMoney_SpendAlerts(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()
	missing := "00000000-0000-0000-0000-0000000000dd"

	// Org A: threshold 25 from the fixture; today's non-shadow spend is
	// r1 (0.000012, seeded day 0) — r2/r3 are day 1, r4/r5 day 2; the
	// cache-hit/no-usage/unknown-price rows contribute zero and the shadow
	// mirror of r1 is excluded.
	settings, err := store.GetOrgSpendAlertSettings(ctx, fx.OrgA)
	require.NoError(t, err)
	require.NotNil(t, settings.ThresholdUSD)
	require.InDelta(t, 25.0, *settings.ThresholdUSD, 1e-9)
	require.Nil(t, settings.LastAlertAt)
	require.InDelta(t, 0.000012, settings.SpendToday, 1e-9,
		"today's spend is the priced non-shadow sum")

	// The unknown-price row keeps its cost_status and zero cost — unpriced
	// is never silently re-priced into the spend sums.
	var costStatus string
	var cost float64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT cost_status, cost_in_usd FROM request_logs
		WHERE org_id::text = $1 AND request_id = $2`, fx.OrgA, fx.Token+"-r5").Scan(&costStatus, &cost))
	require.Equal(t, "unknown_price", costStatus)
	require.Zero(t, cost, "an unpriced row keeps its zero cost")

	settings, err = store.GetOrgSpendAlertSettings(ctx, fx.OrgB)
	require.NoError(t, err)
	require.Nil(t, settings.ThresholdUSD, "org B has no alert configured")
	require.Nil(t, settings.WebhookURL)
	_, err = store.GetOrgSpendAlertSettings(ctx, missing)
	require.Error(t, err, "an unknown org is a business not-found")

	spend, err := store.SpendToday(ctx, fx.OrgA)
	require.NoError(t, err)
	require.InDelta(t, 0.000012, spend, 1e-9)
	spend, err = store.SpendToday(ctx, missing)
	require.NoError(t, err)
	require.Zero(t, spend, "an unknown org has no spend")

	// Settings update round-trip, then restore the fixture threshold.
	webhook := "https://hooks.example.com/imp03d"
	threshold := 30.5
	require.NoError(t, store.UpdateOrgSpendAlertSettings(ctx, fx.OrgA, &threshold, &webhook))
	settings, err = store.GetOrgSpendAlertSettings(ctx, fx.OrgA)
	require.NoError(t, err)
	require.NotNil(t, settings.ThresholdUSD)
	require.InDelta(t, threshold, *settings.ThresholdUSD, 1e-9)
	require.NotNil(t, settings.WebhookURL)
	require.Equal(t, webhook, *settings.WebhookURL)
	require.NoError(t, store.UpdateOrgSpendAlertSettings(ctx, fx.OrgA, nil, nil))
	settings, err = store.GetOrgSpendAlertSettings(ctx, fx.OrgA)
	require.NoError(t, err)
	require.Nil(t, settings.ThresholdUSD)
	// The update is an unconditional UPDATE by contract: a missing org is a
	// no-op success, not an error.
	require.NoError(t, store.UpdateOrgSpendAlertSettings(ctx, missing, &threshold, nil))

	// Restore the fixture threshold so the alert listing sees org A again.
	fixtureThreshold := 25.0
	require.NoError(t, store.UpdateOrgSpendAlertSettings(ctx, fx.OrgA, &fixtureThreshold, nil))

	orgs, err := store.ListOrgsWithSpendAlerts(ctx)
	require.NoError(t, err)
	var orgAFound, orgBFound bool
	for _, o := range orgs {
		switch o.ID {
		case fx.OrgA:
			orgAFound = true
			require.InDelta(t, 25.0, o.ThresholdUSD, 1e-9)
			require.Equal(t, "USD", o.Currency, "presentation defaults")
			require.Equal(t, "UTC", o.Timezone)
		case fx.OrgB:
			orgBFound = true
		}
	}
	require.True(t, orgAFound, "org A (threshold 25) must be listed")
	require.False(t, orgBFound, "org B without a threshold must not be listed")

	// Alert throttling timestamp write + read-back.
	now := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, store.UpdateLastAlertAt(ctx, fx.OrgA, now))
	settings, err = store.GetOrgSpendAlertSettings(ctx, fx.OrgA)
	require.NoError(t, err)
	require.NotNil(t, settings.LastAlertAt)
	require.WithinDuration(t, now, *settings.LastAlertAt, time.Second)
}

// TestSQLContractMoney_SettlementProjections pins the settlement projection
// schema the writers (services/loggerd consumer, pkg/budget batch worker)
// rely on: settlement_jobs across every 0020 lifecycle status with the 0018
// exact amount, the 0020 scheduling/lease columns and the 0023 allowance
// link; budget_allowances escrow rows; session_spend; agent_spend_daily
// micro accumulators; the signed sub-cent credit_transactions entry. CHECK
// and unique-identity rejections are the expected contract answers.
func TestSQLContractMoney_SettlementProjections(t *testing.T) {
	pool := openAdminTestPool(t)
	fx := seedContractFixture(t, pool)
	seedMoneyAuditExtension(t, pool, fx)
	ctx := context.Background()

	// The escrow row seeded by the extension must read back exactly.
	var granted, returned int64
	var status string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT granted_micro_usd, returned_micro_usd, status FROM budget_allowances
		WHERE replica_id = $1`, fx.Token+"-replica").Scan(&granted, &returned, &status))
	require.Equal(t, int64(100000), granted)
	require.Equal(t, int64(0), returned)
	require.Equal(t, "active", status)
	rejectPg(t, "budget_allowances.scope_kind", func(ctx context.Context) error {
		_, err := pool.Exec(ctx, `
			INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, period, org_id,
				granted_micro_usd, returned_micro_usd, status, lease_until)
			VALUES ($1, 'galaxy', $2::uuid, '', $2::uuid, 1, 0, 'active', now())`,
			fx.Token+"-bad", fx.OrgA)
		return err
	})
	rejectPg(t, "budget_allowances.granted_micro_usd floor", func(ctx context.Context) error {
		_, err := pool.Exec(ctx, `
			INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, period, org_id,
				granted_micro_usd, returned_micro_usd, status, lease_until)
			VALUES ($1, 'wallet', $2::uuid, '', $2::uuid, -1, 0, 'active', now())`,
			fx.Token+"-bad", fx.OrgA)
		return err
	})

	// Every lifecycle status reads back with its exact micro amount, and the
	// pending row carries the escrow link.
	type jobRow struct {
		status     string
		amount     int64
		micro      int64
		lease      *time.Time
		allowance  *int64
		attempts   int
		payloadKey string
	}
	rows, err := pool.Query(ctx, `
		SELECT status, amount_cents, amount_micro_usd, lease_until, allowance_id, attempts,
		       payload->>'settled_key'
		FROM settlement_jobs WHERE request_id LIKE $1 ORDER BY id`, fx.Token+"-sj-%")
	require.NoError(t, err)
	var jobs []jobRow
	require.NoError(t, contractRows(rows, func(rows pgx.Rows) error {
		var j jobRow
		if err := rows.Scan(&j.status, &j.amount, &j.micro, &j.lease, &j.allowance, &j.attempts, &j.payloadKey); err != nil {
			return err
		}
		jobs = append(jobs, j)
		return nil
	}))
	require.Len(t, jobs, 5)
	seen := map[string]bool{}
	for i, j := range jobs {
		seen[j.status] = true
		require.Equal(t, int64(1), j.amount, "cents compatibility projection")
		require.Equal(t, int64(12345), j.micro, "the exact 0018 amount must survive")
		require.Equal(t, i, j.attempts)
		require.Equal(t, "imp03d", j.payloadKey, "the jsonb payload must round-trip")
		if j.status == "processing" {
			require.NotNil(t, j.lease, "the processing row holds a lease")
		} else {
			require.Nil(t, j.lease)
		}
		if j.status == "pending" {
			require.NotNil(t, j.allowance, "the pending row links its escrow")
		}
	}
	for _, want := range []string{"pending", "processing", "retry", "settled", "requires_attention"} {
		require.True(t, seen[want], "status %s must be storable", want)
	}
	rejectPg(t, "settlement_jobs.status CHECK", func(ctx context.Context) error {
		_, err := pool.Exec(ctx, `
			INSERT INTO settlement_jobs (org_id, request_id, charge_kind, status)
			VALUES ($1, $2, 'credit_charge', 'forgotten')`, fx.OrgA, fx.Token+"-sj-bad")
		return err
	})
	rejectPg(t, "settlement_jobs unique (org, request, charge_kind)", func(ctx context.Context) error {
		_, err := pool.Exec(ctx, `
			INSERT INTO settlement_jobs (org_id, request_id, charge_kind)
			VALUES ($1, $2, 'credit_charge')`, fx.OrgA, fx.Token+"-sj-0")
		return err
	})

	// session_spend (0023): exact spent/reserved micro, non-negative reserve.
	var spent, sessionReserved int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT spent_micro_usd, reserved_micro_usd FROM session_spend
		WHERE session_key_id::text = $1`, fx.SessionKeyA).Scan(&spent, &sessionReserved))
	require.Equal(t, int64(7777), spent)
	require.Equal(t, int64(1000), sessionReserved)
	_, err = pool.Exec(ctx, `
		INSERT INTO session_spend (session_key_id, spent_micro_usd, reserved_micro_usd)
		VALUES ('00000000-0000-0000-0000-0000000000ee', 1, -1)`)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "a negative session reserve must be rejected")
	require.Equal(t, "23514", pgErr.Code, "the rejection must be the reserved CHECK violation")

	// agent_spend_daily (0020/0023): exact micro accumulator beside the
	// rounded cents projection.
	var costCents, costMicro, agentReserved int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT cost_cents, cost_micro_usd, reserved_micro_usd FROM agent_spend_daily
		WHERE agent_id::text = $1 AND day = current_date`, fx.AgentKeyA).
		Scan(&costCents, &costMicro, &agentReserved))
	require.Equal(t, int64(0), costCents, "sub-cent agent spend rounds to zero cents")
	require.Equal(t, int64(9876), costMicro, "the exact agent micro must survive")
	require.Equal(t, int64(111), agentReserved)

	// credit_transactions (0018): the signed sub-cent ledger entry.
	var txMicro *int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT amount_micro_usd FROM credit_transactions
		WHERE org_id::text = $1 AND request_id = $2`, fx.OrgA, fx.Token+"-micro-1").Scan(&txMicro))
	require.NotNil(t, txMicro)
	require.Equal(t, int64(-500), *txMicro, "the signed micro residue must be durable")
}

// TestSQLContractMoney_AdminReads covers the readable admin methods:
// the admin-user read surface (by id, by email, with hash for login, the
// full sort×direction×active-filter×page matrix), the update lifecycle
// (active toggle, password rotation, nullable display/root set), and the
// org list with its wallet-joining read over every allowlisted sort column
// in both directions plus paging. The list column set structurally excludes
// password_hash (AdminUser carries no hash field; only the login read does).
func TestSQLContractMoney_AdminReads(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()

	email := fx.Token + "-admin@example.com"
	created, err := store.CreateAdminUser(ctx, email, fx.Token+"-admin", "hash-imp03d", false)
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM admin_users WHERE id::text = $1`, created.ID)
	})

	byID, err := store.GetAdminUserByID(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, email, byID.Email)
	require.False(t, byID.IsRoot)
	require.True(t, byID.Active)
	byEmail, err := store.GetAdminUserByEmail(ctx, email)
	require.NoError(t, err)
	require.Equal(t, created.ID, byEmail.ID)
	withHash, err := store.GetAdminUserByEmailWithHash(ctx, email)
	require.NoError(t, err)
	require.Equal(t, "hash-imp03d", withHash.PasswordHash, "the login read must see the hash")
	_, err = store.GetAdminUserByID(ctx, "00000000-0000-0000-0000-0000000000dd")
	require.Error(t, err, "a missing admin user is a business not-found")

	// The list matrix: every allowlisted column in both directions, the
	// active-only filter, and the default page size.
	for _, col := range []string{"id", "email", "display_name", "is_root", "active", "created_at"} {
		for _, desc := range []bool{false, true} {
			for _, onlyActive := range []bool{false, true} {
				name := fmt.Sprintf("ListAdminUsers/sort=%s/desc=%t/active-only=%t", col, desc, onlyActive)
				filter := PageFilter{Page: 1, PageSize: 10,
					Sort: &Sort{Column: col, Desc: desc, Set: true}}
				contract(t, name, func(ctx context.Context) error {
					users, total, err := store.ListAdminUsers(ctx, onlyActive, filter)
					if err != nil {
						return err
					}
					if total < 1 {
						t.Errorf("%s: total %d misses the seeded admin", name, total)
					}
					for _, u := range users {
						if onlyActive && !u.Active {
							t.Errorf("%s: inactive admin leaked through the active-only filter", name)
						}
					}
					return nil
				})
			}
		}
	}
	contract(t, "ListAdminUsers/page2", func(ctx context.Context) error {
		_, _, err := store.ListAdminUsers(ctx, false, NewPageFilter(2, 1))
		return err
	})
	contract(t, "ListAdminUsers/default-page", func(ctx context.Context) error {
		_, _, err := store.ListAdminUsers(ctx, true, NewPageFilter(0, 0))
		return err
	})

	// Update lifecycle.
	newName := fx.Token + "-renamed"
	require.NoError(t, store.UpdateAdminUserActive(ctx, created.ID, false))
	users, _, err := store.ListAdminUsers(ctx, true, NewPageFilter(1, 100))
	require.NoError(t, err)
	for _, u := range users {
		require.NotEqual(t, created.ID, u.ID, "a deactivated admin must leave the active-only list")
	}
	require.NoError(t, store.UpdateAdminUserActive(ctx, created.ID, true))
	require.NoError(t, store.UpdateAdminUserPasswordHash(ctx, created.ID, "hash-rotated"))
	withHash, err = store.GetAdminUserByEmailWithHash(ctx, email)
	require.NoError(t, err)
	require.Equal(t, "hash-rotated", withHash.PasswordHash)

	require.NoError(t, store.UpdateAdminUser(ctx, created.ID, &newName, nil), "display-name-only update")
	byID, err = store.GetAdminUserByID(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, newName, byID.DisplayName)
	require.False(t, byID.IsRoot)
	root := true
	require.NoError(t, store.UpdateAdminUser(ctx, created.ID, nil, &root), "root-only update")
	byID, err = store.GetAdminUserByID(ctx, created.ID)
	require.NoError(t, err)
	require.True(t, byID.IsRoot)
	require.NoError(t, store.UpdateAdminUser(ctx, created.ID, nil, nil), "no-op update")
	require.NoError(t, store.DeleteAdminUser(ctx, created.ID))
	require.Error(t, store.DeleteAdminUser(ctx, created.ID), "a second delete reports not-found")

	// The org list joins the wallet floor and honors every allowlisted sort
	// column in both directions across pages.
	for _, col := range []string{"id", "name", "slug", "currency", "timezone", "created_at"} {
		for _, desc := range []bool{false, true} {
			for _, page := range []int{1, 2} {
				name := fmt.Sprintf("ListOrganizations/sort=%s/desc=%t/page=%d", col, desc, page)
				filter := PageFilter{Page: page, PageSize: 1,
					Sort: &Sort{Column: col, Desc: desc, Set: true}}
				contract(t, name, func(ctx context.Context) error {
					orgs, total, err := store.ListOrganizations(ctx, filter)
					if err != nil {
						return err
					}
					if len(orgs) > 1 {
						t.Errorf("%s: page size 1 returned %d rows", name, len(orgs))
					}
					if total < 2 {
						t.Errorf("%s: total %d misses the seeded organizations", name, total)
					}
					return nil
				})
			}
		}
	}
	contract(t, "ListOrganizations/default-page", func(ctx context.Context) error {
		_, _, err := store.ListOrganizations(ctx, NewPageFilter(1, 0))
		return err
	})
	contract(t, "GetOrganizationBySlug", func(ctx context.Context) error {
		org, err := store.GetOrganizationBySlug(ctx, fx.Token+"-org-a")
		if err != nil {
			return err
		}
		if org.ID != fx.OrgA {
			t.Errorf("GetOrganizationBySlug: got %s, want %s", org.ID, fx.OrgA)
		}
		return nil
	})
}
