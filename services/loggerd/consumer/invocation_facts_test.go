package consumer

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The bound admission's facts row is the authoritative terminal record:
// an admitted charge with a missing, malformed or divergent facts row
// parks before any write — never resolves and never charges from the
// stream side.
func TestAdmittedFactsVerificationParks(t *testing.T) {
	divergentCost := chargedTerminalFacts()
	divergentCost["estimated_cost_usd"] = "9.99"
	divergentModel := chargedTerminalFacts()
	divergentModel["model_used"] = "claude-3"
	noTimestamp := chargedTerminalFacts()
	delete(noTimestamp, "ts")

	tests := []struct {
		name    string
		facts   map[string]any
		wantErr error
	}{
		{
			name:    "no facts row for an admitted invocation",
			facts:   nil,
			wantErr: errTerminalFactsMissing,
		},
		{
			name:    "facts amount differs from the wire",
			facts:   divergentCost,
			wantErr: errTerminalFactsDivergent,
		},
		{
			name:    "facts model differs from the wire",
			facts:   divergentModel,
			wantErr: errTerminalFactsDivergent,
		},
		{
			name:    "mandatory timestamp absent from facts",
			facts:   noTimestamp,
			wantErr: errTerminalFactsDivergent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			execQueries := []string{}
			db := &mockDB{
				QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-abc", "admitted"}}, tt.facts),
				ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
					mu.Lock()
					execQueries = append(execQueries, q)
					mu.Unlock()
					return pgconn.NewCommandTag("INSERT 0 1"), nil
				},
			}
			c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
			err := c.processMessage(context.Background(), invocationChargedMsg("40-1"))
			require.ErrorIs(t, err, tt.wantErr)
			mu.Lock()
			defer mu.Unlock()
			for _, q := range execQueries {
				assert.NotContains(t, q, "INSERT INTO request_logs", "no accounting write survives the facts park")
				assert.NotContains(t, q, "INSERT INTO settlement_jobs", "no charge intent survives the facts park")
			}
		})
	}
}

// The admission-less free pass is reserved for explicit cache semantics:
// zero quotes without a cache_hit_type, a cache hit that still carries a
// reservation, and unpriced terminals all park — none of them may become
// cache history.
func TestUnadmittedNonCacheTerminalParks(t *testing.T) {
	zeroNoCache := invocationCacheHitMsg("41-1")
	delete(zeroNoCache.Values, "cache_hit_type")

	cacheWithReservation := invocationCacheHitMsg("41-2")
	cacheWithReservation.Values["reservations"] = `[{"scope_kind":"wallet","scope_key":"org-abc","period":"","allowance_id":7,"bound_micro_usd":120000}]`

	unpriced := invocationChargedMsg("41-3")
	delete(unpriced.Values, "estimated_cost_usd")
	delete(unpriced.Values, "resale_cost_usd")
	unpriced.Values["reservations"] = `[{"scope_kind":"wallet","scope_key":"org-abc","period":"","allowance_id":7,"bound_micro_usd":120000}]`

	for name, msg := range map[string]redis.XMessage{
		"zero quotes without a cache_hit_type":       zeroNoCache,
		"cache hit that still carries a reservation": cacheWithReservation,
		"unpriced terminal with a reservation":       unpriced,
	} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			execQueries := []string{}
			db := &mockDB{
				QueryRowFn: admissionRow(1, nil, nil), // no admission row
				ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
					mu.Lock()
					execQueries = append(execQueries, q)
					mu.Unlock()
					return pgconn.NewCommandTag("INSERT 0 1"), nil
				},
			}
			c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
			err := c.processMessage(context.Background(), msg)
			require.ErrorIs(t, err, errUnadmittedTerminal)
			mu.Lock()
			defer mu.Unlock()
			for _, q := range execQueries {
				assert.NotContains(t, q, "INSERT INTO request_logs", "an unaccounted identity never becomes cache history")
				assert.NotContains(t, q, "INSERT INTO settlement_jobs", "an unaccounted identity never records intents")
			}
		})
	}
}

// An invocation event against a schema without request_admissions (42P01)
// surfaces the missing schema instead of silently downgrading: the
// transaction is already aborted, so returning nil would strand it.
func TestAdmissionSchemaMissingSurfaces(t *testing.T) {
	db := &mockDB{
		QueryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
			if strings.Contains(query, "FROM request_admissions") {
				return errRow{err: &pgconn.PgError{Code: "42P01"}}
			}
			return errRow{err: pgx.ErrNoRows}
		},
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	err := c.processMessage(context.Background(), invocationChargedMsg("42-1"))
	require.ErrorIs(t, err, errAdmissionSchemaMissing)
}

// A failure of the admission delivered-transition propagates: the
// delivery errors (and is retried) instead of acking an event whose
// admission was never marked delivered.
func TestAdmissionTransitionFailurePropagates(t *testing.T) {
	db := &mockDB{
		QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-abc", "admitted"}}, chargedTerminalFacts()),
		ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(q, "UPDATE request_admissions") {
				return pgconn.CommandTag{}, errors.New("transition blown")
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	err := c.processMessage(context.Background(), invocationChargedMsg("43-1"))
	require.ErrorContains(t, err, "transition admission")
}

// The settlement schema probe for legacy intents must run on the delivery
// transaction, not the pool: at MaxConns=1 a pool-level probe deadlocks
// on the connection the caller already holds. The pool surface here fails
// the test if it is ever probed; the tx surface answers.
func TestLegacyProbeUsesDeliveryTransactionNotPool(t *testing.T) {
	poolProbed := false
	db := &mockDB{
		QueryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
			if strings.Contains(query, "information_schema.columns") {
				poolProbed = true
				t.Errorf("schema probe reached the pool while a delivery transaction was open")
			}
			return errRow{err: pgx.ErrNoRows}
		},
	}
	db.BeginTxFn = func(_ context.Context) (InboxTx, error) {
		return &probeServingTx{parent: db}, nil
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	msg := invocationChargedMsg("44-1")
	delete(msg.Values, "invocation_id")
	require.NoError(t, c.processMessage(context.Background(), msg))
	assert.False(t, poolProbed)
}

// probeServingTx is a delivery transaction whose row reads answer only
// the settlement schema probe (as pre-0028) and fail anything else — a
// single-connection control proving the probe ran inside the tx.
type probeServingTx struct {
	parent *mockDB
}

func (t *probeServingTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return t.parent.Exec(ctx, query, args...)
}

func (t *probeServingTx) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	if strings.Contains(query, "information_schema.columns") {
		return &fakeRow{vals: []any{0}}
	}
	return errRow{err: context.Canceled}
}

func (t *probeServingTx) Commit(context.Context) error   { return nil }
func (t *probeServingTx) Rollback(context.Context) error { return nil }

// A transient probe failure must propagate (delivery error, retry later)
// and must not resolve the schema: the retried delivery probes again and,
// once the probe succeeds, picks the matching legacy arbiter.
func TestProbeTimeoutThenSuccessIsNotCachedAsOldSchema(t *testing.T) {
	var mu sync.Mutex
	probeCalls := 0
	var intentQueries []string
	db := &mockDB{
		QueryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
			if strings.Contains(query, "information_schema.columns") {
				mu.Lock()
				defer mu.Unlock()
				probeCalls++
				if probeCalls == 1 {
					return errRow{err: context.Canceled}
				}
				return &fakeRow{vals: []any{0}}
			}
			return errRow{err: pgx.ErrNoRows}
		},
		ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(q, "INSERT INTO settlement_jobs") {
				mu.Lock()
				intentQueries = append(intentQueries, q)
				mu.Unlock()
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	msg := invocationChargedMsg("45-1")
	delete(msg.Values, "invocation_id")

	err := c.processMessage(context.Background(), msg)
	require.Error(t, err, "a transient probe failure must fail the delivery")
	require.ErrorIs(t, err, context.Canceled, "the probe error propagates unwrapped-as-park")
	assert.NotErrorIs(t, err, errUnadmittedTerminal, "a probe failure is never a park")

	require.NoError(t, c.processMessage(context.Background(), msg), "the retried delivery probes again and succeeds")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, probeCalls, "the failed probe was not cached")
	require.NotEmpty(t, intentQueries, "the successful delivery records its charge intent")
	assert.Contains(t, intentQueries[0], "ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING",
		"the successful probe picks the bare pre-0028 arbiter")
}

// The resolve reason names the path that made the admission durable: a
// live stream delivery resolves 'event_delivered'; the same event replayed
// through the facts-recovery policy resolves 'recovered_from_facts'. The
// two must never be confused in the audit trail.
func TestAdmissionResolveReasonBindsDeliveryPolicy(t *testing.T) {
	run := func(t *testing.T, policy deliveryPolicy, wantReason string) {
		t.Helper()
		var mu sync.Mutex
		reasons := []string{}
		db := &mockDB{
			QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-abc", "admitted"}}, chargedTerminalFacts()),
			ExecFn: func(_ context.Context, q string, args ...any) (pgconn.CommandTag, error) {
				if strings.Contains(q, "UPDATE request_admissions") && len(args) > 0 {
					if reason, ok := args[0].(string); ok {
						mu.Lock()
						reasons = append(reasons, reason)
						mu.Unlock()
					}
				}
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			},
		}
		c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
		require.NoError(t, c.deliverEventPolicy(context.Background(), invocationChargedMsg(""), "request.completed", policy))
		mu.Lock()
		defer mu.Unlock()
		require.Len(t, reasons, 1)
		require.Equal(t, wantReason, reasons[0])
	}
	t.Run("live delivery", func(t *testing.T) { run(t, legacyDeliveryPolicy(), "event_delivered") })
	t.Run("facts recovery", func(t *testing.T) {
		p := factsDeliveryPolicy()
		p.recoveredFromFacts = true
		run(t, p, "recovered_from_facts")
	})
}

// A facts-recovery replay of an already-delivered invocation is a duplicate
// insert (0 rows): the delivery enriches optional history only — exactly
// one admission transition and never a re-emitted charge intent, so the
// invocation-keyed ledger keeps the single debit.
func TestDuplicateInvocationReplayResolvesOnceAndNeverRecharges(t *testing.T) {
	var mu sync.Mutex
	transitions, intents := 0, 0
	db := &mockDB{
		QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-abc", "admitted"}}, chargedTerminalFacts()),
		ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case strings.Contains(q, "UPDATE request_admissions"):
				transitions++
				return pgconn.NewCommandTag("UPDATE 1"), nil
			case strings.Contains(q, "INSERT INTO settlement_jobs"):
				intents++
			case strings.Contains(q, "INSERT INTO request_logs"):
				return pgconn.NewCommandTag("INSERT 0 0"), nil // the row already exists
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	p := factsDeliveryPolicy()
	p.recoveredFromFacts = true
	require.NoError(t, c.deliverEventPolicy(context.Background(), invocationChargedMsg(""), "request.completed", p))
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, transitions, "the replay resolves the admission exactly once")
	assert.Zero(t, intents, "a replayed duplicate never re-emits a charge intent — the single debit stands")
}
