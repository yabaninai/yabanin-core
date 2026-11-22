package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Stream-level behavior of the invocation identity domain: malformed values
// park at dispatch, the admission binding parks cross-org/voided/unbound
// charges before any write, cache-hit identities record without charge, and
// a duplicate invocation enriches optional history without ever recharging.

const testInvocationID = "0f0e0d0c-0b0a-4901-8203-040506070809"

// chargedProducerEvent is the canonical producer event behind both the
// wire fixture and the stored facts fixture: deriving the two from the one
// producer call keeps them byte-consistent and keeps the fixtures honest
// against schema drift — a producer keyset change fails here loudly
// instead of silently narrowing the comparison.
func chargedProducerEvent() eventpublisher.Event {
	return eventpublisher.Event{
		OrgID:            "org-abc",
		RequestID:        "req-inv-1",
		InvocationID:     testInvocationID,
		EventType:        "request.completed",
		TS:               1732212000000,
		ModelRequested:   "gpt-4",
		ModelUsed:        "gpt-4",
		StatusCode:       200,
		TokensIn:         12,
		TokensOut:        34,
		EstimatedCostUSD: 0.0123,
		ResaleCostUSD:    0.05,
		CostStatus:       "billed",
	}
}

// chargedTerminalFacts is the canonical facts map the gateway stores for
// invocationChargedMsg — the full producer keyset, all stringified.
func chargedTerminalFacts() map[string]any {
	ev := chargedProducerEvent()
	facts, err := ev.TerminalAccountingFields()
	if err != nil {
		panic(err)
	}
	typed := make(map[string]any, len(facts))
	for key, value := range facts {
		typed[key] = value
	}
	return typed
}

// invocationChargedMsg is a request.completed event whose resale quote makes
// the wallet plan carry a positive charge. The accounting scalars are the
// producer's own stringifications; canonical empties may be absent from the
// wire (the consumer's empty-string equivalence), everything else must
// match the stored facts exactly.
func invocationChargedMsg(id string) redis.XMessage {
	wire := make(map[string]interface{})
	for key, value := range chargedTerminalFacts() {
		if s := value.(string); s != "" {
			wire[key] = s
		}
	}
	return redis.XMessage{ID: id, Values: wire}
}

// invocationCacheHitMsg is a zero-quote invocation event — the cache-hit
// shape: minted identity, no admission row, no charge, and the gateway's
// free-cache accounting (usage_source none, cost_status cache_hit).
func invocationCacheHitMsg(id string) redis.XMessage {
	msg := invocationChargedMsg(id)
	msg.Values["estimated_cost_usd"] = "0"
	msg.Values["resale_cost_usd"] = "0"
	msg.Values["tokens_in"] = "0"
	msg.Values["tokens_out"] = "0"
	msg.Values["cache_hit_type"] = "exact"
	msg.Values["usage_source"] = "none"
	msg.Values["cost_status"] = "cache_hit"
	return msg
}

// errUnexpectedMockLookup marks a lookup the scenario never configured. It
// is deliberately distinct from pgx.ErrNoRows: a query under the wrong key
// must fail the delivery loudly instead of passing as a legitimate domain
// miss (the false-pass the previous loose helper allowed by ignoring bind
// arguments entirely).
var errUnexpectedMockLookup = errors.New("unexpected mock lookup")

// fixtureIdentity names the three wire identities the lookup queries bind.
// The canonical fixture event fixes them; a scenario that delivers under a
// different identity configures its own.
type fixtureIdentity struct{ invocation, org, request string }

// canonicalIdentity is the identity of chargedProducerEvent.
func canonicalIdentity() fixtureIdentity {
	ev := chargedProducerEvent()
	return fixtureIdentity{invocation: ev.InvocationID, org: ev.OrgID, request: ev.RequestID}
}

// identityFromFacts derives the expected lookup identities from the
// configured facts scenario, falling back to the canonical fixture per
// field. Facts fixtures may diverge from the wire in content (that is what
// the verification tests exercise), but their identity fields always match
// the delivery under test; scenarios without a facts row deliver the
// canonical wire identity.
func identityFromFacts(facts map[string]any) fixtureIdentity {
	id := canonicalIdentity()
	if facts == nil {
		return id
	}
	if v, ok := facts["invocation_id"].(string); ok && v != "" {
		id.invocation = v
	}
	if v, ok := facts["org_id"].(string); ok && v != "" {
		id.org = v
	}
	if v, ok := facts["request_id"].(string); ok && v != "" {
		id.request = v
	}
	return id
}

// sameMockArgs compares bind arguments by rendered value: every production
// bind on these routes is a string, where rendered equality is identity.
func sameMockArgs(got, want []any) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if fmt.Sprint(got[i]) != fmt.Sprint(want[i]) {
			return false
		}
	}
	return true
}

// unexpectedBind fails the lookup with the distinct wrong-key error.
func unexpectedBind(route string, got, want []any) errRow {
	return errRow{err: fmt.Errorf("%w: %s binds %v, want %v", errUnexpectedMockLookup, route, got, want)}
}

// admissionRow routes the mock QueryRow surface under strict lookup
// expectations:
//
//   - the schema probe (0028+ = 1 / pre-0028 = 0);
//   - the reservations mode read ("off" by default — partial-usage billing
//     of failed events stays inert unless a test overrides this route);
//   - the admission lookup, which must bind exactly the scenario's
//     invocation identity (configured row, or configured no-rows);
//   - the terminal-facts lookup, which must bind exactly the scenario's
//     invocation AND org (jsonb payload of the configured map, or
//     configured no-rows);
//   - the optional enrichment probes (tool_calls, policy_decisions),
//     which must bind their production (request, org) / (org, request)
//     identities and answer no-rows — every scenario here starts from an
//     empty ledger;
//   - anything else fails with errUnexpectedMockLookup, never ErrNoRows.
func admissionRow(schemaCols int, admission *fakeRow, facts map[string]any) func(context.Context, string, ...any) pgx.Row {
	id := identityFromFacts(facts)
	factsJSON := ""
	if facts != nil {
		raw, err := json.Marshal(facts)
		if err != nil {
			panic(err) // the canonical fixture must always marshal
		}
		factsJSON = string(raw)
	}
	return func(_ context.Context, query string, args ...any) pgx.Row {
		switch {
		case strings.Contains(query, "information_schema.columns"):
			return &fakeRow{vals: []any{schemaCols}}
		case strings.Contains(query, "FROM organizations"):
			return &fakeRow{vals: []any{"off"}}
		case strings.Contains(query, "FROM request_admissions"):
			if want := []any{id.invocation}; !sameMockArgs(args, want) {
				return unexpectedBind("request_admissions", args, want)
			}
			if admission == nil {
				return errRow{err: pgx.ErrNoRows}
			}
			return admission
		case strings.Contains(query, "FROM request_terminal_facts"):
			if want := []any{id.invocation, id.org}; !sameMockArgs(args, want) {
				return unexpectedBind("request_terminal_facts", args, want)
			}
			if facts == nil {
				return errRow{err: pgx.ErrNoRows}
			}
			return &fakeRow{vals: []any{factsJSON}}
		case strings.Contains(query, "FROM tool_calls") && strings.Contains(query, "LIMIT 1"):
			if want := []any{id.request, id.org}; !sameMockArgs(args, want) {
				return unexpectedBind("tool_calls probe", args, want)
			}
			return errRow{err: pgx.ErrNoRows}
		case strings.Contains(query, "FROM policy_decisions"):
			if want := []any{id.org, id.request, id.invocation}; !sameMockArgs(args, want) {
				return unexpectedBind("policy_decisions probe", args, want)
			}
			return errRow{err: pgx.ErrNoRows}
		default:
			return errRow{err: fmt.Errorf("%w: %q binds %v", errUnexpectedMockLookup, query, args)}
		}
	}
}

// A present malformed invocation_id parks at dispatch, before any database
// write — never a silent legacy-domain downgrade.
func TestMalformedInvocationParksBeforeAnyWrite(t *testing.T) {
	shapes := []any{
		"",           // empty string
		"not-a-uuid", // not a uuid at all
		"urn:uuid:0f0e0d0c-0b0a-4901-8203-040506070809", // URN spelling
		"{0f0e0d0c-0b0a-4901-8203-040506070809}",        // braced spelling
		"0f0e0d0c0b0a49018203040506070809",              // compact
		float64(42),                                     // wrong JSON type
		nil,                                             // JSON null
		map[string]any{"x": "y"},                        // object
	}
	for _, raw := range shapes {
		msg := invocationChargedMsg("30-1")
		msg.Values["invocation_id"] = raw
		var mu sync.Mutex
		execQueries := []string{}
		db := &mockDB{ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			execQueries = append(execQueries, q)
			mu.Unlock()
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		}}
		c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
		err := c.processMessage(context.Background(), msg)
		require.ErrorIs(t, err, errMalformedInvocationID, "raw %v must park as malformed", raw)
		mu.Lock()
		assert.Empty(t, execQueries, "no write of any kind runs for raw %v", raw)
		mu.Unlock()
	}
}

// The admission binding parks a charged invocation event before any
// accounting write when the admission belongs to another org, is voided, or
// is missing entirely for a positive charge.
func TestInvocationAdmissionBindingParks(t *testing.T) {
	tests := []struct {
		name      string
		admission *fakeRow
		wantErr   error
	}{
		{
			name:      "admission org differs from event org",
			admission: &fakeRow{vals: []any{"org-other", "admitted"}},
			wantErr:   errAdmissionOrgConflict,
		},
		{
			name:      "voided admission contradicts a terminal event",
			admission: &fakeRow{vals: []any{"org-abc", "voided"}},
			wantErr:   errAdmissionVoided,
		},
		{
			name:      "positive charge without any bound admission",
			admission: nil,
			wantErr:   errPaidWithoutAdmission,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			execQueries := []string{}
			db := &mockDB{
				QueryRowFn: admissionRow(1, tt.admission, nil), // parks precede any facts lookup
				ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
					mu.Lock()
					execQueries = append(execQueries, q)
					mu.Unlock()
					return pgconn.NewCommandTag("INSERT 0 1"), nil
				},
			}
			c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
			err := c.processMessage(context.Background(), invocationChargedMsg("31-1"))
			require.ErrorIs(t, err, tt.wantErr)
			mu.Lock()
			defer mu.Unlock()
			for _, q := range execQueries {
				assert.NotContains(t, q, "INSERT INTO request_logs", "no accounting write survives the park")
				assert.NotContains(t, q, "INSERT INTO settlement_jobs", "no charge intent survives the park")
			}
		})
	}
}

// A cache-hit identity (minted invocation, no admission row, valid zero
// quote) records its history under the invocation dedupe domain — no silent
// loss, no legacy downgrade, no charge intent.
func TestCacheHitWithoutAdmissionRecordsInvocationHistory(t *testing.T) {
	var mu sync.Mutex
	var logInserts []string
	var logArgs [][]any
	var intentInserts int
	db := &mockDB{
		QueryRowFn: admissionRow(1, nil, nil), // probe: 0028+; admission: no rows; cache hit needs no facts
		ExecFn: func(_ context.Context, q string, a ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case strings.Contains(q, "INSERT INTO request_logs"):
				logInserts = append(logInserts, q)
				logArgs = append(logArgs, a)
			case strings.Contains(q, "INSERT INTO settlement_jobs"):
				intentInserts++
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	msg := invocationCacheHitMsg("32-1")
	msg.Values["team_id"] = "95bba3ea-95ce-4196-92be-fa221efbd2b0"
	require.NoError(t, c.processMessage(context.Background(), msg))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, logInserts, 1, "the cache-hit history row records exactly once")
	assert.Contains(t, logInserts[0], "ON CONFLICT (invocation_id) WHERE invocation_id IS NOT NULL DO NOTHING",
		"the row dedupes on the invocation domain, not the legacy domain")
	require.NotEmpty(t, logArgs[0])
	assert.Equal(t, testInvocationID, logArgs[0][len(logArgs[0])-1],
		"the invocation id is the final bound argument")
	assert.Zero(t, intentInserts, "a cache hit never creates a settlement intent")
}

// A redelivery of the same invocation under a fresh message id (row insert
// reports 0 affected rows) enriches optional history and transitions the
// admission, but never re-emits a charge intent or pending_price record.
func TestDuplicateInvocationEnrichesWithoutRecharge(t *testing.T) {
	var mu sync.Mutex
	var logInsertCount int
	var enrichUpdates []string
	var intentInserts int
	var transitions int
	db := &mockDB{
		QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-abc", "admitted"}}, chargedTerminalFacts()),
		ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case strings.Contains(q, "INSERT INTO request_logs"):
				logInsertCount++
				if logInsertCount > 1 {
					return pgconn.NewCommandTag("INSERT 0 0"), nil // duplicate invocation
				}
			case strings.Contains(q, "UPDATE request_logs SET"):
				enrichUpdates = append(enrichUpdates, q)
			case strings.Contains(q, "INSERT INTO settlement_jobs"):
				intentInserts++
			case strings.Contains(q, "UPDATE request_admissions"):
				transitions++
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))

	values := invocationChargedMsg("33-0").Values
	values["labels"] = `{"tier":"paid","exp":"42"}`
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "33-1", Values: values}))
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "33-2", Values: values}))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 2, logInsertCount, "the second delivery reaches the row insert and takes the duplicate branch")
	require.Len(t, enrichUpdates, 1, "exactly one enrichment UPDATE")
	assert.Contains(t, enrichUpdates[0], "COALESCE(response, $", "content fills only empty columns")
	assert.Contains(t, enrichUpdates[0], "CASE WHEN labels = '{}'::jsonb", "labels fill only the empty object")
	assert.Contains(t, enrichUpdates[0], "WHERE invocation_id = $", "the enrichment targets the invocation identity")
	assert.Equal(t, 1, intentInserts, "the wallet intent exists only from the first delivery — no recharge")
	assert.GreaterOrEqual(t, transitions, 2, "both deliveries run the guarded admission transition")
}

// The first live delivery of a charged, admitted invocation commits the
// invocation-domain intent bytes and the guarded admission transition.
func TestChargedInvocationDeliversWithAdmissionTransition(t *testing.T) {
	var mu sync.Mutex
	var intentQueries []string
	var transitions int
	db := &mockDB{
		QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-abc", "admitted"}}, chargedTerminalFacts()),
		ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case strings.Contains(q, "INSERT INTO settlement_jobs"):
				intentQueries = append(intentQueries, q)
			case strings.Contains(q, "UPDATE request_admissions"):
				transitions++
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	require.NoError(t, c.processMessage(context.Background(), invocationChargedMsg("34-1")))

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, intentQueries, "the wallet charge intent commits with the log")
	assert.Contains(t, intentQueries[0], "ON CONFLICT (org_id, invocation_id, charge_kind) WHERE invocation_id IS NOT NULL DO NOTHING",
		"intent identity is the invocation domain on a 0028+ schema")
	assert.Equal(t, 1, transitions, "the admission transitions to reconciled in the same transaction")
}

// A legacy event (absent invocation_id) never touches the admission table,
// keeps the legacy row bytes and the bare legacy intent arbiter.
func TestLegacyEventSkipsAdmissionBinding(t *testing.T) {
	var mu sync.Mutex
	var logSQL string
	var intentQueries []string
	seenAdmissionLookup := false
	db := &mockDB{
		QueryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
			if strings.Contains(query, "FROM request_admissions") {
				seenAdmissionLookup = true
			}
			if strings.Contains(query, "information_schema.columns") {
				// Pre-0028 probe answer: the bare legacy arbiter.
				return &fakeRow{vals: []any{0}}
			}
			return errRow{err: pgx.ErrNoRows}
		},
		ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case strings.Contains(q, "INSERT INTO request_logs"):
				logSQL = q
			case strings.Contains(q, "INSERT INTO settlement_jobs"):
				intentQueries = append(intentQueries, q)
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	msg := invocationChargedMsg("35-1")
	delete(msg.Values, "invocation_id")
	require.NoError(t, c.processMessage(context.Background(), msg))

	mu.Lock()
	defer mu.Unlock()
	assert.False(t, seenAdmissionLookup, "legacy events never read request_admissions")
	require.NotEmpty(t, logSQL)
	assert.NotContains(t, logSQL, "invocation_id", "legacy row bytes are unchanged")
	require.NotEmpty(t, intentQueries)
	assert.Contains(t, intentQueries[0], "ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING",
		"legacy intent bytes stay on the bare pre-0028 arbiter when the probe reports no column")
}

// A voided admission still parks on the failed-event handler, and the
// budget handler tolerates an absent admission without any charge gate.
func TestFailedEventAdmissionBindingMirrorsComplete(t *testing.T) {
	msg := invocationChargedMsg("36-1")
	msg.Values["event_type"] = "request.failed"
	msg.Values["error"] = "upstream blew up"
	msg.Values["status_code"] = float64(502)

	var mu sync.Mutex
	var wroteLog bool
	db := &mockDB{
		QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-other", "admitted"}}, nil), // org conflict parks before facts
		ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			defer mu.Unlock()
			if strings.Contains(q, "INSERT INTO request_logs") {
				wroteLog = true
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	err := c.processMessage(context.Background(), msg)
	require.ErrorIs(t, err, errAdmissionOrgConflict)
	mu.Lock()
	defer mu.Unlock()
	assert.False(t, wroteLog, "the failed handler parks before its row write too")
}

// Wrong-key control: a delivery whose invocation differs from the
// configured lookup expectations must fail with the distinct router error
// instead of passing as a domain miss. Under the previous loose helper the
// sibling invocation silently reused the canonical fixture's rows (the
// helper ignored bind arguments and mapped every unrecognized lookup to
// ErrNoRows), so tenant-binding assertions could pass against the wrong
// identity.
func TestWrongKeyLookupFailsInsteadOfPassing(t *testing.T) {
	db := &mockDB{
		QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-abc", "admitted"}}, chargedTerminalFacts()),
	}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))

	msg := invocationChargedMsg("37-1")
	msg.Values["invocation_id"] = "11111111-2222-4333-8444-555555555555" // sibling invocation
	err := c.processMessage(context.Background(), msg)
	require.ErrorIs(t, err, errUnexpectedMockLookup)

	// A wrong-org delivery whose admission row agrees with the sibling org
	// passes binding and must then fail the strict facts bind: the facts
	// lookup binds the event's org, which differs from the configured
	// scenario identity.
	siblingDB := &mockDB{
		QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-sibling", "admitted"}}, chargedTerminalFacts()),
	}
	siblingConsumer := NewWithCreditStore(&mockRedis{}, siblingDB, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	sibling := invocationChargedMsg("37-2")
	sibling.Values["org_id"] = "org-sibling"
	err = siblingConsumer.processMessage(context.Background(), sibling)
	require.ErrorIs(t, err, errUnexpectedMockLookup, "a wrong-org delivery fails the strict facts bind too")
}
