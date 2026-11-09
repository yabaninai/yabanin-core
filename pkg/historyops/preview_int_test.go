package historyops

// ENT-HIST-03 integration coverage on a real PostgreSQL stand (skipped under
// -short): counting semantics, the FIX-20 response-view parity pin, grant
// protection, sessions cascade/FK blockers and cross-org isolation.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// previewPeriod pins the seeding window: 2026-03-01..2026-03-05 (closed,
// relative to the static now of 2026-03-10T12:00Z).
var previewPeriod = Period{
	From: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	To:   time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC),
}

func previewNow() time.Time { return time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC) }

func previewSelection(orgID string, families ...Family) Selection {
	sel, err := NewSelection(orgID, "", previewPeriod, families, SelectionFilters{}, previewNow())
	if err != nil {
		panic(err)
	}
	return sel
}

func newIntPreviewer(t *testing.T, pool testPGPool) *Previewer {
	t.Helper()
	seedSchemaMigrations(t, context.Background(), pool, 16)
	return NewPreviewer(pool, func(ctx context.Context) (SchemaStamp, error) {
		return SchemaStampFromDB(ctx, pool)
	}, previewNow)
}

// seedSchemaMigrations simulates the production migration-runner state
// (golang-migrate's version table) on the raw-SQL testdb stand: the stamp
// must read a real head, never silently default.
func seedSchemaMigrations(t *testing.T, ctx context.Context, pool testPGPool, head int64) {
	t.Helper()
	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
	    version bigint NOT NULL, dirty boolean NOT NULL DEFAULT false)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO schema_migrations (version, dirty)
	  SELECT $1, false WHERE NOT EXISTS (SELECT 1 FROM schema_migrations)`, head)
	require.NoError(t, err)
}

// testPGPool keeps the testdb type out of every signature.
type testPGPool = *pgxpool.Pool

func TestPreviewCountingAndParity_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	foreignOrg := seedPreviewOrg(t, ctx, pool)

	// request_logs inside the window: 12 rows — the original 8-shape corpus
	// plus the type-confused shapes (F1, review 0203): the text projection
	// of a STRING v is also '1', so every non-number v must stay legacy on
	// BOTH sides of the parity pin.
	shapes := []struct {
		name     string
		response *string // nil = SQL NULL
	}{
		{"env-complete", strptr(`{"v":1,"kind":"model_response","status":"complete","content":"hello"}`)},
		{"env-partial", strptr(`{"v":1,"kind":"model_response","status":"partial","content":"par"}`)},
		{"env-bad-status", strptr(`{"v":1,"kind":"model_response","status":"weird"}`)},
		{"env-v2", strptr(`{"v":2,"kind":"model_response","status":"complete"}`)},
		{"legacy-string", strptr(`"raw legacy snapshot"`)},
		{"legacy-object", strptr(`{"prompt":"legacy object"}`)},
		{"sql-null", nil},
		{"jsonb-null", strptr(`null`)},
		// Type-confused shapes (F1): SQL ->>'v' and Go json.Unmarshal must
		// agree that none of these is an envelope.
		{"tc-v-string", strptr(`{"v":"1","kind":"model_response","status":"complete"}`)},
		{"tc-v-object", strptr(`{"v":{"n":1},"kind":"model_response","status":"complete"}`)},
		{"tc-v-bool", strptr(`{"v":true,"kind":"model_response","status":"complete"}`)},
		{"tc-kind-number", strptr(`{"v":1,"kind":7,"status":"complete"}`)},
	}
	for i, s := range shapes {
		insertRequestLog(t, ctx, pool, orgID, previewReqID(s.name), time.Date(2026, 3, 2, 0, i, 0, 0, time.UTC), s.response)
	}
	// Out of period + foreign org: must never be counted.
	insertRequestLog(t, ctx, pool, orgID, "req-outside", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), nil)
	insertRequestLog(t, ctx, pool, foreignOrg, "req-foreign", time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), nil)

	previewer := newIntPreviewer(t, pool)
	sel := previewSelection(orgID, FamilyRequestLogs)
	report, err := previewer.Report(ctx, PreviewRequest{Op: OpArchiveCopy, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)

	fp := report.Families[FamilyRequestLogs]
	require.EqualValues(t, 12, fp.Found, "exactly the in-window org rows")
	require.EqualValues(t, 12, fp.Permitted, "archive_copy has no grant protection")
	require.Zero(t, fp.Protected)
	require.Positive(t, fp.ContentBytesEst, "content estimate is present")

	// FIX-20 parity pin: the SQL buckets must agree with the canonical Go
	// reader row by row. Fetch the raw column values over the same scope
	// and classify through ParseResponseEnvelope.
	raws := fetchRawResponses(t, ctx, pool, orgID, previewPeriod)
	goCounts := classifyWithReader(raws)
	require.Equal(t, 12, goCounts.envelope+goCounts.legacy+goCounts.absent)
	rv := fp.ResponseViews
	require.NotNil(t, rv)
	assert.EqualValues(t, goCounts.envelope, rv.Envelope, "envelope bucket parity")
	assert.EqualValues(t, goCounts.legacy, rv.Legacy, "legacy bucket parity")
	assert.EqualValues(t, goCounts.absent, rv.Absent, "absent bucket parity")
	// And the expected split: 2 envelopes, 8 legacy (bad status, v2, legacy
	// string, legacy object, string-v, object-v, bool-v, number-kind — the
	// type-confused shapes must land in legacy on BOTH sides), 2 absent
	// (SQL NULL + jsonb 'null').
	assert.EqualValues(t, 2, rv.Envelope)
	assert.EqualValues(t, 8, rv.Legacy)
	assert.EqualValues(t, 2, rv.Absent)

	// Digest issuance: the report's digest matches a fresh computation.
	stamp, err := SchemaStampFromDB(ctx, pool)
	require.NoError(t, err)
	digest, err := SelectionDigest(OpArchiveCopy, sel, stamp)
	require.NoError(t, err)
	assert.Equal(t, digest, report.SelectionDigest)
	assert.False(t, report.NoOp)
	assert.Empty(t, report.Refusals, "archive_copy with no grants is previewable")
}

func TestPreviewGrantProtectionByOperation_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-granted", time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), nil)
	insertRequestLog(t, ctx, pool, orgID, "req-free", time.Date(2026, 3, 2, 2, 0, 0, 0, time.UTC), nil)
	grantID := seedActiveGrant(t, ctx, pool, orgID, "req-granted", time.Hour)

	previewer := newIntPreviewer(t, pool)
	sel := previewSelection(orgID, FamilyRequestLogs)

	del, err := previewer.Report(ctx, PreviewRequest{Op: OpArchiveRemoveHot, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	fp := del.Families[FamilyRequestLogs]
	require.EqualValues(t, 2, fp.Found)
	assert.EqualValues(t, 1, fp.Protected, "the granted row is protected for delete-family ops")
	assert.EqualValues(t, 1, fp.Permitted)
	assert.Equal(t, []string{grantID}, fp.ProtectedGrantIDs, "grant ids, never tokens")
	require.Len(t, del.Refusals, 1)
	assert.Equal(t, RefusalActiveGrant, del.Refusals[0].Code)
	assert.Equal(t, []string{grantID}, del.Refusals[0].GrantIDs)

	cp, err := previewer.Report(ctx, PreviewRequest{Op: OpArchiveCopy, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	assert.Zero(t, cp.Families[FamilyRequestLogs].Protected,
		"copy operations are not blocked by live grants (design §5.4)")
	assert.Empty(t, cp.Refusals)

	rd, err := previewer.Report(ctx, PreviewRequest{Op: OpRedactContent, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	assert.Zero(t, rd.Families[FamilyRequestLogs].Protected,
		"redact is rights-gated, not grant-protected (CARD 1 interpretation)")

	pg, err := previewer.Report(ctx, PreviewRequest{Op: OpPurge, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	found := false
	for _, r := range pg.Refusals {
		if r.Code == RefusalPurgeConfirmationMissing {
			found = true
		}
	}
	require.True(t, found, "purge preview reports the wholesale refusal")
}

func TestPreviewSessionsCascadeAndBlockers_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	sessionA := insertSession(t, ctx, pool, orgID, time.Date(2026, 3, 2, 3, 0, 0, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionA, "user", "hello there", time.Date(2026, 3, 2, 3, 1, 0, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionA, "assistant", "hi, how can I help", time.Date(2026, 3, 2, 3, 2, 0, 0, time.UTC))
	// request_logs pins the session from below (FK NO ACTION): a naive
	// session delete must fail, and the preview must say so.
	insertRequestLogWithSession(t, ctx, pool, orgID, "req-pins-session", sessionA,
		time.Date(2026, 3, 2, 3, 3, 0, 0, time.UTC), nil)
	// Session without requests and outside the window: neither counted.
	insertSession(t, ctx, pool, orgID, time.Date(2026, 2, 1, 3, 0, 0, 0, time.UTC))

	previewer := newIntPreviewer(t, pool)
	sel := previewSelection(orgID, FamilySessions)
	report, err := previewer.Report(ctx, PreviewRequest{Op: OpArchiveRemoveHot, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)

	fp := report.Families[FamilySessions]
	assert.EqualValues(t, 1, fp.Found)
	assert.EqualValues(t, 1, fp.BlockedByFK,
		"the request-pinned session is reported, never silently dropped")
	require.Len(t, report.Cascades, 1)
	assert.Equal(t, FamilyMessages, report.Cascades[0].Family)
	assert.EqualValues(t, 2, report.Cascades[0].Rows, "the messages cascade is explicit")
	assert.Positive(t, report.Cascades[0].ContentBytesEst)
}

func TestPreviewFamiliesAndEmptySelection_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-with-tools", time.Date(2026, 3, 2, 4, 0, 0, 0, time.UTC), nil)
	_, err := pool.Exec(ctx, `INSERT INTO tool_calls (request_id, org_id, model_used, tool_name, created_at)
	     VALUES ('req-with-tools', $1::uuid, 'glm-5', 'bash', $2)`, orgID, time.Date(2026, 3, 2, 4, 1, 0, 0, time.UTC))
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO tool_call_invocations (request_id, org_id, seq, tool_name, arguments, created_at)
	     VALUES ('req-with-tools', $1::uuid, 0, 'bash', '{"cmd":"ls"}', $2)`, orgID, time.Date(2026, 3, 2, 4, 2, 0, 0, time.UTC))
	require.NoError(t, err)
	// tool_calls of another model inside the window: excluded by the model filter.
	_, err = pool.Exec(ctx, `INSERT INTO tool_calls (request_id, org_id, model_used, tool_name, created_at)
	     VALUES ('req-other-model', $1::uuid, 'claude-3', 'grep', $2)`, orgID, time.Date(2026, 3, 2, 4, 3, 0, 0, time.UTC))
	require.NoError(t, err)

	previewer := newIntPreviewer(t, pool)
	sel, err := NewSelection(orgID, "", previewPeriod,
		[]Family{FamilyToolCalls, FamilyToolCallInvocations, FamilyCacheEntries},
		SelectionFilters{Model: "glm-5"}, previewNow())
	require.NoError(t, err)

	report, err := previewer.Report(ctx, PreviewRequest{Op: OpRedactContent, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	assert.EqualValues(t, 1, report.Families[FamilyToolCalls].Found,
		"model filter scopes tool_calls via model_used")
	assert.EqualValues(t, 1, report.Families[FamilyToolCallInvocations].Found)
	assert.Zero(t, report.Families[FamilyCacheEntries].Found)
	assert.Positive(t, report.Families[FamilyToolCallInvocations].ContentBytesEst,
		"arguments bytes are the invocations' content estimate")

	// A model-scoped selection over cache_entries is still org+period only:
	// metadata filters are request-shaped and never silently narrow families
	// without the columns (documented in familyScope). Built via
	// NewSelection — F2 (review 0203): no hand-mutated Selection, the
	// wire strings and the Period instants must stay consistent by
	// construction.
	emptySel, err := NewSelection(orgID, "", Period{
		From: time.Date(2026, 3, 6, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC),
	}, []Family{FamilyRequestLogs, FamilySessions}, SelectionFilters{}, previewNow())
	require.NoError(t, err)
	empty, err := previewer.Report(ctx, PreviewRequest{Op: OpArchiveCopy, Selection: emptySel, Caller: adminCaller()})
	require.NoError(t, err)
	assert.True(t, empty.NoOp, "an empty selection is a valid no-op answer")
	assert.NotEmpty(t, empty.SelectionDigest, "no-op still issues its digest")
	for family, fp := range empty.Families {
		assert.Zero(t, fp.Found, family)
	}
}

// --- seeding helpers -----------------------------------------------------

func strptr(s string) *string { return &s }

// previewSeedSeq disambiguates fixtures across -count iterations against the
// persistent per-binary stand: everything seeded must tolerate a rerun.
var previewSeedSeq atomic.Uint64

func seedPreviewOrg(t *testing.T, ctx context.Context, pool testPGPool) string {
	t.Helper()
	return seedPreviewOrgNamed(t, ctx, pool, fmt.Sprintf("Itest preview %d-%d",
		time.Now().UnixNano(), previewSeedSeq.Add(1)))
}

func seedPreviewOrgNamed(t *testing.T, ctx context.Context, pool testPGPool, name string) string {
	t.Helper()
	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text", name).Scan(&orgID))
	return orgID
}

func insertRequestLog(t *testing.T, ctx context.Context, pool testPGPool, orgID, requestID string, at time.Time, response *string) {
	t.Helper()
	insertRequestLogWithSession(t, ctx, pool, orgID, requestID, "", at, response)
}

func insertRequestLogWithSession(t *testing.T, ctx context.Context, pool testPGPool, orgID, requestID, sessionID string, at time.Time, response *string) {
	t.Helper()
	var respArg any
	if response != nil {
		respArg = *response
	}
	_, err := pool.Exec(ctx, `INSERT INTO request_logs
	    (org_id, home_region, model_requested, model_used, status_code, duration_ms,
	     tokens_in, tokens_out, request_id, error, response, created_at, session_id)
	  VALUES ($1::uuid, 'sg', 'glm-5', 'glm-5', 200, 10, 1, 1, $2, NULL,
	          $3::jsonb, $4, NULLIF($5, '')::uuid)`,
		orgID, requestID, respArg, at, sessionID)
	require.NoError(t, err)
}

// seedActiveGrant inserts one live payload grant for requestID (one-hour TTL
// unless stated) and returns its id.
func seedActiveGrant(t *testing.T, ctx context.Context, pool testPGPool, orgID, requestID string, ttl time.Duration) string {
	t.Helper()
	var grantorID, granteeID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash) VALUES ($1, 'x') RETURNING id::text`,
		"grantor-"+orgID+"@itest").Scan(&grantorID))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash) VALUES ($1, 'x') RETURNING id::text`,
		"grantee-"+orgID+"@itest").Scan(&granteeID))
	var grantID string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO request_payload_grants
	    (id, token_hash, grantor_root, grantee, org_id, request_id, scope, expires_at)
	  VALUES (gen_random_uuid(), $1, $2::uuid, $3::uuid, $4::uuid, $5, 'payload.read', $6)
	  RETURNING id::text`,
		// token_hash is unique and opaque (sha256 of a fixture nonce): the
		// test never holds or reports a real token.
		[]byte(fmt.Sprintf("fixture-token-%x", sha256.Sum256(
			[]byte(fmt.Sprintf("%s/%s/%d", orgID, requestID, time.Now().UnixNano()))))),
		grantorID, granteeID, orgID, requestID,
		time.Now().Add(ttl)).Scan(&grantID))
	return grantID
}

func insertSession(t *testing.T, ctx context.Context, pool testPGPool, orgID string, at time.Time) string {
	t.Helper()
	var sessionID string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO sessions (org_id, home_region, created_at)
	  VALUES ($1::uuid, 'sg', $2) RETURNING id::text`, orgID, at).Scan(&sessionID))
	return sessionID
}

func insertMessage(t *testing.T, ctx context.Context, pool testPGPool, sessionID, role, content string, at time.Time) {
	t.Helper()
	_, err := pool.Exec(ctx, `INSERT INTO messages (session_id, role, content, home_region, created_at)
	  VALUES ($1::uuid, $2, $3, 'sg', $4)`, sessionID, role, content, at)
	require.NoError(t, err)
}

// fetchRawResponses loads the raw response column over the same scope the
// preview uses (org + period; the request-shape filters are empty here).
func fetchRawResponses(t *testing.T, ctx context.Context, pool testPGPool, orgID string, period Period) [][]byte {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT response FROM request_logs
	   WHERE org_id = $1::uuid AND created_at >= $2 AND created_at <= $3`,
		orgID, period.From, period.To)
	require.NoError(t, err)
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		out = append(out, raw)
	}
	require.NoError(t, rows.Err())
	return out
}

type rawCounts struct{ envelope, legacy, absent int }

// classifyWithReader is the Go-side classification: the canonical reader's
// nil/non-nil verdict plus the NULL/'null' absent rule.
func classifyWithReader(raws [][]byte) rawCounts {
	var c rawCounts
	for _, raw := range raws {
		switch {
		case len(raw) == 0, string(raw) == "null":
			c.absent++
		case adminstore.ParseResponseEnvelope(json.RawMessage(raw)) != nil:
			c.envelope++
		default:
			c.legacy++
		}
	}
	return c
}

// previewReqID maps a shape name to its request id.
func previewReqID(name string) string { return "req-" + name }
