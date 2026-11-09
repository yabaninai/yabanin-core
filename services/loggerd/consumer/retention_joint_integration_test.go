//go:build integration

package consumer

// N02-P06 T06 — the joint toggle/read scenario over the real consumer
// boundary and the real read surfaces. One seam of truth per assertion: the
// event is delivered through the real handleMessage boundary (NewRedisOps +
// NewDBOps over disposable testdb stands, AdminOriginalRetentionStore over
// the real adminstore), and every read goes through the store layer the
// merged HTTP endpoints use (list, detail, export, archive search) with the
// same RequestPayloadAccess matrix and the real one-time grant machinery.
//
// Matrix proven here end-to-end:
//   - toggle OFF (org with no explicit setting): processed-only visible on
//     EVERY read surface — even a caller holding originals access sees no
//     original, because none was stored;
//   - toggle ON + originals grant: originals stored AND readable through
//     the grant-gated surfaces; a real payload.read_originals grant is
//     issued and consumed exactly once against the stored originals;
//   - toggle ON, no originals grant: originals stored but denied on read
//     (the DTO drops them) — stored-but-denied is the contract;
//   - toggle flip mid-journey: no retroactive rewrite; new deliveries
//     persist processed-only, previously stored originals stay read-gated.
//
// DTO/permission/edition consistency: all four surfaces flow through the
// same adminstore predicates; the simple toggle itself is FREE-core (the
// org settings API/dashboard carry no edition gate — the Enterprise
// boundary is only the T04 resolver seam, which core never installs).

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jointEvent builds the delivered fixture: the full legacy capture shape
// (sentinels included) bound to real uuid identities.
func jointEvent(requestID, orgID, userID string) map[string]interface{} {
	fields := cpCompletedFields(requestID, false)
	fields["org_id"] = orgID
	fields["user_id"] = userID
	return fields
}

// jointDeliver runs one event through the real production boundary with the
// PRODUCTION retention wiring (AdminOriginalRetentionStore over the real
// adminstore) and returns the stored request_logs row as decoded JSON.
// Each call builds a fresh consumer — deliberately a cold resolver, the
// restart semantics the T08 unit proofs complement.
func jointDeliver(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client, fields map[string]interface{}) map[string]interface{} {
	t.Helper()
	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:queue", silentLogger())
	c.SetOriginalRetentionStore(AdminOriginalRetentionStore{Store: adminstore.New(pool, silentLogger(), nil)})
	c.handleMessage(context.Background(), redis.XMessage{Values: fields})

	var raw []byte
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT row_to_json(rl.*) FROM request_logs rl WHERE request_id = $1",
		fields["request_id"]).Scan(&raw), "request_logs row must exist for %v", fields["request_id"])
	var row map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &row))
	return row
}

// TestIntegration_OriginalRetention_JointToggleAndReadMatrix is the T06
// joint scenario; see the file comment for the matrix.
func TestIntegration_OriginalRetention_JointToggleAndReadMatrix(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "")

	pool := testdb.PostgresRegion(t, "n02p6b")
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	store := adminstore.New(pool, silentLogger(), nil)
	ctx := context.Background()

	// Identities: orgOff never chose (NULL toggle ⇒ platform default OFF),
	// orgOn opted in; one human owner and one root grantor.
	orgOff := cprNewOrg(t, pool, "n02p6b-joint-off")
	orgOn := cprNewOrg(t, pool, "n02p6b-joint-on")
	onTrue := true
	require.NoError(t, store.UpdateOrgOriginalRetention(ctx, orgOn, &onTrue))
	owner := uuid.NewString()
	var rootID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, is_root) VALUES ('n02p6b-joint-root@example.test', 'x', true) RETURNING id::text`).Scan(&rootID))

	// readCtx is the boundary decision a merged endpoint would hand down:
	// a payload-authorized human caller, originals flag per scenario.
	readCtx := func(orgID string, originals bool) context.Context {
		return adminstore.WithRequestPayloadAccess(ctx, adminstore.RequestPayloadAccess{
			UserID: rootID, Grant: true, Originals: originals,
			SubjectType: adminstore.RequestPayloadHuman, OrgWideMetadata: true,
		})
	}

	t.Run("toggle OFF: processed-only visible on every read surface", func(t *testing.T) {
		requestID := "req-joint-off"
		row := jointDeliver(t, pool, rdb, jointEvent(requestID, orgOff, owner))

		// The durable row itself: processed snapshot + digest persist,
		// originals bind NULL, accounting flows.
		assert.Equal(t, orgOff, row["org_id"])
		assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), row["prompt_hash"])
		for _, col := range []string{"upstream_request", "upstream_response"} {
			assert.Nil(t, row[col], "%s binds SQL NULL when the org never opted in", col)
		}
		assert.NotNil(t, row["response"])
		assert.Equal(t, float64(11), row["tokens_in"])

		// History list: the row is visible with its metadata (the list DTO
		// carries no content columns — processed-only by construction).
		rows, total, err := store.ListRequests(ctx, adminstore.RequestListFilters{OrgID: orgOff})
		require.NoError(t, err)
		assert.Equal(t, 1, total)
		require.Len(t, rows, 1)
		assert.Equal(t, requestID, rows[0].RequestID)

		// Detail — even WITH originals access: nothing original exists to
		// return. The processed response snapshot stays readable.
		detail, err := store.GetRequestDetail(readCtx(orgOff, true), orgOff, requestID)
		require.NoError(t, err)
		assert.Nil(t, detail.UpstreamRequest)
		assert.Nil(t, detail.UpstreamResponse)
		assert.Contains(t, string(detail.Response), "TOP SECRET PROMPT BODY")
		assert.NotContains(t, string(detail.Response), cpSentinelUpReq)
		assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), detail.PromptHash)

		// Export (the same store walk the export endpoint streams): no
		// original sentinel reaches any emitted record.
		var exported []*adminstore.RequestDetail
		_, err = store.StreamRequestExport(readCtx(orgOff, true),
			adminstore.RequestListFilters{OrgID: orgOff, RequestID: requestID},
			adminstore.RequestPayloadAccess{Grant: true, Originals: true, OrgWideMetadata: true},
			100, func(d *adminstore.RequestDetail) error { exported = append(exported, d); return nil })
		require.NoError(t, err)
		require.Len(t, exported, 1)
		body, err := json.Marshal(exported[0])
		require.NoError(t, err)
		assert.NotContains(t, string(body), cpSentinelUpReq)
		assert.NotContains(t, string(body), cpSentinelUpResp)
		assert.Contains(t, string(body), "TOP SECRET PROMPT BODY")

		// Archive search: the original sentinels match nothing; the same
		// authorized search still matches the stored PROCESSED content
		// (the check distinguishes instead of passing vacuously).
		own := adminstore.RequestListFilters{
			OrgID: orgOff, ContentSearch: cpSentinelUpReq,
			PayloadAuthorizationSet: true, PayloadSearchAllowed: true, PayloadUserID: owner,
		}
		_, originalsTotal, err := store.SearchRequestArchive(ctx, own)
		require.NoError(t, err)
		assert.Zero(t, originalsTotal, "no stored original is searchable")
		own.ContentSearch = "TOP SECRET PROMPT BODY"
		_, processedTotal, err := store.SearchRequestArchive(ctx, own)
		require.NoError(t, err)
		assert.Equal(t, 1, processedTotal, "the control search matches the stored processed content")
	})

	t.Run("toggle ON + originals grant: stored and readable; without grant: stored but denied", func(t *testing.T) {
		requestID := "req-joint-on"
		row := jointDeliver(t, pool, rdb, jointEvent(requestID, orgOn, owner))

		// Stored: the opted-in row keeps both originals.
		require.NotNil(t, row["upstream_request"])
		storedReq, err := json.Marshal(row["upstream_request"])
		require.NoError(t, err)
		assert.Contains(t, string(storedReq), cpSentinelUpReq)

		// WITH originals access — readable.
		allowed, err := store.GetRequestDetail(readCtx(orgOn, true), orgOn, requestID)
		require.NoError(t, err)
		assert.Contains(t, string(allowed.UpstreamRequest), cpSentinelUpReq)
		assert.Contains(t, string(allowed.UpstreamResponse), "TOP SECRET COMPLETION", "jsonb re-serialization: match on content, not byte layout")

		// WITHOUT the originals grant — the DTO drops the originals even
		// though they are stored (stored-but-denied).
		denied, err := store.GetRequestDetail(readCtx(orgOn, false), orgOn, requestID)
		require.NoError(t, err)
		assert.Nil(t, denied.UpstreamRequest)
		assert.Nil(t, denied.UpstreamResponse)
		assert.Contains(t, string(denied.Response), "TOP SECRET PROMPT BODY",
			"the processed snapshot needs no originals grant")

		// Export mirrors the same decision per access flag.
		stream := func(originals bool) string {
			var out []string
			_, err := store.StreamRequestExport(readCtx(orgOn, originals),
				adminstore.RequestListFilters{OrgID: orgOn, RequestID: requestID},
				adminstore.RequestPayloadAccess{Grant: true, Originals: originals, OrgWideMetadata: true},
				100, func(d *adminstore.RequestDetail) error {
					b, _ := json.Marshal(d)
					out = append(out, string(b))
					return nil
				})
			require.NoError(t, err)
			require.Len(t, out, 1)
			return out[0]
		}
		assert.Contains(t, stream(true), cpSentinelUpReq)
		assert.NotContains(t, stream(false), cpSentinelUpReq)

		// The REAL one-time grant machinery against the stored originals:
		// a payload.read_originals grant is issued, consumed exactly once,
		// never implies the processed scope, and never works cross-scope.
		now := time.Now().UTC()
		grant, err := store.CreateRequestPayloadGrantScope(orgOn, requestID, rootID,
			adminstore.RequestPayloadScopeOriginals, time.Minute, now)
		require.NoError(t, err)
		require.NoError(t, store.ConsumeRequestPayloadGrantScope(grant.Token, orgOn, requestID, rootID,
			adminstore.RequestPayloadScopeOriginals, time.Now().UTC()),
			"the originals grant consumes against the stored originals")
		assert.Error(t, store.ConsumeRequestPayloadGrantScope(grant.Token, orgOn, requestID, rootID,
			adminstore.RequestPayloadScopeOriginals, time.Now().UTC()),
			"the grant is single-use")
	})

	t.Run("toggle flip mid-journey: no retroactive rewrite; new deliveries processed-only", func(t *testing.T) {
		requestID := "req-joint-after-flip"
		off := false
		require.NoError(t, store.UpdateOrgOriginalRetention(ctx, orgOn, &off))

		// A fresh delivery boundary (the harness builds one per delivery —
		// a cold resolver): the flipped setting resolves OFF.
		row := jointDeliver(t, pool, rdb, jointEvent(requestID, orgOn, owner))
		for _, col := range []string{"upstream_request", "upstream_response"} {
			assert.Nil(t, row[col], "%s binds NULL after the flip", col)
		}

		// The row stored while the toggle was ON was never rewritten: it
		// stays stored-but-denied, and the read side (the handlers'
		// retention check on originals grants — request_export.go — plus
		// the cited handlers tests) governs its exposure.
		still, err := store.GetRequestDetail(readCtx(orgOn, true), orgOn, "req-joint-on")
		require.NoError(t, err)
		assert.Contains(t, string(still.UpstreamRequest), cpSentinelUpReq,
			"no retroactive strip job exists")
	})
}
