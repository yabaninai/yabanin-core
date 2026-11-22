//go:build integration

package adminstore

// Retention-at-disclosure regressions on a REAL Postgres: an originals-scoped
// export must evaluate the org's effective original-text retention as the
// FIRST read of its REPEATABLE READ disclosure snapshot, so an in-flight
// retention disable between the authorize-time preflight and the snapshot
// cannot let retained originals flow under a stale allow.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_RequestExportOriginalsRetentionAtSnapshot pins the snapshot
// retention boundary on the real durable plane: with retention enabled the
// originals canary is disclosed; after an in-flight disable the same
// originals-scoped stream fails closed with ErrOriginalRetentionDisabled
// before any row is read (zero emissions), the refusal is a disclosure
// boundary and not a grant event (the grant stays redeemable), and a
// re-enable control restores the disclosure. The authorize-time preflight
// alone — the stale-allow window this ordering excludes — is covered by the
// handler-level TestFIX08RetentionDisabledAtSnapshotIsFinal and the recorded
// negative-control mutation run.
func TestIntegration_RequestExportOriginalsRetentionAtSnapshot(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID, rootA, _ := corpusOrg(t, store, ctx, "retention")

	const requestID = "retention-snapshot-request"
	rowKey := corpusRequestRow(t, store, ctx, orgID, requestID)
	_, err := store.db.Exec(ctx,
		`UPDATE request_logs SET upstream_url=$2, upstream_request=$3::jsonb, upstream_response=$4::jsonb WHERE id=$1`,
		rowKey, "https://canary.example/v1", `{"canary":"request"}`, `{"canary":"response"}`)
	require.NoError(t, err)

	enabled := true
	require.NoError(t, store.UpdateOrgOriginalRetention(ctx, orgID, &enabled))
	grant, err := store.CreateRequestPayloadGrantScope(orgID, requestID, rootA, RequestPayloadScopeOriginals, time.Minute, time.Now().UTC())
	require.NoError(t, err)

	disclosed := []*RequestDetail{}
	collect := func(d *RequestDetail) error { disclosed = append(disclosed, d); return nil }
	access := RequestPayloadAccess{Grant: true, Originals: true}

	// Control: with retention explicitly enabled the originals canary flows.
	rows, err := store.StreamRequestExport(ctx, RequestListFilters{OrgID: orgID}, access, 10, collect)
	require.NoError(t, err)
	require.Equal(t, 1, rows)
	require.Len(t, disclosed, 1)
	assert.JSONEq(t, `{"canary":"request"}`, string(disclosed[0].UpstreamRequest),
		"with retention enabled, the upstream request snapshot is disclosed")
	assert.JSONEq(t, `{"canary":"response"}`, string(disclosed[0].UpstreamResponse),
		"with retention enabled, the upstream response snapshot is disclosed")
	assert.Equal(t, "https://canary.example/v1", disclosed[0].UpstreamURL)

	// The stale-allow case: retention disabled after the authorize-time
	// preflight must stop the disclosure BEFORE any read.
	require.NoError(t, store.UpdateOrgOriginalRetention(ctx, orgID, boolPtr(false)))
	disclosed = nil
	rows, err = store.StreamRequestExport(ctx, RequestListFilters{OrgID: orgID}, access, 10, collect)
	require.ErrorIs(t, err, ErrOriginalRetentionDisabled,
		"retention off at the disclosure snapshot fails the stream closed")
	require.Zero(t, rows, "the refused disclosure emits nothing")
	require.Empty(t, disclosed, "the refused disclosure discloses no originals")

	// The refusal is a disclosure boundary, not a grant event: the grant was
	// never consumed by the failed stream and stays redeemable.
	peekKey, err := store.PeekRequestPayloadGrantTarget(ctx, grant.Token, orgID, requestID, rootA, time.Now().UTC())
	require.NoError(t, err, "the refused disclosure burns nothing — the grant stays redeemable")
	require.Equal(t, rowKey, peekKey)

	// Control: re-enable → the disclosure works again (deterministic
	// recovery, no latched failure state).
	require.NoError(t, store.UpdateOrgOriginalRetention(ctx, orgID, &enabled))
	disclosed = nil
	rows, err = store.StreamRequestExport(ctx, RequestListFilters{OrgID: orgID}, access, 10, collect)
	require.NoError(t, err)
	require.Equal(t, 1, rows)
	require.Len(t, disclosed, 1)
	assert.NotEmpty(t, disclosed[0].UpstreamRequest, "re-enabled retention restores the originals disclosure")

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM request_payload_grants WHERE org_id = $1::uuid`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM request_logs WHERE org_id = $1::uuid AND request_id = ANY($2)`, orgID, []string{requestID})
	})
}
