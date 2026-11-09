package historyops

// Unit tests for the preview validation wiring (no database): the gates that
// fire before any SQL runs must fail closed, and the nil-pool path must never
// reach a query. The counting semantics are covered by preview_int_test.go
// against real PostgreSQL.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

func previewerNoPool() *Previewer {
	return NewPreviewer(nil, nil, func() time.Time { return testNow })
}

func TestPreviewValidationBeforeAnyQuery(t *testing.T) {
	sel, err := NewSelection(testOrg, "", closedPeriod(), []Family{FamilyRequestLogs},
		SelectionFilters{}, testNow)
	require.NoError(t, err)
	viewer := Caller{UserID: "u-viewer", Role: adminstore.RoleReader,
		Perms: map[adminstore.Permission]bool{adminstore.PermRequestsRead: true}}

	t.Run("unknown operation refused as malformed", func(t *testing.T) {
		_, err := previewerNoPool().Report(context.Background(), PreviewRequest{
			Op: Operation("drop_table"), Selection: sel, Caller: adminCaller(),
		})
		require.ErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("preview is not a previewable operation", func(t *testing.T) {
		_, err := previewerNoPool().Report(context.Background(), PreviewRequest{
			Op: OpPreview, Selection: sel, Caller: adminCaller(),
		})
		require.ErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("viewer passes the preview rights gate", func(t *testing.T) {
		// The rights gate fires before the pool check: passing it lands on
		// the pool error, failing it lands on insufficient_rights.
		_, err := previewerNoPool().Report(context.Background(), PreviewRequest{
			Op: OpArchiveCopy, Selection: sel, Caller: viewer,
		})
		require.ErrorContains(t, err, "database pool", "viewer may preview")
	})

	t.Run("delegated subject may not preview", func(t *testing.T) {
		agent := Caller{UserID: "u-bot", Role: adminstore.RoleOrgAdmin,
			Subject: adminstore.RequestPayloadAgent,
			Perms:   map[adminstore.Permission]bool{adminstore.PermRequestsRead: true}}
		_, err := previewerNoPool().Report(context.Background(), PreviewRequest{
			Op: OpArchiveCopy, Selection: sel, Caller: agent,
		})
		refusal, ok := RefusalOf(err)
		require.True(t, ok)
		assert.Equal(t, RefusalInsufficientRights, refusal.Code)
	})

	t.Run("caller without read right may not preview", func(t *testing.T) {
		caller := Caller{UserID: "u-x", Role: adminstore.RoleReader,
			Perms: map[adminstore.Permission]bool{}}
		_, err := previewerNoPool().Report(context.Background(), PreviewRequest{
			Op: OpArchiveCopy, Selection: sel, Caller: caller,
		})
		refusal, ok := RefusalOf(err)
		require.True(t, ok)
		assert.Equal(t, RefusalInsufficientRights, refusal.Code)
	})

	t.Run("open-period selection refused before any query", func(t *testing.T) {
		openSel := Selection{OrgID: testOrg, Families: []Family{FamilyRequestLogs},
			Period: Period{From: closedPeriod().From, To: testNow.Add(time.Hour)}}
		_, err := previewerNoPool().Report(context.Background(), PreviewRequest{
			Op: OpArchiveCopy, Selection: openSel, Caller: adminCaller(),
		})
		refusal, ok := RefusalOf(err)
		require.True(t, ok)
		assert.Equal(t, RefusalOpenPeriod, refusal.Code)
	})
}
