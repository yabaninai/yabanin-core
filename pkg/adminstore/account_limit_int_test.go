package adminstore

// N04-P06 observable criterion, DB-backed: the 101st and every later account
// are available without a license. Provisioning is gated by nothing but its
// own validation — no seat cap, no activation check, no enabled-account
// ceiling for human, service, agent or CI accounts (owner decision I22).

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStore_AccountsBeyondHundredProvisionWithoutLicense_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	orgID := qaOrg(t, store, ctx)
	team, err := store.GetDefaultTeam(ctx, orgID)
	require.NoError(t, err)

	// Provision well past the retired 100-account limit (I16, cancelled by
	// I22): every account including the 101st must succeed with no license
	// configuration anywhere in the process.
	const total = 101
	stamp := time.Now().UnixNano()
	for i := 0; i < total; i++ {
		u, err := store.CreateDeveloper(ctx, DeveloperUser{
			Email:       fmt.Sprintf("n04p6-%d-%d@example.test", i, stamp),
			DisplayName: fmt.Sprintf("N04-P06 account %d", i+1),
			OrgID:       orgID,
			TeamID:      team.ID,
			Active:      true,
		})
		require.NoError(t, err, "account #%d must provision without any license", i+1)
		require.NotEmpty(t, u.ID)
	}

	list, err := store.ListDevelopers(ctx, orgID)
	require.NoError(t, err)
	require.Len(t, list, total, "no enabled-account ceiling exists: all %d accounts are live", total)

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM developer_users WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations_teams WHERE org_id = $1`, orgID)
	})
}
