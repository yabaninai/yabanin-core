package adminstore

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type snapshotBarrierDB struct {
	pgxdb
	onFirstPipelineRead func()
	once                sync.Once
}

func (db *snapshotBarrierDB) BeginAuditTx(ctx context.Context) (auditTx, error) {
	tx, err := db.pgxdb.BeginAuditTx(ctx)
	if err != nil {
		return nil, err
	}
	return &snapshotBarrierTx{auditTx: tx, db: db}, nil
}

type snapshotBarrierTx struct {
	auditTx
	db *snapshotBarrierDB
}

func (tx *snapshotBarrierTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	rows, err := tx.auditTx.Query(ctx, sql, args...)
	if err == nil && strings.Contains(sql, "FROM policy_pipelines") && !strings.Contains(sql, "JOIN") {
		tx.db.once.Do(tx.db.onFirstPipelineRead)
	}
	return rows, err
}

var _ pgxdb = (*snapshotBarrierDB)(nil)
var _ auditTx = (*snapshotBarrierTx)(nil)

func TestPolicyStore_LoadPolicySnapshot_OrgRLSIntegration(t *testing.T) {
	fx := newPolicyFixture(t)
	ctx := context.Background()
	seed := func(orgID, name string) PolicyPipeline {
		t.Helper()
		p, _, err := fx.store.CreatePolicy(ctx, orgID, name, policyTestYAML, "", "snapshot-test")
		require.NoError(t, err)
		_, err = fx.store.SetActivePolicyVersion(ctx, orgID, p.ID, 1)
		require.NoError(t, err)
		p, err = fx.store.UpdatePolicy(ctx, orgID, p.ID, true)
		require.NoError(t, err)
		_, err = fx.store.SetPolicyAttachments(ctx, orgID, p.ID, []PolicyAttachment{{ModelPattern: "*", Endpoint: "chat", Priority: 4}})
		require.NoError(t, err)
		return p
	}
	policyA := seed(fx.orgA, "snapshot-a")
	_ = seed(fx.orgB, "snapshot-b")

	conn, err := fx.pool.Acquire(ctx)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	}()
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err)
	var user string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_user").Scan(&user))
	require.Equal(t, "yabanin_app", user)

	store := newForTest(rlsConnAdapter{conn.Conn()}, slog.New(slog.DiscardHandler), nil)
	snapshot, err := store.LoadPolicySnapshot(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, snapshot.Policies, 1, "snapshot must not include another org's policy")
	require.Equal(t, policyA.ID, snapshot.Policies[0].ID)
	require.Equal(t, fx.orgA, snapshot.Policies[0].OrgID)
	require.Equal(t, 1, snapshot.Versions[policyA.ID].Version)
	if got, want := snapshot.Versions[policyA.ID].YAML, policyTestYAML; got != want {
		t.Fatalf("snapshot YAML = %q, want exact bytes %q", got, want)
	}
	require.Len(t, snapshot.Attachments[policyA.ID], 1)
	require.Equal(t, fx.orgA, snapshot.Attachments[policyA.ID][0].OrgID)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	partial, err := store.LoadPolicySnapshot(canceled, fx.orgA)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, partial.Policies, "canceled transaction must not return a partial snapshot")
}

func TestPolicyStore_PromptPinsPersistImmutably(t *testing.T) {
	fx := newPolicyFixture(t)
	ctx := context.Background()
	policy, _, err := fx.store.CreatePolicy(ctx, fx.orgA, "prompt-pins", policyTestYAML, "", "snapshot-test")
	require.NoError(t, err)
	_, err = fx.store.SetActivePolicyVersion(ctx, fx.orgA, policy.ID, 1)
	require.NoError(t, err)
	pins := map[string]PromptPin{"org:judge@active": {Ref: "org:judge@active", Version: "1", Body: "resolved v1"}}
	require.NoError(t, fx.store.SavePolicyPromptPins(ctx, fx.orgA, policy.ID, 1, pins))
	require.NoError(t, fx.store.SavePolicyPromptPins(ctx, fx.orgA, policy.ID, 1, map[string]PromptPin{"org:judge@active": {Ref: "org:judge@active", Version: "2", Body: "resolved v2"}}))
	snapshot, err := fx.store.LoadPolicySnapshot(ctx, fx.orgA)
	require.NoError(t, err)
	require.Equal(t, "resolved v1", snapshot.PromptPins[policy.ID+"@1"]["org:judge@active"].Body)
}

func TestPolicyStore_LoadPolicySnapshot_MVCCActivationIntegration(t *testing.T) {
	fx := newPolicyFixture(t)
	ctx := context.Background()
	policy, _, err := fx.store.CreatePolicy(ctx, fx.orgA, "snapshot-race", policyTestYAML, "", "snapshot-test")
	require.NoError(t, err)
	_, err = fx.store.CreatePolicyVersion(ctx, fx.orgA, policy.ID, policyTestYAML+"# version 2\n", "", "snapshot-test")
	require.NoError(t, err)
	_, err = fx.store.SetActivePolicyVersion(ctx, fx.orgA, policy.ID, 1)
	require.NoError(t, err)
	_, err = fx.store.UpdatePolicy(ctx, fx.orgA, policy.ID, true)
	require.NoError(t, err)
	oldAttachments, err := fx.store.SetPolicyAttachments(ctx, fx.orgA, policy.ID, []PolicyAttachment{{ModelPattern: "old-*", Endpoint: "chat", Priority: 1}})
	require.NoError(t, err)
	require.Len(t, oldAttachments, 1)

	conn, err := fx.pool.Acquire(ctx)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	}()
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err)

	var mutationErr error
	barrier := &snapshotBarrierDB{pgxdb: fx.store.db, onFirstPipelineRead: func() {
		_, mutationErr = fx.store.SetActivePolicyVersion(ctx, fx.orgA, policy.ID, 2)
		if mutationErr != nil {
			return
		}
		_, mutationErr = fx.store.SetPolicyAttachments(ctx, fx.orgA, policy.ID, []PolicyAttachment{{ModelPattern: "new-*", Endpoint: "messages", Priority: 9}})
	}}
	store := newForTest(barrier, slog.New(slog.DiscardHandler), nil)
	first, err := store.LoadPolicySnapshot(ctx, fx.orgA)
	require.NoError(t, err)
	require.NoError(t, mutationErr, "concurrent activation/attachment update must commit while snapshot is paused")
	require.Len(t, first.Policies, 1)
	require.Equal(t, 1, first.Policies[0].CurrentVersion, "the first read must retain its original MVCC point")
	require.Equal(t, 1, first.Versions[policy.ID].Version)
	if got, want := first.Versions[policy.ID].YAML, policyTestYAML; got != want {
		t.Fatalf("first snapshot YAML = %q, want exact version-1 bytes %q", got, want)
	}
	require.NotContains(t, first.Versions[policy.ID].YAML, "# version 2")
	require.Equal(t, oldAttachments[0].ID, first.Attachments[policy.ID][0].ID)
	require.Equal(t, "old-*", first.Attachments[policy.ID][0].ModelPattern)

	second, err := store.LoadPolicySnapshot(ctx, fx.orgA)
	require.NoError(t, err)
	require.Equal(t, 2, second.Policies[0].CurrentVersion)
	require.Equal(t, 2, second.Versions[policy.ID].Version)
	if got, want := second.Versions[policy.ID].YAML, policyTestYAML+"# version 2\n"; got != want {
		t.Fatalf("second snapshot YAML = %q, want exact version-2 bytes %q", got, want)
	}
	require.Len(t, second.Attachments[policy.ID], 1)
	require.Equal(t, "new-*", second.Attachments[policy.ID][0].ModelPattern)
}
