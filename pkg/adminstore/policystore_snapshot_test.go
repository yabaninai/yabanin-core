package adminstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

type snapshotAuditTx struct {
	queryFn   func(context.Context, string, ...interface{}) (pgx.Rows, error)
	execs     []string
	committed bool
	rollback  bool
}

func (tx *snapshotAuditTx) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return &mockPGXRow{err: errors.New("unexpected snapshot QueryRow")}
}
func (tx *snapshotAuditTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return tx.queryFn(ctx, sql, args...)
}
func (tx *snapshotAuditTx) Exec(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
	tx.execs = append(tx.execs, sql)
	return pgconn.NewCommandTag("OK"), nil
}
func (tx *snapshotAuditTx) Commit(context.Context) error   { tx.committed = true; return nil }
func (tx *snapshotAuditTx) Rollback(context.Context) error { tx.rollback = true; return nil }

func TestStore_LoadPolicySnapshot_AllOrError(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	queries := 0
	tx := &snapshotAuditTx{queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
		queries++
		switch {
		case strings.Contains(sql, "FROM policy_pipelines") && !strings.Contains(sql, "JOIN"):
			return &mockPGXRows{data: [][]interface{}{{"p1", "org-a", "policy", true, 3, now, now}}}, nil
		case strings.Contains(sql, "FROM policy_versions"):
			return &mockPGXRows{data: [][]interface{}{{"v3", "p1", "org-a", 3, "apiVersion: ypp/v1", "", PolicyLabelActive, "owner", now}}}, nil
		case strings.Contains(sql, "FROM policy_attachments"):
			return &mockPGXRows{data: [][]interface{}{{"a1", "p1", "org-a", "", "*", "chat", 7}}}, nil
		case strings.Contains(sql, "FROM policy_prompt_pins"):
			return &mockPGXRows{data: [][]interface{}{{"p1", 3, "org:judge@active", "4", "pinned bytes"}}}, nil
		default:
			return nil, errors.New("unexpected query")
		}
	}}
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}
	store := newForTest(db, newTestLogger(), nil)

	snapshot, err := store.LoadPolicySnapshot(context.Background(), "org-a")
	require.NoError(t, err)
	require.True(t, tx.committed)
	require.False(t, tx.rollback)
	require.Equal(t, []string{"SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", "SELECT set_config('app.current_org', $1, true)"}, tx.execs)
	require.Equal(t, 4, queries)
	require.Len(t, snapshot.Policies, 1)
	require.Equal(t, "p1", snapshot.Policies[0].ID)
	require.Equal(t, 3, snapshot.Versions["p1"].Version)
	require.Equal(t, "apiVersion: ypp/v1", snapshot.Versions["p1"].YAML)
	require.Equal(t, []PolicyAttachment{{ID: "a1", PolicyID: "p1", OrgID: "org-a", ModelPattern: "*", Endpoint: "chat", Priority: 7}}, snapshot.Attachments["p1"])
	require.Equal(t, PromptPin{Ref: "org:judge@active", Version: "4", Body: "pinned bytes"}, snapshot.PromptPins["p1@3"]["org:judge@active"])
}

func TestStore_LoadPolicySnapshot_QueryFailureRollsBackWithoutPartialValue(t *testing.T) {
	wantErr := errors.New("attachment query failed")
	tx := &snapshotAuditTx{queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
		if strings.Contains(sql, "FROM policy_pipelines") && !strings.Contains(sql, "JOIN") {
			return &mockPGXRows{data: [][]interface{}{{"p1", "org-a", "policy", true, 1, time.Time{}, time.Time{}}}}, nil
		}
		if strings.Contains(sql, "FROM policy_versions") {
			return &mockPGXRows{data: [][]interface{}{{"v1", "p1", "org-a", 1, "yaml", "", PolicyLabelActive, "owner", time.Time{}}}}, nil
		}
		return nil, wantErr
	}}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}, newTestLogger(), nil)

	snapshot, err := store.LoadPolicySnapshot(context.Background(), "org-a")
	require.ErrorIs(t, err, wantErr)
	require.True(t, tx.rollback)
	require.False(t, tx.committed)
	require.Empty(t, snapshot.Policies)
	require.Empty(t, snapshot.Versions)
	require.Empty(t, snapshot.Attachments)
}

func TestStore_LoadPolicySnapshot_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tx := &snapshotAuditTx{queryFn: func(ctx context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
		return nil, ctx.Err()
	}}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}, newTestLogger(), nil)

	snapshot, err := store.LoadPolicySnapshot(ctx, "org-a")
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, tx.rollback)
	require.False(t, tx.committed)
	require.Empty(t, snapshot.Policies)
}
