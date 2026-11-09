package adminstore

// Unit coverage for the persisted prompt pins (migration 0011) and the
// all-or-error snapshot / CAS contracts of policystore.go. Default profile:
// no database — every store call runs against the mock pgxdb/auditTx doubles
// (store_test.go) with SQL-dispatched hooks, so the tests survive shuffle and
// race runs and never touch the shared Postgres stand.
//
// Behavior locked here:
//   - SavePolicyPromptPins writes each resolved pin with
//     ON CONFLICT (org_id, policy_id, policy_version, ref) DO NOTHING: a
//     retry can never replace an activated version's resolved bytes.
//   - LoadPolicySnapshot keys pins by "<policyID>@<version>": label moves
//     (activate v2) leave v1 pins intact, so a rollback finds its original
//     bytes; pins for policies outside the snapshot still load (the gateway
//     ignores unknown keys) — unknown/unresolved pins never fail the read.
//   - Any snapshot query failure rolls back and returns no partial value.
//   - UpdatePolicyCAS applies nothing on a version-token mismatch and
//     surfaces the live row; append/activation/attachment failures inside
//     the CAS transaction roll the whole PUT back.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// policyExecRecord is one Exec captured by policyTxDouble.
type policyExecRecord struct {
	sql  string
	args []interface{}
}

// policyTxDouble is the configurable auditTx double for the policystore
// error-path tests: each hook dispatches on SQL, Execs are recorded, and
// commit/rollback are tracked.
type policyTxDouble struct {
	queryRowFn func(ctx context.Context, sql string, args ...interface{}) pgx.Row
	queryFn    func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	execFn     func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	commitErr  error

	execs      []policyExecRecord
	committed  bool
	rolledBack bool
}

func (tx *policyTxDouble) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if tx.queryRowFn == nil {
		return &mockPGXRow{err: errors.New("unexpected policy QueryRow")}
	}
	return tx.queryRowFn(ctx, sql, args...)
}

func (tx *policyTxDouble) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	if tx.queryFn == nil {
		return nil, errors.New("unexpected policy Query")
	}
	return tx.queryFn(ctx, sql, args...)
}

func (tx *policyTxDouble) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	tx.execs = append(tx.execs, policyExecRecord{sql: sql, args: args})
	if tx.execFn != nil {
		return tx.execFn(ctx, sql, args...)
	}
	return pgconn.NewCommandTag("OK"), nil
}

func (tx *policyTxDouble) Commit(context.Context) error {
	tx.committed = true
	return tx.commitErr
}

func (tx *policyTxDouble) Rollback(context.Context) error { tx.rolledBack = true; return nil }

// failingScanRows wraps mockPGXRows with injectable Scan/Err failures
// (mockPGXRows.Scan itself never fails, so the row-level error paths of the
// snapshot scans need this override).
type failingScanRows struct {
	*mockPGXRows
	scanErr error
	iterErr error
}

func (r *failingScanRows) Scan(dest ...interface{}) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	return r.mockPGXRows.Scan(dest...)
}

func (r *failingScanRows) Err() error {
	if r.iterErr != nil {
		return r.iterErr
	}
	return r.mockPGXRows.Err()
}

func policyPipelineReturnRow(id string, current int) []interface{} {
	return []interface{}{id, "org-a", "policy", false, current, time.Time{}, time.Time{}}
}

func snapshotQueryRows(sql string, pipelines, versions, attachments, pins *mockPGXRows) (*mockPGXRows, bool) {
	switch {
	case strings.Contains(sql, "FROM policy_pipelines") && !strings.Contains(sql, "JOIN"):
		return pipelines, true
	case strings.Contains(sql, "policy_versions pv"):
		return versions, true
	case strings.Contains(sql, "policy_attachments pa"):
		return attachments, true
	case strings.Contains(sql, "FROM policy_prompt_pins"):
		return pins, true
	}
	return nil, false
}

func TestStore_SavePolicyPromptPins_WritesEachResolvedPinWithConflictGuard(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	pins := map[string]PromptPin{
		"org:judge@active": {Ref: "org:judge@active", Version: "3", Body: "judge bytes v3"},
		"org:sum@active":   {Ref: "org:sum@active", Version: "3", Body: "sum bytes v3"},
	}
	require.NoError(t, store.SavePolicyPromptPins(context.Background(), "org-a", "p1", 2, pins))

	require.True(t, tx.committed)
	require.False(t, tx.rolledBack)
	var pinInserts []policyExecRecord
	for _, rec := range tx.execs {
		if strings.Contains(rec.sql, "INSERT INTO policy_prompt_pins") {
			pinInserts = append(pinInserts, rec)
		}
	}
	require.Len(t, pinInserts, 2, "one INSERT per resolved ref")
	seen := map[string][]interface{}{}
	for _, rec := range pinInserts {
		require.Contains(t, rec.sql, "INSERT INTO policy_prompt_pins")
		require.Contains(t, rec.sql,
			"ON CONFLICT (org_id, policy_id, policy_version, ref) DO NOTHING",
			"a retry must never replace an activated version's resolved bytes")
		// Arg order: org, policy, version, ref, prompt_version, body.
		require.Equal(t, "org-a", rec.args[0])
		require.Equal(t, "p1", rec.args[1])
		require.Equal(t, 2, rec.args[2])
		seen[rec.args[3].(string)] = rec.args[4:]
	}
	require.Equal(t, map[string][]interface{}{
		"org:judge@active": {"3", "judge bytes v3"},
		"org:sum@active":   {"3", "sum bytes v3"},
	}, seen)
}

func TestStore_SavePolicyPromptPins_EmptySetStillCommits(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	require.NoError(t, store.SavePolicyPromptPins(context.Background(), "org-a", "p1", 1, nil))
	require.NoError(t, store.SavePolicyPromptPins(context.Background(), "org-a", "p1", 1, map[string]PromptPin{}))
	require.True(t, tx.committed)
	for _, rec := range tx.execs {
		require.NotContains(t, rec.sql, "INSERT INTO policy_prompt_pins", "no resolved refs means no writes")
	}
}

func TestStore_SavePolicyPromptPins_WriteFailureRollsBack(t *testing.T) {
	boom := errors.New("write failed")
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{execFn: func(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "INSERT INTO policy_prompt_pins") {
				return pgconn.NewCommandTag(""), boom
			}
			return pgconn.NewCommandTag("OK"), nil
		}}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	err := store.SavePolicyPromptPins(context.Background(), "org-a", "p1", 1,
		map[string]PromptPin{"org:judge@active": {Ref: "org:judge@active", Version: "1", Body: "b"}})
	require.ErrorIs(t, err, boom)
	require.Contains(t, err.Error(), "save policy prompt pin")
	require.True(t, tx.rolledBack)
	require.False(t, tx.committed, "a failed pin write must not commit")
}

func TestStore_LoadPolicySnapshot_PromptPinsAreVersionScopedAndUnknownRefsSurvive(t *testing.T) {
	// Pins written across two activations: v1 was pinned, the label moved to
	// v2 (new pin set), and one pin references a policy that is not part of
	// this snapshot (deleted concurrently / foreign org row filtered by RLS).
	// All rows must load under their <policy>@<version> key: activating v2
	// leaves v1's bytes untouched, so a rollback to v1 finds its pins.
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	tx := &policyTxDouble{queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
		if rows, ok := snapshotQueryRows(sql,
			&mockPGXRows{data: [][]interface{}{{"p1", "org-a", "policy", true, 2, now, now}}},
			&mockPGXRows{data: [][]interface{}{{"v2", "p1", "org-a", 2, "yaml v2", "", PolicyLabelActive, "owner", now}}},
			&mockPGXRows{},
			&mockPGXRows{data: [][]interface{}{
				{"p1", 1, "org:judge@1", "1", "judge bytes v1"},
				{"p1", 1, "org:sum@1", "1", "sum bytes v1"},
				{"p1", 2, "org:judge@2", "2", "judge bytes v2"},
				{"pX", 9, "org:lost@9", "9", "orphan bytes"},
			}},
		); ok {
			return rows, nil
		}
		return nil, errors.New("unexpected snapshot query: " + sql)
	}}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}, newTestLogger(), nil)

	snapshot, err := store.LoadPolicySnapshot(context.Background(), "org-a")
	require.NoError(t, err)
	require.True(t, tx.committed)
	require.False(t, tx.rolledBack)

	// v1 pins survived the label move to v2.
	require.Equal(t, "judge bytes v1", snapshot.PromptPins["p1@1"]["org:judge@1"].Body)
	require.Equal(t, "sum bytes v1", snapshot.PromptPins["p1@1"]["org:sum@1"].Body)
	// The currently active version carries its own resolved bytes.
	require.Equal(t, PromptPin{Ref: "org:judge@2", Version: "2", Body: "judge bytes v2"}, snapshot.PromptPins["p1@2"]["org:judge@2"])
	// Unknown/unresolved pins load too; resolution is the gateway's job.
	require.Equal(t, "orphan bytes", snapshot.PromptPins["pX@9"]["org:lost@9"].Body)
	require.NotContains(t, snapshot.Versions, "pX", "unknown policies stay out of the active version map")
}

func TestStore_LoadPolicySnapshot_PromptPinRowFailureIsAllOrError(t *testing.T) {
	t.Run("scan failure", func(t *testing.T) {
		tx := &policyTxDouble{queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			if rows, ok := snapshotQueryRows(sql,
				&mockPGXRows{},
				&mockPGXRows{},
				&mockPGXRows{},
				&mockPGXRows{data: [][]interface{}{{"p1", 1, "org:judge@1", "1", "bytes"}}},
			); ok {
				if strings.Contains(sql, "FROM policy_prompt_pins") {
					return &failingScanRows{mockPGXRows: rows, scanErr: errors.New("pin scan failed")}, nil
				}
				return rows, nil
			}
			return nil, errors.New("unexpected snapshot query: " + sql)
		}}
		store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}, newTestLogger(), nil)

		snapshot, err := store.LoadPolicySnapshot(context.Background(), "org-a")
		require.ErrorContains(t, err, "snapshot scan policy prompt pin")
		require.True(t, tx.rolledBack)
		require.False(t, tx.committed)
		require.Empty(t, snapshot.PromptPins, "a failed pin read must not return a partial snapshot")
	})

	t.Run("iteration failure", func(t *testing.T) {
		tx := &policyTxDouble{queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			if rows, ok := snapshotQueryRows(sql,
				&mockPGXRows{},
				&mockPGXRows{},
				&mockPGXRows{},
				&mockPGXRows{data: [][]interface{}{{"p1", 1, "org:judge@1", "1", "bytes"}}},
			); ok {
				if strings.Contains(sql, "FROM policy_prompt_pins") {
					return &failingScanRows{mockPGXRows: rows, iterErr: errors.New("pin iteration failed")}, nil
				}
				return rows, nil
			}
			return nil, errors.New("unexpected snapshot query: " + sql)
		}}
		store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}, newTestLogger(), nil)

		snapshot, err := store.LoadPolicySnapshot(context.Background(), "org-a")
		require.ErrorContains(t, err, "snapshot iterate policy prompt pins")
		require.True(t, tx.rolledBack)
		require.False(t, tx.committed)
		require.Empty(t, snapshot.PromptPins)
	})
}

func TestStore_LoadPolicySnapshot_AnyFailureRollsBackWithoutPartialValue(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	goodPipelines := &mockPGXRows{data: [][]interface{}{{"p1", "org-a", "policy", true, 1, now, now}}}
	goodVersions := &mockPGXRows{data: [][]interface{}{{"v1", "p1", "org-a", 1, "yaml", "", PolicyLabelActive, "owner", now}}}
	goodAttachments := &mockPGXRows{data: [][]interface{}{{"a1", "p1", "org-a", "", "*", "chat", 1}}}
	goodPins := &mockPGXRows{data: [][]interface{}{{"p1", 1, "org:judge@1", "1", "bytes"}}}

	cases := []struct {
		name    string
		queryFn func(sql string) (pgx.Rows, error)
		execErr func(sql string) error
		db      func(*testing.T) pgxdb
		wantErr string
	}{
		{
			name: "pipeline scan failure",
			queryFn: func(sql string) (pgx.Rows, error) {
				rows, ok := snapshotQueryRows(sql, goodPipelines, &mockPGXRows{}, &mockPGXRows{}, &mockPGXRows{})
				if !ok {
					return nil, errors.New("unexpected query " + sql)
				}
				if strings.Contains(sql, "FROM policy_pipelines") {
					return &failingScanRows{mockPGXRows: rows, scanErr: errors.New("scan failed")}, nil
				}
				return rows, nil
			},
			wantErr: "snapshot scan policy pipeline",
		},
		{
			name: "pipeline iteration failure",
			queryFn: func(sql string) (pgx.Rows, error) {
				rows, ok := snapshotQueryRows(sql, goodPipelines, &mockPGXRows{}, &mockPGXRows{}, &mockPGXRows{})
				if !ok {
					return nil, errors.New("unexpected query " + sql)
				}
				if strings.Contains(sql, "FROM policy_pipelines") {
					return &failingScanRows{mockPGXRows: rows, iterErr: errors.New("iterate failed")}, nil
				}
				return rows, nil
			},
			wantErr: "snapshot iterate policy pipelines",
		},
		{
			name: "versions query failure",
			queryFn: func(sql string) (pgx.Rows, error) {
				if strings.Contains(sql, "policy_versions pv") {
					return nil, errors.New("versions query failed")
				}
				rows, ok := snapshotQueryRows(sql, goodPipelines, goodVersions, &mockPGXRows{}, &mockPGXRows{})
				if !ok {
					return nil, errors.New("unexpected query " + sql)
				}
				return rows, nil
			},
			wantErr: "snapshot list active policy versions",
		},
		{
			name: "versions scan failure",
			queryFn: func(sql string) (pgx.Rows, error) {
				rows, ok := snapshotQueryRows(sql, goodPipelines, goodVersions, &mockPGXRows{}, &mockPGXRows{})
				if !ok {
					return nil, errors.New("unexpected query " + sql)
				}
				if strings.Contains(sql, "policy_versions pv") {
					return &failingScanRows{mockPGXRows: rows, scanErr: errors.New("scan failed")}, nil
				}
				return rows, nil
			},
			wantErr: "snapshot scan active policy version",
		},
		{
			name: "versions iteration failure",
			queryFn: func(sql string) (pgx.Rows, error) {
				rows, ok := snapshotQueryRows(sql, goodPipelines, goodVersions, &mockPGXRows{}, &mockPGXRows{})
				if !ok {
					return nil, errors.New("unexpected query " + sql)
				}
				if strings.Contains(sql, "policy_versions pv") {
					return &failingScanRows{mockPGXRows: rows, iterErr: errors.New("iterate failed")}, nil
				}
				return rows, nil
			},
			wantErr: "snapshot iterate active policy versions",
		},
		{
			name: "attachments scan failure",
			queryFn: func(sql string) (pgx.Rows, error) {
				rows, ok := snapshotQueryRows(sql, goodPipelines, goodVersions, goodAttachments, &mockPGXRows{})
				if !ok {
					return nil, errors.New("unexpected query " + sql)
				}
				if strings.Contains(sql, "policy_attachments pa") {
					return &failingScanRows{mockPGXRows: rows, scanErr: errors.New("scan failed")}, nil
				}
				return rows, nil
			},
			wantErr: "snapshot scan policy attachment",
		},
		{
			name: "attachments iteration failure",
			queryFn: func(sql string) (pgx.Rows, error) {
				rows, ok := snapshotQueryRows(sql, goodPipelines, goodVersions, goodAttachments, &mockPGXRows{})
				if !ok {
					return nil, errors.New("unexpected query " + sql)
				}
				if strings.Contains(sql, "policy_attachments pa") {
					return &failingScanRows{mockPGXRows: rows, iterErr: errors.New("iterate failed")}, nil
				}
				return rows, nil
			},
			wantErr: "snapshot iterate policy attachments",
		},
		{
			name:    "isolation failure",
			execErr: func(sql string) error { return errors.New("no isolation") },
			wantErr: "set policy snapshot isolation",
		},
		{
			name: "org GUC failure",
			execErr: func(sql string) error {
				if strings.Contains(sql, "set_config") {
					return errors.New("no GUC")
				}
				return nil
			},
			wantErr: "set policy snapshot org",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &policyTxDouble{
				queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
					return tc.queryFn(sql)
				},
				execFn: func(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
					if tc.execErr != nil {
						return pgconn.NewCommandTag(""), tc.execErr(sql)
					}
					return pgconn.NewCommandTag("OK"), nil
				},
			}
			store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}, newTestLogger(), nil)

			snapshot, err := store.LoadPolicySnapshot(context.Background(), "org-a")
			require.ErrorContains(t, err, tc.wantErr)
			require.True(t, tx.rolledBack)
			require.False(t, tx.committed)
			require.Empty(t, snapshot.Policies, "all-or-error: no partial policies")
			require.Empty(t, snapshot.Versions, "all-or-error: no partial versions")
			require.Empty(t, snapshot.Attachments, "all-or-error: no partial attachments")
			require.Empty(t, snapshot.PromptPins, "all-or-error: no partial pins")
		})
	}

	t.Run("commit failure", func(t *testing.T) {
		tx := &policyTxDouble{
			commitErr: errors.New("commit lost"),
			queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
				rows, ok := snapshotQueryRows(sql, goodPipelines, goodVersions, goodAttachments, goodPins)
				if !ok {
					return nil, errors.New("unexpected query " + sql)
				}
				return rows, nil
			},
		}
		store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}, newTestLogger(), nil)

		_, err := store.LoadPolicySnapshot(context.Background(), "org-a")
		require.ErrorContains(t, err, "commit policy snapshot tx")
	})

	t.Run("nil database", func(t *testing.T) {
		store := newForTest(nil, newTestLogger(), nil)
		_, err := store.LoadPolicySnapshot(context.Background(), "org-a")
		require.ErrorContains(t, err, "database not available")
	})
}

func TestStore_UpdatePolicyCAS_PreconditionMismatchAppliesNothingAndReturnsLiveRow(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			require.Contains(t, sql, "FOR UPDATE", "the token check must lock the row")
			return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 5)}}
		}}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	stale := 4
	p, appended, err := store.UpdatePolicyCAS(context.Background(), "org-a", "p1",
		PolicyUpdate{Enabled: boolPtr(true)}, &stale, "admin@x.test")
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.Equal(t, 5, p.CurrentVersion, "the 409 body carries the CURRENT row to rebase on")
	require.Equal(t, PolicyVersion{}, appended, "nothing is applied on a token mismatch")
	require.True(t, tx.rolledBack)
	require.False(t, tx.committed)
}

func TestStore_UpdatePolicyCAS_YAMLAppendConflictIsRetryable(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			switch {
			case strings.Contains(sql, "FOR UPDATE"):
				return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
			case strings.Contains(sql, "FROM policy_pipelines"):
				// createPolicyVersionTx's existence probe.
				return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
			case strings.Contains(sql, "INSERT INTO policy_versions"):
				return &mockPGXRow{err: &pgconn.PgError{Code: "23505"}}
			}
			return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
		}}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	expect := 1
	gitSHA := "abc123"
	_, _, err := store.UpdatePolicyCAS(context.Background(), "org-a", "p1",
		PolicyUpdate{YAML: strPtr("apiVersion: ypp/v1\n"), GitSHA: &gitSHA}, &expect, "admin@x.test")
	require.ErrorContains(t, err, "concurrent policy update, retry")
	require.True(t, tx.rolledBack)
}

func TestStore_UpdatePolicyCAS_UnknownActiveVersionIsErrNotFound(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			switch {
			case strings.Contains(sql, "FOR UPDATE"):
				return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
			case strings.Contains(sql, "FROM policy_pipelines"):
				// setActivePolicyVersionTx's existence probe.
				return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
			case strings.Contains(sql, "SELECT EXISTS"):
				return &mockPGXRow{data: [][]interface{}{{false}}}
			}
			return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
		}}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	expect := 1
	_, _, err := store.UpdatePolicyCAS(context.Background(), "org-a", "p1",
		PolicyUpdate{ActiveVersion: ptr(9)}, &expect, "admin@x.test")
	require.ErrorIs(t, err, ErrNotFound)
	require.True(t, tx.rolledBack)
}

func TestStore_UpdatePolicyCAS_MidTransactionFailureRollsBackWholePut(t *testing.T) {
	t.Run("enabled flip failure", func(t *testing.T) {
		var tx *policyTxDouble
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			tx = &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
				switch {
				case strings.Contains(sql, "FOR UPDATE"):
					return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
				case strings.Contains(sql, "SET enabled"):
					return &mockPGXRow{err: errors.New("enabled write lost")}
				}
				return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
			}}
			return tx, nil
		}}
		store := newForTest(db, newTestLogger(), nil)

		expect := 1
		_, _, err := store.UpdatePolicyCAS(context.Background(), "org-a", "p1",
			PolicyUpdate{Enabled: boolPtr(true)}, &expect, "admin@x.test")
		require.ErrorContains(t, err, "update policy pipeline")
		require.True(t, tx.rolledBack)
		require.False(t, tx.committed)
	})

	t.Run("attachment replace failure", func(t *testing.T) {
		var tx *policyTxDouble
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			tx = &policyTxDouble{
				queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
					switch {
					case strings.Contains(sql, "FOR UPDATE"):
						return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
					case strings.Contains(sql, "FROM policy_pipelines"):
						// setPolicyAttachmentsTx's existence probe.
						return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
					case strings.Contains(sql, "INSERT INTO policy_attachments"):
						return &mockPGXRow{err: errors.New("attachment write lost")}
					}
					return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
				},
			}
			return tx, nil
		}}
		store := newForTest(db, newTestLogger(), nil)

		expect := 1
		_, _, err := store.UpdatePolicyCAS(context.Background(), "org-a", "p1",
			PolicyUpdate{Attachments: &[]PolicyAttachment{{ModelPattern: "*", Endpoint: "chat", Priority: 1}}},
			&expect, "admin@x.test")
		require.ErrorContains(t, err, "create policy attachment")
		require.True(t, tx.rolledBack)
		require.False(t, tx.committed)
	})
}

func TestStore_UpdatePolicyCAS_RejectsInvalidPayloadBeforeLocking(t *testing.T) {
	var txOpened bool
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		txOpened = true
		return nil, errors.New("must not open a transaction for an invalid payload")
	}}
	store := newForTest(db, newTestLogger(), nil)
	expect := 1

	_, _, err := store.UpdatePolicyCAS(context.Background(), "org-a", "p1",
		PolicyUpdate{YAML: strPtr("")}, &expect, "admin@x.test")
	require.ErrorContains(t, err, "policy yaml is required")

	badPattern := PolicyUpdate{Attachments: &[]PolicyAttachment{{Endpoint: "chat", Priority: 1}}}
	_, _, err = store.UpdatePolicyCAS(context.Background(), "org-a", "p1", badPattern, &expect, "admin@x.test")
	require.ErrorContains(t, err, "attachment model_pattern is required")

	badEndpoint := PolicyUpdate{Attachments: &[]PolicyAttachment{{ModelPattern: "*", Priority: 1}}}
	_, _, err = store.UpdatePolicyCAS(context.Background(), "org-a", "p1", badEndpoint, &expect, "admin@x.test")
	require.ErrorContains(t, err, "attachment endpoint is required")

	badPriority := PolicyUpdate{Attachments: &[]PolicyAttachment{{ModelPattern: "*", Endpoint: "chat", Priority: -1}}}
	_, _, err = store.UpdatePolicyCAS(context.Background(), "org-a", "p1", badPriority, &expect, "admin@x.test")
	require.ErrorContains(t, err, "attachment priority must be >= 0")

	require.False(t, txOpened, "validation failures must reject before the row is locked")
}

func TestPolicyUpdate_EmptyReportsUnrecognizedBodies(t *testing.T) {
	require.True(t, PolicyUpdate{}.Empty())
	require.False(t, PolicyUpdate{YAML: strPtr("yaml")}.Empty())
	require.False(t, PolicyUpdate{GitSHA: strPtr("sha")}.Empty())
	require.False(t, PolicyUpdate{Enabled: boolPtr(true)}.Empty())
	require.False(t, PolicyUpdate{ActiveVersion: ptr(2)}.Empty())
	require.False(t, PolicyUpdate{Attachments: &[]PolicyAttachment{}}.Empty())
}

func TestStore_CreatePolicy_InputValidationRejectsBeforeTransaction(t *testing.T) {
	var txOpened bool
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		txOpened = true
		return nil, errors.New("must not open a transaction for invalid input")
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, _, err := store.CreatePolicy(context.Background(), "", "name", "yaml", "", "creator")
	require.ErrorContains(t, err, "org id is required")

	_, _, err = store.CreatePolicy(context.Background(), "org-a", "", "yaml", "", "creator")
	require.ErrorContains(t, err, "policy name must be 1 to 256 characters")

	_, _, err = store.CreatePolicy(context.Background(), "org-a", strings.Repeat("x", 257), "yaml", "", "creator")
	require.ErrorContains(t, err, "policy name must be 1 to 256 characters")

	_, _, err = store.CreatePolicy(context.Background(), "org-a", "name", "", "", "creator")
	require.ErrorContains(t, err, "policy yaml is required")

	require.False(t, txOpened)
}

func TestStore_CreatePolicy_ConflictingNameSurfacesAlreadyExists(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			require.Contains(t, sql, "INSERT INTO policy_pipelines")
			return &mockPGXRow{err: &pgconn.PgError{Code: "23505"}}
		}}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, _, err := store.CreatePolicy(context.Background(), "org-a", "pii-guard", "yaml", "", "creator")
	require.Contains(t, err.Error(), "already exists in this org")
	require.ErrorContains(t, err, "SQLSTATE 23505", "the unique-violation identity stays wrapped for callers")
	require.True(t, tx.rolledBack, "a conflicted create rolls back instead of committing a half row")
}

func TestStore_CreatePolicy_VersionInsertFailureRollsBack(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			switch {
			case strings.Contains(sql, "INSERT INTO policy_pipelines"):
				return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 0)}}
			case strings.Contains(sql, "INSERT INTO policy_versions"):
				return &mockPGXRow{err: errors.New("version write lost")}
			}
			return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
		}}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, _, err := store.CreatePolicy(context.Background(), "org-a", "pii-guard", "yaml", "", "creator")
	require.ErrorContains(t, err, "create policy version")
	require.True(t, tx.rolledBack)
	require.False(t, tx.committed, "pipeline and first version commit together or not at all")
}

func TestStore_GetPolicy_DBFailureIsWrappedNot404(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			return &mockPGXRow{err: errors.New("connection reset")}
		}}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.GetPolicy(context.Background(), "org-a", "p1")
	require.ErrorContains(t, err, "get policy pipeline")
	require.NotErrorIs(t, err, ErrNotFound, "infrastructure failures must not read as a missing row")
}

func TestStore_ListPolicies_RowFailuresPropagate(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	t.Run("query failure", func(t *testing.T) {
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			return &policyTxDouble{queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
				return nil, errors.New("list failed")
			}}, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.ListPolicies(context.Background(), "org-a")
		require.ErrorContains(t, err, "list policy pipelines")
	})

	t.Run("scan failure", func(t *testing.T) {
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			return &policyTxDouble{queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
				return &failingScanRows{
					mockPGXRows: &mockPGXRows{data: [][]interface{}{{"p1", "org-a", "policy", true, 1, now, now}}},
					scanErr:     errors.New("scan failed"),
				}, nil
			}}, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.ListPolicies(context.Background(), "org-a")
		require.ErrorContains(t, err, "scan policy pipeline")
	})

	t.Run("iteration failure", func(t *testing.T) {
		iterErr := errors.New("iterate failed")
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			return &policyTxDouble{queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
				return &failingScanRows{
					mockPGXRows: &mockPGXRows{data: [][]interface{}{{"p1", "org-a", "policy", true, 1, now, now}}},
					iterErr:     iterErr,
				}, nil
			}}, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.ListPolicies(context.Background(), "org-a")
		require.ErrorIs(t, err, iterErr)
	})
}

func TestStore_CreatePolicyVersion_EmptyYAMLRejectedBeforeTransaction(t *testing.T) {
	var txOpened bool
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		txOpened = true
		return nil, errors.New("must not open a transaction for invalid input")
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.CreatePolicyVersion(context.Background(), "org-a", "p1", "", "", "creator")
	require.ErrorContains(t, err, "policy yaml is required")
	require.False(t, txOpened)
}

func TestStore_ListPolicyVersions_RowFailuresPropagate(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	t.Run("foreign pipeline is not found", func(t *testing.T) {
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			return &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
				require.Contains(t, sql, "FROM policy_pipelines")
				return &mockPGXRow{err: pgx.ErrNoRows}
			}}, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.ListPolicyVersions(context.Background(), "org-a", "p1")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("version scan failure", func(t *testing.T) {
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			return &policyTxDouble{
				queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
					return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
				},
				queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
					return &failingScanRows{
						mockPGXRows: &mockPGXRows{data: [][]interface{}{{"v1", "p1", "org-a", 1, "yaml", "", "draft", "owner", now}}},
						scanErr:     errors.New("scan failed"),
					}, nil
				},
			}, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.ListPolicyVersions(context.Background(), "org-a", "p1")
		require.ErrorContains(t, err, "scan policy version")
	})
}

func TestStore_GetPolicyVersion_MissingVersionIsErrNotFound(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			switch {
			case strings.Contains(sql, "FROM policy_pipelines"):
				return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
			case strings.Contains(sql, "FROM policy_versions"):
				return &mockPGXRow{err: pgx.ErrNoRows}
			}
			return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
		}}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.GetPolicyVersion(context.Background(), "org-a", "p1", 42)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestStore_SetActivePolicyVersion_FailuresRollBack(t *testing.T) {
	pipelineRow := func() pgx.Row { return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}} }

	cases := []struct {
		name       string
		queryRowFn func(sql string) pgx.Row
		execErr    func(sql string) error
		wantErr    string
	}{
		{
			name: "existence check failure",
			queryRowFn: func(sql string) pgx.Row {
				if strings.Contains(sql, "SELECT EXISTS") {
					return &mockPGXRow{err: errors.New("check failed")}
				}
				return pipelineRow()
			},
			wantErr: "check policy version",
		},
		{
			name: "demote failure",
			queryRowFn: func(sql string) pgx.Row {
				if strings.Contains(sql, "SELECT EXISTS") {
					return &mockPGXRow{data: [][]interface{}{{true}}}
				}
				if strings.Contains(sql, "FROM policy_pipelines") {
					return pipelineRow()
				}
				return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
			},
			execErr: func(sql string) error {
				if strings.Contains(sql, "SET label") && strings.Contains(sql, "label = $3") {
					return errors.New("demote lost")
				}
				return nil
			},
			wantErr: "demote active policy version",
		},
		{
			name: "activate failure",
			queryRowFn: func(sql string) pgx.Row {
				if strings.Contains(sql, "SELECT EXISTS") {
					return &mockPGXRow{data: [][]interface{}{{true}}}
				}
				if strings.Contains(sql, "FROM policy_pipelines") {
					return pipelineRow()
				}
				return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
			},
			execErr: func(sql string) error {
				if strings.Contains(sql, "SET label") && strings.Contains(sql, "version = $3") {
					return errors.New("activate lost")
				}
				return nil
			},
			wantErr: "activate policy version",
		},
		{
			name: "pipeline pointer update failure",
			queryRowFn: func(sql string) pgx.Row {
				switch {
				case strings.Contains(sql, "SELECT EXISTS"):
					return &mockPGXRow{data: [][]interface{}{{true}}}
				case strings.Contains(sql, "SET current_version"):
					return &mockPGXRow{err: errors.New("pointer lost")}
				}
				if strings.Contains(sql, "FROM policy_pipelines") {
					return pipelineRow()
				}
				return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
			},
			wantErr: "set active policy version",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tx *policyTxDouble
			db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
				tx = &policyTxDouble{
					queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row { return tc.queryRowFn(sql) },
					execFn: func(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
						if tc.execErr != nil {
							return pgconn.NewCommandTag(""), tc.execErr(sql)
						}
						return pgconn.NewCommandTag("UPDATE 1"), nil
					},
				}
				return tx, nil
			}}
			store := newForTest(db, newTestLogger(), nil)

			_, err := store.SetActivePolicyVersion(context.Background(), "org-a", "p1", 2)
			require.ErrorContains(t, err, tc.wantErr)
			require.True(t, tx.rolledBack, "activation is one transaction: any failure rolls back label + pointer")
		})
	}
}

func TestStore_SetPolicyAttachments_ForeignPolicyAndRowFailures(t *testing.T) {
	t.Run("foreign pipeline is not found", func(t *testing.T) {
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			return &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
				return &mockPGXRow{err: pgx.ErrNoRows}
			}}, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.SetPolicyAttachments(context.Background(), "org-a", "p1",
			[]PolicyAttachment{{ModelPattern: "*", Endpoint: "chat", Priority: 1}})
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("insert failure rolls back", func(t *testing.T) {
		var tx *policyTxDouble
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			tx = &policyTxDouble{
				queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
					if strings.Contains(sql, "FROM policy_pipelines") {
						return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
					}
					if strings.Contains(sql, "INSERT INTO policy_attachments") {
						return &mockPGXRow{err: errors.New("insert lost")}
					}
					return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
				},
			}
			return tx, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.SetPolicyAttachments(context.Background(), "org-a", "p1",
			[]PolicyAttachment{{ModelPattern: "*", Endpoint: "chat", Priority: 1}})
		require.ErrorContains(t, err, "create policy attachment")
		require.True(t, tx.rolledBack, "replace-all must not leave a cleared set behind")
	})
}

func TestStore_ListPolicyAttachments_RowFailuresPropagate(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	t.Run("foreign pipeline is not found", func(t *testing.T) {
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			return &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
				return &mockPGXRow{err: pgx.ErrNoRows}
			}}, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.ListPolicyAttachments(context.Background(), "org-a", "p1")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("scan failure", func(t *testing.T) {
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			return &policyTxDouble{
				queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
					return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
				},
				queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
					return &failingScanRows{
						mockPGXRows: &mockPGXRows{data: [][]interface{}{{"a1", "p1", "org-a", "", "*", "chat", 1, now}}},
						scanErr:     errors.New("scan failed"),
					}, nil
				},
			}, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.ListPolicyAttachments(context.Background(), "org-a", "p1")
		require.ErrorContains(t, err, "scan policy attachment")
	})
}

func TestStore_DeletePolicy_FailuresAreClean(t *testing.T) {
	t.Run("exec failure", func(t *testing.T) {
		var tx *policyTxDouble
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			tx = &policyTxDouble{execFn: func(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "DELETE FROM policy_pipelines") {
					return pgconn.NewCommandTag(""), errors.New("delete lost")
				}
				return pgconn.NewCommandTag("OK"), nil
			}}
			return tx, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		err := store.DeletePolicy(context.Background(), "org-a", "p1")
		require.ErrorContains(t, err, "delete policy pipeline")
		require.True(t, tx.rolledBack)
	})

	t.Run("zero rows is not found", func(t *testing.T) {
		var tx *policyTxDouble
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			tx = &policyTxDouble{}
			return tx, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		err := store.DeletePolicy(context.Background(), "org-a", "p1")
		require.ErrorIs(t, err, ErrNotFound)
		require.True(t, tx.committed, "the empty delete still commits its transaction")
	})
}

func TestStore_withPolicyTx_TransactionFailuresAreWrapped(t *testing.T) {
	t.Run("begin failure", func(t *testing.T) {
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			return nil, errors.New("pool exhausted")
		}}
		store := newForTest(db, newTestLogger(), nil)
		err := store.withPolicyTx(context.Background(), "org-a", func(auditTx) error { return nil })
		require.ErrorContains(t, err, "begin policy tx")
	})

	t.Run("GUC failure rolls back", func(t *testing.T) {
		var tx *policyTxDouble
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			tx = &policyTxDouble{execFn: func(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "set_config") {
					return pgconn.NewCommandTag(""), errors.New("GUC refused")
				}
				return pgconn.NewCommandTag("OK"), nil
			}}
			return tx, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		err := store.withPolicyTx(context.Background(), "org-a", func(auditTx) error { return nil })
		require.ErrorContains(t, err, "set policy isolation GUC")
		require.True(t, tx.rolledBack, "a tx without the isolation GUC must not proceed fail-open")
	})

	t.Run("commit failure", func(t *testing.T) {
		var tx *policyTxDouble
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			tx = &policyTxDouble{commitErr: errors.New("commit lost")}
			return tx, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		err := store.withPolicyTx(context.Background(), "org-a", func(auditTx) error { return nil })
		require.ErrorContains(t, err, "commit policy tx")
	})
}

func TestStore_LoadPolicySnapshot_PromptPinsQueryFailureRollsBack(t *testing.T) {
	tx := &policyTxDouble{queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
		if strings.Contains(sql, "FROM policy_prompt_pins") {
			return nil, errors.New("pins query failed")
		}
		if rows, ok := snapshotQueryRows(sql, &mockPGXRows{}, &mockPGXRows{}, &mockPGXRows{}, &mockPGXRows{}); ok {
			return rows, nil
		}
		return nil, errors.New("unexpected snapshot query: " + sql)
	}}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}, newTestLogger(), nil)

	snapshot, err := store.LoadPolicySnapshot(context.Background(), "org-a")
	require.ErrorContains(t, err, "snapshot list policy prompt pins")
	require.True(t, tx.rolledBack)
	require.False(t, tx.committed)
	require.Empty(t, snapshot.PromptPins)
}

func TestStore_CreatePolicy_GenericPipelineInsertFailureRollsBack(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			return &mockPGXRow{err: errors.New("pipeline write lost")}
		}}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, _, err := store.CreatePolicy(context.Background(), "org-a", "pii-guard", "yaml", "", "creator")
	require.ErrorContains(t, err, "create policy pipeline")
	require.NotErrorIs(t, err, ErrNotFound)
	require.True(t, tx.rolledBack)
}

func TestStore_createPolicyVersionTx_GenericInsertFailureIsWrappedNotRetryable(t *testing.T) {
	var tx *policyTxDouble
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		tx = &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			switch {
			case strings.Contains(sql, "FROM policy_pipelines"):
				return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
			case strings.Contains(sql, "INSERT INTO policy_versions"):
				return &mockPGXRow{err: errors.New("version write lost")}
			}
			return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
		}}
		return tx, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.CreatePolicyVersion(context.Background(), "org-a", "p1", "yaml", "", "creator")
	require.ErrorContains(t, err, "create policy version")
	require.NotContains(t, err.Error(), "concurrent policy update",
		"only the unique violation is the retryable signal")
	require.True(t, tx.rolledBack)
}

func TestStore_ListPolicyVersions_QueryFailurePropagates(t *testing.T) {
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return &policyTxDouble{
			queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
				return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
			},
			queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
				return nil, errors.New("versions read lost")
			},
		}, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.ListPolicyVersions(context.Background(), "org-a", "p1")
	require.ErrorContains(t, err, "list policy versions")
}

func TestStore_GetPolicyVersion_DBFailureIsWrappedNot404(t *testing.T) {
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			if strings.Contains(sql, "FROM policy_pipelines") {
				return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
			}
			return &mockPGXRow{err: errors.New("connection reset")}
		}}, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.GetPolicyVersion(context.Background(), "org-a", "p1", 1)
	require.ErrorContains(t, err, "get policy version")
	require.NotErrorIs(t, err, ErrNotFound, "infrastructure failures must not read as a missing version")
}

func TestStore_SetPolicyAttachments_ValidationWrapperAndClearFailure(t *testing.T) {
	t.Run("validation wrapper rejects before transaction", func(t *testing.T) {
		var txOpened bool
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			txOpened = true
			return nil, errors.New("must not open a transaction for invalid input")
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.SetPolicyAttachments(context.Background(), "org-a", "p1",
			[]PolicyAttachment{{Endpoint: "chat", Priority: 1}})
		require.ErrorContains(t, err, "attachment model_pattern is required")
		require.False(t, txOpened)
	})

	t.Run("clear failure rolls back", func(t *testing.T) {
		var tx *policyTxDouble
		db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
			tx = &policyTxDouble{
				queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
					if strings.Contains(sql, "FROM policy_pipelines") {
						return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
					}
					return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
				},
				execFn: func(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
					if strings.Contains(sql, "DELETE FROM policy_attachments") {
						return pgconn.NewCommandTag(""), errors.New("clear lost")
					}
					return pgconn.NewCommandTag("OK"), nil
				},
			}
			return tx, nil
		}}
		store := newForTest(db, newTestLogger(), nil)
		_, err := store.SetPolicyAttachments(context.Background(), "org-a", "p1",
			[]PolicyAttachment{{ModelPattern: "*", Endpoint: "chat", Priority: 1}})
		require.ErrorContains(t, err, "clear policy attachments")
		require.True(t, tx.rolledBack)
	})
}

func TestStore_ListPolicyAttachments_QueryFailurePropagates(t *testing.T) {
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return &policyTxDouble{
			queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
				return &mockPGXRow{data: [][]interface{}{policyPipelineReturnRow("p1", 1)}}
			},
			queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
				return nil, errors.New("attachments read lost")
			},
		}, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.ListPolicyAttachments(context.Background(), "org-a", "p1")
	require.ErrorContains(t, err, "list policy attachments")
}

func TestStore_UpdatePolicyCAS_LockedReadFailureIsWrappedNot409(t *testing.T) {
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			require.Contains(t, sql, "FOR UPDATE")
			return &mockPGXRow{err: errors.New("lock read lost")}
		}}, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	expect := 1
	_, _, err := store.UpdatePolicyCAS(context.Background(), "org-a", "p1",
		PolicyUpdate{Enabled: boolPtr(true)}, &expect, "admin@x.test")
	require.ErrorContains(t, err, "get policy pipeline (locked)")
	require.NotErrorIs(t, err, ErrPreconditionFailed,
		"a failed locked read is infrastructure, not a token mismatch")
}

func TestStore_ListPolicyVersions_PipelineProbeDBFailureIsWrapped(t *testing.T) {
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return &policyTxDouble{queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			return &mockPGXRow{err: errors.New("connection reset")}
		}}, nil
	}}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.ListPolicyVersions(context.Background(), "org-a", "p1")
	require.ErrorContains(t, err, "get policy pipeline")
	require.NotErrorIs(t, err, ErrNotFound, "infrastructure failures must not read as a missing row")
}

// fakePolicyRedis is the minimal PolicyVersionRedis double for the OP-8
// version-key contract (real Redis round-trips live in the integration
// suite; these tests lock the error translation).
type fakePolicyRedis struct {
	getVal string
	getErr error
	setErr error

	setKey string
	setVal string
	setTTL time.Duration
}

func (f *fakePolicyRedis) Get(context.Context, string) *redis.StringCmd {
	return redis.NewStringResult(f.getVal, f.getErr)
}

func (f *fakePolicyRedis) Set(_ context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd {
	f.setKey, f.setTTL = key, ttl
	if s, ok := value.(string); ok {
		f.setVal = s
	}
	return redis.NewStatusResult("OK", f.setErr)
}

func TestPolicyVersionCache_GetTranslatesMissAndErrors(t *testing.T) {
	t.Run("missing key is version 0, not an error", func(t *testing.T) {
		vc := NewPolicyVersionCache(&fakePolicyRedis{getVal: "", getErr: redis.Nil}, newTestLogger())
		v, err := vc.GetPolicyVersion(context.Background(), "org-a")
		require.NoError(t, err)
		require.Zero(t, v)
	})

	t.Run("redis failure is wrapped", func(t *testing.T) {
		vc := NewPolicyVersionCache(&fakePolicyRedis{getErr: errors.New("redis down")}, newTestLogger())
		_, err := vc.GetPolicyVersion(context.Background(), "org-a")
		require.ErrorContains(t, err, "read policy version")
	})

	t.Run("non-numeric value is a parse error", func(t *testing.T) {
		vc := NewPolicyVersionCache(&fakePolicyRedis{getVal: "not-a-number"}, newTestLogger())
		_, err := vc.GetPolicyVersion(context.Background(), "org-a")
		require.ErrorContains(t, err, `parse policy version "not-a-number"`)
	})
}

func TestPolicyVersionCache_SetWritesNamespacedNanosWithTTL(t *testing.T) {
	fake := &fakePolicyRedis{}
	vc := NewPolicyVersionCache(fake, newTestLogger())

	require.NoError(t, vc.SetPolicyVersion(context.Background(), "org-a", 12345))
	require.Equal(t, PolicyVersionKeyPrefix+"org-a", fake.setKey, "key is the documented prefix + org id")
	require.Equal(t, "12345", fake.setVal, "value is the decimal int64 contract")
	require.Equal(t, PolicyVersionTTL, fake.setTTL)

	fake.setErr = errors.New("redis down")
	err := vc.SetPolicyVersion(context.Background(), "org-a", 12345)
	require.ErrorContains(t, err, "write policy version")
}
