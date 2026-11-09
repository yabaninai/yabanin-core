package consumer

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestRollupDayChunks(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(36 * time.Hour)
	chunks := rollupDayChunks(from, to)
	require.Len(t, chunks, 2)
	require.Equal(t, from, chunks[0][0])
	require.Equal(t, from.Add(24*time.Hour), chunks[0][1])
	require.Equal(t, to, chunks[1][1])
}

func TestParseRollupBackfill(t *testing.T) {
	from, to, err := parseRollupBackfill("2026-09-01T00:00:00Z,2026-09-03T00:00:00Z")
	require.NoError(t, err)
	require.True(t, from.Before(to))
	_, _, err = parseRollupBackfill("nope")
	require.Error(t, err)
	_, _, err = parseRollupBackfill("2026-09-03T00:00:00Z,2026-09-01T00:00:00Z")
	require.Error(t, err)
}

type rollupFakeRow struct {
	val bool
	err error
}

func (r rollupFakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) == 1 {
		if p, ok := dest[0].(*bool); ok {
			*p = r.val
		}
	}
	return nil
}

type rollupFakeTx struct {
	lock      bool
	policies  bool
	execErr   error
	committed bool
	queryErr  error
}

func (f *rollupFakeTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	if f.execErr != nil {
		return pgconn.CommandTag{}, f.execErr
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (f *rollupFakeTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if f.queryErr != nil {
		return rollupFakeRow{err: f.queryErr}
	}
	if rollupContains(sql, "to_regclass") {
		return rollupFakeRow{val: f.policies}
	}
	return rollupFakeRow{val: f.lock}
}

func (f *rollupFakeTx) Commit(context.Context) error   { f.committed = true; return nil }
func (f *rollupFakeTx) Rollback(context.Context) error { return nil }

func rollupContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

type rollupFakeDB struct {
	tx  *rollupFakeTx
	err error
}

func (f rollupFakeDB) Begin(context.Context) (rollupTx, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tx, nil
}

func TestRefreshWindow_Paths(t *testing.T) {
	ctx := context.Background()
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	t.Run("skipped when lock is held", func(t *testing.T) {
		tx := &rollupFakeTx{lock: false}
		skipped, err := (&RollupRefresher{DB: rollupFakeDB{tx: tx}, Log: slog.Default()}).RefreshWindow(ctx, from, to)
		require.NoError(t, err)
		require.True(t, skipped)
		require.False(t, tx.committed)
	})
	t.Run("writes with default keys", func(t *testing.T) {
		tx := &rollupFakeTx{lock: true}
		skipped, err := (&RollupRefresher{DB: rollupFakeDB{tx: tx}, Region: "sg", Log: slog.Default()}).RefreshWindow(ctx, from, to)
		require.NoError(t, err)
		require.False(t, skipped)
		require.True(t, tx.committed)
	})
	t.Run("uses label policies when the table exists", func(t *testing.T) {
		tx := &rollupFakeTx{lock: true, policies: true}
		_, err := (&RollupRefresher{DB: rollupFakeDB{tx: tx}}).RefreshWindow(ctx, from, to)
		require.NoError(t, err)
		require.True(t, tx.committed)
	})
	t.Run("begin and exec errors", func(t *testing.T) {
		_, err := (&RollupRefresher{DB: rollupFakeDB{err: errors.New("down")}}).RefreshWindow(ctx, from, to)
		require.Error(t, err)
		tx := &rollupFakeTx{lock: true, execErr: errors.New("write")}
		_, err = (&RollupRefresher{DB: rollupFakeDB{tx: tx}}).RefreshWindow(ctx, from, to)
		require.Error(t, err)
		tx = &rollupFakeTx{queryErr: errors.New("lock")}
		_, err = (&RollupRefresher{DB: rollupFakeDB{tx: tx}}).RefreshWindow(ctx, from, to)
		require.Error(t, err)
	})
	t.Run("no database", func(t *testing.T) {
		_, err := (&RollupRefresher{}).RefreshWindow(ctx, from, to)
		require.Error(t, err)
	})
}

func TestBackfillAndSchedule(t *testing.T) {
	ctx := context.Background()
	tx := &rollupFakeTx{lock: true}
	ref := &RollupRefresher{DB: rollupFakeDB{tx: tx}, Now: func() time.Time {
		return time.Date(2026, 9, 2, 3, 17, 0, 0, time.UTC)
	}, Log: slog.Default(), Region: "sg"}
	require.NoError(t, ref.Backfill(ctx, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)))

	t.Setenv("YABANIN_ROLLUPS", "0")
	RunRollupSchedule(ctx, ref, nil)

	t.Setenv("YABANIN_ROLLUPS", "1")
	t.Setenv("YABANIN_ROLLUP_BACKFILL", "bad")
	done, cancel := context.WithCancel(ctx)
	cancel()
	RunRollupSchedule(done, ref, func() bool { return false })

	t.Setenv("YABANIN_ROLLUP_BACKFILL", "2026-09-01T00:00:00Z,2026-09-02T00:00:00Z")
	oldRecent, oldClock := rollupRecentEvery, rollupClockEvery
	rollupRecentEvery = time.Hour
	rollupClockEvery = 5 * time.Millisecond
	t.Cleanup(func() {
		rollupRecentEvery = oldRecent
		rollupClockEvery = oldClock
	})
	night, cancelNight := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancelNight()
	RunRollupSchedule(night, ref, func() bool { return true })
}
