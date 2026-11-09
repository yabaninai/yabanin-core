package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAliasLookup_ExactPrefixAndLongest(t *testing.T) {
	book := NewAliasBook(time.Hour, func(context.Context) (map[string]string, error) {
		return map[string]string{
			"claude-sonnet-4-6": "qwen-coder",
			"claude-haiku-*":    "qwen-small",
			"claude-*":          "qwen-any",
		}, nil
	}, nil)

	target, err := book.Lookup(context.Background(), "claude-sonnet-4-6")
	require.NoError(t, err)
	assert.Equal(t, "qwen-coder", target)

	target, err = book.Lookup(context.Background(), "claude-haiku-4-5")
	require.NoError(t, err)
	assert.Equal(t, "qwen-small", target)

	target, err = book.Lookup(context.Background(), "claude-opus-4")
	require.NoError(t, err)
	assert.Equal(t, "qwen-any", target)

	// A loaded book answers "not an alias" authoritatively (no error).
	_, err = book.Lookup(context.Background(), "gpt-4o")
	require.NoError(t, err)
}

func TestResolve_AliasRewritesBeforeLookup(t *testing.T) {
	ctx := context.Background()
	pool := &mockPool{rows: map[string][]any{
		"qwen-coder": {"qwen-coder", "Qwen", "standard", "http://local", "", "vllm", nil, true, int64(0), "GLOBAL"},
		"off":        {"off", "Off", "standard", "", "", "", nil, false, int64(0), "GLOBAL"},
	}}
	r := NewResolver(pool, "fb-model", time.Minute, nil)
	r.UseAliases(NewAliasBook(time.Hour, func(context.Context) (map[string]string, error) {
		return map[string]string{
			"claude-sonnet-4-6": "qwen-coder",
			"claude-haiku-*":    "off",
		}, nil
	}, nil))

	got := r.Resolve(ctx, "claude-sonnet-4-6")
	assert.Equal(t, "qwen-coder", got.ModelName)
	assert.Equal(t, "claude-sonnet-4-6", got.Alias)
	assert.False(t, got.Fallback)

	got = r.Resolve(ctx, "claude-haiku-9")
	assert.True(t, got.Fallback, "alias to a disabled model is an unknown model")
	assert.Equal(t, "fb-model", got.ModelName)
	assert.Equal(t, "claude-haiku-9", got.Alias)

	direct := r.Resolve(ctx, "qwen-coder")
	assert.Empty(t, direct.Alias)
}

func TestQueryAliasesAndReloadFailure(t *testing.T) {
	db := &fakeAliasDB{pairs: [][2]string{{"claude-sonnet-4-6", "qwen-coder"}}}
	got, err := QueryAliases(context.Background(), db)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"claude-sonnet-4-6": "qwen-coder"}, got)

	db.scanErr = assert.AnError
	_, err = QueryAliases(context.Background(), db)
	require.Error(t, err)

	calls := 0
	book := NewAliasBook(0, func(context.Context) (map[string]string, error) {
		calls++
		if calls == 1 {
			return map[string]string{"kept": "target"}, nil
		}
		return nil, assert.AnError
	}, nil)
	target, err := book.Lookup(context.Background(), "kept")
	require.NoError(t, err)
	assert.Equal(t, "target", target)
	// Force the expired-snapshot path the way the pre-RT-06 test forced
	// `loaded = time.Time{}`: keep the maps, zero the timestamp.
	if cur := book.snap.Load(); cur != nil {
		book.snap.Store(&aliasSnapshot{exact: cur.exact, prefixes: cur.prefixes})
	}
	// Failed refresh with an existing snapshot: the stale snapshot keeps
	// serving and stays authoritative (stale-while-error, RT-06).
	target, err = book.Lookup(context.Background(), "kept")
	require.NoError(t, err)
	assert.Equal(t, "target", target)

	var resolver *Resolver
	resolver.UseAliases(book)
	assert.False(t, (*AliasBook)(nil).lookupNothing())
}

func (b *AliasBook) lookupNothing() bool {
	_, err := b.Lookup(context.Background(), "")
	return err != nil
}

type fakeAliasDB struct {
	pairs    [][2]string
	scanErr  error
	queryErr error
}

func (f *fakeAliasDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return &fakeAliasRows{pairs: f.pairs, scanErr: f.scanErr}, nil
}

type fakeAliasRows struct {
	pairs   [][2]string
	i       int
	scanErr error
}

func (r *fakeAliasRows) Close()                                       {}
func (r *fakeAliasRows) Err() error                                   { return nil }
func (r *fakeAliasRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *fakeAliasRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeAliasRows) Next() bool {
	if r.scanErr != nil {
		return r.i == 0
	}
	return r.i < len(r.pairs)
}
func (r *fakeAliasRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	pair := r.pairs[r.i]
	r.i++
	*(dest[0].(*string)) = pair[0]
	*(dest[1].(*string)) = pair[1]
	return nil
}
func (r *fakeAliasRows) Values() ([]any, error) { return nil, nil }
func (r *fakeAliasRows) RawValues() [][]byte    { return nil }
func (r *fakeAliasRows) Conn() *pgx.Conn        { return nil }

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *fakeAliasRows) TypeMap() *pgtype.Map { return nil }
