package adminstore

// Unit tests for the small pure helpers the admin API leans on (validators,
// error rendering, context carry): no DB, every branch pinned. Coverage
// floors ratchet per package — these helpers had no unit coverage at all.

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestValidGraceFloorCents(t *testing.T) {
	require.True(t, ValidGraceFloorCents(GraceFloorMinCents), "the minimum bound is settable")
	require.True(t, ValidGraceFloorCents(-1), "an ordinary overdraft floor is settable")
	require.True(t, ValidGraceFloorCents(GraceFloorMaxCents), "explicit 0 (no overdraft) is settable — AF-01")
	require.False(t, ValidGraceFloorCents(GraceFloorMinCents-1), "below the range is rejected")
	require.False(t, ValidGraceFloorCents(1), "positive floors are rejected")
}

func TestAnalyticsQueryErrorRendering(t *testing.T) {
	require.Equal(t, "invalid_filter: unknown dimension at position 12",
		(&AnalyticsQueryError{Code: "invalid_filter", Msg: "unknown dimension", Pos: 12, HasPos: true}).Error())
	require.Equal(t, "invalid_filter", (&AnalyticsQueryError{Code: "invalid_filter"}).Error(),
		"an empty message renders the bare code")
	require.Equal(t, "invalid_filter: unknown dimension",
		(&AnalyticsQueryError{Code: "invalid_filter", Msg: "unknown dimension"}).Error())
}

func TestMapAnalyticsTimeout(t *testing.T) {
	require.NoError(t, mapAnalyticsTimeout(nil))

	pgCanceled := &pgconn.PgError{Code: "57014"} // query_canceled → statement timeout
	require.ErrorIs(t, mapAnalyticsTimeout(pgCanceled), ErrAnalyticsTimeout)

	pgOther := &pgconn.PgError{Code: "42P01"}
	require.Same(t, error(pgOther), mapAnalyticsTimeout(pgOther), "other PG errors pass through")

	plain := errors.New("connection refused")
	require.Same(t, plain, mapAnalyticsTimeout(plain))
}

func TestPolicyUpdateEmpty(t *testing.T) {
	require.True(t, PolicyUpdate{}.Empty(), "no field set — nothing to update")
	attachments := []PolicyAttachment{{KeyLabel: "prod-key", Priority: 1}}
	for name, u := range map[string]PolicyUpdate{
		"yaml":        {YAML: new(string)},
		"git sha":     {GitSHA: new(string)},
		"enabled":     {Enabled: new(bool)},
		"version":     {ActiveVersion: new(int)},
		"attachments": {Attachments: &attachments},
	} {
		require.False(t, u.Empty(), name+" set — the update carries a field")
	}
}

func TestRequestPayloadContextCarry(t *testing.T) {
	ctx := context.Background()

	_, ok := RequestPayloadSubjectFromContext(ctx)
	require.False(t, ok, "no subject marked")

	subject := RequestPayloadSubject{Type: "agent", AgentID: "agent-1"}
	ctx = WithRequestPayloadSubject(ctx, subject)
	got, ok := RequestPayloadSubjectFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, subject, got)

	_, ok = RequestPayloadAccessFromContext(ctx)
	require.False(t, ok, "no access decision marked")

	access := RequestPayloadAccess{UserID: "u-1", Grant: true, SubjectType: "human"}
	ctx = WithRequestPayloadAccess(ctx, access)
	gotAccess, ok := RequestPayloadAccessFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, access, gotAccess)
}

// TestStoreUnitGuards_NoDB: a Store without a database must fail closed on
// every surface (the same convention as TestCanaryStore_UnitGuards) — never
// a fabricated success.
func TestStoreUnitGuards_NoDB(t *testing.T) {
	s := &Store{}
	ctx := context.Background()

	if _, err := s.GetAdminUserSessionsInvalidatedAt(ctx, "u-1"); err == nil {
		t.Fatal("no db must fail closed")
	}
	if _, err := s.ListKeyRateLimits(ctx); err == nil {
		t.Fatal("no db must fail closed")
	}
	if _, err := s.GetOrgOnboarding(ctx, "00000000-0000-0000-0000-000000000001"); err == nil {
		t.Fatal("no db must fail closed")
	}
	if err := s.UpsertOrgOnboarding(ctx, "00000000-0000-0000-0000-000000000001", true, false); err == nil {
		t.Fatal("no db must fail closed")
	}
}

// TestUpdateMCPUserOAuthTokens_UnitGuards: the upsert path validates kind,
// agent key and secret BEFORE any database round trip, so a caller cannot
// persist half-rotated token material.
func TestUpdateMCPUserOAuthTokens_UnitGuards(t *testing.T) {
	s := &Store{}
	ctx := context.Background()

	if _, err := s.UpdateMCPUserOAuthTokens(ctx, "org", "srv", "", "tok", nil); err == nil {
		t.Fatal("an empty agent key id must be refused")
	}
	if _, err := s.UpdateMCPUserOAuthTokens(ctx, "org", "srv", "key-1", "", nil); err == nil {
		t.Fatal("an empty secret must be refused")
	}
}

// recordingScanner captures Scan destinations so the test can pin the row
// column order — the contract every mcp credential query relies on.
type recordingScanner struct{ dests []any }

func (r *recordingScanner) Scan(dest ...any) error {
	r.dests = dest
	return errors.New("stop after recording")
}

func TestScanMCPCredentialColumnOrder(t *testing.T) {
	server := &MCPServerCredential{}
	rec := &recordingScanner{}
	if err := scanMCPServerCredential(rec, server); err == nil {
		t.Fatal("the stub always stops the scan")
	}
	// The SELECT list order (mcpServerCredColumns) and the scan order must
	// stay in lockstep — a silent reorder would scramble credentials.
	require.Len(t, rec.dests, 11)
	for i, d := range rec.dests {
		require.NotNil(t, d, "server column %d must have a destination", i)
	}

	user := &MCPUserCredential{}
	rec2 := &recordingScanner{}
	if err := scanMCPUserCredential(rec2, user); err == nil {
		t.Fatal("the stub always stops the scan")
	}
	require.Len(t, rec2.dests, 13, "user credential rows carry 13 columns")
	for i, d := range rec2.dests {
		require.NotNil(t, d, "user column %d must have a destination", i)
	}
}
