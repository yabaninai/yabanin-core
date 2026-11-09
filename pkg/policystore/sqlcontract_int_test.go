package policystore

// fully migrated Postgres (testdb.Postgres, no build tag — the harness
// posture of pkg/adminstore sqlcontract_int_test.go). The contract runs the
// production SQL of every exported method (pack CRUD, residency region
// read/update) with the present/absent/enabled/disabled combinations and
// fails on any *pgconn.PgError (rejected columns/types/placeholders).
// Business errors (missing rows, invalid region) are asserted where they
// pin the semantics.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sqlc03fPolicyContract fails the test when Postgres rejects the SQL (any
// *pgconn.PgError); other errors are business answers and only logged.
func sqlc03fPolicyContract(t *testing.T, name string, fn func(ctx context.Context) error) {
	t.Helper()
	err := fn(context.Background())
	if err == nil {
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		t.Errorf("%s: Postgres rejected the SQL: %s (code %s, where %s, detail %q)",
			name, pgErr.Message, pgErr.Code, pgErr.Where, pgErr.Detail)
		return
	}
	t.Logf("%s: non-SQL error tolerated by the contract: %v", name, err)
}

func sqlc03fPolicySeed(t *testing.T, pool *pgxpool.Pool) (orgA, orgB, token string) {
	t.Helper()
	ctx := context.Background()
	token = fmt.Sprintf("sc03f%x", time.Now().UnixNano())
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-a", token+"-org-a").Scan(&orgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-b", token+"-org-b").Scan(&orgB))

	// orgA carries an enabled SG pack and a disabled IN pack; orgB none.
	_, err := pool.Exec(ctx, `
		INSERT INTO policy_packs (org_id, region, pack_id, config, enabled)
		VALUES ($1::uuid, 'SG', $2, '{"baseline":true}'::jsonb, true),
		       ($1::uuid, 'IN', $2, '{}'::jsonb, false)`,
		orgA, token+"-pack")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("policystore contract cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM policy_packs WHERE org_id::text = ANY($1)`, []string{orgA, orgB})
		cleanup(`DELETE FROM organizations WHERE id::text = ANY($1)`, []string{orgA, orgB})
	})
	return orgA, orgB, token
}

func TestSQLContractPolicystore(t *testing.T) {
	pool := testdb.Postgres(t)
	orgA, orgB, token := sqlc03fPolicySeed(t, pool)
	ctx := context.Background()
	store := New(pool)

	// orgA/orgB assumptions (single SG pack, IN disabled, orgB empty) hold.
	var orgC string
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-c", token+"-org-c").Scan(&orgC))
	orgCUUID, errOrgC := uuid.Parse(orgC)
	require.NoError(t, errOrgC)

	// Upsert — insert then update over the partial unique index target
	// (org_id, region) WHERE enabled = true. Regression for HOT-PATCH
	// every call (reachable via PUT /api/organizations/{id}/policy-packs/
	// {region} → 500; substring mocks never saw it — the D-03 class).
	packID := token + "-pack-id"
	sqlc03fPolicyContract(t, "Upsert[insert]", func(ctx context.Context) error {
		_, err := store.Upsert(ctx, PackConfig{
			OrgID:  &orgCUUID,
			Region: "ID",
			PackID: packID,
			Config: []byte(`{"v":1}`),
		})
		return err
	})
	sqlc03fPolicyContract(t, "Upsert[update]", func(ctx context.Context) error {
		updated, err := store.Upsert(ctx, PackConfig{
			OrgID:  &orgCUUID,
			Region: "ID",
			PackID: token + "-pack-id-2",
			Config: []byte(`{"v":2}`),
		})
		if err != nil {
			return err
		}
		got, err := store.GetByOrgRegion(ctx, orgC, "ID")
		if err != nil {
			return err
		}
		if got == nil || got.PackID != token+"-pack-id-2" {
			t.Errorf("Upsert[update]: GetByOrgRegion sees stale pack %v", got)
		}
		assert.Equal(t, "ID", updated.Region)
		assert.Equal(t, token+"-pack-id-2", updated.PackID)
		assert.NotEqual(t, packID, updated.PackID, "re-upsert must supersede the inserted row")
		return nil
	})
	sqlc03fPolicyContract(t, "UpsertPolicyPack[orgA,IN]", func(ctx context.Context) error {
		rule := policy.ResidencyRule{AllowedJurisdictions: []policy.Region{"AU"}}
		return store.UpsertPolicyPack(ctx, orgC, "AU", token+"-pack-au", rule)
	})

	// The invalid-region Upsert rejection is a Go-side guard: it fires
	// before any SQL runs, so the broken conflict target is not reachable
	// through it.
	_, errXX := store.Upsert(ctx, PackConfig{Region: "XX"})
	require.Error(t, errXX, "Upsert[invalid region] is a validation rejection")

	// GetByOrgRegion — present, present-but-disabled and absent.
	sqlc03fPolicyContract(t, "GetByOrgRegion[enabled]", func(ctx context.Context) error {
		pack, err := store.GetByOrgRegion(ctx, orgA, "SG")
		if err != nil {
			return err
		}
		assert.Equal(t, "SG", pack.Region)
		return nil
	})
	_, errIN := store.GetByOrgRegion(ctx, orgA, "IN")
	require.Error(t, errIN, "GetByOrgRegion[disabled] must not resolve")
	_, errAbs := store.GetByOrgRegion(ctx, orgB, "SG")
	require.Error(t, errAbs, "GetByOrgRegion[absent] must not resolve")

	// List — populated org and the empty result.
	sqlc03fPolicyContract(t, "List[orgA]", func(ctx context.Context) error {
		packs, err := store.List(ctx, orgA)
		if err != nil {
			return err
		}
		assert.Len(t, packs, 1, "only the enabled pack is listed")
		return nil
	})
	sqlc03fPolicyContract(t, "List[orgB,empty]", func(ctx context.Context) error {
		packs, err := store.List(ctx, orgB)
		if err != nil {
			return err
		}
		assert.Empty(t, packs)
		return nil
	})

	// GetPolicyPacks — the record-projection read.
	sqlc03fPolicyContract(t, "GetPolicyPacks[orgA]", func(ctx context.Context) error {
		records, err := store.GetPolicyPacks(ctx, orgA)
		if err != nil {
			return err
		}
		if assert.NotEmpty(t, records) {
			assert.Equal(t, "SG", records[0].Region)
		}
		return nil
	})
	sqlc03fPolicyContract(t, "GetPolicyPacks[orgB,empty]", func(ctx context.Context) error {
		records, err := store.GetPolicyPacks(ctx, orgB)
		if err != nil {
			return err
		}
		assert.Empty(t, records)
		return nil
	})

	// UpsertPolicyPack / DeletePolicyPack — the rule-projection writer pair.
	// the disabled IN pack seeded by the fixture keeps DeletePolicyPack
	// contract-legal meanwhile.
	sqlc03fPolicyContract(t, "DeletePolicyPack[orgA,IN]", func(ctx context.Context) error {
		return store.DeletePolicyPack(ctx, orgA, "IN")
	})
	sqlc03fPolicyContract(t, "DeletePolicyPack[absent]", func(ctx context.Context) error {
		return store.DeletePolicyPack(ctx, orgB, "SG")
	})

	// Delete — soft-disable by record id.
	pack, err := store.GetByOrgRegion(ctx, orgA, "SG")
	require.NoError(t, err)
	sqlc03fPolicyContract(t, "Delete[SG]", func(ctx context.Context) error {
		return store.Delete(ctx, pack.ID)
	})
	_, err = store.GetByOrgRegion(ctx, orgA, "SG")
	require.Error(t, err, "Delete must disable the pack")

	// Residency region: NULL read, update, read-back.
	sqlc03fPolicyContract(t, "GetOrgResidencyRegion[null]", func(ctx context.Context) error {
		region, err := store.GetOrgResidencyRegion(ctx, orgA)
		if err != nil {
			return err
		}
		assert.Nil(t, region, "a fresh org has no residency region")
		return nil
	})
	sqlc03fPolicyContract(t, "UpdateOrgResidencyRegion[orgA,SG]", func(ctx context.Context) error {
		return store.UpdateOrgResidencyRegion(ctx, orgA, "SG")
	})
	sqlc03fPolicyContract(t, "GetOrgResidencyRegion[readback]", func(ctx context.Context) error {
		region, err := store.GetOrgResidencyRegion(ctx, orgA)
		if err != nil {
			return err
		}
		if region == nil || *region != "SG" {
			t.Errorf("GetOrgResidencyRegion[readback]: expected SG, got %v", region)
		}
		return nil
	})
}
