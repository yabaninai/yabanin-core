package adminstore

// methods moved out of services/admin/handlers/resale_handlers.go — every
// harness. The two upsert variants are pinned apart: UpsertResalePricing
// (HTTP PUT) reactivates and refreshes the fixed rates on conflict, while
// CreateResalePricing (programmatic) refreshes only markup_pct/updated_at.
// NULL-model normalization (empty name → SQL NULL, the org-wide rule) is
// asserted against the physical row.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func f64Ptr(f float64) *float64 { return &f }

// TestSQLContractResalePricing covers UpsertResalePricing, CreateResalePricing,
// ListResalePricing, ListActiveResalePricing, ListOrgResalePricing,
// ListOrgResalePricingSummary, DeactivateResalePricing, GetResalePricing and
// GetResalePricingByID over insert, conflict-update, deactivate, missing-id
// and NULL-model branches.
func TestSQLContractResalePricing(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()

	org := fx.Token + "-resale-org" // reseller_pricing.org_id is plain text, no FK
	// The production schema allows only ONE active org-wide (NULL-model)
	// rule per org (uniq_reseller_pricing_org_nodel), so the empty-string
	// normalization branch gets its own org.
	orgEmpty := fx.Token + "-resale-org2"
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM reseller_pricing WHERE org_id LIKE $1`, fx.Token+"-resale-org%"); err != nil {
			t.Errorf("resale cleanup: %v", err)
		}
	})

	var modelRuleID, wideRuleID, progRuleID int64

	// HTTP upsert: insert, then conflict-update keeps the row id.
	contract(t, "UpsertResalePricing[insert]", func(ctx context.Context) error {
		id, err := store.UpsertResalePricing(ctx, org, strPtr(fx.Token+"-gpt-x"), 12.5, f64Ptr(1.5), nil)
		if err != nil {
			return err
		}
		if id <= 0 {
			t.Errorf("UpsertResalePricing insert: expected a row id, got %d", id)
		}
		modelRuleID = id
		return nil
	})
	contract(t, "UpsertResalePricing[conflict]", func(ctx context.Context) error {
		id, err := store.UpsertResalePricing(ctx, org, strPtr(fx.Token+"-gpt-x"), 20.0, nil, f64Ptr(2.5))
		if err != nil {
			return err
		}
		if id != modelRuleID {
			t.Errorf("UpsertResalePricing conflict: expected the same row %d, got %d", modelRuleID, id)
		}
		return nil
	})
	contract(t, "GetResalePricing[after-conflict]", func(ctx context.Context) error {
		pr, err := store.GetResalePricing(ctx, modelRuleID)
		if err != nil {
			return err
		}
		if pr.MarkupPct != 20.0 || !pr.Active || pr.FixedInputPerM != nil || pr.FixedOutputPerM == nil || *pr.FixedOutputPerM != 2.5 {
			t.Errorf("GetResalePricing: unexpected refreshed row %+v", pr)
		}
		if pr.CreatedAt.IsZero() || pr.UpdatedAt.IsZero() {
			t.Errorf("GetResalePricing: timestamps must be populated, got %+v", pr)
		}
		return nil
	})

	// Org-wide rule: nil and empty model names both store SQL NULL; the
	// empty-string branch lives on its own org (one active NULL-model rule
	// per org, uniq_reseller_pricing_org_nodel).
	contract(t, "UpsertResalePricing[null-model]", func(ctx context.Context) error {
		id, err := store.UpsertResalePricing(ctx, org, nil, 7.0, nil, nil)
		if err != nil {
			return err
		}
		wideRuleID = id
		return nil
	})
	contract(t, "UpsertResalePricing[empty-model]", func(ctx context.Context) error {
		_, err := store.UpsertResalePricing(ctx, orgEmpty, strPtr(""), 7.5, nil, nil)
		return err
	})
	var nullModels, nullModelsEmpty int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM reseller_pricing WHERE org_id = $1 AND model_name IS NULL`,
		org).Scan(&nullModels))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM reseller_pricing WHERE org_id = $1 AND model_name IS NULL`,
		orgEmpty).Scan(&nullModelsEmpty))
	assert.Equal(t, 1, nullModels, "a nil model name must land as SQL NULL")
	assert.Equal(t, 1, nullModelsEmpty, "an empty model name must land as SQL NULL")
	contract(t, "GetResalePricing[null-model]", func(ctx context.Context) error {
		pr, err := store.GetResalePricing(ctx, wideRuleID)
		if err != nil {
			return err
		}
		if pr.ModelName != nil {
			t.Errorf("GetResalePricing: expected NULL model_name, got %q", *pr.ModelName)
		}
		return nil
	})

	// Deactivate: first call finds the active row, the second does not.
	contract(t, "DeactivateResalePricing[hit]", func(ctx context.Context) error {
		found, err := store.DeactivateResalePricing(ctx, modelRuleID)
		if err != nil {
			return err
		}
		if !found {
			t.Errorf("DeactivateResalePricing: expected the active row to deactivate")
		}
		return nil
	})
	contract(t, "DeactivateResalePricing[miss]", func(ctx context.Context) error {
		found, err := store.DeactivateResalePricing(ctx, modelRuleID)
		if err != nil {
			return err
		}
		if found {
			t.Errorf("DeactivateResalePricing: an inactive row must not deactivate again")
		}
		return nil
	})

	// Missing ids are business answers (HTTP 404), not SQL rejections.
	contract(t, "GetResalePricing[missing]", func(ctx context.Context) error {
		_, err := store.GetResalePricing(ctx, 999999999)
		switch err {
		case nil:
			t.Errorf("GetResalePricing: expected ErrNoRows for a missing id")
		default:
			require.ErrorIs(t, err, pgx.ErrNoRows)
		}
		return nil
	})

	// Programmatic create: on conflict only markup_pct/updated_at move —
	// the deactivated row must NOT come back active and fixed rates stay.
	contract(t, "CreateResalePricing[insert]", func(ctx context.Context) error {
		id, err := store.CreateResalePricing(ctx, org, strPtr(fx.Token+"-prog-model"), 9.0, f64Ptr(0.5), f64Ptr(0.6))
		if err != nil {
			return err
		}
		progRuleID = id
		return nil
	})
	contract(t, "CreateResalePricing[deactivate-then-conflict]", func(ctx context.Context) error {
		if _, err := store.DeactivateResalePricing(ctx, progRuleID); err != nil {
			return err
		}
		id, err := store.CreateResalePricing(ctx, org, strPtr(fx.Token+"-prog-model"), 11.0, f64Ptr(9.9), f64Ptr(9.9))
		if err != nil {
			return err
		}
		if id != progRuleID {
			t.Errorf("CreateResalePricing conflict: expected the same row %d, got %d", progRuleID, id)
		}
		pr, found, err := store.GetResalePricingByID(ctx, progRuleID)
		if err != nil {
			return err
		}
		if !found {
			t.Errorf("GetResalePricingByID: the conflicted row must exist")
			return nil
		}
		if pr.Active {
			t.Errorf("CreateResalePricing: programmatic conflict must not reactivate the row")
		}
		if pr.MarkupPct != 11.0 || pr.FixedInputPerM == nil || *pr.FixedInputPerM != 0.5 {
			t.Errorf("CreateResalePricing: markup must refresh and fixed rates stay, got %+v", pr)
		}
		return nil
	})

	// List surfaces: full list carries inactive rows, the active list does
	// not, and the org-scoped lists answer only for their org.
	contract(t, "ListResalePricing", func(ctx context.Context) error {
		items, err := store.ListResalePricing(ctx)
		if err != nil {
			return err
		}
		seen := map[int64]ResalePricing{}
		for _, pr := range items {
			if pr.OrgID != nil && *pr.OrgID == org {
				seen[pr.ID] = pr
			}
		}
		if _, ok := seen[modelRuleID]; !ok {
			t.Errorf("ListResalePricing: inactive row %d must still be listed", modelRuleID)
		}
		if _, ok := seen[wideRuleID]; !ok {
			t.Errorf("ListResalePricing: org-wide row %d must be listed", wideRuleID)
		}
		if len(seen) < 3 {
			t.Errorf("ListResalePricing: expected at least 3 rows for %s, got %d", org, len(seen))
		}
		return nil
	})
	contract(t, "ListActiveResalePricing", func(ctx context.Context) error {
		items, err := store.ListActiveResalePricing(ctx)
		if err != nil {
			return err
		}
		lastID := int64(0)
		for _, pr := range items {
			if !pr.Active {
				t.Errorf("ListActiveResalePricing: inactive row %d leaked", pr.ID)
			}
			if pr.ID < lastID {
				t.Errorf("ListActiveResalePricing: ids must ascend, %d after %d", pr.ID, lastID)
			}
			lastID = pr.ID
			if pr.ID == modelRuleID || pr.ID == progRuleID {
				t.Errorf("ListActiveResalePricing: deactivated rows %d/%d must not be listed", modelRuleID, progRuleID)
			}
		}
		return nil
	})
	contract(t, "ListOrgResalePricing", func(ctx context.Context) error {
		items, err := store.ListOrgResalePricing(ctx, org)
		if err != nil {
			return err
		}
		if len(items) < 3 {
			t.Errorf("ListOrgResalePricing: expected >=3 rows, got %d", len(items))
		}
		for _, pr := range items {
			if pr.CreatedAt.IsZero() {
				t.Errorf("ListOrgResalePricing: full projection must carry timestamps, got %+v", pr)
			}
		}
		return nil
	})
	contract(t, "ListOrgResalePricing[unknown-org]", func(ctx context.Context) error {
		items, err := store.ListOrgResalePricing(ctx, fx.Token+"-no-such-org")
		if err != nil {
			return err
		}
		if len(items) != 0 {
			t.Errorf("ListOrgResalePricing: unknown org must answer empty, got %d rows", len(items))
		}
		return nil
	})
	contract(t, "ListOrgResalePricingSummary", func(ctx context.Context) error {
		items, err := store.ListOrgResalePricingSummary(ctx, org)
		if err != nil {
			return err
		}
		if len(items) < 3 {
			t.Errorf("ListOrgResalePricingSummary: expected >=3 rows, got %d", len(items))
		}
		return nil
	})

	// The programmatic summary get answers found=false together with the
	// ErrNoRows error for a missing id (original helper contract).
	contract(t, "GetResalePricingByID[missing]", func(ctx context.Context) error {
		pr, found, err := store.GetResalePricingByID(ctx, 999999999)
		if err == nil {
			t.Errorf("GetResalePricingByID: expected ErrNoRows for a missing id")
		} else if found || pr != nil {
			t.Errorf("GetResalePricingByID: expected (nil, false, err) for a missing id, got (%v, %v, %v)", pr, found, err)
		} else {
			require.ErrorIs(t, err, pgx.ErrNoRows)
		}
		return nil
	})
}
