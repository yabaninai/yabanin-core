package adminstore

// methods moved out of services/admin/handlers/sovereign_handlers.go —
// ListSovereignModels (the country/cn_flagged filter and ordering),
// SetSovereignModelEnabled and the org_sovereignty_policy get/upsert pair,
// carry non-NULL country/jurisdiction/vendor_hq, mirroring production
// sovereign seeds (the projection scans into plain strings).

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestSQLContractSovereign(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()

	cnModel := fx.Token + "-sov-cn"
	inModel := fx.Token + "-sov-in"
	controlModel := fx.Token + "-sov-control"

	// Seed: one CN-flagged model, one IN model (both listed) and a control
	// row without country and without the CN flag (not listed).
	for _, m := range []struct {
		name, country, jurisdiction, soTier, vendorHQ string
		cnFlagged                                     bool
	}{
		{cnModel, "CN", "CN", "full", "HQ-CN", true},
		{inModel, "IN", "IN", "partial", "HQ-IN", false},
		{controlModel, "", "", "foreign", "", false},
	} {
		var country, jurisdiction, vendorHQ any
		if m.country != "" {
			country = m.country
		}
		if m.jurisdiction != "" {
			jurisdiction = m.jurisdiction
		}
		if m.vendorHQ != "" {
			vendorHQ = m.vendorHQ
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO models_registry (model_name, display_name, tier, provider, country, jurisdiction, sovereignty_tier, vendor_hq, cn_flagged)
			VALUES ($1, $1, 'smart', 'openai-compat', $2, $3, $4, $5, $6)`,
			m.name, country, jurisdiction, m.soTier, vendorHQ, m.cnFlagged)
		require.NoError(t, err, "seed model %s", m.name)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM models_registry WHERE model_name LIKE $1`, fx.Token+"-sov-%"); err != nil {
			t.Errorf("sovereign model cleanup: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM org_sovereignty_policy WHERE org_id = $1`, fx.OrgA); err != nil {
			t.Errorf("sovereignty policy cleanup: %v", err)
		}
	})

	// The list returns only country/CN-flagged models, ordered by country
	// then model name, with every field round-tripping.
	contract(t, "ListSovereignModels", func(ctx context.Context) error {
		models, err := store.ListSovereignModels(ctx)
		if err != nil {
			return err
		}
		byName := map[string]SovereignModel{}
		for _, m := range models {
			byName[m.Name] = m
		}
		for _, name := range []string{cnModel, inModel} {
			if _, ok := byName[name]; !ok {
				t.Errorf("ListSovereignModels: seeded model %s must be listed", name)
			}
		}
		if _, ok := byName[controlModel]; ok {
			t.Errorf("ListSovereignModels: control row without country/CN flag must not be listed")
		}
		if m := byName[cnModel]; m.Name != "" {
			if !m.CNFlag || !m.Enabled || m.Country != "CN" || m.Juris != "CN" || m.SoTier != "full" || m.VendorHQ != "HQ-CN" || m.Display != cnModel {
				t.Errorf("ListSovereignModels: CN row round-trip mismatch: %+v", m)
			}
		}
		if m := byName[inModel]; m.Name != "" {
			if m.CNFlag || m.Country != "IN" || m.SoTier != "partial" {
				t.Errorf("ListSovereignModels: IN row round-trip mismatch: %+v", m)
			}
		}
		// Ordering: country ascending, then model name.
		lastCountry, lastName := "", ""
		for _, m := range models {
			if m.Country < lastCountry || (m.Country == lastCountry && m.Name < lastName) {
				t.Errorf("ListSovereignModels: ordering violated at %s/%s after %s/%s", m.Country, m.Name, lastCountry, lastName)
			}
			lastCountry, lastName = m.Country, m.Name
		}
		return nil
	})

	// Toggle: the flip is visible in the list projection (no enabled filter).
	contract(t, "SetSovereignModelEnabled", func(ctx context.Context) error {
		if err := store.SetSovereignModelEnabled(ctx, inModel, false); err != nil {
			return err
		}
		models, err := store.ListSovereignModels(ctx)
		if err != nil {
			return err
		}
		for _, m := range models {
			if m.Name == inModel && m.Enabled {
				t.Errorf("SetSovereignModelEnabled: %s must read back disabled", inModel)
			}
		}
		var enabled bool
		if err := pool.QueryRow(ctx,
			`SELECT enabled FROM models_registry WHERE model_name = $1`, inModel).Scan(&enabled); err != nil {
			return err
		}
		if enabled {
			t.Errorf("SetSovereignModelEnabled: physical row for %s must be disabled", inModel)
		}
		return store.SetSovereignModelEnabled(ctx, inModel, true)
	})

	// Policy get/upsert pair, including the conflict-update branch.
	contract(t, "UpsertOrgSovereigntyPolicy[insert]", func(ctx context.Context) error {
		return store.UpsertOrgSovereigntyPolicy(ctx, fx.OrgA, &OrgSovereigntyPolicy{
			RequiredTier:      "full",
			ExcludedCountries: []string{"US", "CN"},
			BuyerJurisdiction: "EU",
			CNAllowed:         true,
		})
	})
	contract(t, "GetOrgSovereigntyPolicy[inserted]", func(ctx context.Context) error {
		p, err := store.GetOrgSovereigntyPolicy(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		if p.RequiredTier != "full" || p.BuyerJurisdiction != "EU" || !p.CNAllowed ||
			len(p.ExcludedCountries) != 2 || p.ExcludedCountries[0] != "US" || p.ExcludedCountries[1] != "CN" {
			t.Errorf("GetOrgSovereigntyPolicy: round-trip mismatch: %+v", p)
		}
		return nil
	})
	contract(t, "UpsertOrgSovereigntyPolicy[conflict]", func(ctx context.Context) error {
		return store.UpsertOrgSovereigntyPolicy(ctx, fx.OrgA, &OrgSovereigntyPolicy{
			RequiredTier:      "partial",
			ExcludedCountries: []string{},
			BuyerJurisdiction: "IN",
			CNAllowed:         false,
		})
	})
	contract(t, "GetOrgSovereigntyPolicy[updated]", func(ctx context.Context) error {
		p, err := store.GetOrgSovereigntyPolicy(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		if p.RequiredTier != "partial" || p.BuyerJurisdiction != "IN" || p.CNAllowed || len(p.ExcludedCountries) != 0 {
			t.Errorf("GetOrgSovereigntyPolicy: upsert must overwrite every field, got %+v", p)
		}
		return nil
	})

	// A missing policy row is a business answer (the handler falls back to
	// its default policy on this error).
	contract(t, "GetOrgSovereigntyPolicy[missing]", func(ctx context.Context) error {
		p, err := store.GetOrgSovereigntyPolicy(ctx, fx.Token+"-no-such-policy-org")
		switch {
		case err == nil:
			t.Errorf("GetOrgSovereigntyPolicy: expected ErrNoRows for a missing org")
		case p != nil:
			t.Errorf("GetOrgSovereigntyPolicy: expected a nil policy beside the error, got %+v", p)
		default:
			require.ErrorIs(t, err, pgx.ErrNoRows)
		}
		return nil
	})
}
