package handlers

// Handler acceptance: the rights matrices (root passes any
// org; analytics.read reads the spend window; budgets.manage reads budgets
// and the ledger; members without the permission are 403; non-members are
// 404 without an existence leak; unknown/missing capability is 501), the
// window/limit parsing contracts, the carbon-knob propagation, and the
// rates-catalog operations: root-only diff (pure function) and promote
// (reason-mandatory, refusal-422, audited pricer swap with untouched pricer
// on every failure path).
//
// The probes run on the bare domain mounts with context-injected identities
// (caps pattern); the full session+CSRF router contract lives in
// currencies_routing_test.go (package handlers_test).

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- capability fixtures: state rides package-level vars because
// mockStore's struct lives in another test file; package tests run
// sequentially (no t.Parallel). ----

var (
	currenciesRollup  *adminstore.UnitSpendRollup
	currenciesCaps    *adminstore.BudgetCapsStatus
	currenciesLedger  *adminstore.CreditsLedgerView
	currenciesErrMode error // when set, every capability read returns it

	currenciesLastFrom, currenciesLastTo time.Time
	currenciesLastCarbon                 *float64
	currenciesLastLimit                  int
)

func resetCurrenciesState() {
	currenciesRollup = nil
	currenciesCaps = nil
	currenciesLedger = nil
	currenciesErrMode = nil
	currenciesLastFrom, currenciesLastTo = time.Time{}, time.Time{}
	currenciesLastCarbon = nil
	currenciesLastLimit = 0
}

func (m *mockStore) GetUnitSpendRollup(_ context.Context, orgID string, from, to time.Time) (*adminstore.UnitSpendRollup, error) {
	currenciesLastFrom, currenciesLastTo = from, to
	if currenciesErrMode != nil {
		return nil, currenciesErrMode
	}
	if orgID == "org-gone" {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	if currenciesRollup != nil {
		return currenciesRollup, nil
	}
	return &adminstore.UnitSpendRollup{
		OrgID:        orgID,
		Window:       adminstore.SpendWindow{From: from.Format(time.RFC3339), To: to.Format(time.RFC3339)},
		Requests:     7,
		CreditsScale: adminstore.WalletUnitScale,
	}, nil
}

func (m *mockStore) GetBudgetCapsStatus(_ context.Context, orgID string, carbonLimitGrams *float64) (*adminstore.BudgetCapsStatus, error) {
	currenciesLastCarbon = carbonLimitGrams
	if currenciesErrMode != nil {
		return nil, currenciesErrMode
	}
	if orgID == "org-gone" {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	if currenciesCaps != nil {
		return currenciesCaps, nil
	}
	return &adminstore.BudgetCapsStatus{
		OrgID:        orgID,
		CreditsScale: adminstore.WalletUnitScale,
	}, nil
}

func (m *mockStore) GetCreditsLedgerView(_ context.Context, orgID string, limit int) (*adminstore.CreditsLedgerView, error) {
	currenciesLastLimit = limit
	if currenciesErrMode != nil {
		return nil, currenciesErrMode
	}
	if orgID == "org-gone" {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	if currenciesLedger != nil {
		return currenciesLedger, nil
	}
	return &adminstore.CreditsLedgerView{
		OrgID:        orgID,
		CreditsScale: adminstore.WalletUnitScale,
	}, nil
}

// currenciesFixture seeds the membership matrix and mounts the domain routes
// on a bare router (session middleware replaced by context injection).
func currenciesFixture(t *testing.T) (*mockStore, *AdminHandlers, chi.Router) {
	t.Helper()
	resetCurrenciesState()
	store := newMockStore()
	store.orgMembers["u-orgadmin/org-1"] = &adminstore.OrgMembership{UserID: "u-orgadmin", OrgID: "org-1", Role: adminstore.RoleOrgAdmin}
	store.orgMembers["u-reader/org-1"] = &adminstore.OrgMembership{UserID: "u-reader", OrgID: "org-1", Role: adminstore.RoleReader}
	store.orgMembers["u-partner/org-1"] = &adminstore.OrgMembership{UserID: "u-partner", OrgID: "org-1", Role: adminstore.RolePartner}
	h := newTestAdminH(store)
	t.Cleanup(h.Stop)
	r := chi.NewRouter()
	h.mountCurrenciesRoutes(r)
	return store, h.AdminHandlers, r
}

// currenciesRequest injects the fixture identity via the adminauth context
// keys the gates read (the caps probe pattern).
func currenciesRequest(t *testing.T, r chi.Router, userID string, root bool, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if userID != "" {
		ctx := req.Context()
		ctx = context.WithValue(ctx, adminauth.ContextKeyUserID{}, userID)
		ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, userID+"@x.test")
		ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, root)
		req = req.WithContext(ctx)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// ---- units spend ----

func TestCurrenciesUnitsSpend_RightsMatrixAndWindow(t *testing.T) {
	_, _, r := currenciesFixture(t)

	t.Run("root reads any org", func(t *testing.T) {
		rec := currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/units/spend?org_id=org-2", "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var got adminstore.UnitSpendRollup
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		assert.Equal(t, "org-2", got.OrgID)
		assert.Equal(t, adminstore.WalletUnitScale, got.CreditsScale)
	})

	t.Run("org member with analytics.read reads (admin and reader)", func(t *testing.T) {
		for _, uid := range []string{"u-orgadmin", "u-reader"} {
			rec := currenciesRequest(t, r, uid, false, http.MethodGet, "/api/units/spend?org_id=org-1", "")
			require.Equal(t, http.StatusOK, rec.Code, "uid=%s body=%s", uid, rec.Body.String())
		}
	})

	t.Run("member without analytics.read is 404 (no leak), non-member 404", func(t *testing.T) {
		for _, uid := range []string{"u-partner", "u-lone"} {
			rec := currenciesRequest(t, r, uid, false, http.MethodGet, "/api/units/spend?org_id=org-1", "")
			require.Equal(t, http.StatusNotFound, rec.Code, "uid=%s body=%s", uid, rec.Body.String())
		}
	})

	t.Run("window parsing: default 30d, explicit RFC3339, bad values 400", func(t *testing.T) {
		rec := currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/units/spend?org_id=org-2", "")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.WithinDuration(t, currenciesLastTo, currenciesLastFrom.Add(30*24*time.Hour), time.Second, "default window is 30 days")

		rec = currenciesRequest(t, r, "root-op", true, http.MethodGet,
			"/api/units/spend?org_id=org-2&from=2026-10-01T00:00:00Z&to=2026-10-31T00:00:00Z", "")
		require.Equal(t, http.StatusOK, rec.Code)
		from, err := time.Parse(time.RFC3339, "2026-10-01T00:00:00Z")
		require.NoError(t, err)
		assert.Equal(t, from.UTC(), currenciesLastFrom)
		assert.True(t, currenciesLastTo.Equal(time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)), "got %s", currenciesLastTo)

		for _, q := range []string{"from=not-a-time", "to=also-bad", "from=2026-11-01T00:00:00Z&to=2026-10-01T00:00:00Z"} {
			rec = currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/units/spend?org_id=org-2&"+q, "")
			require.Equal(t, http.StatusBadRequest, rec.Code, "q=%s body=%s", q, rec.Body.String())
		}
	})

	t.Run("missing org_id is 400 before identity checks", func(t *testing.T) {
		rec := currenciesRequest(t, r, "", false, http.MethodGet, "/api/units/spend", "")
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("store not-found maps to 404, other errors to 500", func(t *testing.T) {
		rec := currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/units/spend?org_id=org-gone", "")
		require.Equal(t, http.StatusNotFound, rec.Code)

		currenciesErrMode = fmt.Errorf("db down")
		defer func() { currenciesErrMode = nil }()
		rec = currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/units/spend?org_id=org-2", "")
		require.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

// ---- budgets ----

func TestCurrenciesBudgets_MatrixAndCarbonKnob(t *testing.T) {
	_, _, r := currenciesFixture(t)

	t.Run("root reads any org", func(t *testing.T) {
		rec := currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/budgets?org_id=org-2", "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("member with budgets.manage reads, member without is 403, non-member 404", func(t *testing.T) {
		rec := currenciesRequest(t, r, "u-orgadmin", false, http.MethodGet, "/api/budgets?org_id=org-1", "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		for _, tc := range []struct {
			uid  string
			want int
		}{
			{"u-reader", http.StatusForbidden}, // analytics.read is not budgets.manage
			{"u-partner", http.StatusForbidden},
			{"u-lone", http.StatusNotFound},
		} {
			rec := currenciesRequest(t, r, tc.uid, false, http.MethodGet, "/api/budgets?org_id=org-1", "")
			require.Equal(t, tc.want, rec.Code, "uid=%s body=%s", tc.uid, rec.Body.String())
		}
	})

	t.Run("carbon knob propagates: set, unset, malformed", func(t *testing.T) {
		t.Setenv(envCarbonBudgetGrams, "250.5")
		rec := currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/budgets?org_id=org-2", "")
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotNil(t, currenciesLastCarbon)
		assert.InDelta(t, 250.5, *currenciesLastCarbon, 1e-9)

		t.Setenv(envCarbonBudgetGrams, "")
		rec = currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/budgets?org_id=org-2", "")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Nil(t, currenciesLastCarbon, "no cap configured is nil (unknown), never zero")

		for _, bad := range []string{"not-a-number", "-5", "NaN", "Inf", "0"} {
			t.Setenv(envCarbonBudgetGrams, bad)
			rec = currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/budgets?org_id=org-2", "")
			require.Equal(t, http.StatusOK, rec.Code, "malformed knob degrades to unknown, not an error (%s)", bad)
			assert.Nil(t, currenciesLastCarbon, "malformed knob %q must be nil", bad)
		}
	})

	t.Run("store not-found maps to 404", func(t *testing.T) {
		rec := currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/budgets?org_id=org-gone", "")
		require.Equal(t, http.StatusNotFound, rec.Code)
	})
}

// ---- credits ledger ----

func TestCurrenciesCreditsLedger_MatrixAndLimitClamp(t *testing.T) {
	_, _, r := currenciesFixture(t)

	t.Run("root and budgets.manage member read", func(t *testing.T) {
		rec := currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/credits/ledger?org_id=org-2", "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		rec = currenciesRequest(t, r, "u-orgadmin", false, http.MethodGet, "/api/credits/ledger?org_id=org-1", "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("member without budgets.manage is 403, non-member 404", func(t *testing.T) {
		rec := currenciesRequest(t, r, "u-reader", false, http.MethodGet, "/api/credits/ledger?org_id=org-1", "")
		require.Equal(t, http.StatusForbidden, rec.Code)

		rec = currenciesRequest(t, r, "u-lone", false, http.MethodGet, "/api/credits/ledger?org_id=org-1", "")
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("limit is clamped through adminstore.ClampLedgerLimit", func(t *testing.T) {
		cases := []struct {
			raw  string
			want int
		}{
			{"", adminstore.LedgerDefaultLimit},
			{"0", adminstore.LedgerDefaultLimit},
			{"-7", adminstore.LedgerDefaultLimit},
			{"25", 25},
			{"999", adminstore.LedgerMaxLimit},
		}
		for _, tc := range cases {
			target := "/api/credits/ledger?org_id=org-2"
			if tc.raw != "" {
				target += "&limit=" + tc.raw
			}
			rec := currenciesRequest(t, r, "root-op", true, http.MethodGet, target, "")
			require.Equal(t, http.StatusOK, rec.Code, "limit=%q body=%s", tc.raw, rec.Body.String())
			assert.Equal(t, tc.want, currenciesLastLimit, "limit=%q", tc.raw)
		}

		rec := currenciesRequest(t, r, "root-op", true, http.MethodGet, "/api/credits/ledger?org_id=org-2&limit=abc", "")
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// ---- carbon knob unit table ----

func TestCarbonBudgetGramsOverride(t *testing.T) {
	t.Setenv(envCarbonBudgetGrams, "")
	assert.Nil(t, carbonBudgetGramsOverride(), "unset means no cap")

	t.Setenv(envCarbonBudgetGrams, "42")
	v := carbonBudgetGramsOverride()
	require.NotNil(t, v)
	assert.InDelta(t, 42.0, *v, 1e-9)

	for _, bad := range []string{"abc", "", "-1", "NaN", "Inf", "-Inf", "1e999"} {
		t.Setenv(envCarbonBudgetGrams, bad)
		assert.Nil(t, carbonBudgetGramsOverride(), "knob %q must degrade to nil", bad)
	}
}

// ---- rates catalog view ----

func TestCurrenciesRatesCatalogView(t *testing.T) {
	_, h, r := currenciesFixture(t)
	_ = h

	rec := currenciesRequest(t, r, "u-reader", false, http.MethodGet, "/api/rates/catalog", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var got struct {
		Ref     adminstore.RatesCatalogRef `json:"ref"`
		Catalog struct {
			Version string            `json:"version"`
			Models  []json.RawMessage `json:"models"`
		} `json:"catalog"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.NotEmpty(t, got.Ref.Version)
	assert.NotEmpty(t, got.Ref.Digest)
	assert.NotEmpty(t, got.Ref.PackDigest)
	assert.NotEmpty(t, got.Ref.Provenance)
	assert.NotEmpty(t, got.Catalog.Models, "the full sealed catalog body is served")
}

// ---- pack fixtures (exported pricing API only) ----

func currenciesActiveModel(provider, model string, in, out float64, reviewer string) pricing.RefModel {
	amtIn, amtOut := in, out
	return pricing.RefModel{
		Provider:      provider,
		Model:         model,
		Currency:      "USD",
		Status:        pricing.RefStatusActive,
		EffectiveFrom: "2026-11-01",
		VerifiedAt:    "2026-11-02",
		Rates: []pricing.RefRate{
			{Axis: pricing.AxisInput, Unit: pricing.RefUnitPer1MTokens, Amount: &amtIn},
			{Axis: pricing.AxisOutput, Unit: pricing.RefUnitPer1MTokens, Amount: &amtOut},
		},
		Sources: []pricing.RefSource{{
			Kind:       pricing.RefSourceURL,
			Ref:        "https://pricing.example.test/" + provider + "/" + model,
			VerifiedAt: "2026-11-02",
		}},
		Reviewer: reviewer,
	}
}

func currenciesTestCatalog(version, supersedes string, models []pricing.RefModel) pricing.Catalog {
	c := pricing.Catalog{
		SchemaVersion: pricing.RefSchemaVersion,
		Version:       version,
		GeneratedAt:   "2026-11-02",
		Source:        "handler test assembly (deterministic fixture)",
		Models:        models,
	}
	if supersedes != "" {
		c.Supersedes = supersedes
	}
	return c
}

func currenciesSealedPack(t *testing.T, c pricing.Catalog) []byte {
	t.Helper()
	sealed, err := pricing.SealCatalog(c)
	require.NoError(t, err)
	b, err := json.Marshal(sealed)
	require.NoError(t, err)
	pack, err := pricing.BuildRefPack(b, nil)
	require.NoError(t, err)
	out, err := pricing.MarshalRefPack(pack)
	require.NoError(t, err)
	return out
}

// currenciesPromoteBody renders the POST body for a pack.
func currenciesPromoteBody(t *testing.T, pack []byte, reason string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"pack": string(pack), "reason": reason})
	require.NoError(t, err)
	return string(b)
}

// currenciesTweakedCommittedPack builds a promotion candidate from the real
// committed pack: one active input rate +0.25, version bumped, chain pinned
// to the committed digest. Returns the pack and the sealed next digest.
func currenciesTweakedCommittedPack(t *testing.T) ([]byte, string) {
	t.Helper()
	_, cat, err := pricing.LoadRefPack(pricing.BundledRefPackJSON())
	require.NoError(t, err)
	tweaked := false
	for i := range cat.Models {
		m := &cat.Models[i]
		if m.Status != pricing.RefStatusActive {
			continue
		}
		for j := range m.Rates {
			if m.Rates[j].Axis == pricing.AxisInput && m.Rates[j].Amount != nil {
				*m.Rates[j].Amount += 0.25
				tweaked = true
				break
			}
		}
		if tweaked {
			break
		}
	}
	require.True(t, tweaked, "committed pack has an active input rate to tweak")
	cat.Version = "999.0.0-rates-promote"
	cat.Supersedes = cat.Digest
	sealed, err := pricing.SealCatalog(cat)
	require.NoError(t, err)
	require.NotEmpty(t, sealed.Digest)
	require.NotEqual(t, cat.Supersedes, sealed.Digest, "a sealed candidate must not reuse the committed digest")
	b, err := json.Marshal(sealed)
	require.NoError(t, err)
	pack, err := pricing.BuildRefPack(b, nil)
	require.NoError(t, err)
	out, err := pricing.MarshalRefPack(pack)
	require.NoError(t, err)
	return out, sealed.Digest
}

// currenciesRefusalPacks author a draft predecessor and its unreviewed
// activation, independently of the shipped catalog's entries.
func currenciesRefusalPacks(t *testing.T) ([]byte, []byte) {
	t.Helper()
	active := currenciesActiveModel("synthetic-handler", "reviewed", 17, 29, "fixture-reviewer")
	draft := currenciesActiveModel("synthetic-handler", "unreviewed", 31, 43, "")
	draft.Status = pricing.RefStatusDraft
	previous := currenciesSealedPack(t, currenciesTestCatalog("synthetic-draft-anchor", "", []pricing.RefModel{active, draft}))
	_, cat, err := pricing.LoadRefPack(previous)
	require.NoError(t, err)
	draft.Status = pricing.RefStatusActive
	next := currenciesTestCatalog("synthetic-unreviewed-activation", cat.Digest, []pricing.RefModel{active, draft})
	return previous, currenciesSealedPack(t, next)
}

// currenciesUnchainedPack drops the Supersedes pin from a candidate. The
// catalog travels verbatim inside the pack envelope as a JSON object.
func currenciesUnchainedPack(t *testing.T, pack []byte) []byte {
	t.Helper()
	var env map[string]any
	require.NoError(t, json.Unmarshal(pack, &env))
	sealed, ok := env["catalog"].(map[string]any)
	require.True(t, ok, "pack envelope carries the catalog as a JSON object")
	sealed["supersedes"] = ""
	env["catalog"] = sealed
	out, err := json.Marshal(env)
	require.NoError(t, err)
	return out
}

// ---- rates diff (root-only, pure function) ----

func TestCurrenciesRatesDiff_HandlerContract(t *testing.T) {
	_, _, r := currenciesFixture(t)

	small := currenciesSealedPack(t, currenciesTestCatalog("900.0.0-diff", "",
		[]pricing.RefModel{
			currenciesActiveModel("fprov", "zeta", 1.0, 2.0, "reviewer-a"),
			currenciesActiveModel("fprov", "eta", 3.0, 4.0, "reviewer-b"),
		}))

	t.Run("non-root is 403 before any parsing", func(t *testing.T) {
		rec := currenciesRequest(t, r, "u-orgadmin", false, http.MethodPost, "/api/rates/diff",
			currenciesPromoteBody(t, small, ""))
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	})

	t.Run("root diffs a candidate against the committed catalog", func(t *testing.T) {
		rec := currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/diff",
			currenciesPromoteBody(t, small, ""))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var report adminstore.RatesDiffReport
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &report))
		assert.False(t, report.Refused)
		assert.Contains(t, report.Rendered, "summary:")
		assert.Positive(t, report.Added+report.Removed, "a two-model candidate differs from the committed catalog")
	})

	t.Run("malformed body and missing pack are 400", func(t *testing.T) {
		rec := currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/diff", `{"pack":`)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		rec = currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/diff", `{"reason":"no pack"}`)
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("a tampered pack is 400 with the loader reason", func(t *testing.T) {
		var env map[string]any
		require.NoError(t, json.Unmarshal(small, &env))
		env["pack_sha256"] = strings.Repeat("ab", 32)
		tampered, err := json.Marshal(env)
		require.NoError(t, err)
		rec := currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/diff",
			currenciesPromoteBody(t, tampered, ""))
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "rates diff: next pack")
	})
}

// ---- rates promote ----

func TestCurrenciesRatesPromote_HappyPathAudited(t *testing.T) {
	store, _, r := currenciesFixture(t)

	prev := pricing.DefaultFilePricer()
	t.Cleanup(func() { pricing.SetDefaultFilePricer(prev) })

	next, nextDigest := currenciesTweakedCommittedPack(t)

	rec := currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/promote",
		currenciesPromoteBody(t, next, "rate refresh"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var prom adminstore.RatesPromotion
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &prom))
	assert.True(t, prom.Applied)
	assert.Equal(t, "999.0.0-rates-promote", prom.After.Version)
	assert.NotEqual(t, prom.Before.Digest, prom.After.Digest)
	assert.False(t, prom.Diff.Refused)

	after, ok := pricing.DefaultFilePricer().CatalogProvenance()
	require.True(t, ok, "the promoted pricer serves a reference catalog")
	assert.Equal(t, nextDigest, after.Digest, "the default pricer was re-seated on the new catalog")
	assert.Equal(t, "999.0.0-rates-promote", after.Version)

	require.Equal(t, 1, store.auditRecordCount(), "exactly one journal entry")
	jr := store.lastAuditRecord(t)
	assert.Equal(t, "rates_catalog_promote", jr.Action)
	assert.Equal(t, "rates/catalog", jr.Resource)
	assert.Contains(t, jr.Details, "999.0.0-rates-promote")
	assert.Contains(t, jr.After, "999.0.0-rates-promote")
}

func TestCurrenciesRatesPromote_RefusedJournaledPricerUntouched(t *testing.T) {
	store, h, r := currenciesFixture(t)
	previous, next := currenciesRefusalPacks(t)
	pack, cat, err := pricing.LoadRefPack(previous)
	require.NoError(t, err)
	pool := testdb.Postgres(t)
	_, err = pool.Exec(t.Context(), `INSERT INTO rates_catalog_state
		(id, catalog_version, catalog_digest, pack_sha256, pack_json, activated_by)
		VALUES (1, $1, $2, $3, $4, 'synthetic-handler-refusal')`, cat.Version, cat.Digest, pack.PackSHA256, previous)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, cleanupErr := pool.Exec(ctx, `DELETE FROM rates_catalog_state WHERE id = 1 AND activated_by = 'synthetic-handler-refusal'`)
		require.NoError(t, cleanupErr)
	})
	durable := adminstore.New(pool, slog.Default(), nil)
	h.SetRatesCatalogStore(durable)

	prev := pricing.DefaultFilePricer()
	t.Cleanup(func() { pricing.SetDefaultFilePricer(prev) })
	before, _ := prev.CatalogProvenance()

	rec := currenciesRequest(t, r, "synthetic-handler-refusal", true, http.MethodPost, "/api/rates/promote",
		currenciesPromoteBody(t, next, "try to sneak"))
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())

	var body struct {
		Refused       bool                        `json:"refused"`
		RefusalReason string                      `json:"refusal_reason"`
		Report        *adminstore.RatesDiffReport `json:"report"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.True(t, body.Refused)
	assert.NotEmpty(t, body.RefusalReason)
	require.NotNil(t, body.Report)
	assert.True(t, body.Report.Refused)

	after, ok := pricing.DefaultFilePricer().CatalogProvenance()
	if ok {
		assert.Equal(t, before, after, "a refusal never touches the pricer")
	}
	assert.Same(t, prev, pricing.DefaultFilePricer(), "refusal must not replace the process pricer")
	persisted, found, err := durable.DurableRatesCatalogPackJSON(t.Context())
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, previous, persisted, "refusal must preserve the durable predecessor")

	require.Equal(t, 1, store.auditRecordCount())
	jr := store.lastAuditRecord(t)
	assert.Equal(t, "rates_catalog_promote_refused", jr.Action)
}

func TestCurrenciesRatesPromote_InputValidation(t *testing.T) {
	_, _, r := currenciesFixture(t)

	prev := pricing.DefaultFilePricer()
	t.Cleanup(func() { pricing.SetDefaultFilePricer(prev) })
	before, _ := prev.CatalogProvenance()

	next, _ := currenciesTweakedCommittedPack(t)

	t.Run("non-root is 403", func(t *testing.T) {
		rec := currenciesRequest(t, r, "u-orgadmin", false, http.MethodPost, "/api/rates/promote",
			currenciesPromoteBody(t, next, "not root"))
		require.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("reason is mandatory", func(t *testing.T) {
		for _, body := range []string{
			currenciesPromoteBody(t, next, ""),
			`{"pack":"{}"}`,
		} {
			rec := currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/promote", body)
			require.Equal(t, http.StatusBadRequest, rec.Code, body)
			assert.Contains(t, rec.Body.String(), "reason is required")
		}
	})

	t.Run("chain break is 400 and the pricer is untouched", func(t *testing.T) {
		rec := currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/promote",
			currenciesPromoteBody(t, currenciesUnchainedPack(t, next), "forgot the chain"))
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		after, ok := pricing.DefaultFilePricer().CatalogProvenance()
		if ok {
			assert.Equal(t, before, after)
		}
	})

	t.Run("an invalid pack is 400", func(t *testing.T) {
		rec := currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/promote",
			currenciesPromoteBody(t, []byte(`{"catalog":"{}"}`), "garbage"))
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// ---- AUDIT-P1-04: body-limit ceiling + durable-path wiring ----

// TestRatesPromoteBodyLimit_PrefixCeilingPassesFullPack pins the router
// mount against an authored large operator pack: under the old global 1 MiB
// ceiling the promotion body died at the middleware (decode error before
// the handler ran); the per-prefix /api/rates/ ceiling (16 MiB) lets the
// full envelope reach the promote handler, which answers with its own
// chain refusal (the synthetic pack does not declare the committed predecessor).
func TestRatesPromoteBodyLimit_PrefixCeilingPassesFullPack(t *testing.T) {
	_, h, _ := currenciesFixture(t)
	build := func(mw func(http.Handler) http.Handler) chi.Router {
		r := chi.NewRouter()
		r.Use(mw)
		h.mountCurrenciesRoutes(r)
		return r
	}
	models := make([]pricing.RefModel, 4096)
	for i := range models {
		models[i] = currenciesActiveModel("synthetic-size-fixture", fmt.Sprintf("model-%04d", i), 17, 29, "fixture-reviewer")
	}
	pack := currenciesSealedPack(t, currenciesTestCatalog("large-operator-fixture", "", models))
	_, _, err := pricing.LoadRefPack(pack)
	require.NoError(t, err, "body-size fixture must remain a valid sealed pack")
	body := currenciesPromoteBody(t, pack, "full-size probe")
	require.Greater(t, len(body), 1024*1024,
		"the synthetic pack body must exceed the global admin ceiling for this probe to mean anything")
	require.Less(t, len(body), 16*1024*1024, "fixture must fit the rates-specific ceiling")

	t.Run("global 1MiB ceiling refuses the full pack at the middleware", func(t *testing.T) {
		r := build(httpmw.MaxBody(1024 * 1024))
		rec := currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/promote", body)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "malformed JSON body",
			"the pack never reaches the handler under the old ceiling")
	})

	t.Run("per-prefix ceiling lets the full pack reach the handler", func(t *testing.T) {
		r := build(httpmw.MaxBodyByPrefix(1024*1024, 16*1024*1024, "/api/rates/"))
		rec := currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/promote", body)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "catalog chain",
			"the body reached the handler: its own chain refusal, not a body-size failure")
		assert.NotContains(t, rec.Body.String(), "malformed")
	})
}

// TestRatesCatalogDiff_FailsClosedWithoutPool pins the no-silent-fallback
// contract: when the rates-catalog store is wired but cannot read the
// active-of-record, the diff must answer 500 — never silently diff against
// the bundled anchor (a stale anchor could bless a promotion the active
// chain forbids).
func TestRatesCatalogDiff_FailsClosedWithoutPool(t *testing.T) {
	_, h, r := currenciesFixture(t)

	small := currenciesSealedPack(t, currenciesTestCatalog("901.0.0-diff", "",
		[]pricing.RefModel{currenciesActiveModel("fprov", "alpha", 1.0, 2.0, "reviewer-a")}))

	h.SetRatesCatalogStore(&adminstore.Store{}) // wired, but pool-less: reads error
	rec := currenciesRequest(t, r, "root-op", true, http.MethodPost, "/api/rates/diff",
		currenciesPromoteBody(t, small, ""))
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
}
