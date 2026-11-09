package handlers

// The Units & Spend + Policies workspace backend —
// additive read surfaces over the slice-1..3 adminstore measures plus the
// slice-4/5 rates-catalog operations. This file owns only HTTP: routing,
// rights, parsing and journaling; every computation lives in pkg/adminstore
// (currencies_measure.go, currencies_spend.go, currencies_budgets.go,
// currencies_ledger.go, currencies_rates.go) and pkg/pricing.
//
// Routes (all mounted on the `protected` session+CSRF group):
//
//	GET  /api/units/spend    — org-scoped measure rollup (analytics.read;
//	                           root passes for any org; failures are 404,
//	                           no tenant-existence leak)
//	GET  /api/budgets        — org cap status (budgets.manage; non-member
//	                           404, member-without-permission 403 — the
//	                           caps/credits visibility matrix)
//	GET  /api/credits/ledger — wallet + transactions view (budgets.manage)
//	GET  /api/rates/catalog  — the committed reference-pricing citation and
//	                           full sealed catalog body. Public pricing data:
//	                           any authenticated session may read it, the
//	                           same data the gateway prices with.
//	POST /api/rates/diff     — ROOT-ONLY review diff of a candidate sealed
//	                           pack against the committed catalog. Pure
//	                           function: no state changes, no journaling.
//	POST /api/rates/promote  — ROOT-ONLY audited pricer swap: chain check,
//	                           blessed diff, serveability probe, then
//	                           SetDefaultFilePricer. Refusals (review gate)
//	                           are 422 data; every other candidate problem
//	                           (bad pack, chain break, unserveable) is 400
//	                           with the operator-facing reason.
//
// The carbon budget used by GET /api/budgets is read from
// YABANIN_CARBON_BUDGET_GRAMS per request (positive finite float, grams
// CO2e). It is configuration, not mutable state, so it is not wired as an
// AdminHandlers field; when the operator surface for the knob exists, that
// wiring point replaces this reader (one call site).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// envCarbonBudgetGrams is the carbon cap knob read by GET /api/budgets.
const envCarbonBudgetGrams = "YABANIN_CARBON_BUDGET_GRAMS"

// carbonBudgetGramsOverride parses the env knob per request. An unset,
// malformed, non-finite or non-positive value means "no carbon cap
// configured" (nil) — the budgets view reports the carbon cap as unknown
// instead of inventing a default.
func carbonBudgetGramsOverride() *float64 {
	raw := strings.TrimSpace(os.Getenv(envCarbonBudgetGrams))
	if raw == "" {
		return nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return nil
	}
	return &v
}

// CurrenciesSpendStore is the narrow capability for GET /api/units/spend
// (type-asserted from StoreInterface like OrgCapsStore). Stores that predate
// the currencies program answer 501 instead of silently degrading.
type CurrenciesSpendStore interface {
	GetUnitSpendRollup(ctx context.Context, orgID string, from, to time.Time) (*adminstore.UnitSpendRollup, error)
}

// CurrenciesBudgetsStore is the narrow capability for GET /api/budgets.
type CurrenciesBudgetsStore interface {
	GetBudgetCapsStatus(ctx context.Context, orgID string, carbonLimitGrams *float64) (*adminstore.BudgetCapsStatus, error)
}

// CurrenciesLedgerStore is the narrow capability for GET /api/credits/ledger.
type CurrenciesLedgerStore interface {
	GetCreditsLedgerView(ctx context.Context, orgID string, limit int) (*adminstore.CreditsLedgerView, error)
}

func (h *AdminHandlers) currenciesSpendStore() CurrenciesSpendStore {
	s, _ := h.store.(CurrenciesSpendStore)
	return s
}

func (h *AdminHandlers) currenciesBudgetsStore() CurrenciesBudgetsStore {
	s, _ := h.store.(CurrenciesBudgetsStore)
	return s
}

func (h *AdminHandlers) currenciesLedgerStore() CurrenciesLedgerStore {
	s, _ := h.store.(CurrenciesLedgerStore)
	return s
}

// mountCurrenciesRoutes registers the currencies surfaces on the protected
// (session+CSRF) group. Gates live in the handlers, like the neighboring
// org-scoped mounts.
func (h *AdminHandlers) mountCurrenciesRoutes(r chi.Router) {
	r.Get("/api/units/spend", h.UnitsSpend())
	r.Get("/api/budgets", h.BudgetCaps())
	r.Get("/api/credits/ledger", h.CreditsLedger())
	r.Get("/api/rates/catalog", h.RatesCatalogView())
	r.Post("/api/rates/diff", h.RatesCatalogDiff())
	r.Post("/api/rates/promote", h.RatesCatalogPromote())
}

// currenciesBudgetsRead gates the budgets/ledger views on the caps/credits
// visibility matrix: root passes for any org; a non-member gets the bare
// 404 (the org stays invisible); a member without budgets.manage gets 403
// (the org is theirs, the money view is not).
func (h *AdminHandlers) currenciesBudgetsRead(w http.ResponseWriter, r *http.Request, orgID string) bool {
	if orgID == "" {
		h.respondError(w, r, fmt.Errorf("org_id is required"), http.StatusBadRequest)
		return false
	}
	if isRoot(r) {
		return true
	}
	role, ok := h.callerRoleOnOrg(r, orgID)
	if !ok {
		writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
		return false
	}
	if !adminstore.RoleHas(string(role), adminstore.PermBudgetsManage) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "insufficient permission for this organization"})
		return false
	}
	return true
}

// requireRootForRates gates the rates-catalog mutations on a root session
// (the same double check as the request-payload grants: the session must be
// root AND carry a user id, so a malformed root cookie cannot pass).
func requireRootForRates(w http.ResponseWriter, r *http.Request) bool {
	if isRoot(r) && requestUserID(r) != "" {
		return true
	}
	writeJSON(w, http.StatusForbidden, apiError{Error: "root session is required for the rates catalog"})
	return false
}

// ratesPackBody is the POST /api/rates/diff and /api/rates/promote request.
// Pack is the full sealed pack JSON (the chain-verified artifact, currently
// ~2.3 MB raw / ~2.6 MB JSON-escaped for the committed reference set). The
// router mounts httpmw.MaxBodyByPrefix with a 16 MiB ceiling for the
// /api/rates/ prefix (AUDIT-P1-04), so full-size promotion bodies pass
// while the global admin API keeps its 1 MiB limit.
type ratesPackBody struct {
	Pack   string `json:"pack"`
	Reason string `json:"reason"`
}

// decodeRatesPackBody parses and structurally validates the body.
func decodeRatesPackBody(w http.ResponseWriter, r *http.Request) (*ratesPackBody, bool) {
	var req ratesPackBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
		return nil, false
	}
	if strings.TrimSpace(req.Pack) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "pack is required"})
		return nil, false
	}
	return &req, true
}

// UnitsSpend handles GET /api/units/spend?org_id=&from=&to= — the measured
// org window (tokens, USD, credits, gCO2e lines with fidelity/provenance).
// from/to are optional RFC3339 timestamps; the default window is the last
// 30 days ending now (UTC).
func (h *AdminHandlers) UnitsSpend() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if !h.requireOrgRead(w, r, orgID, adminstore.PermAnalyticsRead) {
			return
		}
		from, to, err := parseSpendWindow(r.URL.Query().Get("from"), r.URL.Query().Get("to"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		store := h.currenciesSpendStore()
		if store == nil {
			h.respondError(w, r, fmt.Errorf("units spend store not available"), http.StatusNotImplemented)
			return
		}
		rollup, err := store.GetUnitSpendRollup(r.Context(), orgID, from, to)
		if err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			h.respondError(w, r, fmt.Errorf("get units spend: %w", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rollup)
	}
}

// parseSpendWindow resolves the optional from/to RFC3339 query values to the
// measured window: default to=now, from=to-30d (UTC).
func parseSpendWindow(fromRaw, toRaw string) (time.Time, time.Time, error) {
	to := time.Now().UTC()
	from := to.Add(-30 * 24 * time.Hour)
	if toRaw != "" {
		parsed, err := time.Parse(time.RFC3339, toRaw)
		if err != nil {
			return from, to, fmt.Errorf("to must be an RFC3339 timestamp")
		}
		to = parsed.UTC()
	}
	if fromRaw != "" {
		parsed, err := time.Parse(time.RFC3339, fromRaw)
		if err != nil {
			return from, to, fmt.Errorf("from must be an RFC3339 timestamp")
		}
		from = parsed.UTC()
	}
	if from.After(to) {
		return from, to, fmt.Errorf("from must not be after to")
	}
	return from, to, nil
}

// BudgetCaps handles GET /api/budgets?org_id= — the month-to-date cap
// status lines (USD budget, credits, gCO2e when configured). The carbon cap
// comes from YABANIN_CARBON_BUDGET_GRAMS; unset/malformed means the carbon
// cap is unknown, not zero.
func (h *AdminHandlers) BudgetCaps() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if !h.currenciesBudgetsRead(w, r, orgID) {
			return
		}
		store := h.currenciesBudgetsStore()
		if store == nil {
			h.respondError(w, r, fmt.Errorf("budgets store not available"), http.StatusNotImplemented)
			return
		}
		status, err := store.GetBudgetCapsStatus(r.Context(), orgID, carbonBudgetGramsOverride())
		if err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			h.respondError(w, r, fmt.Errorf("get budget caps: %w", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, status)
	}
}

// CreditsLedger handles GET /api/credits/ledger?org_id=&limit= — the wallet
// balance, the starter-grant claim state and the transaction page (1..100,
// default from adminstore.ClampLedgerLimit).
func (h *AdminHandlers) CreditsLedger() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if !h.currenciesBudgetsRead(w, r, orgID) {
			return
		}
		limit := 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "limit must be an integer"})
				return
			}
			limit = parsed
		}
		store := h.currenciesLedgerStore()
		if store == nil {
			h.respondError(w, r, fmt.Errorf("credits ledger store not available"), http.StatusNotImplemented)
			return
		}
		view, err := store.GetCreditsLedgerView(r.Context(), orgID, adminstore.ClampLedgerLimit(limit))
		if err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			h.respondError(w, r, fmt.Errorf("get credits ledger: %w", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, view)
	}
}

// RatesCatalogView handles GET /api/rates/catalog — the active-of-record
// pricing: the citation (version, digests, provenance, notices) plus the
// full sealed catalog body. With the rates-catalog store wired the payload
// is the durably promoted catalog (every process reports the same citation,
// AUDIT-P1-04); without it, the committed reference pack. Session-
// authenticated only: this is the same pricing data every gateway request
// is priced with, so any admin session may read it (no org gate, no store
// dependency beyond the optional rates-catalog store).
func (h *AdminHandlers) RatesCatalogView() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.ratesCatalogStore != nil {
			cat, err := h.ratesCatalogStore.CurrentDurableRatesCatalog(r.Context())
			if err != nil {
				h.respondError(w, r, fmt.Errorf("load active rates catalog: %w", err), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, cat)
			return
		}
		cat, err := adminstore.CurrentRefRatesCatalog()
		if err != nil {
			h.respondError(w, r, fmt.Errorf("load reference catalog: %w", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, cat)
	}
}

// RatesCatalogDiff handles POST /api/rates/diff — the root-only review diff
// of a candidate sealed pack against the active-of-record catalog (the
// durably promoted pack when the rates-catalog store is wired, else the
// committed reference catalog) — the SAME anchor the promotion chain check
// verifies, so a diff blessed by the UI can never fail the promote for
// anchor reasons. Pure function: the response carries the full report
// (rendered diff, counters, review-needed flags) and a refused diff is 422
// data, not an error. The committed state and the pricer are never touched.
func (h *AdminHandlers) RatesCatalogDiff() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRootForRates(w, r) {
			return
		}
		req, ok := decodeRatesPackBody(w, r)
		if !ok {
			return
		}
		// Diff compares sealed pack bodies: prev is the active-of-record,
		// next is the candidate verbatim. DiffRefRatesCatalogs loads and
		// schema-checks both sides (an invalid candidate is an error, a
		// refused review gate is 422 data below).
		anchor := pricing.BundledRefPackJSON()
		if h.ratesCatalogStore != nil {
			pack, _, err := h.ratesCatalogStore.DurableRatesCatalogPackJSON(r.Context())
			if err != nil {
				// No silent fallback to the bundled anchor: a stale anchor
				// could bless a diff the active chain forbids.
				h.respondError(w, r, fmt.Errorf("load active rates catalog: %w", err), http.StatusInternalServerError)
				return
			}
			anchor = pack
		}
		report, err := adminstore.DiffRefRatesCatalogs(anchor, []byte(req.Pack))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		if report.Refused {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"refused":        true,
				"refusal_reason": report.RefusalReason,
				"report":         report,
			})
			return
		}
		writeJSON(w, http.StatusOK, report)
	}
}

// RatesCatalogPromote handles POST /api/rates/promote — the root-only,
// reason-mandatory, audited pricer swap. With the rates-catalog store wired
// the promotion is durable (AUDIT-P1-04): one transaction writes the
// active-of-record row and materializes models_pricing, so every process
// serves the promoted prices (within the DBPricer TTL) and restarts keep
// them; the store-side PromoteRefCatalogDurable runs chain verification
// against the active-of-record → blessed diff → serveability probe →
// materialization and writes nothing on any failure. Without the store the
// legacy in-memory PromoteRefCatalog re-seat applies. A refusal is a 422
// with the report (journaled), every other candidate problem is a 400 with
// the reason, and success journals the before/after citations as a
// full-block diff.
func (h *AdminHandlers) RatesCatalogPromote() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRootForRates(w, r) {
			return
		}
		req, ok := decodeRatesPackBody(w, r)
		if !ok {
			return
		}
		reason := mutationReason(req.Reason, r)
		if reason == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "reason is required"})
			return
		}
		var prom *adminstore.RatesPromotion
		var err error
		if h.ratesCatalogStore != nil {
			// requireRootForRates guarantees a user id; the store treats an
			// empty operator stamp as a hard error (audit-column integrity).
			prom, err = h.ratesCatalogStore.PromoteRefCatalogDurable(r.Context(), []byte(req.Pack), requestUserID(r))
		} else {
			prom, err = adminstore.PromoteRefCatalog([]byte(req.Pack))
		}
		if err != nil {
			var refusal *adminstore.RatesRefusal
			if errors.As(err, &refusal) {
				details := fmt.Sprintf("refused: %s", refusal.Error())
				h.auditLogActionDiff(r, "rates_catalog_promote_refused", "rates/catalog", details, nil, refusal.Report)
				writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
					"refused":        true,
					"refusal_reason": refusal.Report.RefusalReason,
					"report":         refusal.Report,
				})
				return
			}
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		details := fmt.Sprintf("version=%s reason=%s", prom.After.Version, reason)
		if prom.Persisted {
			details += fmt.Sprintf(" persisted=true materialization added=%d updated=%d removed=%d skipped=%d",
				prom.Materialization.Added, prom.Materialization.Updated,
				prom.Materialization.Removed, prom.Materialization.Skipped)
		}
		h.auditLogActionDiff(r, "rates_catalog_promote", "rates/catalog", details, prom.Before, prom.After)
		writeJSON(w, http.StatusOK, prom)
	}
}
