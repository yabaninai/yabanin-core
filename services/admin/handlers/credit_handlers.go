package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/clientip"
	"github.com/reireirei/yabanin/pkg/credits"
)

// creditAuditDropsTotal counts credit-audit entries dropped because the
// bounded audit queue was full — the observability surface for audit loss
var creditAuditDropsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "credit_audit_dropped_total",
	Help: "Credit audit entries dropped because the bounded audit queue was full.",
})

// auditQueueSize bounds the pending credit-audit entries. Overflow is
// counted in creditAuditDropsTotal instead of growing without limit.
const auditQueueSize = 128

// CreditHandlers handles credit/wallet operations for reseller billing.
type CreditHandlers struct {
	store          *credits.Store
	log            LoggerAdapter
	auditLogger    auditInsertLogger
	trustedProxies []string

	auditQueue chan creditAuditEntry
	auditOnce  sync.Once
}

// creditAuditEntry carries the request-derived audit fields. They are
// extracted synchronously — nothing reads the request after the handler
// returns. before/after are sanitized balance snapshots and reason the
type creditAuditEntry struct {
	action, resource, details  string
	adminID, adminName, ipAddr string
	before, after              []byte
	reason                     string
}

// auditInsertLogger is the minimal interface needed by CreditHandlers for
// audit logging. It is the full-record AF-10 protocol (snapshots/reason
// included), so the top-up reason reaches the same hash-chained journal the
// rest of the admin surface writes to; the legacy reason-less v1 wrapper
// would drop it.
type auditInsertLogger interface {
	InsertAuditLogEntry(ctx context.Context, rec adminstore.AuditLogEntryRecord) error
}

// NewCreditHandlers creates handlers backed by the credits store.
func NewCreditHandlers(store *credits.Store, log LoggerAdapter) *CreditHandlers {
	return &CreditHandlers{store: store, log: log}
}

// SetAuditLogger injects an audit logger for financial operations (top-ups).
func (h *CreditHandlers) SetAuditLogger(al auditInsertLogger, trustedProxies []string) {
	h.auditLogger = al
	h.trustedProxies = trustedProxies
}

// generateAuditID creates a random hex string ID for audit entries.
func generateAuditID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("audit-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// fireAuditLog enqueues an audit entry on a bounded single-worker queue so
// the HTTP response isn't blocked and audit writes never grow goroutines
// context — a financial audit entry must survive client cancellation — but
// runs under a short per-entry timeout. Request-derived fields (including
// the reason from the X-Audit-Reason header) are read synchronously.
// Overflow drops the entry and counts it in credit_audit_dropped_total.
func (h *CreditHandlers) fireAuditLog(r *http.Request, action, resource string, details string, before, after json.RawMessage) {
	if h.auditLogger == nil {
		return
	}
	h.enqueueCreditAudit(creditAuditEntry{
		action:    action,
		resource:  resource,
		details:   details,
		adminID:   adminIDFromContext(r),
		adminName: adminNameFromContext(r),
		ipAddr:    clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), h.trustedProxies),
		before:    before,
		after:     after,
		reason:    auditReason(r),
	})
}

// enqueueCreditAudit is the single bounded-queue entry point shared by the
// request-derived audit path and the server-side starter-grant journal.
func (h *CreditHandlers) enqueueCreditAudit(entry creditAuditEntry) {
	if h.auditLogger == nil {
		return
	}
	h.auditOnce.Do(func() {
		h.auditQueue = make(chan creditAuditEntry, auditQueueSize)
		go h.auditWorker()
	})
	select {
	case h.auditQueue <- entry:
	default:
		creditAuditDropsTotal.Inc()
		h.log.Error("credit audit queue full; dropping audit entry",
			"action", entry.action, "dropped_total", creditAuditDropsTotal)
	}
}

// auditWorker is the single durable consumer of the credit-audit queue.
func (h *CreditHandlers) auditWorker() {
	for entry := range h.auditQueue {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := h.auditLogger.InsertAuditLogEntry(ctx, adminstore.AuditLogEntryRecord{
			ID:        generateAuditID(),
			Action:    entry.action,
			Resource:  entry.resource,
			Details:   entry.details,
			AdminID:   entry.adminID,
			AdminName: entry.adminName,
			IPAddress: entry.ipAddr,
			Before:    string(entry.before),
			After:     string(entry.after),
			Reason:    entry.reason,
		})
		cancel()
		if err != nil {
			h.log.Error("failed to write credit audit log", "error", err, "action", entry.action)
		}
	}
}

// TopUpRequest is the body for POST /api/orgs/{id}/credits/topup. Reason is
// consumers may send the field — body first, header as the fallback
// (mutationReason, NEXT-18f). Optional: without either, the top-up is still
// journalled, only without a reason.
type TopUpRequest struct {
	AmountCents int64  `json:"amount_cents"`
	InvoiceRef  string `json:"invoice_ref"`
	Reason      string `json:"reason"`
}

// HandleTopUp processes a manual credit top-up for an org.
func (h *CreditHandlers) HandleTopUp(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if orgID == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org ID is required"})
		return
	}

	var req TopUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
		return
	}

	if req.AmountCents <= 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "amount_cents must be positive"})
		return
	}

	before := h.creditBalanceSnapshot(r.Context(), orgID)
	if err := h.store.TopUp(r.Context(), orgID, req.AmountCents, req.InvoiceRef); err != nil {
		h.log.Error("credit top-up failed", "org_id", orgID, "error", err)
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	after := h.creditBalanceSnapshot(r.Context(), orgID)

	//nolint:contextcheck // the audit write is intentionally detached from the request context — a financial audit entry must survive client cancellation; each entry runs under its own 5s timeout
	h.topUpAudit(r, orgID, req, before, after)
	h.log.Info("credit top-up processed", "org_id", orgID, "amount_cents", req.AmountCents, "invoice_ref", req.InvoiceRef)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "topped_up",
		"org_id":       orgID,
		"amount_cents": req.AmountCents,
		"increase_usd": float64(req.AmountCents) / 100.0,
	})
}

// topUpAudit journals one completed top-up (NEXT-18f org-settings pattern):
// symmetric before/after balance snapshots plus the operator reason — the
// JSON body `reason` field first, the X-Audit-Reason header as the fallback.
// A missing reason still journals the entry (the money facts must survive).
func (h *CreditHandlers) topUpAudit(r *http.Request, orgID string, req TopUpRequest, before, after map[string]any) {
	mutationReason(req.Reason, r)
	h.fireAuditLog(r, "credit_top_up", fmt.Sprintf("org:%s", orgID),
		fmt.Sprintf("credit_top_up org_id=%s amount_cents=%d invoice_ref=%s", orgID, req.AmountCents, req.InvoiceRef),
		auditSnapshot(before), auditSnapshot(after))
}

// creditBalanceSnapshot renders the current wallet balance as one journal
// snapshot side. A read failure degrades to nil — the journal keeps the
// other side, and the mutation itself is never blocked by a snapshot
// problem (mirrors orgBudgetSettingsBefore).
func (h *CreditHandlers) creditBalanceSnapshot(ctx context.Context, orgID string) map[string]any {
	if h.store == nil {
		return nil
	}
	bal, err := h.store.GetBalance(ctx, orgID)
	if err != nil {
		return nil
	}
	return map[string]any{"org_id": bal.OrgID, "balance_cents": bal.BalanceCents}
}

// HandleGetBalance returns the current balance for an org.
func (h *CreditHandlers) HandleGetBalance(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if orgID == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org ID is required"})
		return
	}

	bal, err := h.store.GetBalance(r.Context(), orgID)
	if err != nil {
		h.log.Error("get balance failed", "org_id", orgID, "error", err)
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"org_id":        bal.OrgID,
		"balance_cents": bal.BalanceCents,
		"balance_usd":   float64(bal.BalanceCents) / 100.0,
		"updated_at":    bal.UpdatedAt,
	})
}

// HandleGetTransactions returns recent transactions for an org.
func (h *CreditHandlers) HandleGetTransactions(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if orgID == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org ID is required"})
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	txns, err := h.store.GetTransactions(r.Context(), orgID, limit)
	if err != nil {
		h.log.Error("get transactions failed", "org_id", orgID, "error", err)
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"org_id": orgID,
		"limit":  limit,
		"count":  len(txns),
		"txns":   txns,
	})
}

// HandleLowBalance returns all orgs with balance below a threshold.
func (h *CreditHandlers) HandleLowBalance(w http.ResponseWriter, r *http.Request) {
	threshold := int64(-500) // 5 dollars below zero by default
	if t := r.URL.Query().Get("threshold"); t != "" {
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			threshold = n
		}
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	orgIDs, err := h.store.LowBalanceOrgs(r.Context(), threshold, limit)
	if err != nil {
		h.log.Error("low balance query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	// The wire contract is a JSON array (web LowBalanceOrgsResponse.org_ids:
	// string[]). A no-hit query yields a Go nil slice, which encodes as null
	// and crashed the dashboard budgets page on every fresh demo org
	// (null.includes). Encode the empty answer as [].
	if orgIDs == nil {
		orgIDs = []string{}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"threshold_cents": threshold,
		"count":           len(orgIDs),
		"org_ids":         orgIDs,
	})
}

// ---- W-CRED: beta starter grant + org-scoped wallet reads ----

// GrantBetaStarterCredits applies the beta starter grant to a freshly created
// org (both org-creation paths land here: the seed runner calls the package
// directly, the admin create-org API — the org+invite flow — calls this).
// Idempotent per org: exactly one "beta-starter-grant" ledger row ever.
//
// Best-effort by design: a grant failure must not fail an already-committed
// org creation (the client would retry into a slug conflict), so it logs
// loudly instead. The amount comes from BETA_STARTER_CREDITS_CENTS
// (default 5000); zero disables.
func (h *AdminHandlers) GrantBetaStarterCredits(r *http.Request, orgID string) {
	if h.billing.credit == nil || orgID == "" {
		return // credits surface not wired, or nothing to grant onto
	}
	amount := credits.StarterGrantCents()
	if amount <= 0 {
		return // disabled by configuration
	}
	before := h.billing.credit.creditBalanceSnapshot(r.Context(), orgID)
	granted, err := h.billing.credit.store.EnsureStarterGrant(r.Context(), orgID, amount)
	if err != nil {
		h.logger.Error("beta starter grant failed", "org_id", orgID, "amount_cents", amount, "error", err)
		return
	}
	if granted {
		h.billing.credit.starterGrantAudit(r, orgID, amount, before)
	}
}

// starterGrantAudit journals one applied starter grant with the fixed server
// motive "beta-starter-grant" (the X-Audit-Reason equivalent for a grant no
// operator directly requested), including the balance snapshots.
func (h *CreditHandlers) starterGrantAudit(r *http.Request, orgID string, amountCents int64, before map[string]any) {
	after := h.creditBalanceSnapshot(r.Context(), orgID)
	//nolint:contextcheck // the audit write is intentionally detached from the request context — the same durability rule as the top-up surface (each entry runs under its own 5s timeout)
	h.enqueueCreditAudit(creditAuditEntry{
		action:    "credit_starter_grant",
		resource:  fmt.Sprintf("org:%s", orgID),
		details:   fmt.Sprintf("beta_starter_grant org_id=%s amount_cents=%d reason=%s", orgID, amountCents, credits.StarterGrantReason),
		adminID:   adminIDFromContext(r),
		adminName: adminNameFromContext(r),
		ipAddr:    clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), h.trustedProxies),
		before:    auditSnapshot(before),
		after:     auditSnapshot(after),
		reason:    credits.StarterGrantReason,
	})
}

// RequireOrgPermissionCreditsRead gates the org-scoped credit wallet reads
// (GET /api/orgs/{id}/credits/balance and /transactions) behind
// adminstore.PermBudgetsManage on the target org — the org-admin view of
// their own wallet, previously root-only. The foreign-org dimension is
// fail-closed the S01 way:
//
//	root (platform operator)          → pass
//	member with budgets.manage        → pass
//	member without budgets.manage     → 403 (authenticated, not allowed)
//	no membership on the target org   → 404 (the wallet's existence stays hidden)
//
// Named with the RequireOrgPermission fragment so the route inventories
// classify it as an org-permission gate (the org_credentials.go precedent).
func (h *AdminHandlers) RequireOrgPermissionCreditsRead() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isRoot(r) {
				next.ServeHTTP(w, r)
				return
			}
			orgID := targetOrgID(r)
			if orgID == "" {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "org target required"})
				return
			}
			role, ok := h.callerRoleOnOrg(r, orgID)
			if !ok {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			if !adminstore.RoleHas(string(role), adminstore.PermBudgetsManage) {
				writeJSON(w, http.StatusForbidden, apiError{Error: "insufficient permission for this organization"})
				return
			}
			// Pin the resolved org as the request scope for the handler layer.
			ctx := context.WithValue(r.Context(), ctxKeyOrgScope{}, orgID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
