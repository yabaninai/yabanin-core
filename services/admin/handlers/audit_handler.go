package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/clientip"
)

// auditReasonHeader is the operator-supplied motive for a mutating action
// (AUX-14b). Optional; trimmed and length-capped before it reaches the journal.
const auditReasonHeader = "X-Audit-Reason"

// auditReasonMaxRunes caps the stored reason; longer input is cut, not dropped.
const auditReasonMaxRunes = 512

// auditWriteTimeout bounds one synchronous audit persistence attempt. The
// context is detached from the request, so an audit write survives request
// cancellation but never hangs forever on a sick store.
const auditWriteTimeout = 5 * time.Second

// auditDeliveryInterval is the background drain cadence for the durable
// outbox and the memory-pending queue.
const auditDeliveryInterval = 10 * time.Second

// auditPendingCap bounds the memory-only pending queue. Entries beyond the
// cap are dropped with an error log — they were never durable, and the drop
// is reported, not silent.
const auditPendingCap = 1000

// auditReason extracts the reason for the journal from the request header.
func auditReason(r *http.Request) string {
	reason := strings.TrimSpace(r.Header.Get(auditReasonHeader))
	if reason == "" {
		return ""
	}
	runes := []rune(reason)
	if len(runes) > auditReasonMaxRunes {
		reason = string(runes[:auditReasonMaxRunes])
	}
	return reason
}

// adminIDFromContext extracts the authenticated admin's ID from request context.
func adminIDFromContext(r *http.Request) string {
	if v := r.Context().Value(adminauth.ContextKeyUserID{}); v != nil {
		return v.(string)
	}
	return ""
}

// adminNameFromContext extracts the authenticated admin's display name from request context.
func adminNameFromContext(r *http.Request) string {
	if v := r.Context().Value(adminauth.ContextKeyEmail{}); v != nil {
		return v.(string)
	}
	return ""
}

// generateID creates a random hex string ID.
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// auditLogAction logs an audit entry for sensitive operations.
func (h *AdminHandlers) auditLogAction(r *http.Request, action, resource, details string) {
	h.auditLogActionWithCtx(r.Context(), r, action, resource, details)
}

// auditLogActionWithCtx logs an audit entry using the provided context.
func (h *AdminHandlers) auditLogActionWithCtx(ctx context.Context, r *http.Request, action, resource, details string) {
	h.recordAudit(ctx, r, action, resource, details, nil, nil)
}

// auditLogActionDiff logs an audit entry with before/after entity snapshots
// (AUX-14b). Both values are JSON-sanitized first: secret-like fields are
// redacted and oversized payloads degrade to a truncation marker. The
// operator reason always comes from the X-Audit-Reason request header.
func (h *AdminHandlers) auditLogActionDiff(r *http.Request, action, resource, details string, before, after any) {
	h.recordAudit(r.Context(), r, action, resource, details, auditSnapshot(before), auditSnapshot(after))
}

// recordAudit is the single journal write path: it stamps the entry (full
// sanitized snapshots, reason, timestamp) and persists it (AF-10).
func (h *AdminHandlers) recordAudit(ctx context.Context, r *http.Request, action, resource, details string, before, after json.RawMessage) {
	entry := AuditLogEntry{
		ID:        generateID(),
		Action:    action,
		Resource:  resource,
		Details:   details,
		AdminID:   adminIDFromContext(r),
		AdminName: adminNameFromContext(r),
		IPAddress: clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), h.trustedProxies),
		Timestamp: time.Now().UTC(),
		Before:    before,
		After:     after,
		Reason:    auditReason(r),
	}
	h.persistAudit(ctx, entry)
}

// a zero Timestamp — a writer that skipped stamping — resolves to now UTC, so
// neither the durable row nor the buffer/pending queues can serve
// "0001-01-01" as an audit time.
func stampAuditTimestamp(e AuditLogEntry) AuditLogEntry {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	return e
}

// persistAudit makes the entry durable — synchronously, in this order:
//
//  1. Direct append into the hash-chained admin_audit_logs table (the full
//     sanitized record). Success here is durable success: the API serves the
//     journal from this table, so a restart or a second instance returns it.
//  2. On failure: a durable outbox intent committed to the same DB — the
//     entry survives a process restart and the delivery loop drains it.
//  3. Only when even the outbox is unreachable does the entry stay in the
//     bounded memory-pending queue (retried by the delivery loop, counted in
//     pending_audit_entries) — it is never reported as durable.
//
// This replaces the old fire-and-forget goroutine, which could lose an audit
// entry on process exit while the HTTP response already reported success.
func (h *AdminHandlers) persistAudit(requestCtx context.Context, e AuditLogEntry) {
	e = stampAuditTimestamp(e)
	js := h.auditJournal()
	if js == nil {
		h.bufferAppendAudit(e) // degraded/legacy stores and tests: in-buffer only
		return
	}

	rec := auditRecordFromEntry(e)
	wctx, cancel := context.WithTimeout(context.WithoutCancel(requestCtx), auditWriteTimeout)
	defer cancel()

	err := js.InsertAuditLogEntry(wctx, rec)
	if err == nil {
		return // durably journalled
	}
	h.auditLog().Error("audit journal write failed; recording durable outbox intent",
		"error", err, "action", e.Action, "entry_id", e.ID)

	if err := js.EnqueueAuditOutbox(wctx, rec); err != nil {
		h.pendingAppendAudit(e)
		h.auditLog().Error("audit outbox unavailable; entry held in memory pending retry",
			"error", err, "entry_id", e.ID)
		return
	}
	// Durable intent recorded — try to deliver immediately; the delivery
	// loop retries with backoff otherwise.
	h.flushAuditDelivery(wctx)
	h.ensureAuditDeliveryLoop(requestCtx)
}

// ensureAuditDeliveryLoop starts the background delivery loop once. It lives
// on the first audit write (not the constructor) so its context is inherited
// from a request instead of a bare Background.
func (h *AdminHandlers) ensureAuditDeliveryLoop(requestCtx context.Context) {
	h.auditLoopOnce.Do(func() {
		loopCtx, cancel := context.WithCancel(context.WithoutCancel(requestCtx))
		h.auditMu.Lock()
		h.auditCancel = cancel
		h.auditMu.Unlock()
		go h.auditDeliveryLoop(loopCtx)
	})
}

// auditRecordFromEntry converts the API entry into the persisted record.
func auditRecordFromEntry(e AuditLogEntry) adminstore.AuditLogEntryRecord {
	return adminstore.AuditLogEntryRecord{
		ID:        e.ID,
		Action:    e.Action,
		Resource:  e.Resource,
		Details:   e.Details,
		AdminID:   e.AdminID,
		AdminName: e.AdminName,
		IPAddress: e.IPAddress,
		CreatedAt: e.Timestamp,
		Before:    string(e.Before),
		After:     string(e.After),
		Reason:    e.Reason,
	}
}

// bufferAppendAudit is the legacy in-buffer append (degraded stores without
// the AF-10 capability).
func (h *AdminHandlers) bufferAppendAudit(e AuditLogEntry) {
	h.auditMu.Lock()
	h.auditLogBuffer = append(h.auditLogBuffer, e)
	if len(h.auditLogBuffer) > 2000 {
		h.auditLogBuffer = h.auditLogBuffer[len(h.auditLogBuffer)-1000:]
	}
	h.auditMu.Unlock()
}

// pendingAppendAudit keeps a not-yet-durable entry for the delivery loop.
func (h *AdminHandlers) pendingAppendAudit(e AuditLogEntry) {
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	if len(h.auditPending) >= auditPendingCap {
		dropped := h.auditPending[0]
		h.auditPending = h.auditPending[1:]
		h.auditLog().Error("audit pending queue overflow; dropped oldest non-durable entry",
			"dropped_entry_id", dropped.ID, "action", dropped.Action)
	}
	h.auditPending = append(h.auditPending, e)
}

// pendingAuditCount reports how many entries this process still owes the
// durable journal (the DB outbox adds its own count).
func (h *AdminHandlers) pendingAuditCount() int {
	h.auditMu.RLock()
	defer h.auditMu.RUnlock()
	return len(h.auditPending)
}

// flushAuditDelivery retries the memory-pending queue into the durable
// outbox, then drains due outbox rows into the hash-chained journal.
// Best-effort: errors are logged, entries stay queued.
func (h *AdminHandlers) flushAuditDelivery(ctx context.Context) {
	js := h.auditJournal()
	if js == nil {
		return
	}

	h.auditMu.Lock()
	pending := h.auditPending
	h.auditPending = nil
	h.auditMu.Unlock()

	var undelivered []AuditLogEntry
	for _, e := range pending {
		if err := js.EnqueueAuditOutbox(ctx, auditRecordFromEntry(e)); err != nil {
			undelivered = append(undelivered, e)
		}
	}
	if len(undelivered) > 0 {
		h.auditMu.Lock()
		h.auditPending = append(undelivered, h.auditPending...)
		h.auditMu.Unlock()
	}

	for {
		delivered, err := js.DrainAuditOutbox(ctx, 100)
		if err != nil {
			h.auditLog().Warn("audit outbox drain failed; will retry", "error", err)
			return
		}
		if delivered == 0 {
			return
		}
	}
}

// auditDeliveryLoop drains the durable outbox and the memory-pending queue
// until the context is cancelled (Stop). A process restart loses nothing:
// undelivered entries that made it to the outbox live in the DB.
func (h *AdminHandlers) auditDeliveryLoop(ctx context.Context) {
	ticker := time.NewTicker(auditDeliveryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			drainCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			h.flushAuditDelivery(drainCtx)
			cancel()
		}
	}
}

// auditLog returns the handler logger, never nil (struct-literal test
// instances may leave it unset).
func (h *AdminHandlers) auditLog() *slog.Logger {
	if h.logger != nil {
		return h.logger
	}
	return slog.Default()
}
