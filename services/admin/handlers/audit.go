package handlers

import (
	"context"
	"net/http"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

type contextKey string

// AuditLogEntry is the persisted-entry type in adminstore, so the API, the in-memory legacy
// buffer, and the DB read path share one representation.
//
// AUX-14b: Before/After carry JSON snapshots of the entity state around a
// mutating action and Reason carries the operator-supplied motive
// (X-Audit-Reason header). Snapshots are sanitized at write time — secret-like
// fields (key_hash, password_hash, tokens, …) never leave the handler
// (audit_snapshot.go).
//
// AF-10: with a durable audit journal (AuditJournalStore) the full sanitized
// record — snapshots and reason included — is persisted synchronously into
// the hash-chained admin_audit_logs table, and ListAuditLogs reads it back
// from the DB. The per-process buffer remains only as the legacy path for
// stores without the capability.
type AuditLogEntry = adminstore.AuditLogEntry

// AuditLogger is the interface for persisting audit entries.
type AuditLogger interface {
	LogEntry(ctx context.Context, entry AuditLogEntry) error
}

// AuditMiddleware adds audit logging context and headers to responses.
func AuditMiddleware(logger AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rid, ok := r.Context().Value(contextKey("requestID")).(string); ok && rid != "" {
				w.Header().Set("X-Request-Id", rid)
			}
			next.ServeHTTP(w, r)
		})
	}
}
