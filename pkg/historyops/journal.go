package historyops

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// Journal action vocabulary (03-RIGHTS-MODEL §5): history_op.<op>.<verb>.
// started/denied/completed cover the design; batch and canceled are added
// with the same naming pattern so destructive progress is auditable per
// batch (rows-affected and digest per batch — §5).
const (
	ActionStarted   = "started"
	ActionBatch     = "batch"
	ActionCompleted = "completed"
	ActionCanceled  = "canceled"
	ActionDenied    = "denied"
)

// JournalAction builds a fully qualified audit action name.
func JournalAction(op Operation, verb string) string {
	return "history_op." + string(op) + "." + verb
}

// Entry is one journal record. Details carry identifiers and flags only —
// never payload content, never grant tokens (03-RIGHTS-MODEL §5).
type Entry struct {
	Action string    // full action name (JournalAction)
	OrgID  string    // owning org
	JobID  string    // managed job id
	Op     Operation // operation
	Actor  JobActor  // attributed principal
	// Details are scalar audit fields (string/int64/bool); they are JSON-
	// encoded by journal adapters.
	Details map[string]any
}

// Journaler records engine journal entries. Implementations decide durability
// and audit-degradation behavior (the adminstore-backed adapter inherits the
// outbox/memory-pending degradation of the shared audit seam).
type Journaler interface {
	Journal(ctx context.Context, e Entry) error
}

// MemoryJournaler collects entries in memory — test helper and reference
// implementation.
type MemoryJournaler struct {
	mu      sync.Mutex
	entries []Entry
}

// Journal implements Journaler.
func (m *MemoryJournaler) Journal(_ context.Context, e Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}

// Entries returns a snapshot of journalled entries.
func (m *MemoryJournaler) Entries() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Entry, len(m.entries))
	copy(out, m.entries)
	return out
}

// Reset drops all journalled entries.
func (m *MemoryJournaler) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = nil
}

// Count returns how many entries carry the given action suffix (verb).
func (m *MemoryJournaler) Count(verb string) int {
	n := 0
	for _, e := range m.Entries() {
		if len(e.Action) >= len(verb) && e.Action[len(e.Action)-len(verb):] == verb {
			n++
		}
	}
	return n
}

// AuditJournaler adapts the engine journal onto the durable admin audit seam
// (AF-10): each entry becomes an adminstore.AuditLogEntryRecord inserted via
// the store's audit path, so history-operation entries join the same
// hash-chained journal as every other admin action and any audit degradation
// (outbox / memory-pending) applies identically. DO-NOT-TOUCH: append-only,
// never rewritten.
type AuditJournaler struct {
	// Insert persists one sanitized record (wire to adminstore.Store.
	// InsertAuditLogEntry — a function, so this package does not depend on a
	// concrete store instance).
	Insert func(ctx context.Context, rec adminstore.AuditLogEntryRecord) error
	now    func() time.Time
}

// NewAuditJournaler wires the adapter onto an audit insert function, e.g.
// NewAuditJournaler(store.InsertAuditLogEntry).
func NewAuditJournaler(insert func(ctx context.Context, rec adminstore.AuditLogEntryRecord) error) *AuditJournaler {
	return &AuditJournaler{Insert: insert, now: time.Now}
}

// Journal implements Journaler.
func (a *AuditJournaler) Journal(ctx context.Context, e Entry) error {
	details, err := json.Marshal(e.Details)
	if err != nil {
		// Details are built by the engine from scalars; marshal failure is a
		// programming error — store a marker instead of malformed JSON.
		details = []byte(`{"journal_marshal_error":true}`)
	}
	actor := e.Actor.Normalized()
	rec := adminstore.AuditLogEntryRecord{
		ID:       uuid.NewString(),
		Action:   e.Action,
		Resource: "historyops_job:" + e.JobID,
		Details:  string(details),
		AdminID:  actor.Author,
		// AdminName/IPAddress stay empty: the engine has no HTTP request in
		// scope; the handler layer enriches if it needs to.
		CreatedAt: a.now(),
		Reason:    "org:" + e.OrgID + " op:" + string(e.Op) + " actor:" + string(actor.Type),
	}
	return a.Insert(ctx, rec)
}

// detailf is a small helper the engine uses to build scalar detail maps.
func detailf(pairs ...any) map[string]any {
	out := make(map[string]any, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		key, ok := pairs[i].(string)
		if !ok {
			panic(fmt.Sprintf("historyops: detailf key must be string, got %T", pairs[i]))
		}
		out[key] = pairs[i+1]
	}
	return out
}
