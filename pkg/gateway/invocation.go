package cli

// invocation.go — Preview2 durable per-invocation accounting writer.
//
// Every request that can spend paid provider quota gets a server-minted
// invocation_id (canonical uuid, distinct from the client X-Request-ID,
// which stays correlation-only). The identity is minted once per request;
// the durable start (request_admissions row) commits at the FIRST PAID
// DISPATCH — after the cache lookup, mirroring the reservation gate's
// reserve() placement — so the free-cache identity path (cache hit:
// minted uuid on the event, no admission row, no terminal facts) cannot
// collide with paid accounting.
//
// Fail-closed posture (owner verdict, Preview2): an admission write
// failure or lost ack refuses the request with the I40
// history_unavailable 503 envelope and ZERO provider arrivals — retries
// and fallbacks included. The store seam is explicit: production wiring
// injects the pool-backed store, isolated tests inject a fake, and the
// store itself NEVER no-ops on a missing pool — it fails closed.
//
// Terminal facts (request_terminal_facts) commit synchronously at
// finalize, BEFORE the completion event is published, from the
// coordinator's content-free projection (Event.TerminalAccountingFields —
// validated identity/tenant/type, allowlisted scalars, re-encoded
// reservation tuples, used_org_key preserved). On a facts-write failure
// the event MUST NOT publish: usage already spent without durable facts
// stays discoverable as an unresolved admission instead of silently
// masquerading as durably accounted.
//
// Lifecycle race rules (all transitions serialized under the holder
// mutex): dispatch is blocked from the first void ATTEMPT (a proven
// never-dispatched start can never dispatch later, even while the void
// row-write is retrying after a database error) AND from a failed
// admission commit (outcome unknown — the SAME holder can never grant a
// fallback hop; only a fresh client invocation, with a newly minted
// identity, may retry); terminal facts cannot commit on a voided or
// void-pending identity; void cannot commit after terminal facts (facts
// are authoritative — the consumer reconciles from them). A terminal
// re-commit is always re-verified against the durable row (never
// short-circuited locally): an identical projection is a no-op win, a
// changed one surfaces ErrTerminalFactsDivergent.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	apierrors "github.com/reireirei/yabanin/pkg/errors"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// Durable invocation kinds (request_admissions.kind CHECK domain). Chat
// and every synchronous nonchat provider-direct endpoint (embeddings,
// completions, native protocols, audio, batch lines) are 'chat'-class
// request/response invocations; 'stream' marks SSE-class dispatch; the
// endpoint detail rides the terminal facts' endpoint field, not the kind.
const (
	invocationKindChat   = "chat"
	invocationKindStream = "stream"
	invocationKindJudge  = "judge"
	invocationKindShadow = "shadow"
)

func validInvocationKind(kind string) bool {
	switch kind {
	case invocationKindChat, invocationKindStream, invocationKindJudge, invocationKindShadow:
		return true
	}
	return false
}

var (
	// ErrInvocationStoreUnavailable marks a failed/lost-ack durable write:
	// the caller must fail closed (zero provider arrivals for admission,
	// no publish for terminal facts) with the history_unavailable
	// envelope. Retriable at the caller's discretion.
	ErrInvocationStoreUnavailable = errors.New("invocation accounting store unavailable")
	// ErrInvocationVoided marks a dispatch attempt on an identity whose
	// void was attempted or completed — a path-ordering bug, not
	// retriable by dispatching.
	ErrInvocationVoided = errors.New("invocation voided or void pending")
	// ErrInvocationTerminal marks an attempt to dispatch or void an
	// identity whose terminal facts already committed.
	ErrInvocationTerminal = errors.New("invocation terminal facts already committed")
	// ErrTerminalFactsDivergent marks a terminal re-commit whose org,
	// kind or payload disagrees with the committed row. The first commit
	// stays authoritative; divergence is surfaced loudly, never silently
	// accepted and never overwritten.
	ErrTerminalFactsDivergent = errors.New("terminal facts diverge from committed row")
)

// admissionRecord is the durable start row (request_admissions).
type admissionRecord struct {
	InvocationID    string
	OrgID           string
	Kind            string
	ClientRequestID string
	SessionID       string
	APIKeyID        *int64
	SessionKeyID    *int64
	ModelRequested  string
}

// terminalFactsRecord is the synchronous terminal write
// (request_terminal_facts). Fields is the validated content-free
// projection; the store persists it verbatim as jsonb.
type terminalFactsRecord struct {
	InvocationID    string
	OrgID           string
	Kind            string
	ClientRequestID string
	Fields          map[string]string
}

// invocationStore is the durable-accounting seam. Production injects
// NewPGInvocationStore over the gateway pool; isolated tests inject a
// fake. A missing pool fails closed — it never degrades to a no-op.
type invocationStore interface {
	AdmitInvocation(ctx context.Context, rec admissionRecord) error
	VoidInvocation(ctx context.Context, invocationID string) error
	RecordTerminalFacts(ctx context.Context, rec terminalFactsRecord) error
}

// invocationIdentity is the per-request minted identity and its durable
// lifecycle state. It rides the request context (the reservation gate's
// pattern) so stream finishers, native finishers, the judge client and
// the shadow runner reach it without signature churn.
type invocationIdentity struct {
	id              string
	orgID           string
	clientRequestID string
	sessionID       string
	apiKeyID        string
	sessionKeyID    string
	modelRequested  string

	mu              sync.Mutex
	kind            string // kind recorded at first paid dispatch
	admitted        bool   // durable start committed
	startRefused    bool   // admission commit failed: this holder never dispatches
	dispatchBlocked bool   // void attempted: dispatch forbidden from here on
	voided          bool   // void row-write committed
	terminal        bool   // terminal facts committed
}

// mintInvocationID returns a fresh canonical uuid string. The wire
// validates canonical form; malformed values park rather than downgrade
// to the legacy dedupe domain, so only canonical uuids are ever emitted.
func mintInvocationID() string { return uuid.NewString() }

// newInvocationIdentity captures the request's correlation and
// attribution fields. Key ids arrive as header strings; the schema stores
// bigint, so unparsable values bind NULL (correlation is not identity —
// a lost key id must never fail accounting).
func newInvocationIdentity(orgID, clientRequestID, sessionID, apiKeyID, sessionKeyID, modelRequested string) *invocationIdentity {
	return &invocationIdentity{
		id:              mintInvocationID(),
		orgID:           orgID,
		clientRequestID: clientRequestID,
		sessionID:       sessionID,
		apiKeyID:        apiKeyID,
		sessionKeyID:    sessionKeyID,
		modelRequested:  modelRequested,
	}
}

// ID returns the minted canonical uuid.
func (h *invocationIdentity) ID() string { return h.id }

// Admitted reports whether the durable start committed.
func (h *invocationIdentity) Admitted() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.admitted
}

// Kind returns the dispatch kind recorded at admission ("" before).
func (h *invocationIdentity) Kind() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.kind
}

// invocationKeyID parses a header key id into the schema's bigint column;
// empty or unparsable binds NULL.
func invocationKeyID(s string) *int64 {
	if s == "" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	return &n
}

func (h *invocationIdentity) admissionRecord(kind string) admissionRecord {
	return admissionRecord{
		InvocationID:    h.id,
		OrgID:           h.orgID,
		Kind:            kind,
		ClientRequestID: h.clientRequestID,
		SessionID:       h.sessionID,
		APIKeyID:        invocationKeyID(h.apiKeyID),
		SessionKeyID:    invocationKeyID(h.sessionKeyID),
		ModelRequested:  h.modelRequested,
	}
}

// beginPaidDispatch commits the durable start exactly once per request,
// under the kind of the first dispatch (a stream fallback after a failed
// JSON hop in one request is still one invocation). Retry/fallback loops
// call it before every hop; only the first lands, the rest are no-ops.
// Fail-closed: a store error returns without marking admitted; a voided
// or void-pending identity refuses dispatch outright.
func nilInvocationStore(store invocationStore) error {
	if store == nil {
		return fmt.Errorf("%w: nil store", ErrInvocationStoreUnavailable)
	}
	return nil
}

func (h *invocationIdentity) beginPaidDispatch(ctx context.Context, store invocationStore, kind string) error {
	if !validInvocationKind(kind) {
		return fmt.Errorf("invalid invocation kind %q", kind)
	}
	if err := nilInvocationStore(store); err != nil {
		return err
	}
	// Both accounting tables bind org_id NOT NULL and the terminal
	// projection rejects an empty tenant: an org-less paid request could
	// be dispatched but never durably accounted, so it refuses up front
	// (fail-closed) instead of failing its terminal commit after the
	// provider was already paid.
	if h.orgID == "" {
		return fmt.Errorf("%w: %s has no tenant attribution", ErrInvocationStoreUnavailable, h.id)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.startRefused:
		return fmt.Errorf("%w: start refusal latched for %s", ErrInvocationStoreUnavailable, h.id)
	case h.dispatchBlocked || h.voided:
		return fmt.Errorf("%w: %s", ErrInvocationVoided, h.id)
	case h.terminal:
		return fmt.Errorf("%w: %s", ErrInvocationTerminal, h.id)
	case h.admitted:
		return nil
	}
	if err := store.AdmitInvocation(ctx, h.admissionRecord(kind)); err != nil {
		// The commit outcome is unknown: this holder can never grant a
		// dispatch (a fallback hop would risk unaccounted spend). Only
		// a fresh client invocation — a newly minted identity — retries.
		h.startRefused = true
		return fmt.Errorf("%w: admit %s: %w", ErrInvocationStoreUnavailable, h.id, err)
	}
	h.kind, h.admitted = kind, true
	return nil
}

// void marks a start proven never to have dispatched. Dispatch is blocked
// from the ATTEMPT (a proven-never-dispatched identity can never dispatch
// later); the row-write is retriable — a database error leaves voided
// false so the caller can retry, while dispatch stays disabled. Void is
// refused outright once terminal facts committed (facts are
// authoritative; the consumer reconciles from them).
func (h *invocationIdentity) void(ctx context.Context, store invocationStore) error {
	if err := nilInvocationStore(store); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dispatchBlocked = true
	if h.terminal {
		return fmt.Errorf("%w: cannot void %s", ErrInvocationTerminal, h.id)
	}
	if h.voided || !h.admitted {
		// Never-admitted identities (free-cache path, pre-dispatch
		// refusals) have no row; the local block is the whole story.
		h.voided = true
		return nil
	}
	if err := store.VoidInvocation(ctx, h.id); err != nil {
		return fmt.Errorf("%w: void %s: %w", ErrInvocationStoreUnavailable, h.id, err)
	}
	h.voided = true
	return nil
}

// recordTerminalFacts commits the synchronous terminal write from the
// validated projection map (Event.TerminalAccountingFields output,
// consumed verbatim — never the raw event struct). Idempotent under
// exact equality: an identical re-commit (retry after a lost publish
// ack) is a no-op win; a conflicting org, kind or payload surfaces
// ErrTerminalFactsDivergent with the committed row's identity. Terminal
// facts require the admission row (composite FK) and are refused on a
// voided identity.
func (h *invocationIdentity) recordTerminalFacts(ctx context.Context, store invocationStore, fields map[string]string) error {
	if err := nilInvocationStore(store); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.voided, h.dispatchBlocked:
		return fmt.Errorf("%w: terminal facts refused on voided %s", ErrInvocationVoided, h.id)
	case !h.admitted:
		return fmt.Errorf("terminal facts require an admitted invocation: %s", h.id)
	}
	if len(fields) == 0 {
		return fmt.Errorf("terminal facts projection is empty: %s", h.id)
	}
	rec := terminalFactsRecord{
		InvocationID:    h.id,
		OrgID:           h.orgID,
		Kind:            h.kind,
		ClientRequestID: h.clientRequestID,
		Fields:          fields,
	}
	if err := store.RecordTerminalFacts(ctx, rec); err != nil {
		if errors.Is(err, ErrTerminalFactsDivergent) {
			return err
		}
		return fmt.Errorf("%w: terminal facts %s: %w", ErrInvocationStoreUnavailable, h.id, err)
	}
	h.terminal = true
	return nil
}

// commitInvocationTerminal stamps nothing on the event — the finalizer
// must already have set ev.InvocationID to the holder's id and a single
// ev.TS > 0 before BOTH the facts commit and the publish (one timestamp,
// one identity, both surfaces agree). It projects the content-free
// fields and commits them; a projection or store failure fails the
// finalization loudly (the event must not publish).
func (h *invocationIdentity) commitInvocationTerminal(ctx context.Context, store invocationStore, ev *eventpub.Event) error {
	if ev == nil {
		return errors.New("terminal commit requires an event")
	}
	if ev.InvocationID != h.id {
		return fmt.Errorf("event invocation %q is not the admitted identity %q", ev.InvocationID, h.id)
	}
	if ev.OrgID != h.orgID {
		return fmt.Errorf("event org %q is not the admitted org %q for %s", ev.OrgID, h.orgID, h.id)
	}
	fields, err := ev.TerminalAccountingFields()
	if err != nil {
		return fmt.Errorf("terminal projection for %s: %w", h.id, err)
	}
	return h.recordTerminalFacts(ctx, store, fields)
}

// --- PostgreSQL store ---

// pgInvocationStore is the production store over the gateway pool. A nil
// pool fails every method closed — zero provider arrivals — instead of
// granting a silent no-op.
type pgInvocationStore struct {
	pool *pgxpool.Pool
}

// NewPGInvocationStore binds the durable-accounting store to the gateway
// pool. The pool must be the production pool (services/run wiring); a
// nil pool keeps every method fail-closed as defense in depth.
func NewPGInvocationStore(pool *pgxpool.Pool) invocationStore {
	return pgInvocationStore{pool: pool}
}

func (s pgInvocationStore) AdmitInvocation(ctx context.Context, rec admissionRecord) error {
	if s.pool == nil {
		return fmt.Errorf("%w: no pool", ErrInvocationStoreUnavailable)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO request_admissions
			(invocation_id, org_id, kind, client_request_id, session_id,
			 api_key_id, session_key_id, model_requested, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'admitted')`,
		rec.InvocationID, rec.OrgID, rec.Kind, nullIfEmpty(rec.ClientRequestID),
		nullIfEmpty(rec.SessionID), rec.APIKeyID, rec.SessionKeyID,
		nullIfEmpty(rec.ModelRequested)); err != nil {
		return err
	}
	return nil
}

func (s pgInvocationStore) VoidInvocation(ctx context.Context, invocationID string) error {
	if s.pool == nil {
		return fmt.Errorf("%w: no pool", ErrInvocationStoreUnavailable)
	}
	// The UPDATE takes the admission row lock; the terminal-facts writer
	// takes the same lock BEFORE inserting facts, so the two order
	// linearizably. The NOT EXISTS guard is the state side of that
	// serialization: terminal evidence (present facts) outranks void even
	// while the admission row still reads 'admitted' — the consumer
	// reconciles from facts, never from a void.
	tag, err := s.pool.Exec(ctx, `
		UPDATE request_admissions
		SET state = 'voided', resolved_at = now(), resolve_reason = 'proven_no_dispatch'
		WHERE invocation_id = $1 AND state = 'admitted'
		  AND NOT EXISTS (SELECT 1 FROM request_terminal_facts f
		                  WHERE f.invocation_id = request_admissions.invocation_id)`,
		invocationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Serialize against recovery and idempotent retries: a row already
		// 'voided' is a no-op win; terminal facts or a reconciler-won state
		// refuse the void loudly.
		var state string
		var hasFacts bool
		if qerr := s.pool.QueryRow(ctx, `
			SELECT a.state,
			       EXISTS (SELECT 1 FROM request_terminal_facts f
			               WHERE f.invocation_id = a.invocation_id)
			FROM request_admissions a WHERE a.invocation_id = $1`,
			invocationID).Scan(&state, &hasFacts); qerr != nil {
			if errors.Is(qerr, pgx.ErrNoRows) {
				return fmt.Errorf("%w: void target %s missing", ErrInvocationStoreUnavailable, invocationID)
			}
			return qerr
		}
		switch {
		case hasFacts:
			return fmt.Errorf("%w: void of %s lost the race to terminal facts", ErrInvocationTerminal, invocationID)
		case state == "voided":
			return nil // idempotent retry of an already-voided start
		default:
			return fmt.Errorf("%w: void of %s lost the race to state %q", ErrInvocationTerminal, invocationID, state)
		}
	}
	return nil
}

// RecordTerminalFacts persists the projection verbatim as jsonb and is
// idempotent under exact equality: the guarded conflict arm updates
// nothing (first commit authoritative) and returns
// ErrTerminalFactsDivergent when org, kind or payload disagree.
//
// The write runs in one transaction that first takes the admission row
// lock (SELECT ... FOR UPDATE) and validates state: the plain foreign key
// alone cannot order facts against a concurrent void — the row lock does.
// 'voided' refuses facts (the start is proven never-dispatched); every
// other state accepts, because facts are the authoritative terminal
// evidence: 'unresolved' means the grace sweep classified a missing
// terminal write that has now arrived (late facts still materialize), and
// 'reconciled' means the facts row already exists and only the equality
// arm below can still decide the retry.
func (s pgInvocationStore) RecordTerminalFacts(ctx context.Context, rec terminalFactsRecord) error {
	if s.pool == nil {
		return fmt.Errorf("%w: no pool", ErrInvocationStoreUnavailable)
	}
	event, err := json.Marshal(rec.Fields)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: begin terminal tx for %s: %w", ErrInvocationStoreUnavailable, rec.InvocationID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := insertInvocationFacts(ctx, tx, rec, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return s.verifyFailedCommit(ctx, rec, event, err)
	}
	return nil
}

// A fresh read distinguishes an acknowledged-by-storage commit from a
// transaction that can be retried under the same invocation.
func (s pgInvocationStore) verifyFailedCommit(ctx context.Context, rec terminalFactsRecord, event []byte, cause error) error {
	state, err := s.verifyTerminalFacts(ctx, rec, event)
	if err != nil {
		return fmt.Errorf("%w: commit terminal facts for %s: %w (verify: %w)",
			ErrInvocationStoreUnavailable, rec.InvocationID, cause, err)
	}
	switch state {
	case terminalVerifyIdentical:
		return nil
	case terminalVerifyDivergent:
		return fmt.Errorf("%w: commit verification for %s", ErrTerminalFactsDivergent, rec.InvocationID)
	default:
		return fmt.Errorf("%w: commit terminal facts for %s: %w", ErrInvocationStoreUnavailable, rec.InvocationID, cause)
	}
}

// Serialize the terminal write with a concurrent void of the same admission.
func insertInvocationFacts(ctx context.Context, tx pgx.Tx, rec terminalFactsRecord, event []byte) error {
	var state string
	if err := tx.QueryRow(ctx, `
		SELECT state FROM request_admissions
		WHERE invocation_id = $1 AND org_id = $2
		FOR UPDATE`, rec.InvocationID, rec.OrgID).Scan(&state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: admission %s (org %s) missing for terminal facts",
				ErrInvocationStoreUnavailable, rec.InvocationID, rec.OrgID)
		}
		return err
	}
	if state == "voided" {
		return fmt.Errorf("%w: terminal facts refused for voided %s", ErrInvocationVoided, rec.InvocationID)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO request_terminal_facts (invocation_id, org_id, kind, client_request_id, event)
		VALUES ($1, $2, $3, $4, $5::jsonb)
		ON CONFLICT (invocation_id) DO UPDATE
			SET committed_at = request_terminal_facts.committed_at
			WHERE request_terminal_facts.org_id = EXCLUDED.org_id
			  AND request_terminal_facts.kind   = EXCLUDED.kind
			  AND request_terminal_facts.client_request_id IS NOT DISTINCT FROM EXCLUDED.client_request_id
			  AND request_terminal_facts.event  = EXCLUDED.event
		RETURNING invocation_id`,
		rec.InvocationID, rec.OrgID, rec.Kind, nullIfEmpty(rec.ClientRequestID), event)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: invocation=%s", ErrTerminalFactsDivergent, rec.InvocationID)
	}
	return nil
}

// terminalVerifyState classifies the same-ID verification read after an
// ambiguous commit.
type terminalVerifyState int8

const (
	terminalVerifyAbsent    terminalVerifyState = iota // commit did not land
	terminalVerifyIdentical                            // commit landed; row matches
	terminalVerifyDivergent                            // row exists but differs
)

// verifyTerminalFacts re-reads the facts row for the SAME invocation ID
// outside any transaction — a plain read suffices because the row, once
// committed, is immutable.
func (s pgInvocationStore) verifyTerminalFacts(ctx context.Context, rec terminalFactsRecord, event []byte) (terminalVerifyState, error) {
	var identical bool
	err := s.pool.QueryRow(ctx, `
		SELECT org_id = $2 AND kind = $3 AND client_request_id IS NOT DISTINCT FROM $4::text
		       AND event = $5::jsonb
		FROM request_terminal_facts WHERE invocation_id = $1`,
		rec.InvocationID, rec.OrgID, rec.Kind, nullIfEmpty(rec.ClientRequestID), event).Scan(&identical)
	if errors.Is(err, pgx.ErrNoRows) {
		return terminalVerifyAbsent, nil
	}
	if err != nil {
		return terminalVerifyAbsent, fmt.Errorf("verify terminal facts %s: %w", rec.InvocationID, err)
	}
	if identical {
		return terminalVerifyIdentical, nil
	}
	return terminalVerifyDivergent, nil
}

// invocationCtxKey rides the request context like the reservation gate:
// minted once at central admission, read at the first paid dispatch site
// and at the single finishRequest terminal funnel.
type invocationCtxKeyType struct{}

var invocationCtxKey invocationCtxKeyType

func withInvocationIdentity(ctx context.Context, h *invocationIdentity) context.Context {
	if h == nil {
		return ctx
	}
	return context.WithValue(ctx, invocationCtxKey, h)
}

// invocationIDFromCtx renders the holder id for logs ("" when absent).
func invocationIDFromCtx(ctx context.Context) string {
	if h := invocationIdentityFrom(ctx); h != nil {
		return h.ID()
	}
	return ""
}

func invocationIdentityFrom(ctx context.Context) *invocationIdentity {
	h, _ := ctx.Value(invocationCtxKey).(*invocationIdentity)
	return h
}

// invocationKindForChat maps the chat pipeline transport to the durable
// kind domain: SSE clients are 'stream'; JSON chat (and nonchat sync
// riding this pipeline) is 'chat'. Endpoint detail rides the facts.
func invocationKindForChat(stream bool) string {
	if stream {
		return invocationKindStream
	}
	return invocationKindChat
}

// confirmPaidInvocation orders the durable start BEFORE the first paid
// provider dispatch (mirroring reservationGate.reserve: post-cache-miss,
// once per request — retries, fallbacks and hops inside one request share
// the single admission; the kind binds to the transport actually
// dispatched first). CENTRAL BINDING: a nil holder OR a nil store refuses
// the paid call — there is no production bypass (a missing identity or an
// unwired store is a misconfiguration, not legacy mode); isolated tests
// wire an explicit fake store. Timeout and lost-ACK commits are failures
// of unknown outcome and refuse the same way.
func (gw *gateway) confirmPaidInvocation(ctx context.Context, kind string) error {
	h := invocationIdentityFrom(ctx)
	if h == nil {
		return fmt.Errorf("%w: no invocation identity on the request context (admission core must mint one)",
			ErrInvocationStoreUnavailable)
	}
	if gw.invocations == nil {
		return fmt.Errorf("%w: no invocation store wired on the gateway", ErrInvocationStoreUnavailable)
	}
	return h.beginPaidDispatch(ctx, gw.invocations, kind)
}

// writeInvocationStartRefusal answers a failed durable start with the
// external code EXACTLY history_unavailable — same envelope family as the
// I40 durable-history outage: a deployment-level condition, not a wallet
// or budget refusal. Zero provider arrivals accompany it.
func writeInvocationStartRefusal(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrInvocationStoreUnavailable) {
		apierrors.WriteWithCode(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
			"durable request accounting temporarily unavailable: the paid call was not sent because its start could not be confirmed",
			"history_unavailable")
		return
	}
	apierrors.Write(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI,
		fmt.Sprintf("refusing paid dispatch: %v", err))
}

// stampAndCommitInvocationTerminal is the finishRequest funnel seam: it
// stamps the minted identity on the event and, for an ADMITTED invocation,
// commits the content-free terminal facts with a BOUNDED INDEPENDENT
// context (client cancellation must not kill the accounting write; values
// are preserved via WithoutCancel) and one TS so the facts row and the
// published event agree. Returns the facts-commit error: the funnel then
// withholds the event from the consumer (a published completion whose
// facts row is absent parks in the consumer) and the reconciler's grace
// sweep owns the admitted-without-facts row (unresolved → attention).
// Cache hits and legacy (holder absent) carry identity without facts.
func (gw *gateway) stampAndCommitInvocationTerminal(ctx context.Context, ev *eventpub.Event, l *slog.Logger) error {
	h := invocationIdentityFrom(ctx)
	if h == nil {
		return nil
	}
	ev.InvocationID = h.ID()
	if !h.Admitted() {
		return nil // free-cache contract: id on the wire, no admission row, no facts
	}
	if gw.invocations == nil {
		return fmt.Errorf("%w: admitted invocation %s has no store to commit terminal facts", ErrInvocationStoreUnavailable, h.ID())
	}
	if ev.TS == 0 {
		ev.TS = time.Now().UnixMilli()
	}
	err := retryInvocationWrite(ctx, func(ctx context.Context) error {
		return h.commitInvocationTerminal(ctx, gw.invocations, ev)
	})
	if err != nil {
		l.Error("terminal facts commit failed after paid dispatch; withholding event from consumer",
			"invocation_id", h.ID(), "error", err)
	}
	return err
}

// Call only when every candidate was rejected before any upstream dispatch.
func (gw *gateway) voidUndispatchedInvocation(ctx context.Context, l *slog.Logger) {
	h := invocationIdentityFrom(ctx)
	if h == nil || !h.Admitted() {
		return
	}
	err := retryInvocationWrite(ctx, func(ctx context.Context) error {
		return h.void(ctx, gw.invocations)
	})
	if err != nil {
		l.Error("could not close admission after local refusal", "invocation_id", h.ID(), "error", err)
	}
}

// Both operations use a stable invocation ID and permit identical recommits.
func retryInvocationWrite(ctx context.Context, write func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalFactsTimeout)
	defer cancel()
	for attempt := 1; ; attempt++ {
		err := write(ctx)
		if attempt == terminalFactsAttempts || !shouldRetryTerminalCommit(err) {
			return err
		}
		select {
		case <-time.After(terminalFactsRetryBackoff << uint(attempt-1)):
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		}
	}
}

// shouldRetryTerminalCommit decides the bounded idempotent same-UUID/
// same-payload terminal recommit (owner transport review): the write is
// idempotent under exact equality, so ANY ambiguous outcome — transient
// transaction classes (40001 serialization_failure, 40P01 deadlock) and
// transport ambiguity (disconnect before OR after commit: never-landed
// retries as a plain insert, landed-but-unacked retries into the
// equality arm) — is safe to recommit within the bounded independent
// window. Deterministic outcomes are not retried: a divergent stored
// payload can never converge, and a definitive SQL rejection (constraint,
// disk) fails closed so the reconciler owns the admitted row.
func shouldRetryTerminalCommit(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrTerminalFactsDivergent) {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == "40001", pgErr.Code == "40P01":
			// serialization_failure / deadlock_detected
			return true
		case pgErr.Code == "57P01", pgErr.Code == "57P02", pgErr.Code == "57P03":
			// admin_shutdown / crash_shutdown / cannot_connect_now: the
			// session was killed before commit (physical oracle
			// pg_terminate_backend) — outcome unknown, recommit safe.
			return true
		case strings.HasPrefix(pgErr.Code, "08"):
			// connection_exception class (08006 connection_failure,
			// 08003 connection_does_not_exist…): same unknown-outcome
			// posture as a transport EOF.
			return true
		}
		return false
	}
	return isTransportAmbiguity(err)
}

// isTransportAmbiguity reports connection-level unknowns: EOF mid-write,
// resets, broken pipes, net timeouts, or the bounded window expiring
// mid-attempt. None of them determines whether the row landed.
func isTransportAmbiguity(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// accountingCommitFailedCode is the external code for a POST-DISPATCH
// terminal-facts failure: the provider work already ran, so this is NOT a
// safe-retry signal (a retry re-bills under a new invocation).
const accountingCommitFailedCode = "accounting_commit_failed"

// writeTerminalAccountingFailure answers the client after usage was
// already dispatched upstream but its durable record could not be
// committed. Deliberately no safe-retry language (central binding): the
// reconciler owns the admitted row; support reconciles the charge.
func writeTerminalAccountingFailure(w http.ResponseWriter) {
	w.Header().Set("X-Should-Retry", "false")
	apierrors.WriteWithCode(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI,
		"upstream request completed but its durable usage record could not be committed; NOT safe to retry — support reconciles the charge",
		accountingCommitFailedCode)
}

// terminalFactsTimeout bounds the independent finalization so a stuck
// store cannot pin request goroutines indefinitely.
const terminalFactsTimeout = 3 * time.Second

// terminalFactsAttempts bounds the transient-PG retry ladder inside one
// terminalFactsTimeout window; the backoff shifts per attempt.
const terminalFactsAttempts = 3

// terminalFactsRetryBackoff is the base delay before the first retry.
const terminalFactsRetryBackoff = 60 * time.Millisecond

// nullIfEmpty binds NULL for absent correlation fields.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
