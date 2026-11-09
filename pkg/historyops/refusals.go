package historyops

import (
	"errors"
	"fmt"
)

// RefusalCode names a typed, user-visible refusal. The codes mirror the
// refusal catalogue in the ENT-HIST preview-operation design (§7) so callers
// and future i18n/openapi surfaces can map them 1:1:
//
//	digest_mismatch            presented digest does not match a fresh preview
//	                           over the same selection and schema stamp
//	open_period                period reaches into the currently open hour
//	protected_family           lineage/policy decisions are not selectable
//	no_destination             archive op enqueued without a destination
//	unsupported_destination    destination scheme/shape is not supported
//	foreign_destination        destination points outside this org's namespace
//	                           (extension of §7 for URL-addressed boundaries)
//	active_grant               a live payload grant blocks the destructive op
//	insufficient_rights        caller/actor is not allowed to run this op
//	selector_rejected          content-search/YQL selectors are not accepted
//	purge_confirmation_missing purge requires a verified confirmation token
//	archive_checksum_mismatch  archive verification failed; the destructive
//	                           half is withheld (§7 extension — the backlog's
//	                           "checksum mismatch does not permit hot delete"
//	                           AC, HISTORY-LIFECYCLE-BACKLOG card 03)
//	cascade_changed            the sessions cascade grew between the message
//	                           archive and the pre-delete count: messages that
//	                           would die unarchived; the delete is withheld
//	blocked_by_fk              selected rows are pinned by surviving rows the
//	                           operation would not delete (e.g. sessions under
//	                           out-of-scope request_logs); the catalogue lists
//	                           it as a preview count — the delete-family op
//	                           turns it into a fail-closed refusal
type RefusalCode string

// The refusal catalogue. Values are wire-stable identifiers (see §7).
const (
	RefusalDigestMismatch           RefusalCode = "digest_mismatch"
	RefusalOpenPeriod               RefusalCode = "open_period"
	RefusalProtectedFamily          RefusalCode = "protected_family"
	RefusalNoDestination            RefusalCode = "no_destination"
	RefusalUnsupportedDestination   RefusalCode = "unsupported_destination"
	RefusalForeignDestination       RefusalCode = "foreign_destination"
	RefusalActiveGrant              RefusalCode = "active_grant"
	RefusalInsufficientRights       RefusalCode = "insufficient_rights"
	RefusalSelectorRejected         RefusalCode = "selector_rejected"
	RefusalPurgeConfirmationMissing RefusalCode = "purge_confirmation_missing"
	RefusalArchiveChecksum          RefusalCode = "archive_checksum_mismatch"
	RefusalCascadeChanged           RefusalCode = "cascade_changed"
	RefusalBlockedByFK              RefusalCode = "blocked_by_fk"
)

// Refusal is a typed refusal per the ENT-HIST refusal catalogue. Refusals are
// fail-closed outcomes: they never partially mutate state, and they are always
// journalled when produced by the engine (03-RIGHTS-MODEL §5: every operation
// attempt — allowed or refused — is journalled).
type Refusal struct {
	Code   RefusalCode
	Detail string
	// GrantIDs, for RefusalActiveGrant, names the payload grants that block
	// the operation. Grant identifiers only — never grant tokens and never
	// payload content.
	GrantIDs []string
}

// Error implements the error interface. The message never embeds payload
// content: it carries the refusal code and the caller-provided detail.
func (r *Refusal) Error() string {
	if r.Detail == "" {
		return fmt.Sprintf("historyops: refused (%s)", r.Code)
	}
	return fmt.Sprintf("historyops: refused (%s): %s", r.Code, r.Detail)
}

// Refuse builds a typed refusal with a formatted detail message.
func Refuse(code RefusalCode, format string, args ...any) *Refusal {
	detail := ""
	if format != "" {
		detail = fmt.Sprintf(format, args...)
	}
	return &Refusal{Code: code, Detail: detail}
}

// WithGrants attaches blocking grant identifiers to the refusal (grant ids
// only — never tokens).
func (r *Refusal) WithGrants(ids ...string) *Refusal {
	r.GrantIDs = append(r.GrantIDs, ids...)
	return r
}

// RefusalOf extracts a typed refusal from an error chain. ok is false when
// err is nil or does not carry a refusal.
func RefusalOf(err error) (*Refusal, bool) {
	var r *Refusal
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

// ErrInvalidRequest marks malformed engine input (validation errors that are
// not part of the refusal catalogue: unknown parameters, negative bounds,
// missing required actor fields). It is a 400-class precondition, not a
// rights decision, so it is deliberately outside the refusal catalogue.
var ErrInvalidRequest = errors.New("historyops: invalid request")

// ErrBatchApplied reports that a destructive batch was already fully applied
// in an earlier at-least-once execution (crash-window replay): the export
// found no rows left, so the archive and delete halves are skipped and the
// engine treats the batch as a successful no-op.
var ErrBatchApplied = errors.New("historyops: batch already fully applied")

// Sentinels for job-store outcomes (HTTP mapping later: 404 / 409-class).
var (
	// ErrDuplicateJob is returned by JobStore.CreateJob when the (org,
	// idempotency key) pair already exists — the engine converts it into the
	// idempotent replay (same job, never a second cleanup).
	ErrDuplicateJob = errors.New("historyops: idempotency key already used")

	// ErrQueueEmpty is returned by JobStore.ClaimNext when no job is
	// claimable right now (empty queue or no attempt due yet).
	ErrQueueEmpty = errors.New("historyops: queue empty")

	// ErrNotFound is returned for job lookups that do not resolve within the
	// requesting org. Forged or foreign job identifiers are indistinguishable
	// from unknown ones — zero state leakage (03-RIGHTS-MODEL §4). Job store
	// implementations also return it for absent idempotency keys.
	ErrNotFound = errors.New("historyops: job not found")
	// ErrLeaseLost is returned when a worker tries to advance a job whose
	// lease it no longer holds (expired and re-claimed, or finalized).
	ErrLeaseLost = errors.New("historyops: lease lost")
	// ErrJobTerminal is returned when cancel is requested on a job that has
	// already reached a terminal state.
	ErrJobTerminal = errors.New("historyops: job already terminal")
)
