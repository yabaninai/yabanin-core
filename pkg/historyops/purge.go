package historyops

// ENT-HIST-07 (CARD 2) — purge: the hard-delete operation for selected
// history families. Unlike redact_content (content columns rewritten in
// place), purge removes whole rows and is therefore bound to the strictest
// gates in the operation set:
//
//   - Confirmation (AC-1): the confirmation token IS the fresh preview
//     digest. The digest is scope+schema bound (digest.go), so echoing it
//     proves the operator saw exactly this scope over exactly this schema.
//     Single-use replay protection comes from the forced idempotency key:
//     the (org, digest) pair can enqueue exactly one purge job, ever. A
//     durable single-use hashed-token store with a short TTL would need an
//     additional table (card: "the migration belongs to this card"); the
//     stateless digest echo satisfies the observable token contract without
//     DDL (bound to the digest, single use, missing/mismatched refused).
//     See the record for the deferred durable store.
//   - Protection (AC-2): requests under live payload grants are skipped into
//     protected (preview parity); the op refuses active_grant when ALL
//     selected requests are protected and nothing else remains (rule of
//     ENT-HIST-06 AC-4). A grant appearing between plan and batch N stops
//     the job before that batch via PurgeGrantGuard (engine.BatchGuard).
//   - Ordering/orphans (AC-4, mirroring ENT-HIST-06): tool_call/
//     tool_call_invocation rows are deleted in the same logical unit
//     (transaction) as their request rows — there is no physical FK, so
//     orphaning would otherwise be silent; standalone tool rows (in scope
//     but not attached to any planned request) form their own batches;
//     sessions go LAST, and only when no selected session is still pinned by
//     an out-of-scope request_logs row (request_logs.session_id FK NO
//     ACTION, 0001:5551) — otherwise the job refuses blocked_by_fk before
//     the first batch touches zero rows.
//   - No-op (AC-3): an empty selection completes with zero effects; purge
//     never archives (no destination rules).
//
// Every delete is id-precise (WHERE id = ANY(...), never predicate-based per
// ENT-HIST-06 AC-2), executed one batch per transaction, and counted by
// actual rows deleted — a replayed batch deletes nothing and reports zero.
// The messages cascade is deleted EXPLICITLY (counted under FamilyMessages)
// instead of relying on the ON DELETE CASCADE, so the terminal counts are
// honest. request_lineage, policy decisions, log_export_watermark and rollup
// buckets are never touched (protected families / out-of-scope machinery).

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

const defaultPurgeBatchSize = 500

// PurgeConfig tunes the purge runner. Zero values fall back to the defaults.
type PurgeConfig struct {
	// BatchSize is the maximum number of primary-row ids captured into one
	// planned batch (request batches additionally carry the tool rows
	// attached to those requests). Default 500.
	BatchSize int
}

// PurgeRunner implements Runner for OpPurge.
type PurgeRunner struct {
	pool      *pgxpool.Pool
	batchSize int
}

// NewPurgeRunner builds the purge runner. The caller MUST also wire
// NewPurgeGrantGuard via Engine.SetBatchGuard so grants created after the
// plan stop the job before the next batch.
func NewPurgeRunner(pool *pgxpool.Pool, cfg PurgeConfig) *PurgeRunner {
	size := cfg.BatchSize
	if size <= 0 {
		size = defaultPurgeBatchSize
	}
	return &PurgeRunner{pool: pool, batchSize: size}
}

var _ Runner = (*PurgeRunner)(nil)

// VerifySnapshot re-checks the digest inside one consistent snapshot:
// schema drift between the previewed digest and the execute-time world
// refuses digest_mismatch before any planning or deletion.
func (r *PurgeRunner) VerifySnapshot(ctx context.Context, job *Job) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("historyops: purge snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	stamp, err := SchemaStampFromDB(ctx, tx)
	if err != nil {
		return err
	}
	expected, err := SelectionDigest(OpPurge, job.Selection, stamp)
	if err != nil {
		return err
	}
	if expected != job.SelectionDigest {
		return Refuse(RefusalDigestMismatch,
			"selection digest drifted from the confirmed purge scope; run the preview again")
	}
	return tx.Commit(ctx)
}

// purgeRequestRow is one planned request_logs row: the deletion target id
// plus its request_id text (the key that ties tool rows and grants to it).
type purgeRequestRow struct {
	ID        int64
	RequestID string
}

// purgeSelection is one family's in-scope row ids captured at plan time.
type purgeSelection struct {
	requestRows    []purgeRequestRow
	plannedReqIDs  map[string]bool    // request_id text -> planned for deletion
	toolIDs        []int64            // standalone (no planned parent request)
	invocationIDs  []int64            // standalone (no planned parent request)
	cacheIDs       []string           // uuids
	sessionIDs     []string           // uuids
	attachedTools  map[string][]int64 // request_id (text) -> tool_call ids
	attachedInvocs map[string][]int64 // request_id (text) -> invocation ids
}

// Plan captures the id-precise deletion plan inside ONE read-only snapshot:
//
//  1. in-scope request rows, minus rows whose request_id carries a live
//     payload grant (skipped into protected, preview parity);
//  2. all selected sessions pinned by request rows that will NOT be deleted
//     by this job refuse blocked_by_fk before the first batch;
//  3. tool rows attached to planned requests ride those request batches;
//     in-scope tool rows without a planned parent form standalone batches;
//  4. cache batches;
//  5. sessions LAST (children of this same job's request batches are gone
//     by the time the sessions batches run).
//
// The plan is captured into the checkpoint before the first batch, so a
// restart resumes exactly the captured ids. An all-protected selection (or
// a protection-caused empty plan) refuses active_grant with the blocking
// grant ids; a genuinely empty selection plans nothing (no-op completion).
func (r *PurgeRunner) Plan(ctx context.Context, job *Job) ([][]string, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("historyops: purge plan snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	sel := job.Selection
	selected := func(f Family) bool {
		for _, f2 := range sel.Families {
			if f2 == f {
				return true
			}
		}
		return false
	}

	work := &purgeSelection{
		plannedReqIDs:  map[string]bool{},
		attachedTools:  map[string][]int64{},
		attachedInvocs: map[string][]int64{},
	}
	protectedCount := int64(0)
	var protectedGrantIDs []string

	if selected(FamilyRequestLogs) {
		w, args := adminstore.RequestListWhere(sel.RequestListFilters())
		// Buffer this query fully before the protected-grants query runs on
		// the same snapshot connection (pgx serializes queries per conn).
		type scopedRow struct {
			id    int64
			reqID string
		}
		rows, err := tx.Query(ctx,
			"SELECT rl.id, rl.request_id FROM request_logs rl WHERE "+w+" ORDER BY rl.id", args...)
		if err != nil {
			return nil, fmt.Errorf("historyops: purge select requests: %w", err)
		}
		var scoped []scopedRow
		for rows.Next() {
			var row scopedRow
			if err := rows.Scan(&row.id, &row.reqID); err != nil {
				rows.Close()
				return nil, fmt.Errorf("historyops: scan purge requests: %w", err)
			}
			scoped = append(scoped, row)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("historyops: iterate purge requests: %w", err)
		}
		rows.Close()

		protected, grants, err := protectedRequestIDs(ctx, tx, w, args)
		if err != nil {
			return nil, err
		}
		protectedCount = int64(len(protected))
		protectedGrantIDs = grants
		for _, row := range scoped {
			if protected[row.reqID] {
				continue // skipped into protected, preview parity
			}
			work.requestRows = append(work.requestRows, purgeRequestRow{ID: row.id, RequestID: row.reqID})
			work.plannedReqIDs[row.reqID] = true
		}
	}

	if selected(FamilySessions) {
		w, args, err := familyScope(ctx, tx, sel, FamilySessions)
		if err != nil {
			return nil, err
		}
		sessionIDs, err := selectStrings(ctx, tx,
			"SELECT id::text FROM sessions WHERE "+w+" ORDER BY id", args)
		if err != nil {
			return nil, err
		}
		// Sessions pinned by request rows that survive this job can never be
		// deleted (request_logs.session_id FK NO ACTION) — refuse instead of
		// failing mid-batch or silently dropping the session. Pins from this
		// job's own planned request rows are fine: those batches run first.
		blocked, err := countBlockedSessions(ctx, tx, w, args, plannedRequestTextIDs(work))
		if err != nil {
			return nil, err
		}
		if blocked > 0 {
			return nil, Refuse(RefusalBlockedByFK,
				"%d selected session(s) are still pinned by request rows this purge would not delete; narrow the selection first",
				blocked)
		}
		work.sessionIDs = sessionIDs
	}

	// Tool rows: attached ones ride their request's batch (same logical
	// unit), the rest form standalone batches.
	if selected(FamilyToolCalls) {
		w, args, err := familyScope(ctx, tx, sel, FamilyToolCalls)
		if err != nil {
			return nil, err
		}
		if err := collectToolRows(ctx, tx, w, args, work, true); err != nil {
			return nil, err
		}
	}
	if selected(FamilyToolCallInvocations) {
		w, args, err := familyScope(ctx, tx, sel, FamilyToolCallInvocations)
		if err != nil {
			return nil, err
		}
		if err := collectToolRows(ctx, tx, w, args, work, false); err != nil {
			return nil, err
		}
	}
	if selected(FamilyCacheEntries) {
		w, args, err := familyScope(ctx, tx, sel, FamilyCacheEntries)
		if err != nil {
			return nil, err
		}
		work.cacheIDs, err = selectStrings(ctx, tx,
			"SELECT id::text FROM cache_entries WHERE "+w+" ORDER BY id", args)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("historyops: commit purge plan: %w", err)
	}

	// ENT-HIST-06 AC-4 rule: refuse when protection empties the plan.
	if len(work.requestRows)+len(work.toolIDs)+len(work.invocationIDs)+
		len(work.cacheIDs)+len(work.sessionIDs) == 0 && protectedCount > 0 {
		return nil, Refuse(RefusalActiveGrant,
			"all %d selected request(s) are under live payload grants; nothing remains to purge",
			protectedCount).WithGrants(protectedGrantIDs...)
	}

	return assemblePurgeBatches(work, r.batchSize), nil
}

// ExecuteBatch deletes exactly one captured batch inside one transaction.
// Counts are actual deleted rows: replaying a batch deletes nothing and
// reports zero (at-least-once execution, exactly-once effect). Sessions are
// always deleted last inside their batch, after their messages were deleted
// explicitly so the cascade is counted, not silent.
func (r *PurgeRunner) ExecuteBatch(ctx context.Context, job *Job, batchIndex int, ids []string) (FamilyCounts, error) {
	groups := make(map[Family][]string, 4)
	for _, pid := range ids {
		family, raw, err := decodePlanID(pid)
		if err != nil {
			return FamilyCounts{}, err
		}
		if !selectionHasFamily(job.Selection, family) {
			return FamilyCounts{}, fmt.Errorf("%w: batch family %q is outside the job selection", ErrInvalidRequest, family)
		}
		groups[family] = append(groups[family], raw)
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return FamilyCounts{}, fmt.Errorf("historyops: purge batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	counts := FamilyCounts{}
	deleteOrder := []Family{
		FamilyToolCallInvocations, FamilyToolCalls, FamilyRequestLogs,
		FamilyCacheEntries, FamilySessions,
	}
	for _, family := range deleteOrder {
		raw := groups[family]
		if len(raw) == 0 {
			continue
		}
		var query string
		var args any
		switch family {
		case FamilyToolCallInvocations, FamilyToolCalls, FamilyRequestLogs:
			intIDs, err := parseBigIntIDs(raw)
			if err != nil {
				return FamilyCounts{}, err
			}
			args = intIDs
			query = "DELETE FROM " + purgeTable(family) + " WHERE id = ANY($1::bigint[]) RETURNING 1"
		case FamilyCacheEntries:
			args = raw
			query = "DELETE FROM cache_entries WHERE id = ANY($1::uuid[]) RETURNING 1"
		case FamilySessions:
			// Explicitly count the message cascade first, then the sessions:
			// if the messages delete already reported the rows, a failed
			// sessions delete rolls the whole batch back (no partial state).
			msgIDs := raw
			n, err := execReturningCount(ctx, tx,
				"DELETE FROM messages WHERE session_id = ANY($1::uuid[]) RETURNING 1", msgIDs)
			if err != nil {
				return FamilyCounts{}, err
			}
			counts[FamilyMessages] += n
			args = msgIDs
			query = "DELETE FROM sessions WHERE id = ANY($1::uuid[]) RETURNING 1"
		}
		n, err := execReturningCount(ctx, tx, query, args)
		if err != nil {
			return FamilyCounts{}, fmt.Errorf("historyops: purge %s: %w", family, err)
		}
		counts[family] += n
	}
	if err := tx.Commit(ctx); err != nil {
		return FamilyCounts{}, fmt.Errorf("historyops: commit purge batch: %w", err)
	}
	return counts, nil
}

// purgeTable maps a family to its physical table for the id-precise DELETEs.
func purgeTable(f Family) string {
	switch f {
	case FamilyToolCallInvocations:
		return "tool_call_invocations"
	case FamilyToolCalls:
		return "tool_calls"
	default:
		return "request_logs"
	}
}

// plannedRequestTextIDs renders the planned request ids as text for the
// session-pin blocker check (empty when request_logs is not selected).
func plannedRequestTextIDs(work *purgeSelection) []string {
	out := make([]string, 0, len(work.requestRows))
	for _, row := range work.requestRows {
		out = append(out, strconv.FormatInt(row.ID, 10))
	}
	return out
}

// protectedRequestIDs returns the in-scope request_ids (text) that carry a
// live payload grant — same live-grant rule as the preview's protected
// bucket — plus the (capped) grant identifiers for the refusal detail.
func protectedRequestIDs(ctx context.Context, ex adminstore.RequestQueryRunner, w string, args []any) (map[string]bool, []string, error) {
	q := `SELECT rl.request_id, g.id::text
	     FROM request_logs rl
	     JOIN request_payload_grants g
	       ON g.org_id = rl.org_id AND g.request_id = rl.request_id
	     WHERE rl.id IN (SELECT id FROM request_logs WHERE ` + w + `)
	       AND g.revoked_at IS NULL AND g.consumed_at IS NULL AND g.expires_at > now()
	     ORDER BY 1, 2`
	rows, err := ex.Query(ctx, q, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("historyops: purge protected requests: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	var grants []string
	for rows.Next() {
		var reqID, grantID string
		if err := rows.Scan(&reqID, &grantID); err != nil {
			return nil, nil, fmt.Errorf("historyops: scan protected requests: %w", err)
		}
		out[reqID] = true
		grants = append(grants, grantID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("historyops: iterate protected requests: %w", err)
	}
	if len(grants) > maxReportedGrantIDs {
		grants = grants[:maxReportedGrantIDs]
	}
	return out, grants, nil
}

// selectStrings loads an id column inside the plan snapshot.

// countBlockedSessions counts selected sessions still pinned by request rows
// OUTSIDE the planned request set (pins from the planned set disappear with
// their earlier batches and are fine).
func countBlockedSessions(ctx context.Context, ex adminstore.RequestQueryRunner, w string, args []any, planned []string) (int64, error) {
	if planned == nil {
		planned = []string{}
	}
	q := `SELECT COUNT(*) FROM sessions s WHERE ` + w + `
	     AND EXISTS (
	       SELECT 1 FROM request_logs rl
	        WHERE rl.session_id = s.id
	          AND NOT (rl.id::text = ANY($` + strconv.Itoa(len(args)+1) + `::text[])))`
	args = append(args, planned)
	return countSimple(ctx, ex, q, args)
}

// collectToolRows loads in-scope tool rows (tool_calls or invocations) and
// splits them into request-attached ids (ride their request's batch) and
// standalone ids (their own batches).
func collectToolRows(ctx context.Context, ex adminstore.RequestQueryRunner, w string, args []any, work *purgeSelection, toolCalls bool) error {
	table := "tool_call_invocations"
	if toolCalls {
		table = "tool_calls"
	}
	rows, err := ex.Query(ctx,
		"SELECT id::text, request_id FROM "+table+" WHERE "+w+" ORDER BY id", args...)
	if err != nil {
		return fmt.Errorf("historyops: purge select %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var idText, reqID string
		if err := rows.Scan(&idText, &reqID); err != nil {
			return fmt.Errorf("historyops: scan %s: %w", table, err)
		}
		id, err := strconv.ParseInt(idText, 10, 64)
		if err != nil {
			return fmt.Errorf("%w: %s id %q", ErrInvalidRequest, table, idText)
		}
		if work.plannedReqIDs[reqID] {
			if toolCalls {
				work.attachedTools[reqID] = append(work.attachedTools[reqID], id)
			} else {
				work.attachedInvocs[reqID] = append(work.attachedInvocs[reqID], id)
			}
			continue
		}
		if toolCalls {
			work.toolIDs = append(work.toolIDs, id)
		} else {
			work.invocationIDs = append(work.invocationIDs, id)
		}
	}
	return rows.Err()
}

// assemblePurgeBatches chunks the captured ids into ordered batches:
// request batches (each carrying the tool rows attached to its requests in
// the same logical unit), standalone tool batches, cache batches, and
// sessions LAST. The sessions-last property is structural: by the time a
// sessions batch runs, every request batch of this same plan has committed,
// so the FK pins from this job's own request rows are gone.
func assemblePurgeBatches(work *purgeSelection, batchSize int) [][]string {
	var batches [][]string
	push := func(ids []string) {
		for len(ids) > 0 {
			n := batchSize
			if len(ids) < n {
				n = len(ids)
			}
			batches = append(batches, ids[:n:n])
			ids = ids[n:]
		}
	}

	// Request batches: request ids plus every attached tool row.
	for i := 0; i < len(work.requestRows); i += batchSize {
		end := i + batchSize
		if end > len(work.requestRows) {
			end = len(work.requestRows)
		}
		batch := make([]string, 0, end-i)
		for _, row := range work.requestRows[i:end] {
			batch = append(batch, encodePlanID(FamilyRequestLogs, strconv.FormatInt(row.ID, 10)))
			for _, tid := range work.attachedTools[row.RequestID] {
				batch = append(batch, encodePlanID(FamilyToolCalls, strconv.FormatInt(tid, 10)))
			}
			for _, iid := range work.attachedInvocs[row.RequestID] {
				batch = append(batch, encodePlanID(FamilyToolCallInvocations, strconv.FormatInt(iid, 10)))
			}
		}
		batches = append(batches, batch)
	}

	// Standalone tool rows: in scope but not attached to any planned request.
	standaloneTools := make([]string, 0, len(work.toolIDs))
	for _, id := range work.toolIDs {
		standaloneTools = append(standaloneTools, encodePlanID(FamilyToolCalls, strconv.FormatInt(id, 10)))
	}
	push(standaloneTools)

	standaloneInvocs := make([]string, 0, len(work.invocationIDs))
	for _, id := range work.invocationIDs {
		standaloneInvocs = append(standaloneInvocs, encodePlanID(FamilyToolCallInvocations, strconv.FormatInt(id, 10)))
	}
	push(standaloneInvocs)

	cacheIDs := make([]string, 0, len(work.cacheIDs))
	for _, id := range work.cacheIDs {
		cacheIDs = append(cacheIDs, encodePlanID(FamilyCacheEntries, id))
	}
	push(cacheIDs)

	sessionIDs := make([]string, 0, len(work.sessionIDs))
	for _, id := range work.sessionIDs {
		sessionIDs = append(sessionIDs, encodePlanID(FamilySessions, id))
	}
	push(sessionIDs)

	return batches
}

// selectionHasFamily reports whether the family is part of the selection
// (defense-in-depth for corrupted checkpoints).
func selectionHasFamily(sel Selection, f Family) bool {
	for _, f2 := range sel.Families {
		if f2 == f {
			return true
		}
	}
	return false
}

// selectStrings loads an id column inside the plan snapshot.
func selectStrings(ctx context.Context, ex adminstore.RequestQueryRunner, q string, args []any) ([]string, error) {
	rows, err := ex.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("historyops: purge select: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("historyops: purge scan id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// execReturningCount runs a mutation and returns the number of rows it
// reported (DELETE ... RETURNING 1).
func execReturningCount(ctx context.Context, tx pgx.Tx, query string, args any) (int64, error) {
	tag, err := tx.Exec(ctx, query, args)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------------------
// Enqueue path (engine.go delegates OpPurge here) and the per-batch guard.
// ---------------------------------------------------------------------------

// enqueuePurge is the purge-specific enqueue flow. Gate order mirrors the
// generic flow with one structural difference forced by AC-1: the
// confirmation token is validated against a FRESH digest before creation,
// and the idempotency key IS that digest — one confirmed scope can enqueue
// exactly one purge job, ever (single use without a token store).
func (e *Engine) enqueuePurge(ctx context.Context, req EnqueueRequest, actor JobActor) (*Job, error) {
	if actor.Type == ActorUser {
		if err := AuthorizeEnqueue(req.Op, req.Caller); err != nil {
			e.journalDenial(ctx, req, actor, err)
			return nil, err
		}
	}
	if err := req.Selection.Validate(e.cfg.Now()); err != nil {
		return nil, err
	}
	stamp, err := e.cfg.Stamp(ctx)
	if err != nil {
		return nil, fmt.Errorf("historyops: schema stamp: %w", err)
	}
	expected, err := SelectionDigest(req.Op, req.Selection, stamp)
	if err != nil {
		return nil, err
	}
	// Single-use replay FIRST (generic-flow parity): a repeated digest key
	// returns the stored job — even a replay that omits or mistypes the
	// confirmation replays the original decision, never a second destructive
	// pass. The caller-supplied idempotency key is ignored for purge: the
	// digest is the single-use token.
	existing, err := e.store.JobByIdempotencyKey(ctx, req.OrgID, expected)
	if err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if req.Confirmation == "" {
		err := Refuse(RefusalPurgeConfirmationMissing,
			"purge requires the confirmation token issued with the previewed digest")
		e.journalDenial(ctx, req, actor, err)
		return nil, err
	}
	if req.Confirmation != expected {
		err := Refuse(RefusalDigestMismatch,
			"purge confirmation does not match a fresh preview; run the preview again")
		e.journalDenial(ctx, req, actor, err)
		return nil, err
	}
	// The confirmation echo proved PresentedDigest-class freshness (it IS
	// the fresh digest), so the generic digest-match check is subsumed.
	job := &Job{
		OrgID:           req.OrgID,
		Op:              req.Op,
		Selection:       req.Selection,
		SelectionDigest: expected,
		Stamp:           stamp,
		IdempotencyKey:  expected,
		Confirmed:       FamilyCounts{},
		Actor:           actor.Normalized(),
	}
	if err := e.store.CreateJob(ctx, job); err != nil {
		if errors.Is(err, ErrDuplicateJob) {
			return e.store.JobByIdempotencyKey(ctx, req.OrgID, expected)
		}
		return nil, err
	}
	e.journalEntry(ctx, Entry{
		Action: JournalAction(req.Op, ActionStarted),
		OrgID:  job.OrgID,
		JobID:  job.ID,
		Op:     job.Op,
		Actor:  job.Actor,
		Details: detailf(
			"digest", job.SelectionDigest,
			"families", strings.Join(familyNames(job.Selection.Families), ","),
			"actor_type", string(job.Actor.Type),
			"policy_version", job.Actor.PolicyVersion,
		),
	})
	return job, nil
}

// PurgeGrantGuard is the engine BatchGuard for purge jobs: a payload grant
// created (or still live) against a request whose row sits in the CURRENT
// batch stops the job before that batch with active_grant — the plan-time
// skip cannot see grants that appear after the snapshot.
type PurgeGrantGuard struct {
	pool *pgxpool.Pool
}

// NewPurgeGrantGuard builds the live-grant batch guard.
func NewPurgeGrantGuard(pool *pgxpool.Pool) *PurgeGrantGuard {
	return &PurgeGrantGuard{pool: pool}
}

var _ BatchGuard = (*PurgeGrantGuard)(nil)

// BatchAllowed refuses when any request row of this batch carries a live
// payload grant. Grant identifiers only — never tokens (03-RIGHTS-MODEL §5).
func (g *PurgeGrantGuard) BatchAllowed(ctx context.Context, job *Job, ids []string) error {
	if job == nil || job.Op != OpPurge {
		return nil
	}
	var reqIDs []int64
	for _, pid := range ids {
		family, raw, err := decodePlanID(pid)
		if err != nil {
			return err
		}
		if family != FamilyRequestLogs {
			continue
		}
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("%w: request plan id %q", ErrInvalidRequest, pid)
		}
		reqIDs = append(reqIDs, parsed)
	}
	if len(reqIDs) == 0 {
		return nil
	}
	var grants []string
	if err := g.pool.QueryRow(ctx,
		`SELECT COALESCE(array_agg(DISTINCT g.id::text ORDER BY g.id::text), '{}')
	     FROM request_logs rl
	     JOIN request_payload_grants g
	       ON g.org_id = rl.org_id AND g.request_id = rl.request_id
	     WHERE rl.id = ANY($1::bigint[])
	       AND g.revoked_at IS NULL AND g.consumed_at IS NULL AND g.expires_at > now()`,
		reqIDs).Scan(&grants); err != nil {
		return fmt.Errorf("historyops: purge grant guard: %w", err)
	}
	if len(grants) == 0 {
		return nil
	}
	if len(grants) > maxReportedGrantIDs {
		grants = grants[:maxReportedGrantIDs]
	}
	return Refuse(RefusalActiveGrant,
		"%d live payload grant(s) cover request(s) in this batch", len(grants)).WithGrants(grants...)
}
