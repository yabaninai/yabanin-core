package historyops

// ENT-HIST-06 — the archive_and_remove_hot operation: copy every selected
// row to org-namespace cold storage (the exact archive_copy primitives) and
// delete ONLY the exported ids, in one batch = one unit (backlog card 06,
// HISTORY-LIFECYCLE-BACKLOG; backlog card 03's AC: a failed, incomplete or
// checksum-mismatched archive write never permits the hot delete).
//
// Batch semantics:
//
//   - Every batch exports its exact planned ids first (completeness gate:
//     short/reordered/empty exports refuse archive_checksum_mismatch), writes
//     the JSONL + manifest, verifies the read-back when the store can read,
//     and only then deletes those exact ids. Counts are the actual
//     RowsAffected, so a crash-window replay counts zero by nature.
//   - Request batches are units: their tool_calls/tool_call_invocations
//     children are captured as their own id-precise batches immediately
//     before the parent chunk (children first; the child join goes through
//     request_logs because the chunk carries row ids and the children carry
//     request_id texts). Child batches and standalone tool batches are
//     DISJOINT by construction — the standalone scope excludes rows whose
//     request_id belongs to a selected request — so no row is exported
//     twice and a completeness gate can never trip over the job's own
//     earlier batches.
//   - Sessions are planned only when not pinned by any request_logs row (the
//     preview's BlockedByFK rule) and the delete re-checks the pin, so the
//     FK can never make the delete fail; their message cascade is counted
//     explicitly before the delete.
//   - Active payload grants protect request rows AND their tool children:
//     protected requests are skipped into the checkpoint's protected report
//     (PlanReporter), and refusing with active_grant happens exactly when
//     every selected request is protected and no other permitted rows remain
//     (04-ACCEPTANCE card 06).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// liveGrantPredicate is the live payload-grant condition — the exact
// predicate the preview's protection count uses (countProtectedGrants):
// unrevoked, unconsumed, unexpired.
const liveGrantPredicate = `g.revoked_at IS NULL AND g.consumed_at IS NULL AND g.expires_at > now()`

// requestHasLiveGrant is the correlated EXISTS form keyed on a table's
// (org_id, request_id) pair; alias is the referencing table's alias.
func requestHasLiveGrant(alias string) string {
	return `EXISTS (
	SELECT 1 FROM request_payload_grants g
	WHERE g.org_id = ` + alias + `.org_id AND g.request_id = ` + alias + `.request_id
	  AND ` + liveGrantPredicate + `)`
}

// sessionNotPinned is the FK-safety predicate: a session may only be deleted
// when no request_logs row pins it (request_logs.session_id → sessions FK,
// NO ACTION — preview.go countSessions reports the pinned ones rather than
// letting the delete fail).
const sessionNotPinned = `NOT EXISTS (SELECT 1 FROM request_logs rl WHERE rl.session_id = sessions.id)`

// ArchiveRemoveHotRunner implements the archive_and_remove_hot operation
// (backlog card 06): archive_copy's export discipline, then the hot delete
// of exactly the exported ids.
type ArchiveRemoveHotRunner struct {
	// DB is the pgx pool the runner plans, exports and deletes against.
	DB HistoryDB
	// ResolveDestination — same contract as ArchiveCopyRunner.
	ResolveDestination func(dest string) (ColdStorage, error)
	// BatchSize is the maximum rows per captured batch. Zero or negative
	// falls back to defaultArchiveBatchSize.
	BatchSize int
	// Now overrides the clock (tests). Nil = time.Now.
	Now func() time.Time
}

func (r *ArchiveRemoveHotRunner) batchSize() int {
	if r.BatchSize > 0 {
		return r.BatchSize
	}
	return defaultArchiveBatchSize
}

func (r *ArchiveRemoveHotRunner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// resolveStore — same refusal-first destination handling as archive_copy:
// re-validate at run time, resolve, and refuse on every failure mode (zero
// deletes can ever happen behind a broken destination).
func (r *ArchiveRemoveHotRunner) resolveStore(job *Job) (ColdStorage, error) {
	if err := validateArchiveDestination(job.Op, job.OrgID, job.Destination); err != nil {
		return nil, err
	}
	if r.ResolveDestination == nil {
		return nil, Refuse(RefusalNoDestination,
			"operation %s has no destination resolver wired", job.Op)
	}
	store, err := r.ResolveDestination(job.Destination)
	if err != nil {
		return nil, Refuse(RefusalUnsupportedDestination,
			"destination resolver: %v", err)
	}
	if store == nil {
		return nil, Refuse(RefusalNoDestination,
			"destination resolved to no cold storage")
	}
	return store, nil
}

// VerifySnapshot implements Runner: destination probe (resolve and discard —
// validation only, zero writes) plus the shared snapshot checks.
func (r *ArchiveRemoveHotRunner) VerifySnapshot(ctx context.Context, job *Job) error {
	if _, err := r.resolveStore(job); err != nil {
		return err
	}
	return verifyArchiveSnapshot(ctx, r.DB, r.now, job)
}

// planProtectedRequestIDs lists the in-scope request ids that carry a live
// payload grant — the rows the destructive plan skips (ascending; the caller
// caps the reported slice).
func (r *ArchiveRemoveHotRunner) planProtectedRequestIDs(ctx context.Context, sel Selection) ([]string, error) {
	w, args, err := familyScope(ctx, r.DB, sel, FamilyRequestLogs)
	if err != nil {
		return nil, err
	}
	q := "SELECT rl.id::text FROM request_logs rl WHERE " + w +
		" AND " + requestHasLiveGrant("rl") + " ORDER BY rl.id"
	rows, err := r.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("historyops: plan protected requests: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("historyops: plan protected requests scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// planProtectedGrantIDs lists the payload-grant ids that block the selected
// requests — the identifiers the active_grant refusal reports (preview
// parity: grant ids, never row ids and never tokens).
func (r *ArchiveRemoveHotRunner) planProtectedGrantIDs(ctx context.Context, sel Selection) ([]string, error) {
	w, args, err := familyScope(ctx, r.DB, sel, FamilyRequestLogs)
	if err != nil {
		return nil, err
	}
	q := "SELECT g.id::text FROM request_payload_grants g WHERE " + liveGrantPredicate +
		" AND EXISTS (SELECT 1 FROM request_logs rl WHERE " + w +
		" AND rl.org_id = g.org_id AND rl.request_id = g.request_id) ORDER BY g.id"
	rows, err := r.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("historyops: plan protected grants: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("historyops: plan protected grants scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// planUnprotectedRequests lists the in-scope request ids WITHOUT a live
// grant — the rows this operation may archive and delete.
func (r *ArchiveRemoveHotRunner) planUnprotectedRequests(ctx context.Context, sel Selection) ([]string, error) {
	w, args, err := familyScope(ctx, r.DB, sel, FamilyRequestLogs)
	if err != nil {
		return nil, err
	}
	q := "SELECT rl.id::text FROM request_logs rl WHERE " + w +
		" AND NOT " + requestHasLiveGrant("rl") + " ORDER BY rl.id"
	rows, err := r.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("historyops: plan request ids: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("historyops: plan request ids scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// planChildIDs lists the tool-family children of one request chunk. The
// chunk carries request_logs ROW ids while the children carry request_id
// texts, so the join goes through request_logs: a child belongs to the chunk
// when its request_id is the request_id of one of the chunk's rows. Children
// of protected requests cannot appear here: their parents are not in any
// chunk.
func (r *ArchiveRemoveHotRunner) planChildIDs(ctx context.Context, orgID string, family Family, rowIDs []string) ([]string, error) {
	switch family {
	case FamilyToolCalls, FamilyToolCallInvocations:
	default:
		return nil, fmt.Errorf("historyops: family %q has no request_id children: %w", family, ErrInvalidRequest)
	}
	q := "SELECT t.id::text FROM " + string(family) + " t WHERE t.org_id = $1::uuid AND EXISTS (" +
		"SELECT 1 FROM request_logs rl WHERE rl.org_id = t.org_id AND rl.request_id = t.request_id" +
		" AND rl.id = ANY($2::text[]::bigint[])) ORDER BY t.id"
	rows, err := r.DB.Query(ctx, q, orgID, rowIDs)
	if err != nil {
		return nil, fmt.Errorf("historyops: plan %s children: %w", family, err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("historyops: plan %s children scan: %w", family, err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// planStandaloneToolIDs lists the destructive scope of a tool family minus
// the children owned by the request plan: a tool row whose request_id
// belongs to one of the selected request_logs ROWS dies in its parent's
// chunk (children first), so the standalone scope must exclude it — the join
// goes through request_logs for the same row-id/request-id reason as
// planChildIDs. The exclusion is period-independent: a child created outside
// the selection window still dies with its parent, so no interaction is
// archived half. Live-grant protection applies here too: children of
// protected requests must not be destroyed through the standalone door
// either. When request_logs is not selected there is no overlap to exclude.
func (r *ArchiveRemoveHotRunner) planStandaloneToolIDs(ctx context.Context, sel Selection, family Family, selectedRowIDs []string) ([]string, error) {
	w, args, err := familyScope(ctx, r.DB, sel, family)
	if err != nil {
		return nil, err
	}
	pred := w + " AND NOT " + requestHasLiveGrant(string(family))
	if len(selectedRowIDs) > 0 {
		args = append(args, selectedRowIDs)
		pred += fmt.Sprintf(
			" AND NOT EXISTS (SELECT 1 FROM request_logs rl WHERE rl.org_id = %s.org_id"+
				" AND rl.request_id = %s.request_id AND rl.id = ANY($%d::text[]::bigint[]))",
			string(family), string(family), len(args))
	}
	q := "SELECT id::text FROM " + string(family) + " WHERE " + pred + " ORDER BY id"
	rows, err := r.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("historyops: plan standalone %s: %w", family, err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("historyops: plan standalone %s scan: %w", family, err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// planUnpinnedSessions lists the in-scope sessions no request_logs row pins
// (the FK-safe subset; pinned sessions are reported by the preview and stay,
// making the plan the conservative superset of what is safe to delete).
func (r *ArchiveRemoveHotRunner) planUnpinnedSessions(ctx context.Context, sel Selection) ([]string, error) {
	w, args, err := familyScope(ctx, r.DB, sel, FamilySessions)
	if err != nil {
		return nil, err
	}
	q := "SELECT id::text FROM sessions WHERE " + w + " AND " + sessionNotPinned + " ORDER BY id"
	rows, err := r.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("historyops: plan unpinned sessions: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("historyops: plan unpinned sessions scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// familyHasRows reports whether a family's destructive scope still holds at
// least one row — used only in the all-protected corner to decide whether
// anything else remains (the refusal is restricted to that corner; the happy
// path never pays for it).
func familyHasRows(ctx context.Context, db HistoryDB, from string, pred string, args []any) (bool, error) {
	var exists bool
	if err := db.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM "+from+" WHERE "+pred+")", args...,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("historyops: remaining-rows probe: %w", err)
	}
	return exists, nil
}

// Plan implements Runner. Emission order is deterministic and captured once:
// request units first (per chunk: tool_call_invocations children, tool_calls
// children, then the parent requests), then the remaining families in the
// selection's canonical order with their destructive scope. Execution order
// is FK-safe by construction — children are id-precise and disjoint from the
// standalone tool scope, and sessions were planned only when unpinned.
func (r *ArchiveRemoveHotRunner) Plan(ctx context.Context, job *Job) ([][]string, error) {
	sel := job.Selection
	var out [][]string

	var selectedRowIDs []string
	hasRequests := false
	for _, f := range sel.Families {
		if f == FamilyRequestLogs {
			hasRequests = true
			break
		}
	}

	if hasRequests {
		protected, err := r.planProtectedRequestIDs(ctx, sel)
		if err != nil {
			return nil, err
		}
		reqIDs, err := r.planUnprotectedRequests(ctx, sel)
		if err != nil {
			return nil, err
		}
		// The all-protected corner (04-ACCEPTANCE card 06): when every
		// selected request is under a live grant AND no other permitted row
		// remains, the operation refuses with active_grant instead of
		// silently completing as a no-op. When other families still have
		// permitted rows the op proceeds and only skips the protected
		// requests (skip-and-continue).
		if len(reqIDs) == 0 {
			other := false
			for _, f := range sel.Families {
				switch f {
				case FamilyRequestLogs:
					continue
				case FamilyCacheEntries:
					w, args, err := familyScope(ctx, r.DB, sel, f)
					if err != nil {
						return nil, err
					}
					other, err = familyHasRows(ctx, r.DB, string(f), w, args)
					if err != nil {
						return nil, err
					}
				case FamilySessions:
					w, args, err := familyScope(ctx, r.DB, sel, f)
					if err != nil {
						return nil, err
					}
					other, err = familyHasRows(ctx, r.DB, string(f), w+" AND "+sessionNotPinned, args)
					if err != nil {
						return nil, err
					}
				case FamilyToolCalls, FamilyToolCallInvocations:
					ids, err := r.planStandaloneToolIDs(ctx, sel, f, reqIDs)
					if err != nil {
						return nil, err
					}
					other = len(ids) > 0
				}
				if other {
					break
				}
			}
			if !other && len(protected) > 0 {
				grants, err := r.planProtectedGrantIDs(ctx, sel)
				if err != nil {
					return nil, err
				}
				if len(grants) > maxReportedGrantIDs {
					grants = grants[:maxReportedGrantIDs]
				}
				return nil, Refuse(RefusalActiveGrant,
					"every selected request is under a live payload grant and no other permitted rows remain; nothing archived, nothing deleted",
				).WithGrants(grants...)
			}
		}
		selectedRowIDs = reqIDs
	}

	if hasRequests {
		for _, chunk := range chunkPlan(FamilyRequestLogs, selectedRowIDs, r.batchSize()) {
			_, chunkIDs, err := decodeBatch(chunk)
			if err != nil {
				return nil, err
			}
			// Children first, invocations before calls, then the parents.
			for _, child := range []Family{FamilyToolCallInvocations, FamilyToolCalls} {
				childIDs, err := r.planChildIDs(ctx, sel.OrgID, child, chunkIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, chunkPlan(child, childIDs, r.batchSize())...)
			}
			out = append(out, chunk)
		}
	}

	for _, family := range sel.Families {
		switch family {
		case FamilyRequestLogs:
			continue // handled as units above
		case FamilyToolCalls, FamilyToolCallInvocations:
			ids, err := r.planStandaloneToolIDs(ctx, sel, family, selectedRowIDs)
			if err != nil {
				return nil, err
			}
			out = append(out, chunkPlan(family, ids, r.batchSize())...)
		case FamilyCacheEntries:
			ids, err := planFamilyIDs(ctx, r.DB, sel, family)
			if err != nil {
				return nil, err
			}
			out = append(out, chunkPlan(family, ids, r.batchSize())...)
		case FamilySessions:
			ids, err := r.planUnpinnedSessions(ctx, sel)
			if err != nil {
				return nil, err
			}
			out = append(out, chunkPlan(family, ids, r.batchSize())...)
		}
	}
	return out, nil
}

// PlanReport implements PlanReporter: the protected request ids this plan
// skipped, capped at maxReportedGrantIDs with the truncated flag — captured
// into the checkpoint alongside the plan, so a restart-resumed job keeps the
// same report. Identifiers only.
func (r *ArchiveRemoveHotRunner) PlanReport(ctx context.Context, job *Job, cp *Checkpoint) error {
	for _, f := range job.Selection.Families {
		if f != FamilyRequestLogs {
			continue
		}
		ids, err := r.planProtectedRequestIDs(ctx, job.Selection)
		if err != nil {
			return err
		}
		if len(ids) > maxReportedGrantIDs {
			ids = ids[:maxReportedGrantIDs]
			cp.ProtectedTruncated = true
		}
		cp.ProtectedIDs = ids
		return nil
	}
	return nil
}

// deleteByIDs deletes exactly the exported ids of one batch and reports the
// actual RowsAffected — the replay-safe count (a re-execution of an already
// applied batch deletes nothing and counts nothing). The paired xmin guard
// (audit HIST-04) restricts the delete to the exact row versions the archive
// holds: a row mutated after its export simply stays hot (its changed
// content is never destroyed unarchived; a fresh re-run archives it).
func deleteByIDs(ctx context.Context, db HistoryDB, family Family, orgID string, ids, xmins []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	if len(ids) != len(xmins) {
		return 0, fmt.Errorf("historyops: family %s: %d ids vs %d xmins: %w",
			family, len(ids), len(xmins), ErrInvalidRequest)
	}
	idArg, err := familyIDArg(family, ids)
	if err != nil {
		return 0, err
	}
	q := "DELETE FROM " + string(family) + " t" +
		" USING unnest($2" + familyIDCast(family) + ", $3::text[]) AS p(id, xmin)" +
		" WHERE t.org_id = $1::uuid AND t.id = p.id AND t.xmin::text = p.xmin"
	tag, err := db.Exec(ctx, q, orgID, idArg, xmins)
	if err != nil {
		return 0, fmt.Errorf("historyops: delete %s batch: %w", family, err)
	}
	return tag.RowsAffected(), nil
}

// verifyNoLiveGrants re-checks, immediately before the delete, that none of
// the batch's rows gained a live payload grant after the plan narrowed them
// (audit HIST-04: plan-time narrowing alone leaves a plan→delete window in
// which a grant could be issued and its payload destroyed unarchived).
// Refuses active_grant naming the blocking grant ids (capped, identifier-only
// — plan-time report parity). Sessions and cache rows carry no request_id and
// are not grantable; their protection rides the request_logs scope.
func verifyNoLiveGrants(ctx context.Context, db HistoryDB, family Family, orgID string, ids []string) error {
	var via string
	switch family {
	case FamilyRequestLogs:
		via = string(FamilyRequestLogs)
	case FamilyToolCalls, FamilyToolCallInvocations:
		via = string(family)
	default:
		return nil
	}
	q := `SELECT g.id::text FROM request_payload_grants g
	  WHERE g.org_id = $1::uuid AND ` + liveGrantPredicate + `
	    AND EXISTS (
	      SELECT 1 FROM ` + via + ` t
	      WHERE t.org_id = g.org_id AND t.request_id = g.request_id
	        AND t.id = ANY($2` + familyIDCast(family) + `))
	  ORDER BY g.id LIMIT $3`
	idArg, err := familyIDArg(family, ids)
	if err != nil {
		return err
	}
	rows, err := db.Query(ctx, q, orgID, idArg, maxReportedGrantIDs+1)
	if err != nil {
		return fmt.Errorf("historyops: verify live grants for %s: %w", family, err)
	}
	defer rows.Close()
	var grants []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("historyops: scan live grants for %s: %w", family, err)
		}
		grants = append(grants, id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("historyops: iterate live grants for %s: %w", family, err)
	}
	if len(grants) == 0 {
		return nil
	}
	truncated := ""
	if len(grants) > maxReportedGrantIDs {
		grants = grants[:maxReportedGrantIDs]
		truncated = " (list truncated)"
	}
	return Refuse(RefusalActiveGrant,
		"%s batch gained %d live payload grant(s) after the plan; blocking grant ids: %s%s — rows stay hot",
		family, len(grants), strings.Join(grants, ", "), truncated)
}

// verifyMessageCascadeUnchanged re-checks, immediately before the sessions
// delete, that the live cascade is EXACTLY the archived one, row-version-wise
// (audit HIST-02 + HIST-04): messages inserted after the cascade export
// snapshot, or messages whose row was updated (xmin moved) since, would die
// unarchived — the count includes them, the caller refuses. Returns the
// number of such messages; 0 means the delete destroys nothing unarchived.
func verifyMessageCascadeUnchanged(ctx context.Context, db HistoryDB, orgID string, sessionIDs, archivedMsgIDs, archivedMsgXmins []string) (int64, error) {
	if len(archivedMsgIDs) != len(archivedMsgXmins) {
		return 0, fmt.Errorf("historyops: cascade archive: %d ids vs %d xmins: %w",
			len(archivedMsgIDs), len(archivedMsgXmins), ErrInvalidRequest)
	}
	q := `SELECT COUNT(*) FROM messages m
	  JOIN sessions s ON s.id = m.session_id
	    AND s.org_id = $1::uuid AND s.id = ANY($2::uuid[])
	    AND NOT EXISTS (SELECT 1 FROM request_logs rl WHERE rl.session_id = s.id)
	  LEFT JOIN unnest($3::bigint[], $4::text[]) AS a(id, xmin) ON a.id = m.id
	  WHERE a.id IS NULL OR a.xmin IS DISTINCT FROM m.xmin::text`
	var n int64
	msgArg, err := familyIDArg(FamilyMessages, archivedMsgIDs)
	if err != nil {
		return 0, err
	}
	if err := db.QueryRow(ctx, q, orgID, sessionIDs, msgArg, archivedMsgXmins).
		Scan(&n); err != nil {
		return 0, fmt.Errorf("historyops: verify message cascade: %w", err)
	}
	return n, nil
}

// deleteSessionsBatch deletes the batch's sessions with the pin guard
// (defense in depth — the plan already excluded pinned sessions; a pin that
// appeared after planning must not turn the delete into an FK failure, the
// session just stays behind as part of the conservative superset) and the
// paired xmin guard (HIST-04: only exactly-archived session versions are
// removed; a mutated session stays hot).
func deleteSessionsBatch(ctx context.Context, db HistoryDB, orgID string, ids, xmins []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	if len(ids) != len(xmins) {
		return 0, fmt.Errorf("historyops: sessions batch: %d ids vs %d xmins: %w",
			len(ids), len(xmins), ErrInvalidRequest)
	}
	// The sessions table is referenced UNALIASED so the shared
	// sessionNotPinned predicate (bare sessions.id) applies verbatim.
	q := "DELETE FROM sessions" +
		" USING unnest($2::uuid[], $3::text[]) AS p(id, xmin)" +
		" WHERE sessions.org_id = $1::uuid AND sessions.id = p.id" +
		" AND sessions.xmin::text = p.xmin AND " + sessionNotPinned
	tag, err := db.Exec(ctx, q, orgID, ids, xmins)
	if err != nil {
		return 0, fmt.Errorf("historyops: delete sessions batch: %w", err)
	}
	return tag.RowsAffected(), nil
}

// countMessageCascade counts, immediately before the delete, the messages
// that will cascade with the sessions of this batch — only sessions the
// delete can actually remove (the pin guard included). It is the reported
// FamilyMessages figure; the fail-closed gate is
// verifyMessageCascadeUnchanged, which is version-aware (HIST-02/HIST-04):
// inserts and updates after the archive snapshot both refuse the delete.
func countMessageCascade(ctx context.Context, db HistoryDB, orgID string, sessionIDs []string) (int64, error) {
	// The sessions table is referenced UNALIASED so the shared
	// sessionNotPinned predicate (bare sessions.id) applies verbatim.
	q := `SELECT COUNT(*) FROM messages m
	  WHERE EXISTS (
	    SELECT 1 FROM sessions
	    WHERE sessions.id = m.session_id AND sessions.org_id = $1::uuid AND sessions.id = ANY($2::uuid[])
	      AND ` + sessionNotPinned + `)`
	var n int64
	if err := db.QueryRow(ctx, q, orgID, sessionIDs).Scan(&n); err != nil {
		return 0, fmt.Errorf("historyops: count message cascade: %w", err)
	}
	return n, nil
}

// batchExport is one batch's archived state: the primary rows plus, for
// sessions batches, the derived message cascade — ids with their xmin
// system versions (HIST-04), which the delete half re-checks so only
// exactly-archived row versions are removed.
type batchExport struct {
	ids      []string
	xmins    []string
	msgIDs   []string
	msgXmins []string
}

// archiveAndDelete runs the export-archive gate for one batch: export the
// planned ids that still exist (subset-gated), write JSONL + manifest, and
// verify the read-back when the store can read. Sessions batches
// additionally archive the message cascade as a derived object (audit
// HIST-02: the DELETE cascades to messages, so the cascade is captured, not
// destroyed). Any failure refuses before the delete half runs (backlog card
// 03 AC). Returns ErrBatchApplied when the batch was already fully applied
// in an earlier at-least-once execution.
func (r *ArchiveRemoveHotRunner) archiveAndDelete(ctx context.Context, job *Job, batchIndex int, family Family, ids []string, store ColdStorage) (*batchExport, error) {
	fetched, xmins, payloads, err := exportBatchRows(ctx, r.DB, job.OrgID, family, ids)
	if err != nil {
		return nil, err
	}
	if err := verifyArchiveSubset(family, ids, fetched, payloads); err != nil {
		return nil, err
	}
	if len(fetched) == 0 {
		// Crash-window replay of a fully applied batch: nothing left to
		// archive or delete — the exactly-once skip, reported as a sentinel
		// so callers can distinguish it from an empty live batch.
		return nil, ErrBatchApplied
	}
	base := archiveManifest{
		Table:         string(family),
		Scope:         job.OrgID,
		Rows:          len(fetched),
		Redacted:      false,
		ExportedAt:    job.CreatedAt.UTC().Format(time.RFC3339Nano),
		SchemaVersion: FamiliesSchemaVersion,
		Op:            string(job.Op),
		OrgID:         job.OrgID,
		Digest:        job.SelectionDigest,
		JobID:         job.ID,
		PeriodFrom:    job.Selection.Period.From.UTC().Format(time.RFC3339Nano),
		PeriodTo:      job.Selection.Period.To.UTC().Format(time.RFC3339Nano),
		Batch:         batchIndex,
	}
	key := archiveObjectKey(job.OrgID, job.SelectionDigest, job.ID, batchIndex, family)
	manifest, err := writeArchiveObject(ctx, store, key, base, payloads)
	if err != nil {
		return nil, err
	}
	// The checksum gate: a failed, incomplete or mismatched archive write
	// leaves the hot rows in place (backlog card 03 AC). The refusal fails
	// the job fail-closed; the engine never retries a refusal.
	if err := verifyArchiveReadback(ctx, store, key, manifest); err != nil {
		return nil, err
	}
	out := &batchExport{ids: fetched, xmins: xmins}
	if family != FamilySessions {
		return out, nil
	}

	// The derived cascade archive: every message that the sessions DELETE
	// would take with it, archived under the same job's identity and
	// verified like the primary object (HIST-02).
	msgIDs, msgXmins, msgPayloads, err := exportSessionMessages(ctx, r.DB, job.OrgID, fetched)
	if err != nil {
		return nil, err
	}
	if len(msgIDs) == 0 {
		return out, nil
	}
	cascadeManifest := base
	cascadeManifest.Table = string(FamilyMessages)
	cascadeManifest.Rows = len(msgIDs)
	mkey := archiveObjectKey(job.OrgID, job.SelectionDigest, job.ID, batchIndex, FamilyMessages)
	cascadeManifest, err = writeArchiveObject(ctx, store, mkey, cascadeManifest, msgPayloads)
	if err != nil {
		return nil, err
	}
	if err := verifyArchiveReadback(ctx, store, mkey, cascadeManifest); err != nil {
		return nil, err
	}
	out.msgIDs, out.msgXmins = msgIDs, msgXmins
	return out, nil
}

// ExecuteBatch implements Runner: archive the exported rows, then delete
// exactly the exported ids. Counts are the actual deletes (plus the explicit
// message-cascade count on sessions batches), so the engine's at-least-once
// execution is exactly-once in effect; reported counts can under-count in
// the engine's crash window between ExecuteBatch and SaveCheckpoint, where
// the replay observes an empty export and skips the batch (known limitation,
// documented in the card record).
func (r *ArchiveRemoveHotRunner) ExecuteBatch(ctx context.Context, job *Job, batchIndex int, batch []string) (FamilyCounts, error) {
	family, ids, err := decodeBatch(batch)
	if err != nil {
		return nil, err
	}
	store, err := r.resolveStore(job)
	if err != nil {
		return nil, err
	}
	ex, err := r.archiveAndDelete(ctx, job, batchIndex, family, ids, store)
	if err != nil {
		if errors.Is(err, ErrBatchApplied) {
			// The batch was already fully applied: no rows left to export
			// or delete. Idempotent no-op for the replay path.
			return FamilyCounts{}, nil
		}
		return nil, err
	}
	// The post-archive grant re-check (HIST-04): a payload grant issued
	// after the plan must stop the delete even though the plan narrowed it
	// away — the archive stays, the rows stay hot, the job fails
	// fail-closed.
	if err := verifyNoLiveGrants(ctx, r.DB, family, job.OrgID, ex.ids); err != nil {
		return nil, err
	}
	if family == FamilySessions {
		// The version-aware cascade gate (HIST-02 + HIST-04): anything
		// inserted or updated after the cascade archive snapshot would
		// die unarchived — refuse fail-closed, everything stays hot for a
		// fresh re-run.
		grew, err := verifyMessageCascadeUnchanged(ctx, r.DB, job.OrgID, ex.ids, ex.msgIDs, ex.msgXmins)
		if err != nil {
			return nil, err
		}
		if grew > 0 {
			return nil, Refuse(RefusalCascadeChanged,
				"message cascade changed after its archive: %d message(s) inserted or updated and unarchived; refusing to destroy them",
				grew)
		}
		cascade, err := countMessageCascade(ctx, r.DB, job.OrgID, ex.ids)
		if err != nil {
			return nil, err
		}
		deleted, err := deleteSessionsBatch(ctx, r.DB, job.OrgID, ex.ids, ex.xmins)
		if err != nil {
			return nil, err
		}
		// The cascade count is reported only when the delete actually
		// removed sessions: the xmin guard can leave every session hot (a
		// post-archive mutation), in which case no message died and none
		// is counted.
		if deleted == 0 {
			return FamilyCounts{}, nil
		}
		return FamilyCounts{FamilySessions: deleted, FamilyMessages: cascade}, nil
	}
	deleted, err := deleteByIDs(ctx, r.DB, family, job.OrgID, ex.ids, ex.xmins)
	if err != nil {
		return nil, err
	}
	return FamilyCounts{family: deleted}, nil
}
