package historyops

// ENT-HIST-03 — preview counts: the dry-run answer to "what would this
// operation affect" (02-PREVIEW-OPERATION-DESIGN §3), computed with the exact
// predicates a real operation would plan with.
//
// Shape-agnostic by construction: counts are SQL COUNTs over predicates, not
// column-value walks — except the response-view classification, which is the
// one place FIX-20's envelope shape matters. The SQL bucketing CASE below and
// the canonical Go reader (adminstore.ParseResponseEnvelope) must agree; the
// integration test preview_int_test.go pins that parity row by row.
//
// Read-only snapshot: every count in one report comes from ONE REPEATABLE
// READ READ ONLY transaction (mirror of StreamRequestExport), so counts
// cannot drift mid-answer and a preview never holds write locks.
//
// Identifiers only: the report carries counts, ids and flags — never payload
// bytes. content_bytes_est is a pg_column_size ESTIMATE and labelled as such.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// maxReportedGrantIDs bounds the grant-id list in one report: a selection
// with more live grants is reported with the first (deterministic) slice and
// TruncatedGrantIDs set; the operation would refuse anyway.
const maxReportedGrantIDs = 100

// Previewer computes preview reports against the live database.
type Previewer struct {
	pool  *pgxpool.Pool
	stamp func(ctx context.Context) (SchemaStamp, error)
	now   func() time.Time
}

// NewPreviewer builds a previewer. stamp defaults to the zero stamp when nil;
// production wiring passes the migration-head reader (SchemaStampFromDB).
func NewPreviewer(pool *pgxpool.Pool, stamp func(ctx context.Context) (SchemaStamp, error), now func() time.Time) *Previewer {
	if stamp == nil {
		stamp = func(context.Context) (SchemaStamp, error) {
			return SchemaStamp{FamiliesSchemaVersion: FamiliesSchemaVersion}, nil
		}
	}
	if now == nil {
		now = time.Now
	}
	return &Previewer{pool: pool, stamp: stamp, now: now}
}

// SchemaStampFromDB reads the migration head from the migrations table on the
// given executor (pool or snapshot transaction). It is the production Stamp
// for both the engine and the previewer so a digest can never be issued under
// stale column assumptions (design §4).
func SchemaStampFromDB(ctx context.Context, ex adminstore.RequestQueryRunner) (SchemaStamp, error) {
	var head int64
	if err := ex.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&head); err != nil {
		return SchemaStamp{}, fmt.Errorf("historyops: schema stamp: %w", err)
	}
	return SchemaStamp{MigrationHead: head, FamiliesSchemaVersion: FamiliesSchemaVersion}, nil
}

// PreviewRequest names the operation to preview (a real operation, not
// "preview"), its selection and the caller whose read rights gate the report.
type PreviewRequest struct {
	Op        Operation
	Selection Selection
	Caller    Caller
}

// ResponseViewCounts classifies request_logs.response values in the
// selection — the FIX-20 reader buckets, counted:
//   - Envelope: v1 model_response envelopes (ParseResponseEnvelope != nil,
//     status complete|partial).
//   - Legacy: anything else non-empty (pre-FIX-20 payload snapshots,
//     malformed values).
//   - Absent: SQL NULL and the jsonb 'null' written for denied rows.
type ResponseViewCounts struct {
	Envelope int64 `json:"envelope"`
	Legacy   int64 `json:"legacy"`
	Absent   int64 `json:"absent"`
}

// FamilyPreview is the per-family count block. Which fields apply depends on
// the family (documented per field); non-applicable fields stay zero.
type FamilyPreview struct {
	// Found: rows matching the selection scope for this family.
	Found int64 `json:"found"`
	// Permitted: rows the previewed operation would act on under the
	// caller's rights (found minus protected).
	Permitted int64 `json:"permitted"`
	// Protected: rows in scope the operation would leave alone — active
	// payload grants for delete-family operations (design §5.4).
	Protected int64 `json:"protected"`
	// ProtectedGrantIDs: the live grant ids causing the protection (no
	// tokens — tokens are never stored). request_logs only, delete-family
	// ops only; capped at maxReportedGrantIDs with TruncatedGrantIDs.
	ProtectedGrantIDs []string `json:"protected_grant_ids,omitempty"`
	TruncatedGrantIDs bool     `json:"truncated_grant_ids,omitempty"`
	// ResponseViews: FIX-20 envelope/legacy/absent classification of the
	// response column. request_logs only.
	ResponseViews *ResponseViewCounts `json:"response_views,omitempty"`
	// ContentBytesEst: estimate of content-bearing bytes the operation
	// would touch (redact: the content columns; delete-family: the payload
	// columns that die with the row). ESTIMATE ONLY.
	ContentBytesEst int64 `json:"content_bytes_est"`
	// BlockedByFK: sessions still referenced by request_logs rows — a
	// naive delete would fail with a foreign-key violation, so these
	// sessions are reported, never silently dropped. sessions only.
	BlockedByFK int64 `json:"blocked_by_fk"`
}

// CascadePreview counts rows that would be affected through a cascade or
// dependent path. Cascades must never be silent (design §3: sessions carry
// their messages with them; request_logs rows pin sessions from below).
type CascadePreview struct {
	Family Family `json:"family"`
	// Rows: message rows that would cascade with the selected sessions
	// (messages.session_id ON DELETE CASCADE).
	Rows int64 `json:"rows"`
	// ContentBytesEst: estimate of the message content bytes involved.
	ContentBytesEst int64  `json:"content_bytes_est"`
	Note            string `json:"note,omitempty"`
}

// PreviewReport is the answer to one preview request.
type PreviewReport struct {
	Op              Operation                `json:"op"`
	SelectionDigest string                   `json:"selection_digest"`
	Stamp           SchemaStamp              `json:"schema_stamp"`
	NoOp            bool                     `json:"no_op"`
	Families        map[Family]FamilyPreview `json:"families"`
	Cascades        []CascadePreview         `json:"cascades,omitempty"`
	// Refusals lists the catalogue reasons the corresponding real enqueue
	// would be refused (e.g. purge confirmation missing, live grants on a
	// delete-family scope). Empty = previewable. The preview itself still
	// reports counts: an operator must see WHY an op would refuse.
	Refusals []*Refusal `json:"refusals,omitempty"`
}

// Report computes the preview inside one read-only snapshot transaction.
// Validation failures (rights, malformed selection, unknown op) return
// errors/refusals before any query runs.
func (p *Previewer) Report(ctx context.Context, req PreviewRequest) (*PreviewReport, error) {
	if !ValidOperation(req.Op) || req.Op == OpPreview {
		return nil, fmt.Errorf("%w: unknown operation %q", ErrInvalidRequest, req.Op)
	}
	if err := req.Selection.Validate(p.now()); err != nil {
		return nil, err
	}
	if err := AuthorizePreview(req.Caller); err != nil {
		return nil, err
	}
	if p == nil || p.pool == nil {
		return nil, fmt.Errorf("historyops: preview requires a database pool")
	}
	stamp, err := p.stamp(ctx)
	if err != nil {
		return nil, err
	}
	digest, err := SelectionDigest(req.Op, req.Selection, stamp)
	if err != nil {
		return nil, err
	}

	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("historyops: begin preview snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	report := &PreviewReport{
		Op:              req.Op,
		SelectionDigest: digest,
		Stamp:           stamp,
		Families:        make(map[Family]FamilyPreview, len(req.Selection.Families)),
	}
	for _, family := range req.Selection.Families {
		fp, err := p.countFamily(ctx, tx, req, family)
		if err != nil {
			return nil, err
		}
		report.Families[family] = fp
	}
	if err := p.countCascades(ctx, tx, req, report); err != nil {
		return nil, err
	}
	report.Refusals = previewRefusals(req, report)

	total := int64(0)
	for _, fp := range report.Families {
		total += fp.Found
	}
	for _, c := range report.Cascades {
		total += c.Rows
	}
	report.NoOp = total == 0

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("historyops: commit preview snapshot: %w", err)
	}
	return report, nil
}

// previewRefusals derives the catalogue entries the real enqueue would hit.
func previewRefusals(req PreviewRequest, report *PreviewReport) []*Refusal {
	var out []*Refusal
	if req.Op == OpPurge {
		out = append(out, Refuse(RefusalPurgeConfirmationMissing,
			"purge requires the confirmation token issued with this preview digest"))
	}
	if req.Op.destroysContent() {
		for family, fp := range report.Families {
			if fp.Protected > 0 {
				out = append(out, Refuse(RefusalActiveGrant,
					"%d row(s) in %s are under live payload grants",
					fp.Protected, family).WithGrants(fp.ProtectedGrantIDs...))
			}
		}
	}
	return out
}

// destroysContent reports whether the operation destroys or rewrites content
// in place (the grant-protection rule: active payload grants protect rows
// against delete-family operations per design §5.4; redact_content is gated
// by explicit payload rights instead, 03-RIGHTS-MODEL §3).
func (op Operation) destroysContent() bool {
	return op == OpArchiveRemoveHot || op == OpPurge
}

// familyScope describes which selection predicates apply to a family (the
// metadata filters are request-shaped; families without the columns are not
// silently narrowed by them).
//
//	request_logs:          org + period + team + all metadata filters (the
//	                       exact requestListWhere predicate)
//	tool_calls:            org + period + model_used + task_id + request_id
//	tool_call_invocations: org + period + request_id
//	cache_entries:         org + period
//	sessions:              org + period
func familyScope(ctx context.Context, ex adminstore.RequestQueryRunner, sel Selection, family Family) (string, []any, error) {
	base := []any{sel.OrgID, sel.Period.From, sel.Period.To}
	switch family {
	case FamilyRequestLogs:
		w, args := adminstore.RequestListWhere(sel.RequestListFilters())
		return w, args, nil
	case FamilyToolCalls:
		w := "org_id = $1 AND created_at >= $2 AND created_at <= $3"
		args := base
		if sel.Filters.Model != "" {
			args = append(args, sel.Filters.Model)
			w += fmt.Sprintf(" AND model_used = $%d", len(args))
		}
		if sel.Filters.TaskID != "" {
			args = append(args, sel.Filters.TaskID)
			w += fmt.Sprintf(" AND task_id = $%d", len(args))
		}
		if sel.Filters.RequestID != "" {
			args = append(args, sel.Filters.RequestID)
			w += fmt.Sprintf(" AND request_id = $%d", len(args))
		}
		return w, args, nil
	case FamilyToolCallInvocations:
		w := "org_id = $1 AND created_at >= $2 AND created_at <= $3"
		args := base
		if sel.Filters.RequestID != "" {
			args = append(args, sel.Filters.RequestID)
			w += fmt.Sprintf(" AND request_id = $%d", len(args))
		}
		return w, args, nil
	case FamilyCacheEntries, FamilySessions:
		w := "org_id = $1 AND created_at >= $2 AND created_at <= $3"
		return w, base, nil
	default:
		return "", nil, fmt.Errorf("historyops: preview scope for family %q: %w", family, ErrInvalidRequest)
	}
}

// countFamily computes one family's block inside the snapshot.
func (p *Previewer) countFamily(ctx context.Context, ex adminstore.RequestQueryRunner, req PreviewRequest, family Family) (FamilyPreview, error) {
	w, args, err := familyScope(ctx, ex, req.Selection, family)
	if err != nil {
		return FamilyPreview{}, err
	}
	fp := FamilyPreview{}
	switch family {
	case FamilyRequestLogs:
		fp.Found, err = countRequestsScope(ctx, ex, w, args)
		if err != nil {
			return FamilyPreview{}, err
		}
		if req.Op.destroysContent() {
			if err := countProtectedGrants(ctx, ex, w, args, &fp); err != nil {
				return FamilyPreview{}, err
			}
		}
		if fp.ResponseViews, err = countResponseViews(ctx, ex, w, args); err != nil {
			return FamilyPreview{}, err
		}
		if fp.ContentBytesEst, err = countRequestContentBytes(ctx, ex, w, args); err != nil {
			return FamilyPreview{}, err
		}
	case FamilyToolCalls:
		fp.Found, err = countSimple(ctx, ex, "SELECT COUNT(*) FROM tool_calls WHERE "+w, args)
		if err != nil {
			return FamilyPreview{}, err
		}
	case FamilyToolCallInvocations:
		fp.Found, err = countSimple(ctx, ex, "SELECT COUNT(*) FROM tool_call_invocations WHERE "+w, args)
		if err != nil {
			return FamilyPreview{}, err
		}
		if fp.ContentBytesEst, err = countSimple(ctx, ex,
			"SELECT COALESCE(SUM(COALESCE(pg_column_size(arguments), 0)), 0) FROM tool_call_invocations WHERE "+w, args); err != nil {
			return FamilyPreview{}, err
		}
	case FamilyCacheEntries:
		fp.Found, err = countSimple(ctx, ex, "SELECT COUNT(*) FROM cache_entries WHERE "+w, args)
		if err != nil {
			return FamilyPreview{}, err
		}
		if fp.ContentBytesEst, err = countSimple(ctx, ex,
			"SELECT COALESCE(SUM(COALESCE(pg_column_size(response), 0) + COALESCE(pg_column_size(sse_chunks), 0)), 0) FROM cache_entries WHERE "+w, args); err != nil {
			return FamilyPreview{}, err
		}
	case FamilySessions:
		if err := countSessions(ctx, ex, w, args, &fp); err != nil {
			return FamilyPreview{}, err
		}
	default:
		return FamilyPreview{}, fmt.Errorf("historyops: preview for family %q: %w", family, ErrInvalidRequest)
	}
	fp.Permitted = fp.Found - fp.Protected
	return fp, nil
}

// countRequestsScope counts request_logs rows with the shared predicate.
func countRequestsScope(ctx context.Context, ex adminstore.RequestQueryRunner, w string, args []any) (int64, error) {
	var n int64
	if err := ex.QueryRow(ctx, "SELECT COUNT(*) FROM request_logs rl WHERE "+w, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("historyops: count request_logs: %w", err)
	}
	return n, nil
}

// countSimple runs a single-scalar count/sum query.
func countSimple(ctx context.Context, ex adminstore.RequestQueryRunner, q string, args []any) (int64, error) {
	var n int64
	if err := ex.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("historyops: count: %w", err)
	}
	return n, nil
}

// countProtectedGrants counts selected request_logs rows that carry a live
// payload grant (unrevoked, unconsumed, unexpired) and collects the grant ids
// — identifiers only, capped. Design §5.4: destroying a row under a live
// one-time grant would turn redemption into a 404 after the root was told the
// grant exists.
func countProtectedGrants(ctx context.Context, ex adminstore.RequestQueryRunner, w string, args []any, fp *FamilyPreview) error {
	// The scope predicate is written for a bare request_logs scan (unqualified
	// org_id/request_id); both columns exist on the grants table too, so the
	// predicate runs inside a subquery and the join references it by alias.
	q := `SELECT COUNT(DISTINCT filtered.request_id),
	       COALESCE(array_agg(DISTINCT g.id::text ORDER BY g.id::text), '{}')
	     FROM (
	       SELECT rl.org_id, rl.request_id FROM request_logs rl WHERE ` + w + `
	     ) filtered
	     JOIN request_payload_grants g
	       ON g.org_id = filtered.org_id AND g.request_id = filtered.request_id
	     WHERE g.revoked_at IS NULL AND g.consumed_at IS NULL AND g.expires_at > now()`
	var ids []string
	if err := ex.QueryRow(ctx, q, args...).Scan(&fp.Protected, &ids); err != nil {
		return fmt.Errorf("historyops: count protected grants: %w", err)
	}
	if len(ids) > maxReportedGrantIDs {
		ids = ids[:maxReportedGrantIDs]
		fp.TruncatedGrantIDs = true
	}
	fp.ProtectedGrantIDs = ids
	return nil
}

// countResponseViews classifies the response column with the SQL CASE whose
// buckets must match adminstore.ParseResponseEnvelope (pinned by the
// integration parity test): NULL and the jsonb 'null' literal are absent;
// a v1 model_response envelope with a known status is envelope; everything
// else is legacy. The jsonb_typeof guard on v keeps parity by construction
// for type-confused inputs: '1' is also the text projection of the STRING
// "1", but ParseResponseEnvelope unmarshals v into an int and would classify
// {"v":"1",...} as legacy — only a NUMBER-typed v may count as the envelope
// version.
func countResponseViews(ctx context.Context, ex adminstore.RequestQueryRunner, w string, args []any) (*ResponseViewCounts, error) {
	q := `SELECT CASE
	      WHEN rl.response IS NULL THEN 'absent'
	      WHEN rl.response = 'null'::jsonb THEN 'absent'
	      WHEN jsonb_typeof(rl.response) = 'object'
	           AND rl.response->>'v' = '1'
	           AND jsonb_typeof(rl.response->'v') = 'number'
	           AND rl.response->>'kind' = 'model_response'
	           AND rl.response->>'status' IN ('complete', 'partial') THEN 'envelope'
	      ELSE 'legacy'
	    END AS bucket, COUNT(*)
	  FROM request_logs rl WHERE ` + w + ` GROUP BY 1`
	rows, err := ex.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("historyops: classify response views: %w", err)
	}
	defer rows.Close()
	out := &ResponseViewCounts{}
	for rows.Next() {
		var bucket string
		var n int64
		if err := rows.Scan(&bucket, &n); err != nil {
			return nil, fmt.Errorf("historyops: scan response views: %w", err)
		}
		switch bucket {
		case "envelope":
			out.Envelope = n
		case "legacy":
			out.Legacy = n
		case "absent":
			out.Absent = n
		}
	}
	return out, rows.Err()
}

// countRequestContentBytes estimates the content-bearing bytes on selected
// request_logs rows: the redact_content target columns (response,
// upstream_request, upstream_response, error) — also the bytes a
// delete-family operation would destroy with the row.
func countRequestContentBytes(ctx context.Context, ex adminstore.RequestQueryRunner, w string, args []any) (int64, error) {
	return countSimple(ctx, ex,
		`SELECT COALESCE(SUM(
		    COALESCE(pg_column_size(rl.response), 0) +
		    COALESCE(pg_column_size(rl.upstream_request), 0) +
		    COALESCE(pg_column_size(rl.upstream_response), 0) +
		    COALESCE(LENGTH(rl.error), 0)), 0)
		  FROM request_logs rl WHERE `+w, args)
}

// countSessions computes the sessions block: found, the sessions still pinned
// by request_logs (FK NO ACTION — a naive delete fails, never silently
// cascades), plus nothing else. The message cascade is counted separately in
// countCascades so it is visible even when the caller previews without
// touching anything.
func countSessions(ctx context.Context, ex adminstore.RequestQueryRunner, w string, args []any, fp *FamilyPreview) error {
	if err := ex.QueryRow(ctx,
		`SELECT COUNT(*),
	       COUNT(*) FILTER (WHERE EXISTS (
	         SELECT 1 FROM request_logs rl WHERE rl.session_id = sessions.id))
	     FROM sessions WHERE `+w, args...).Scan(&fp.Found, &fp.BlockedByFK); err != nil {
		return fmt.Errorf("historyops: count sessions: %w", err)
	}
	return nil
}

// countCascades counts the message rows that would cascade with the selected
// sessions (messages.session_id ON DELETE CASCADE) — explicitly, never
// silently (design §3). The sessions scope is org+period only (metadata
// filters are request-shaped and never apply to sessions), so the joined
// predicate is written alias-qualified here rather than string-mangled from
// familyScope.
func (p *Previewer) countCascades(ctx context.Context, ex adminstore.RequestQueryRunner, req PreviewRequest, report *PreviewReport) error {
	hasSessions := false
	for _, f := range req.Selection.Families {
		if f == FamilySessions {
			hasSessions = true
			break
		}
	}
	if !hasSessions {
		return nil
	}
	c := CascadePreview{
		Family: FamilyMessages,
		Note:   "messages cascade with their session (ON DELETE CASCADE); counted explicitly",
	}
	if err := ex.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(COALESCE(pg_column_size(m.content), 0)), 0)
	     FROM messages m JOIN sessions s ON m.session_id = s.id
	     WHERE s.org_id = $1 AND s.created_at >= $2 AND s.created_at <= $3`,
		req.Selection.OrgID, req.Selection.Period.From, req.Selection.Period.To,
	).Scan(&c.Rows, &c.ContentBytesEst); err != nil {
		return fmt.Errorf("historyops: count message cascade: %w", err)
	}
	report.Cascades = append(report.Cascades, c)
	return nil
}

// FamilyMessages is the dependent family behind the sessions cascade.
const FamilyMessages = Family("messages")
