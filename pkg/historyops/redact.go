package historyops

// redact.go implements the redact_content operation (lane ENT-HIST-04): the
// content-rewrite operation that destroys payload bytes while every metadata
// signal stays intact. What it nulls per family (card AC-1, the only content
// surfaces in migrations/0001_init.up.sql):
//
//	request_logs          response, upstream_request, upstream_response,
//	                      error            -> SQL NULL
//	tool_call_invocations arguments        -> SQL NULL
//	cache_entries         response         -> 'null'::jsonb (column is NOT NULL;
//	                      the jsonb null literal is the codebase's absent marker,
//	                      see adminstore response-view buckets)
//	                      sse_chunks       -> SQL NULL
//	messages              content          -> '' (column is NOT NULL), reached
//	                      through the selected sessions
//	tool_calls            no content column -> zero-effect family: planned as
//	                      nothing, reported as nothing
//
// Metadata that MUST survive (card AC-2, the counts-invariant): row existence,
// prompt_hash, tokens_in/out, status_code, duration, model fields, labels,
// updated rollups, request_lineage rows, the audit hash chain. Only content
// bytes disappear; the preview's counts invariant (found/permitted/cascades)
// is unchanged by a completed redact — only response views shift to absent and
// content_bytes_est drops.
//
// Idempotency (Runner contract): ExecuteBatch is idempotent per (job, batch,
// ids). Every UPDATE carries a not-already-redacted guard, so a re-executed
// batch (crash between execution and checkpoint) rewrites nothing and returns
// zero rows — at-least-once execution still yields exactly-once effect and
// exactly-once counts.
//
// Rights: enqueue of redact_content requires org-admin role plus explicit
// requests.read_payloads and requests.read_originals grants (rights.go,
// 03-RIGHTS-MODEL §3). Per-row grant protection deliberately does NOT apply to
// redact_content: the caller's explicit grants are the authorization (pinned
// by preview_int_test.go: preview reports protected=0 for redact).
//
// Identifier hygiene: refusal and journal details carry counts, digests and
// row ids — never payload bytes. Nothing redacted is ever logged.

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// defaultRedactBatchSize bounds the number of row ids one ExecuteBatch call
// rewrites (and therefore one transaction locks). 500 matches the engine
// test default scale: big enough for throughput, small enough to stay far
// below any lock/queue pressure threshold.
const defaultRedactBatchSize = 500

// RedactConfig tunes the redact_content runner. Zero values are valid.
type RedactConfig struct {
	// BatchSize bounds the row ids planned per batch. <= 0 selects
	// defaultRedactBatchSize.
	BatchSize int
}

// RedactRunner implements Runner for OpRedactContent. Registered by the
// wiring layer via Engine.RegisterRunner(OpRedactContent, NewRedactRunner(...)).
type RedactRunner struct {
	pool      *pgxpool.Pool
	batchSize int
}

// NewRedactRunner wires the redact_content runner against a regional pool.
// The pool MUST be pinned to one region (app.region set) per the regional
// data-ownership rule (03-RIGHTS-MODEL §1); org scoping itself is enforced by
// every predicate here.
func NewRedactRunner(pool *pgxpool.Pool, cfg RedactConfig) *RedactRunner {
	size := cfg.BatchSize
	if size <= 0 {
		size = defaultRedactBatchSize
	}
	return &RedactRunner{pool: pool, batchSize: size}
}

// Compile-time contract check.
var _ Runner = (*RedactRunner)(nil)

// VerifySnapshot re-checks the enqueued job inside one consistent snapshot:
// the schema stamp must still be the database stamp and the recorded digest
// must still match the selection over that stamp. Any drift refuses
// digest_mismatch fail-closed — zero rows touched.
func (r *RedactRunner) VerifySnapshot(ctx context.Context, job *Job) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("historyops: begin redact snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	stamp, err := SchemaStampFromDB(ctx, tx)
	if err != nil {
		return err
	}
	digest, err := SelectionDigest(OpRedactContent, job.Selection, stamp)
	if err != nil {
		return err
	}
	if digest != job.SelectionDigest {
		return Refuse(RefusalDigestMismatch,
			"selection changed since enqueue: recomputed digest %q does not match job digest %q",
			digest, job.SelectionDigest)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("historyops: commit redact snapshot: %w", err)
	}
	return nil
}

// Plan captures the id-precise batches inside ONE repeatable-read snapshot,
// mirroring the preview's predicates exactly (familyScope + the request-list
// where clause): the planned ids are exactly the preview's permitted rows.
// Ids are family-scoped strings ("request_logs/42") so ExecuteBatch can
// derive the target family from the captured plan alone.
func (r *RedactRunner) Plan(ctx context.Context, job *Job) ([][]string, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("historyops: begin redact plan: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	var ids []string
	for _, family := range job.Selection.Families {
		famIDs, err := redactableIDs(ctx, tx, job.Selection, family)
		if err != nil {
			return nil, err
		}
		for _, id := range famIDs {
			ids = append(ids, encodePlanID(family, id))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("historyops: commit redact plan: %w", err)
	}
	return chunkIDs(ids, r.batchSize), nil
}

// ExecuteBatch applies exactly one captured batch inside one read-committed
// transaction. Counts are physical effects: rows actually rewritten (a row
// already redacted by an earlier execution returns zero and is not counted).
// Session batches report the messages they redacted (FamilyMessages) — the
// session rows themselves carry no content column.
func (r *RedactRunner) ExecuteBatch(ctx context.Context, job *Job, _ int, ids []string) (FamilyCounts, error) {
	allowed := make(map[Family]bool, len(job.Selection.Families))
	for _, f := range job.Selection.Families {
		allowed[f] = true
	}
	groups := make(map[Family][]string, len(job.Selection.Families))
	for _, pid := range ids {
		family, raw, err := decodePlanID(pid)
		if err != nil {
			return nil, err
		}
		// Defense in depth against a corrupted checkpoint: never rewrite a
		// family the selection does not name.
		if !allowed[family] {
			return nil, fmt.Errorf("%w: plan id %q names family outside the selection", ErrInvalidRequest, pid)
		}
		groups[family] = append(groups[family], raw)
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("historyops: begin redact batch: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	counts := FamilyCounts{}
	// Iterate in the selection's canonical order: deterministic statements,
	// deterministic journal details.
	for _, family := range job.Selection.Families {
		rawIDs := groups[family]
		if len(rawIDs) == 0 {
			continue
		}
		n, err := r.redactFamily(ctx, tx, family, rawIDs)
		if err != nil {
			return nil, err
		}
		counts[redactCountFamily(family)] += n
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("historyops: commit redact batch: %w", err)
	}
	return counts, nil
}

// redactCountFamily maps a planned family to the family its physical effects
// are counted under: redacting a session rewrites its messages.
func redactCountFamily(family Family) Family {
	if family == FamilySessions {
		return FamilyMessages
	}
	return family
}

// redactFamily rewrites one family's content columns for the given ids with
// the guarded, id-precise UPDATEs. Returns the number of rows actually
// rewritten.
func (r *RedactRunner) redactFamily(ctx context.Context, tx pgx.Tx, family Family, rawIDs []string) (int64, error) {
	switch family {
	case FamilyRequestLogs:
		ids, err := parseBigIntIDs(rawIDs)
		if err != nil {
			return 0, err
		}
		return execRedactCount(ctx, tx, `
			UPDATE request_logs rl
			   SET response = NULL, upstream_request = NULL,
			       upstream_response = NULL, error = NULL
			 WHERE rl.id = ANY($1::bigint[])
			   AND (rl.response IS NOT NULL OR rl.upstream_request IS NOT NULL
			        OR rl.upstream_response IS NOT NULL OR rl.error IS NOT NULL)
			RETURNING 1`, ids)
	case FamilyToolCallInvocations:
		ids, err := parseBigIntIDs(rawIDs)
		if err != nil {
			return 0, err
		}
		return execRedactCount(ctx, tx, `
			UPDATE tool_call_invocations
			   SET arguments = NULL
			 WHERE id = ANY($1::bigint[])
			   AND arguments IS NOT NULL
			RETURNING 1`, ids)
	case FamilyCacheEntries:
		// response is NOT NULL: the jsonb null literal is the codebase's
		// absent marker (same bucket the preview counts as absent).
		return execRedactCount(ctx, tx, `
			UPDATE cache_entries
			   SET response = 'null'::jsonb, sse_chunks = NULL
			 WHERE id = ANY($1::uuid[])
			   AND (response <> 'null'::jsonb OR sse_chunks IS NOT NULL)
			RETURNING 1`, rawIDs)
	case FamilySessions:
		// Sessions carry no content column; their content lives in messages.
		return execRedactCount(ctx, tx, `
			UPDATE messages
			   SET content = ''
			 WHERE session_id = ANY($1::uuid[])
			   AND content <> ''
			RETURNING 1`, rawIDs)
	case FamilyToolCalls:
		// Zero-effect family (no content column): the plan never carries
		// tool_calls ids; reaching this arm means a corrupted checkpoint.
		return 0, fmt.Errorf("%w: family %q has no content surface", ErrInvalidRequest, family)
	default:
		return 0, fmt.Errorf("%w: unknown redact family %q", ErrInvalidRequest, family)
	}
}

// execRedactCount runs one guarded UPDATE and counts the rows it rewrote.
func execRedactCount(ctx context.Context, tx pgx.Tx, query string, ids any) (int64, error) {
	rows, err := tx.Query(ctx, query, ids)
	if err != nil {
		return 0, fmt.Errorf("historyops: redact rows: %w", err)
	}
	defer rows.Close()
	var n int64
	for rows.Next() {
		var one int64
		if err := rows.Scan(&one); err != nil {
			return 0, fmt.Errorf("historyops: scan redact row: %w", err)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("historyops: redact rows: %w", err)
	}
	return n, nil
}

// redactableIDs selects the ids one family would redact, in deterministic
// order, with the exact preview predicates. tool_calls is a zero-effect
// family (no content column): it contributes no ids by design.
func redactableIDs(ctx context.Context, ex adminstore.RequestQueryRunner, sel Selection, family Family) ([]string, error) {
	if family == FamilyToolCalls {
		return nil, nil
	}
	w, args, err := familyScope(ctx, ex, sel, family)
	if err != nil {
		return nil, err
	}
	var q string
	switch family {
	case FamilyRequestLogs:
		// The request-list predicate is written for a bare request_logs scan
		// (unqualified columns), so the alias-only form matches the preview.
		q = "SELECT rl.id::text FROM request_logs rl WHERE " + w + " ORDER BY rl.id"
	case FamilyToolCallInvocations:
		q = "SELECT id::text FROM tool_call_invocations WHERE " + w + " ORDER BY id"
	case FamilyCacheEntries:
		q = "SELECT id::text FROM cache_entries WHERE " + w + " ORDER BY id"
	case FamilySessions:
		q = "SELECT id::text FROM sessions WHERE " + w + " ORDER BY id"
	default:
		return nil, fmt.Errorf("%w: unknown redact family %q", ErrInvalidRequest, family)
	}
	rows, err := ex.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("historyops: plan %s ids: %w", family, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("historyops: scan %s id: %w", family, err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("historyops: plan %s ids: %w", family, err)
	}
	return out, nil
}

// encodePlanID builds the family-scoped plan identifier "<family>/<id>".
// Family names never contain "/", so the split is unambiguous.
func encodePlanID(family Family, id string) string {
	return string(family) + "/" + id
}

// decodePlanID splits a captured plan identifier back into family and raw id.
// Unknown families are malformed checkpoints (engine-store corruption), not
// refusals.
func decodePlanID(planID string) (Family, string, error) {
	name, raw, ok := strings.Cut(planID, "/")
	if !ok {
		return "", "", fmt.Errorf("%w: malformed plan id %q", ErrInvalidRequest, planID)
	}
	for _, f := range SelectableFamilies {
		if string(f) == name {
			return f, raw, nil
		}
	}
	return "", "", fmt.Errorf("%w: plan id %q names unknown family %q", ErrInvalidRequest, planID, name)
}

// chunkIDs splits ordered ids into batches of at most size (0/negative =
// defaultRedactBatchSize).
func chunkIDs(ids []string, size int) [][]string {
	if size <= 0 {
		size = defaultRedactBatchSize
	}
	var out [][]string
	for start := 0; start < len(ids); start += size {
		end := start + size
		if end > len(ids) {
			end = len(ids)
		}
		out = append(out, ids[start:end])
	}
	return out
}

// parseBigIntIDs converts planned raw ids into bigints for the ANY($1)
// predicates. A malformed id means a corrupted checkpoint — fail the batch
// (transient retries exhaust into a terminal failure) rather than rewrite a
// guessed subset.
func parseBigIntIDs(raw []string) ([]int64, error) {
	out := make([]int64, len(raw))
	for i, s := range raw {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: plan id %q is not a bigint", ErrInvalidRequest, s)
		}
		out[i] = n
	}
	return out, nil
}
