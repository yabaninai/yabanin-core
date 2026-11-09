package historyops

// ENT-HIST-05 — the archive_copy operation: copy selected history rows to
// org-namespace cold storage as JSONL objects with sha256 manifests, driven
// through the managed-job engine (backlog card 05, HISTORY-LIFECYCLE-BACKLOG).
//
// Invariants this file owns:
//
//   - Deterministic, idempotent objects: the cold key
//     historyops/<org>/<digest>/job-<id>/batch-<i>/<family>.jsonl and its
//     manifest are pure functions of (org, selection digest, JOB id, batch
//     index, family, row bytes), so a re-run of the same batch rewrites
//     byte-identical objects and never duplicates or inflates counts. The
//     job-id component makes different executions of the same selection
//     disjoint objects: a repeated selection (same digest, new idempotency
//     key, late-arriving rows) can never overwrite the first job's archive
//     (HIST-03).
//   - Non-overwriting writes: when the store has a read side, an existing
//     object is never silently replaced — identical bytes are the
//     crash-window replay (skipped), different bytes refuse
//     (archive_checksum_mismatch) (HIST-03).
//   - Export completeness before any external effect: the snapshot fetch must
//     return EXACTLY the planned ids; a short, reordered or empty-row export
//     refuses (archive_checksum_mismatch) and the job fails fail-closed.
//   - Exactly-once counting without a durable archive index: whether a batch
//     still contributes to confirmed counts is derived from the durable
//     checkpoint alone (batchCountDelta), so the at-least-once execution of a
//     crash window does not double-count.
//   - Destination rules run twice: at enqueue (engine.validateDestination
//     delegates here) and again at run time, so a job never touches a
//     namespace enqueue would have refused.
//
// Layering: ColdStorage/ArchiveVerifier are structural mirrors of the
// loggerd consumer's cold-storage contract — pkg/ never imports services/.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// HistoryDB is the database seam for the archive runners: the method set of
// a pgx pool — and of a pgx transaction, which the snapshot-scoped exports
// run inside. Declared structurally so the runners depend on an interface,
// not on the concrete pool type.
type HistoryDB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
}

// ColdStorage is the local structural mirror of the cold-storage write
// contract the loggerd consumer uses (Write(ctx, key, data)). Mirrored — not
// imported — so this package stays free of services/ dependencies; the
// production wiring passes the consumer's store, which satisfies this
// interface structurally.
type ColdStorage interface {
	Write(ctx context.Context, key string, data []byte) error
}

// ArchiveVerifier is the optional read side of cold storage: stores that can
// read objects back let the archive runners verify what landed (checksum
// match) before anything destructive runs. Write-only stores (the retention
// FSStore is one) degrade to the Write-error discipline plus the
// completeness gate below — a degraded verification path, never a silent
// pass: the refusal semantics of archive_checksum_mismatch are unchanged.
type ArchiveVerifier interface {
	Read(ctx context.Context, key string) ([]byte, error)
}

// validateArchiveDestination is the single source of truth for the archive
// destination rules — the engine's enqueue gate (validateDestination) and the
// run-time re-validation both delegate here: archive ops need a destination
// (no_destination), only file:// roots are supported
// (unsupported_destination), the path must not escape via traversal and must
// stay inside THIS org's historyops namespace (foreign_destination).
func validateArchiveDestination(op Operation, orgID, dest string) error {
	if dest == "" {
		return Refuse(RefusalNoDestination,
			"operation %s requires a destination", op)
	}
	if !strings.HasPrefix(dest, "file://") {
		return Refuse(RefusalUnsupportedDestination,
			"only file:// destinations are supported")
	}
	path := strings.TrimPrefix(dest, "file://")
	if strings.Contains(path, "..") {
		return Refuse(RefusalUnsupportedDestination, "destination path must not contain ..")
	}
	if !strings.Contains(path, "/historyops/"+orgID+"/") &&
		!strings.HasSuffix(path, "/historyops/"+orgID) {
		return Refuse(RefusalForeignDestination,
			"destination must stay inside org %s historyops namespace", orgID)
	}
	return nil
}

// verifyArchiveSnapshot re-checks a claimed job against the live database
// before planning: the schema stamp must still digest to the digest the
// preview presented (drift refuses fail-closed), the selection must still
// validate, and archive operations re-validate their destination at run
// time. Shared by both archive runners.
func verifyArchiveSnapshot(ctx context.Context, db HistoryDB, now func() time.Time, job *Job) error {
	stamp, err := SchemaStampFromDB(ctx, db)
	if err != nil {
		return err
	}
	digest, err := SelectionDigest(job.Op, job.Selection, stamp)
	if err != nil {
		return err
	}
	if digest != job.SelectionDigest {
		return Refuse(RefusalDigestMismatch,
			"selection no longer digests to the presented digest; run the preview again")
	}
	if err := job.Selection.Validate(now()); err != nil {
		return err
	}
	if job.Op.needsDestination() {
		if err := validateArchiveDestination(job.Op, job.OrgID, job.Destination); err != nil {
			return err
		}
	}
	return nil
}

// batchFamilyPrefix marks the family of a plan batch. Row ids are decimal
// digits (bigint families) or uuid hex/dashes (uuid families), so the
// "family:" marker can never collide with an id.
const batchFamilyPrefix = "family:"

// encodeBatch stamps a plan batch with its family.
func encodeBatch(family Family, ids []string) []string {
	out := make([]string, 0, len(ids)+1)
	out = append(out, batchFamilyPrefix+string(family))
	return append(out, ids...)
}

// decodeBatch splits a stamped plan batch back into family and ids. A batch
// without a well-formed marker is a corrupt checkpoint — an invalid-request
// error, not something to best-effort guess.
func decodeBatch(batch []string) (Family, []string, error) {
	if len(batch) == 0 || !strings.HasPrefix(batch[0], batchFamilyPrefix) {
		return "", nil, fmt.Errorf("historyops: corrupt plan batch: %w", ErrInvalidRequest)
	}
	family := Family(strings.TrimPrefix(batch[0], batchFamilyPrefix))
	return family, batch[1:], nil
}

// batchCountDelta decides whether executing the batch at plan position
// batchIndex now still contributes to the confirmed counts. The answer is
// derived from the durable checkpoint alone (confirmed counts vs the sizes
// of the earlier batches of the same family), so it is stable across
// processes and restarts: the engine executes a batch at least once (crash
// between ExecuteBatch success and SaveCheckpoint), and this gate is what
// keeps the at-least-once re-execution from inflating the archive counts.
// The destructive runner (remove.go) does not need it — its counts are the
// actual RowsAffected, which are zero on a replay by nature.
func batchCountDelta(plan [][]string, batchIndex int, confirmed FamilyCounts) (int64, error) {
	if batchIndex < 0 || batchIndex >= len(plan) {
		return 0, fmt.Errorf("historyops: batch index %d outside plan of %d batches: %w",
			batchIndex, len(plan), ErrInvalidRequest)
	}
	family, ids, err := decodeBatch(plan[batchIndex])
	if err != nil {
		return 0, err
	}
	var prior int64
	for i := 0; i < batchIndex; i++ {
		f, earlier, err := decodeBatch(plan[i])
		if err != nil {
			return 0, err
		}
		if f == family {
			prior += int64(len(earlier))
		}
	}
	have := confirmed[family]
	switch {
	case have == prior:
		// This batch is not yet checkpointed — it counts.
		return int64(len(ids)), nil
	case have == prior+int64(len(ids)):
		// Already checkpointed: the crash-window replay contributes zero.
		return 0, nil
	default:
		return 0, fmt.Errorf(
			"historyops: checkpoint count drift for family %s: confirmed %d, batches before index %d sum to %d, batch size %d: %w",
			family, have, batchIndex, prior, len(ids), ErrInvalidRequest)
	}
}

// archiveObjectKey returns the cold-storage key for one archived batch.
// Every component is deterministic, so a re-run of the same batch rewrites
// byte-identical objects (the idempotent-replay property) and objects stay
// inside the historyops/ namespace, disjoint from the loggerd exporter keys.
// The job-id component scopes objects to one concrete execution: two jobs
// with the same selection digest (a repeated selection after late arrivals)
// produce disjoint keys, so the second job's batch-0 can never overwrite the
// first job's batch-0 (HIST-03) — object identity carries durable job
// identity, not just selection identity.
func archiveObjectKey(orgID, digest, jobID string, batchIndex int, family Family) string {
	return fmt.Sprintf("historyops/%s/%s/job-%s/batch-%d/%s.jsonl",
		orgID, digest, keySafeJobID(jobID), batchIndex, family)
}

// keySafeJobID restricts the job-id key component to characters that cannot
// alter the key's path shape. Job ids are UUIDs (NewJobID) and always pass
// through unchanged; the sanitizer is defense in depth for the free-form ids
// tests and exotic stores may carry.
func keySafeJobID(id string) string {
	if id == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// archiveManifest mirrors the loggerd exporter's manifest contract (table,
// scope, rows, sha256, redacted, cutoff_days, exported_at) and adds the
// historyops extension fields. exported_at is pinned to the job's creation
// time rather than wall-clock now() so a re-run serializes byte-identical
// manifests. cutoff_days is 0 by contract: retention-window semantics do not
// apply here — the period bounds are explicit below.
type archiveManifest struct {
	Table      string `json:"table"`
	Scope      string `json:"scope"`
	Rows       int    `json:"rows"`
	Sha256     string `json:"sha256"`
	Redacted   bool   `json:"redacted"`
	CutoffDays int    `json:"cutoff_days"`
	ExportedAt string `json:"exported_at"`

	SchemaVersion int    `json:"schema_version"`
	Op            string `json:"op,omitempty"`
	OrgID         string `json:"org_id,omitempty"`
	Digest        string `json:"selection_digest,omitempty"`
	// JobID is the durable identity of the execution that wrote the object:
	// the manifest answers "which job archived this" without key parsing
	// (HIST-03: object identity contains durable job/plan identity).
	JobID      string `json:"job_id,omitempty"`
	PeriodFrom string `json:"period_from,omitempty"`
	PeriodTo   string `json:"period_to,omitempty"`
	// Batch has no omitempty: batch 0 is a legitimate, common index and its
	// manifest must still carry the field.
	Batch int `json:"batch"`
}

// writeArchiveObject serializes payloads as JSONL (one row_to_json document
// per line, verbatim PG serialization), computes the sha256 over exactly the
// written bytes and writes object + manifest through the cold store. It
// returns the manifest WITH the computed sha256 — the caller's copy must be
// used for the read-back comparison, never the pre-write value.
//
// Writes are non-overwriting (HIST-03): on stores with a read side, an
// existing object is compared first — byte-identical content is the
// engine's at-least-once replay (nothing is written), different content
// refuses the execution instead of replacing an earlier archive. On
// write-only stores the discipline degrades to the Write-error path, exactly
// like the read-back checksum gate.
func writeArchiveObject(ctx context.Context, store ColdStorage, key string, m archiveManifest, payloads [][]byte) (archiveManifest, error) {
	var buf bytes.Buffer
	for _, p := range payloads {
		buf.Write(p)
		buf.WriteByte('\n')
	}
	sum := sha256.Sum256(buf.Bytes())
	m.Sha256 = hex.EncodeToString(sum[:])
	manifest, err := json.Marshal(m)
	if err != nil {
		return m, fmt.Errorf("historyops: marshal archive manifest for %s: %w", key, err)
	}
	if err := writeArchiveBytes(ctx, store, key, buf.Bytes()); err != nil {
		return m, fmt.Errorf("historyops: write archive object %s: %w", key, err)
	}
	if err := writeArchiveBytes(ctx, store, key+".manifest.json", manifest); err != nil {
		return m, fmt.Errorf("historyops: write archive manifest %s: %w", key+".manifest.json", err)
	}
	return m, nil
}

// writeArchiveBytes writes data under key without ever replacing existing
// content: stores with a read side compare first — identical bytes are the
// idempotent replay (no write), different bytes refuse (a repeated selection
// with new rows must never overwrite an earlier archive; HIST-03). A read
// error is treated as "absent at this moment" and the write proceeds — the
// same degradation the read-back checksum gate accepts for read-incapable
// stores.
func writeArchiveBytes(ctx context.Context, store ColdStorage, key string, data []byte) error {
	verifier, ok := store.(ArchiveVerifier)
	if !ok {
		return store.Write(ctx, key, data)
	}
	existing, err := verifier.Read(ctx, key)
	if err == nil {
		if !bytes.Equal(existing, data) {
			return Refuse(RefusalArchiveChecksum,
				"archive object %s already exists with different content; refusing to overwrite", key)
		}
		return nil
	}
	return store.Write(ctx, key, data)
}

// verifyArchiveReadback re-reads the written object when the store supports
// reads and compares the sha256 against the manifest — the backlog AC's
// "a failed or incomplete write does not permit hot delete" belt. Stores
// without Read rely on the Write-error discipline; the completeness gate has
// already refused short exports before any byte was written.
func verifyArchiveReadback(ctx context.Context, store ColdStorage, key string, m archiveManifest) error {
	verifier, ok := store.(ArchiveVerifier)
	if !ok {
		return nil
	}
	data, err := verifier.Read(ctx, key)
	if err != nil {
		return Refuse(RefusalArchiveChecksum, "archive read-back failed for %s: %v", key, err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != m.Sha256 {
		return Refuse(RefusalArchiveChecksum,
			"archive checksum mismatch for %s: written %s, read back %s", key, m.Sha256, got)
	}
	return nil
}

// verifyArchiveCompleteness refuses unless the snapshot returned EXACTLY the
// planned ids in order, each with a non-empty serialization. The archive is
// the provenance record the destructive half later relies on; "mostly
// exported" is a refusal, not a warning (backlog card 03 AC). Used by the
// copy-only runner: it never deletes, so a missing planned row can only mean
// external drift and must stop the job.
func verifyArchiveCompleteness(family Family, planned, fetched []string, payloads [][]byte) error {
	if len(fetched) != len(planned) {
		return Refuse(RefusalArchiveChecksum,
			"archive incomplete for %s: planned %d row(s), snapshot returned %d",
			family, len(planned), len(fetched))
	}
	for i := range planned {
		if fetched[i] != planned[i] {
			return Refuse(RefusalArchiveChecksum,
				"archive incomplete for %s: planned id %s but snapshot returned %s at position %d",
				family, planned[i], fetched[i], i)
		}
		if len(payloads[i]) == 0 {
			return Refuse(RefusalArchiveChecksum,
				"archive incomplete for %s: row %s serialized to no bytes", family, planned[i])
		}
	}
	return nil
}

// verifyArchiveSubset is the destructive runner's gate: every exported id
// must be a planned id, in the plan's ascending order, with non-empty
// serialization — but the export may be a strict subset. Rows planned but no
// longer present are rows this job already archived and deleted in an earlier
// at-least-once execution (deletes are single atomic statements, so no
// partial state survives a crash) or rows removed externally after planning;
// both are legitimately absent. An EMPTY export means the whole batch was
// already applied — the replay skips it (the exactly-once behavior for the
// engine's restart window between ExecuteBatch and SaveCheckpoint). The
// invariant that matters is untouched: THE DELETE SET IS EXACTLY THE EXPORT
// SET of the same execution, so every deleted row was verifiably archived
// first.
func verifyArchiveSubset(family Family, planned, fetched []string, payloads [][]byte) error {
	pos := 0
	for i, id := range fetched {
		for pos < len(planned) && planned[pos] != id {
			pos++
		}
		if pos == len(planned) {
			return Refuse(RefusalArchiveChecksum,
				"archive export for %s returned unplanned id %s at position %d",
				family, id, i)
		}
		pos++
		if len(payloads[i]) == 0 {
			return Refuse(RefusalArchiveChecksum,
				"archive incomplete for %s: row %s serialized to no bytes", family, id)
		}
	}
	return nil
}

// familyIDCast returns the explicit SQL cast for an id-list parameter
// (::uuid[] or ::bigint[]). Always total: ANY() can infer the element type
// from the bound value, but multi-argument unnest (the version-guarded
// deletes) cannot — an untyped parameter there fails with "unnest(unknown)
// is not unique" (pgx v5.12 sends the parameter type as unknown).
func familyIDCast(family Family) string {
	switch family {
	case FamilySessions, FamilyCacheEntries:
		return "::uuid[]"
	default:
		return "::bigint[]"
	}
}

// familyIDArg encodes a batch's ids for the ANY(...) list: uuid families
// keep their string form (cast to uuid[] at the call site); bigint families
// are parsed to int64 so the engine keeps using the primary-key index
// instead of a text-cast scan. A non-numeric id in a bigint batch is a
// corrupt checkpoint (invalid request), never a best-effort skip.
func familyIDArg(family Family, ids []string) (any, error) {
	switch family {
	case FamilySessions, FamilyCacheEntries:
		return ids, nil
	case FamilyRequestLogs, FamilyToolCalls, FamilyToolCallInvocations, FamilyMessages:
		out := make([]int64, len(ids))
		for i, raw := range ids {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("historyops: family %s: id %q is not a bigint: %w",
					family, raw, ErrInvalidRequest)
			}
			out[i] = n
		}
		return out, nil
	default:
		return nil, fmt.Errorf("historyops: unknown family %q: %w", family, ErrInvalidRequest)
	}
}

// exportBatchRows fetches one batch's rows inside a REPEATABLE READ READ
// ONLY transaction with the session timezone pinned to UTC, so the
// row_to_json serialization is deterministic (byte-stable re-runs) and the
// fetch cannot drift mid-batch. Returns the fetched ids in plan order, their
// xmin system versions (audit HIST-04: the delete half may only remove the
// exact versions it archived) and the verbatim row JSON documents.
//
// The plan-order guarantee is enforced client-side (F-3/R1): the wire has
// been observed to deliver complete, plan-only result sets in permuted
// order under load, which verifyArchiveSubset's subsequence check would
// refuse as "unplanned id". Sorting fetched triples into the planned id
// order after fetch makes every consumer (verification, digest, chunking)
// depend only on the plan, never on transport behavior.
func exportBatchRows(ctx context.Context, db HistoryDB, orgID string, family Family, ids []string) ([]string, []string, [][]byte, error) {
	idArg, err := familyIDArg(family, ids)
	if err != nil {
		return nil, nil, nil, err
	}
	// The table is referenced through its alias (not a derived table): the
	// xmin system column only resolves on the real row, and row_to_json of
	// a table alias serializes exactly the table's columns, system columns
	// excluded — the same verbatim payload as the previous derived form.
	q := `SELECT t.id::text, t.xmin::text, COALESCE(row_to_json(t)::text, '')
	  FROM ` + string(family) + ` t
	  WHERE t.org_id = $1::uuid AND t.id = ANY($2` + familyIDCast(family) + `)
	  ORDER BY t.id`

	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("historyops: begin export snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	// SET LOCAL is session-local state, permitted in read-only transactions;
	// it pins timestamptz rendering for this snapshot only.
	if _, err := tx.Exec(ctx, "SET LOCAL TimeZone = 'UTC'"); err != nil {
		return nil, nil, nil, fmt.Errorf("historyops: pin export timezone: %w", err)
	}
	rows, err := tx.Query(ctx, q, orgID, idArg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("historyops: export %s batch: %w", family, err)
	}
	fetched, xmins, payloads, err := scanExportRows(rows)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("historyops: commit export snapshot: %w", err)
	}
	sortExportToPlan(fetched, xmins, payloads, ids)
	return fetched, xmins, payloads, nil
}

// sortExportToPlan reorders fetched (id, xmin, payload) triples into the
// planned id order, in place (F-3/R1). Ids absent from the plan — a phantom
// the server should not have returned — sort ahead of planned rows in
// stable encounter order: the reorder is deterministic and verifyArchiveSubset
// still refuses them (sorting never hides a phantom, it only neutralizes
// permutations of rows that are all in the plan).
func sortExportToPlan(fetched, xmins []string, payloads [][]byte, planned []string) {
	pos := make(map[string]int, len(planned))
	for i, id := range planned {
		if _, seen := pos[id]; !seen {
			pos[id] = i
		}
	}
	order := make([]int, len(fetched))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		pa, okA := pos[fetched[a]]
		pb, okB := pos[fetched[b]]
		switch {
		case okA && okB:
			return pa < pb
		case okA != okB:
			return !okA
		default:
			return false // both unplanned: keep stable encounter order
		}
	})
	reorderExportTriples(fetched, xmins, payloads, order)
}

// sortExportByID reorders the cascade-export triples into ascending id
// order, in place (F-3/R1). Messages ids are bigints, so ids that all parse
// numerically compare numerically (matching the query's ORDER BY m.id);
// anything else falls back to lexicographic comparison — deterministic
// either way, and never a transport dependency.
func sortExportByID(fetched, xmins []string, payloads [][]byte) {
	numeric := make([]int64, len(fetched))
	allNumeric := true
	for i, id := range fetched {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			allNumeric = false
			break
		}
		numeric[i] = n
	}
	order := make([]int, len(fetched))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		if allNumeric {
			return numeric[a] < numeric[b]
		}
		return fetched[a] < fetched[b]
	})
	reorderExportTriples(fetched, xmins, payloads, order)
}

// reorderExportTriples applies a permutation of positions to the parallel
// export slices, in place.
func reorderExportTriples(fetched, xmins []string, payloads [][]byte, order []int) {
	tmpIDs := make([]string, len(order))
	tmpXmins := make([]string, len(order))
	tmpPayloads := make([][]byte, len(order))
	for dst, src := range order {
		tmpIDs[dst] = fetched[src]
		tmpXmins[dst] = xmins[src]
		tmpPayloads[dst] = payloads[src]
	}
	copy(fetched, tmpIDs)
	copy(xmins, tmpXmins)
	copy(payloads, tmpPayloads)
}

// scanExportRows collects the (id, xmin, verbatim row JSON) triples of an
// export query — the shared tail of the export paths. xmins ride along for
// the delete half's version guard (HIST-04).
func scanExportRows(rows pgx.Rows) ([]string, []string, [][]byte, error) {
	defer rows.Close()
	var fetched []string
	var xmins []string
	var payloads [][]byte
	for rows.Next() {
		var idText, xminText, payload string
		if err := rows.Scan(&idText, &xminText, &payload); err != nil {
			return nil, nil, nil, fmt.Errorf("historyops: scan export row: %w", err)
		}
		fetched = append(fetched, idText)
		xmins = append(xmins, xminText)
		payloads = append(payloads, []byte(payload))
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("historyops: iterate export rows: %w", err)
	}
	return fetched, xmins, payloads, nil
}

// exportSessionMessages exports the message cascade of the batch's sessions —
// every message whose session is among the ids — inside its own REPEATABLE
// READ READ ONLY transaction with the session timezone pinned to UTC (the
// exportBatchRows discipline). This is the derived archive (audit HIST-02):
// the sessions DELETE cascades to messages, so the cascade must be captured
// before the delete, not destroyed silently. Messages of pinned sessions are
// included; the archive may therefore be a superset of what dies (harmless —
// restore skips rows that are still live). The returned stream is sorted
// into ascending id order client-side (F-3/R1).
func exportSessionMessages(ctx context.Context, db HistoryDB, orgID string, sessionIDs []string) ([]string, []string, [][]byte, error) {
	q := `SELECT m.id::text, m.xmin::text, COALESCE(row_to_json(m)::text, '')
	  FROM messages m
	  JOIN sessions s ON s.id = m.session_id
	  WHERE s.org_id = $1::uuid AND m.session_id = ANY($2::uuid[])
	  ORDER BY m.id`

	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("historyops: begin cascade export snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	// SET LOCAL is session-local state, permitted in read-only transactions;
	// it pins timestamptz rendering for this snapshot only.
	if _, err := tx.Exec(ctx, "SET LOCAL TimeZone = 'UTC'"); err != nil {
		return nil, nil, nil, fmt.Errorf("historyops: pin cascade export timezone: %w", err)
	}
	rows, err := tx.Query(ctx, q, orgID, sessionIDs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("historyops: export message cascade: %w", err)
	}
	fetched, xmins, payloads, err := scanExportRows(rows)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("historyops: commit cascade export snapshot: %w", err)
	}
	sortExportByID(fetched, xmins, payloads)
	return fetched, xmins, payloads, nil
}

// planFamilyIDs selects the in-scope row ids for one family, ascending — the
// order both the chunking and the completeness check rely on. This is the
// UNPROTECTED scope: archive_copy is non-destructive, so active grants do
// not exclude anything here (the destructive runner narrows further).
func planFamilyIDs(ctx context.Context, db HistoryDB, sel Selection, family Family) ([]string, error) {
	w, args, err := familyScope(ctx, db, sel, family)
	if err != nil {
		return nil, err
	}
	var q string
	switch family {
	case FamilyRequestLogs:
		q = "SELECT rl.id::text FROM request_logs rl WHERE " + w + " ORDER BY rl.id"
	case FamilyToolCalls, FamilyToolCallInvocations, FamilyCacheEntries, FamilySessions:
		q = "SELECT id::text FROM " + string(family) + " WHERE " + w + " ORDER BY id"
	default:
		return nil, fmt.Errorf("historyops: plan for family %q: %w", family, ErrInvalidRequest)
	}
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("historyops: plan %s ids: %w", family, err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("historyops: plan %s scan id: %w", family, err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// chunkPlan splits one family's ids into marker-stamped batches of at most
// batchLen rows.
func chunkPlan(family Family, ids []string, batchLen int) [][]string {
	var out [][]string
	for start := 0; start < len(ids); start += batchLen {
		end := start + batchLen
		if end > len(ids) {
			end = len(ids)
		}
		out = append(out, encodeBatch(family, ids[start:end]))
	}
	return out
}

// ArchiveCopyRunner implements the archive_copy operation (backlog card 05):
// copy every selected row to org-namespace cold storage as JSONL + manifest,
// without touching the hot tables. It is non-destructive, so active payload
// grants do not protect rows from being ARCHIVED (the destructive runner in
// remove.go enforces protection); counts are archive counts, not deletes.
type ArchiveCopyRunner struct {
	// DB is the pgx pool the runner plans and exports against.
	DB HistoryDB
	// ResolveDestination turns the job's (already validated) destination URI
	// into the cold-storage client. Returning (nil, nil) means "nothing
	// wired behind this destination" (no_destination); an error means the
	// destination scheme is not served (unsupported_destination). Production
	// wiring adapts the loggerd consumer's store lookup.
	ResolveDestination func(dest string) (ColdStorage, error)
	// BatchSize is the maximum rows per captured batch. Zero or negative
	// falls back to defaultArchiveBatchSize.
	BatchSize int
	// Now overrides the clock (tests). Nil = time.Now.
	Now func() time.Time
}

// defaultArchiveBatchSize is the plan chunk size.
const defaultArchiveBatchSize = 500

func (r *ArchiveCopyRunner) batchSize() int {
	if r.BatchSize > 0 {
		return r.BatchSize
	}
	return defaultArchiveBatchSize
}

func (r *ArchiveCopyRunner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// resolveStore validates the destination again at run time and resolves the
// cold store. Every failure mode is a refusal — a destination problem can
// never be retried into success (fail-closed, zero external writes).
func (r *ArchiveCopyRunner) resolveStore(job *Job) (ColdStorage, error) {
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

// VerifySnapshot implements Runner: destination probe (resolves and discards
// the store — validation only, zero writes) plus the shared snapshot checks.
func (r *ArchiveCopyRunner) VerifySnapshot(ctx context.Context, job *Job) error {
	if _, err := r.resolveStore(job); err != nil {
		return err
	}
	return verifyArchiveSnapshot(ctx, r.DB, r.now, job)
}

// Plan implements Runner: for every selected family (canonical order), the
// in-scope ids ascending, chunked into family-stamped batches.
func (r *ArchiveCopyRunner) Plan(ctx context.Context, job *Job) ([][]string, error) {
	var out [][]string
	for _, family := range job.Selection.Families {
		ids, err := planFamilyIDs(ctx, r.DB, job.Selection, family)
		if err != nil {
			return nil, err
		}
		out = append(out, chunkPlan(family, ids, r.batchSize())...)
	}
	return out, nil
}

// ExecuteBatch implements Runner: export the batch exactly (completeness
// gate), write JSONL + manifest, verify the read-back when the store can
// read, and count the batch exactly once (batchCountDelta gate). The engine
// re-executes a batch at least once across crash windows; both the object
// bytes and the counts are stable under that replay.
func (r *ArchiveCopyRunner) ExecuteBatch(ctx context.Context, job *Job, batchIndex int, batch []string) (FamilyCounts, error) {
	family, ids, err := decodeBatch(batch)
	if err != nil {
		return nil, err
	}
	delta, err := batchCountDelta(job.Checkpoint.Plan, batchIndex, job.Confirmed)
	if err != nil {
		return nil, err
	}
	if delta == 0 {
		// Crash-window replay of an already-checkpointed batch: the archive
		// objects were written before the checkpoint was saved (write →
		// count → save order), so skipping is the exactly-once behavior.
		return FamilyCounts{}, nil
	}
	store, err := r.resolveStore(job)
	if err != nil {
		return nil, err
	}
	fetched, _, payloads, err := exportBatchRows(ctx, r.DB, job.OrgID, family, ids)
	if err != nil {
		return nil, err
	}
	if err := verifyArchiveCompleteness(family, ids, fetched, payloads); err != nil {
		return nil, err
	}
	key := archiveObjectKey(job.OrgID, job.SelectionDigest, job.ID, batchIndex, family)
	manifest := archiveManifest{
		Table:         string(family),
		Scope:         job.OrgID,
		Rows:          len(ids),
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
	manifest, err = writeArchiveObject(ctx, store, key, manifest, payloads)
	if err != nil {
		return nil, err
	}
	if err := verifyArchiveReadback(ctx, store, key, manifest); err != nil {
		return nil, err
	}
	return FamilyCounts{family: delta}, nil
}
