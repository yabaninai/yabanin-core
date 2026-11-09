package historyops

// flakeProbeDB arms TestArchiveRemoveHotStandaloneTools_Integration with
// decision-grade diagnostics around the archive export, because a refusal of
// the form "archive export ... returned unplanned id N at position i" cannot
// be produced by the product code against one consistent database:
// exportBatchRows binds id = ANY($2) to exactly the planned ids inside one
// repeatable-read transaction and verifyArchiveSubset compares the fetched
// stream against that same slice, so a refusal means the result stream
// delivered rows in an order/content the server did not send (transport
// level) or the pool spoke to more than one server.
//
// Evidence captured (every line prefixed "f3probe:" so run logs stay
// greppable):
//
//   - identity: backend pid, postmaster start time, system_identifier and
//     snapshot — at runner entry, at every tool_calls query and inside the
//     export transaction (identity drift = the pool used two servers);
//   - plan/export binding: the exact ids bound to ANY($2) and every fetched
//     id in Next() order;
//   - ownership: on the same repeatable-read snapshot, the org owner of
//     every fetched id plus the family table's full row set for the org
//     (xmin included) — a fetched id owned by another org would be a
//     phantom row that never existed under this org;
//   - ordering: fetched ids and org-scan ids must be numerically ascending
//     (every involved query ends in ORDER BY id), so a non-ascending
//     sequence is direct evidence of transport-level result reordering;
//   - sequence state: tool_calls_id_seq last_value/is_called at runner
//     entry, read without nextval (id determinism across occurrences).
//
// The probe is test-only, adds no sleeps, changes no assertions and mutates
// nothing: every extra statement is a plain read. The export transaction
// never receives a statement that has not been proven to parse on this
// stand — an ERROR would abort the transaction and turn the probe into the
// failure it hunts.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const flakeProbePoolIdentitySQL = `SELECT pg_backend_pid()::text,
	   pg_postmaster_start_time()::text,
	   (SELECT system_identifier FROM pg_control_system())::text,
	   pg_current_snapshot()::text,
	   (SELECT last_value::text || '/' || is_called::text FROM tool_calls_id_seq)`

// The tx-level identity uses pg_current_snapshot(): inside a transaction it
// returns the fixed repeatable-read snapshot, and it (plus the other three
// expressions) is proven to parse on this stand — the pool-level variant
// runs the same expressions. An ERROR inside the export transaction would
// abort it and poison the export itself, so no other statement runs there.
const flakeProbeTxIdentitySQL = `SELECT pg_backend_pid()::text,
	   pg_postmaster_start_time()::text,
	   (SELECT system_identifier FROM pg_control_system())::text,
	   pg_current_snapshot()::text`

// flakeProbeDB wraps the shared pool for one test run. The zero-value is
// unusable; construct with newFlakeProbeDB.
type flakeProbeDB struct {
	HistoryDB // embedded: everything un-intercepted delegates
	t         *testing.T
	pool      *pgxpool.Pool
	org       string

	mu  sync.Mutex
	seq int // f3probe event counter for stable ordering in interleaved logs
}

func newFlakeProbeDB(t *testing.T, pool *pgxpool.Pool, org string) *flakeProbeDB {
	t.Helper()
	p := &flakeProbeDB{HistoryDB: pool, t: t, pool: pool, org: org}
	p.identity(context.Background(), "runner-entry", nil)
	return p
}

func (p *flakeProbeDB) log(format string, args ...any) {
	p.mu.Lock()
	p.seq++
	n := p.seq
	p.mu.Unlock()
	p.t.Logf("f3probe: #%d %s", n, fmt.Sprintf(format, args...))
}

// identity captures the DB identity line for the current connection context.
// tx non-nil means the read runs inside the export transaction (xact
// snapshot); otherwise the pool-level snapshot is used.
func (p *flakeProbeDB) identity(ctx context.Context, phase string, tx pgx.Tx) {
	sql := flakeProbePoolIdentitySQL
	if tx != nil {
		sql = flakeProbeTxIdentitySQL
	}
	var pid, pm, sysid, snap, seqExtra string
	if tx != nil {
		if err := tx.QueryRow(ctx, sql).Scan(&pid, &pm, &sysid, &snap); err != nil {
			p.log("phase=%s identity-error: %v", phase, err)
			return
		}
		p.log("phase=%s pid=%s pm=%s sysid=%s snap=%s", phase, pid, pm, sysid, snap)
		return
	}
	if err := p.pool.QueryRow(ctx, sql).Scan(&pid, &pm, &sysid, &snap, &seqExtra); err != nil {
		p.log("phase=%s identity-error: %v", phase, err)
		return
	}
	p.log("phase=%s pid=%s pm=%s sysid=%s snap=%s seq=%s", phase, pid, pm, sysid, snap, seqExtra)
}

// touchesToolCalls reports whether the statement reads or plans tool_calls
// (plan queries, export rows, verify snapshots). The identity capture and id
// recording hook only those statements to keep the probe quiet elsewhere.
func touchesToolCalls(sql string) bool {
	return strings.Contains(sql, "tool_calls")
}

func (p *flakeProbeDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if touchesToolCalls(sql) {
		p.identity(ctx, "query:"+sqlHead(sql), nil)
	}
	rows, err := p.HistoryDB.Query(ctx, sql, args...)
	if err != nil || !touchesToolCalls(sql) {
		return rows, err
	}
	return &flakeProbeRows{ctx: ctx, inner: rows, probe: p, phase: "query", planned: plannedFromArgs(args)}, nil
}

func (p *flakeProbeDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if touchesToolCalls(sql) {
		p.identity(ctx, "queryrow:"+sqlHead(sql), nil)
	}
	return p.HistoryDB.QueryRow(ctx, sql, args...)
}

func (p *flakeProbeDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return p.HistoryDB.Exec(ctx, sql, args...)
}

func (p *flakeProbeDB) BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	tx, err := p.HistoryDB.BeginTx(ctx, txOptions)
	if err != nil {
		return nil, err
	}
	return &flakeProbeTx{Tx: tx, probe: p}, nil
}

// flakeProbeTx intercepts the export transaction: the repeatable-read
// snapshot is where the refusal decides, so identity and ownership evidence
// must come from inside it.
type flakeProbeTx struct {
	pgx.Tx // embedded: Commit/Rollback/Exec/Begin/... delegate
	probe  *flakeProbeDB
}

func (tx *flakeProbeTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	isExport := strings.Contains(sql, "row_to_json")
	if isExport {
		tx.probe.identity(ctx, "export-pre", tx.Tx)
		tx.probe.log("phase=export-pre planned=%v", plannedFromArgs(args))
	}
	rows, err := tx.Tx.Query(ctx, sql, args...)
	if err != nil || !isExport {
		return rows, err
	}
	return &flakeProbeRows{ctx: ctx, inner: rows, probe: tx.probe, phase: "export", table: exportTable(sql), tx: tx.Tx, planned: plannedFromArgs(args)}, nil
}

// exportTable extracts the family table from the export SQL, so the
// ownership crosscheck reads the same table the export read instead of
// assuming tool_calls. Two shapes exist: the derived form
// ("FROM (SELECT * FROM <family> ...") and the flattened table-alias form
// the version-guarded export uses since HIST-04 ("FROM <family> t").
func exportTable(sql string) string {
	const marker = "FROM (SELECT * FROM "
	if i := strings.Index(sql, marker); i >= 0 {
		rest := sql[i+len(marker):]
		end := strings.IndexAny(rest, " \n\t)")
		if end < 0 {
			return ""
		}
		return rest[:end]
	}
	// Flattened form: the earliest known family table after FROM.
	best := ""
	bestAt := -1
	for _, f := range append(append([]Family{}, SelectableFamilies...), FamilyMessages) {
		at := strings.Index(sql, "FROM "+string(f)+" ")
		if at >= 0 && (bestAt < 0 || at < bestAt) {
			best, bestAt = string(f), at
		}
	}
	return best
}

func (tx *flakeProbeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return tx.Tx.Exec(ctx, sql, args...)
}

// flakeProbeRows records every fetched id as the runner streams them and, on
// drain or close, cross-checks ownership on the same snapshot. It never
// alters the result stream: every inner method passes through untouched.
type flakeProbeRows struct {
	ctx      context.Context // caller ctx from the intercepted Query; used by the crosscheck
	inner    pgx.Rows
	probe    *flakeProbeDB
	phase    string
	table    string // family table extracted from the intercepted export SQL
	tx       pgx.Tx // non-nil only for export rows: enables the ownership crosscheck
	planned  []string
	fetched  []string
	finished bool
}

func (r *flakeProbeRows) Next() bool {
	ok := r.inner.Next()
	if ok {
		raw := r.inner.RawValues()
		if len(raw) > 0 {
			r.fetched = append(r.fetched, string(raw[0])) // copy: RawValues dies on next Next
		}
		return true
	}
	r.finish()
	return false
}

func (r *flakeProbeRows) Scan(dest ...any) error        { return r.inner.Scan(dest...) }
func (r *flakeProbeRows) Err() error                    { return r.inner.Err() }
func (r *flakeProbeRows) CommandTag() pgconn.CommandTag { return r.inner.CommandTag() }
func (r *flakeProbeRows) FieldDescriptions() []pgconn.FieldDescription {
	return r.inner.FieldDescriptions()
}
func (r *flakeProbeRows) Values() ([]any, error) { return r.inner.Values() }
func (r *flakeProbeRows) RawValues() [][]byte    { return r.inner.RawValues() }
func (r *flakeProbeRows) Conn() *pgx.Conn        { return r.inner.Conn() }
func (r *flakeProbeRows) TypeMap() *pgtype.Map   { return r.inner.TypeMap() } // pgx v5.12 added this to pgx.Rows

func (r *flakeProbeRows) Close() {
	r.finish()
	r.inner.Close()
}

// finish runs once: logs fetched ids and, inside the export transaction,
// answers the only two questions that separate the surviving hypotheses:
// who owns the fetched ids (same snapshot!) and what does the org actually
// hold.
func (r *flakeProbeRows) finish() {
	if r.finished {
		return
	}
	r.finished = true
	p := r.probe
	p.log("phase=%s-rows fetched=%v", r.phase, r.fetched)
	if r.tx == nil || len(r.fetched) == 0 {
		return
	}
	ctx := r.ctx
	ids := make([]int64, 0, len(r.fetched))
	for _, raw := range r.fetched {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			p.log("phase=verify fetched id %q is not a bigint: %v", raw, err)
			return
		}
		ids = append(ids, n)
	}
	rows, err := r.tx.Query(ctx,
		"SELECT id::text, org_id::text FROM "+r.table+" WHERE id = ANY($1::bigint[]) ORDER BY id", ids)
	if err != nil {
		p.log("phase=verify ownership query error: %v", err)
		return
	}
	type owner struct{ id, org string }
	var owners []owner
	for rows.Next() {
		var o owner
		if err := rows.Scan(&o.id, &o.org); err != nil {
			p.log("phase=verify ownership scan error: %v", err)
			rows.Close()
			return
		}
		owners = append(owners, o)
	}
	if err := rows.Err(); err != nil {
		p.log("phase=verify ownership iterate error: %v", err)
		return
	}
	orgRows, err := r.tx.Query(ctx,
		"SELECT id::text, xmin::text FROM "+r.table+" WHERE org_id = $1::uuid ORDER BY id", p.org)
	if err != nil {
		p.log("phase=verify org scan error: %v", err)
		return
	}
	var orgRowsList []orgRow
	for orgRows.Next() {
		var o orgRow
		if err := orgRows.Scan(&o.id, &o.xmin); err != nil {
			p.log("phase=verify org scan scan error: %v", err)
			orgRows.Close()
			return
		}
		orgRowsList = append(orgRowsList, o)
	}
	if err := orgRows.Err(); err != nil {
		p.log("phase=verify org scan iterate error: %v", err)
		return
	}
	p.log("phase=verify org=%s orgrows=%v owners=%v planned=%v fetched=%v",
		shortOrg(p.org), orgRowsList, owners, r.planned, r.fetched)
	if !isAscending(r.fetched) {
		p.log("ANOMALY: fetched ids %v are not in ascending order — the export orders by id "+
			"server-side, so this sequence proves transport-level result reordering", r.fetched)
	}
	orgIDs := orgRowIDs(orgRowsList)
	if !isAscending(orgIDs) {
		p.log("ANOMALY: org scan ids %v are not in ascending order despite ORDER BY id — "+
			"transport-level result reordering on an independent query in the same test", orgIDs)
	}
	for _, o := range owners {
		if o.org != p.org {
			p.log("ANOMALY: fetched id %s is owned by org %s, not the tracked org %s — "+
				"the export stream carried a row that does not exist under the planned org "+
				"(transport-level phantom, not plan/export predicate skew)", o.id, o.org, shortOrg(p.org))
		}
	}
	for _, id := range r.fetched {
		inPlanned := false
		for _, pid := range r.planned {
			if pid == id {
				inPlanned = true
				break
			}
		}
		if !inPlanned {
			p.log("ANOMALY: fetched id %s is not in the planned set %v — with ANY($2) bound to "+
				"exactly the planned ids this row cannot come from one consistent database", id, r.planned)
		}
	}
}

func sqlHead(sql string) string {
	one := strings.Join(strings.Fields(sql), " ")
	if len(one) > 60 {
		return one[:60]
	}
	return one
}

// isAscending reports whether a decimal-id sequence is non-decreasing
// numerically (lexicographic string order would put "10" before "9").
// Non-bigint sequences (uuid families) are not order-checked.
func isAscending(ids []string) bool {
	var prev int64
	for i, raw := range ids {
		cur, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return true
		}
		if i > 0 && cur < prev {
			return false
		}
		prev = cur
	}
	return true
}

type orgRow struct{ id, xmin string }

func orgRowIDs(rows []orgRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.id
	}
	return out
}

func plannedFromArgs(args []any) []string {
	if len(args) < 2 {
		return nil
	}
	ids, ok := args[1].([]int64)
	if !ok {
		return []string{"<unparsed>"}
	}
	out := make([]string, len(ids))
	for i, n := range ids {
		out[i] = strconv.FormatInt(n, 10)
	}
	return out
}

// shortOrg keeps log lines readable: first uuid segment is unique per test run.
func shortOrg(org string) string {
	if len(org) > 8 {
		return org[:8]
	}
	return org
}
