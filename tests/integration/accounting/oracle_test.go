//go:build integration

package accounting

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for the oracle connection
)

const httpOK = http.StatusOK

// httpGet performs a plain GET with a hard timeout.
func httpGet(timeout time.Duration, url string) (*http.Response, error) {
	client := &http.Client{Timeout: timeout}
	return client.Get(url)
}

// httpPostJSON sends one authenticated chat-completions request and returns
// the decoded status and body. The X-Request-ID is run-namespaced for
// ledger/database filtering, but no window assertion depends on it.
func httpPostJSON(timeout time.Duration, url, apiKey, requestID, payload string) (int, string, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Request-ID", requestID)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

// errorEnvelope is the product's structured error response contract.
type errorEnvelope struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// decodeErrorCode extracts error.code from a structured error body. ok is
// false when the body is not a decodable error envelope.
func decodeErrorCode(body string) (code string, ok bool) {
	var env errorEnvelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		return "", false
	}
	return env.Error.Code, true
}

// oracle is a read-only independent observer of the stand's database. It
// connects as the container's postgres superuser — the same connection
// privilege the DR drill uses — which bypasses forced row-level security,
// and it never writes except to apply operator-level stand configuration
// (role bootstrap, pricing) and the documented fault-injection controls.
type oracle struct {
	t     *testing.T
	db    *sql.DB
	orgID string
}

// newOracle opens the oracle connection. Organization binding is resolved
// after seeding via resolveOrg.
func newOracle(t *testing.T, s *stand) *oracle {
	t.Helper()
	db, err := sql.Open("pgx", s.ownerDSN)
	if err != nil {
		t.Fatalf("harness: oracle connect: %v", err)
	}
	o := &oracle{t: t, db: db}
	if err := db.Ping(); err != nil {
		t.Fatalf("harness: oracle ping: %v", err)
	}
	return o
}

// resolveOrg binds the oracle to the stand's organization. Every
// request-scoped query is org-bound so cross-organization rows can never
// satisfy an assertion of this stand.
func (o *oracle) resolveOrg(t *testing.T, s *stand) {
	t.Helper()
	if err := o.db.QueryRow(`SELECT id::text FROM organizations WHERE name = $1`, s.orgName).Scan(&o.orgID); err != nil {
		t.Fatalf("harness: oracle org lookup for %s: %v", s.orgName, err)
	}
}

// close releases the oracle connection.
func (o *oracle) close() { _ = o.db.Close() }

// oracleRequestLogCount is the number of request_logs rows for the request
// id inside the given organization. request_logs.org_id is a uuid column;
// the parameter is the org id in canonical text form.
func (s *stand) oracleRequestLogCount(t *testing.T, rid, orgID string) int {
	t.Helper()
	return s.oracleCount(t, `SELECT count(*) FROM request_logs WHERE request_id = $1 AND org_id = $2::uuid`, rid, orgID)
}

// oracleCount runs a single-int scalar query.
func (s *stand) oracleCount(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.oracleDB.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("harness: oracle query %q: %v", query, err)
	}
	return n
}

// requestRow is the durable accounting view of one request.
type requestRow struct {
	Status    int
	TokensIn  int
	TokensOut int
	CostUSD   float64
	Err       sql.NullString
	CreatedAt time.Time
	OrgID     string
}

// oracleRequestRow fetches the accounting row for one request id, bound to
// the given organization. ok=false when no row exists.
func (s *stand) oracleRequestRow(t *testing.T, rid, orgID string) (requestRow, bool) {
	t.Helper()
	var r requestRow
	err := s.oracleDB.db.QueryRow(`
		SELECT status_code, tokens_in, tokens_out, cost_in_usd, error, created_at, org_id::text
		FROM request_logs WHERE request_id = $1 AND org_id = $2::uuid`, rid, orgID).
		Scan(&r.Status, &r.TokensIn, &r.TokensOut, &r.CostUSD, &r.Err, &r.CreatedAt, &r.OrgID)
	if err == sql.ErrNoRows {
		return r, false
	}
	if err != nil {
		t.Fatalf("harness: oracle request row: %v", err)
	}
	return r, true
}

// oracleRequestLogRows returns every request_logs row for rid in the given
// organization, oldest first. Multi-invocation correlation ids legitimately
// produce multiple rows (one per minted invocation).
func (s *stand) oracleRequestLogRows(t *testing.T, rid, orgID string) []requestRow {
	t.Helper()
	rows, err := s.oracleDB.db.Query(`
		SELECT status_code, tokens_in, tokens_out, cost_in_usd, error, created_at, org_id::text
		FROM request_logs WHERE request_id = $1 AND org_id = $2::uuid
		ORDER BY created_at`, rid, orgID)
	if err != nil {
		t.Fatalf("harness: oracle request rows query: %v", err)
	}
	defer rows.Close()
	var out []requestRow
	for rows.Next() {
		var r requestRow
		if err := rows.Scan(&r.Status, &r.TokensIn, &r.TokensOut, &r.CostUSD, &r.Err, &r.CreatedAt, &r.OrgID); err != nil {
			t.Fatalf("harness: oracle request rows scan: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("harness: oracle request rows: %v", err)
	}
	return out
}

// oracleWalletUsageRows returns the micro-USD amount of every usage
// transaction for rid in the given organization, oldest first. Per-row
// amounts (not just sums) prove each debit is individually signed negative.
func (s *stand) oracleWalletUsageRows(t *testing.T, rid, orgID string) []int64 {
	t.Helper()
	rows, err := s.oracleDB.db.Query(`
		SELECT coalesce(amount_micro_usd, 0)
		FROM credit_transactions WHERE request_id = $1 AND org_id = $2 AND type = 'usage'
		ORDER BY id`, rid, orgID)
	if err != nil {
		t.Fatalf("harness: oracle wallet usage query: %v", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var micro int64
		if err := rows.Scan(&micro); err != nil {
			t.Fatalf("harness: oracle wallet usage scan: %v", err)
		}
		out = append(out, micro)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("harness: oracle wallet usage rows: %v", err)
	}
	return out
}

// creditTotals summarizes the charge surface for one request id.
type creditTotals struct {
	UsageRows   int
	TopupRows   int
	SumMicroUSD int64
	SumCents    int64
}

// oracleCreditTotals reads the credit ledger position for one request in
// the given organization (credit_transactions.org_id is text).
func (s *stand) oracleCreditTotals(t *testing.T, rid, orgID string) creditTotals {
	t.Helper()
	var c creditTotals
	rows, err := s.oracleDB.db.Query(`
		SELECT type, amount_cents, coalesce(amount_micro_usd, 0)
		FROM credit_transactions WHERE request_id = $1 AND org_id = $2`, rid, orgID)
	if err != nil {
		t.Fatalf("harness: oracle credit query: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var typ string
		var cents, micro int64
		if err := rows.Scan(&typ, &cents, &micro); err != nil {
			t.Fatalf("harness: oracle credit scan: %v", err)
		}
		switch typ {
		case "usage":
			c.UsageRows++
		case "topup":
			c.TopupRows++
		}
		c.SumCents += cents
		c.SumMicroUSD += micro
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("harness: oracle credit rows: %v", err)
	}
	return c
}

// oracleSettlementJobs counts settlement jobs for one request id in the
// given organization (settlement_jobs.org_id is text).
func (s *stand) oracleSettlementJobs(t *testing.T, rid, orgID string) int {
	t.Helper()
	return s.oracleCount(t, `SELECT count(*) FROM settlement_jobs WHERE request_id = $1 AND org_id = $2`, rid, orgID)
}

// oracleSettlementKinds returns the per-charge-kind settlement intent
// counts for one request id in the given organization. The intent set is
// the consumer's planned charge scopes (wallet resale_deduction, team_,
// agent_, session_ spend); exact maps, not totals, are compared across
// event redelivery so a duplicate intent of any kind is visible.
func (s *stand) oracleSettlementKinds(t *testing.T, rid, orgID string) map[string]int {
	t.Helper()
	rows, err := s.oracleDB.db.Query(`
		SELECT charge_kind, count(*) FROM settlement_jobs
		WHERE request_id = $1 AND org_id = $2 GROUP BY charge_kind`, rid, orgID)
	if err != nil {
		t.Fatalf("harness: oracle settlement kinds query: %v", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			t.Fatalf("harness: oracle settlement kinds scan: %v", err)
		}
		out[kind] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("harness: oracle settlement kinds rows: %v", err)
	}
	return out
}

// requireSettlementIntents asserts the exact per-kind intent set for one
// request. Unlike a before/after total comparison, exact equality cannot
// pass vacuously when no intent was ever created.
func (s *stand) requireSettlementIntents(t *testing.T, rid, orgID, phase string, want map[string]int) {
	t.Helper()
	got := s.oracleSettlementKinds(t, rid, orgID)
	if len(got) != len(want) {
		t.Fatalf("%s: settlement intent set for %s = %v, want exactly %v", phase, rid, got, want)
	}
	for kind, n := range want {
		if got[kind] != n {
			t.Fatalf("%s: settlement intent set for %s = %v, want exactly %v", phase, rid, got, want)
		}
	}
}

// requireWalletIntentPresent pins the one intent kind that is
// unconditional for a positive-cost completion (consumer source: a
// positive quote always plans the wallet resale_deduction scope). It is
// the non-vacuity anchor before any before/after intent comparison.
func (s *stand) requireWalletIntentPresent(t *testing.T, rid, orgID, phase string) map[string]int {
	t.Helper()
	kinds := s.oracleSettlementKinds(t, rid, orgID)
	if kinds["resale_deduction"] != 1 {
		t.Fatalf("%s: settlement intents for %s = %v, want exactly 1 resale_deduction (the wallet scope a positive quote always plans)", phase, rid, kinds)
	}
	return kinds
}

// oracleEventInboxClaim returns the committed event_inbox delivery claim
// for one Redis stream entry. The product persists (source, consumer,
// event_id) = (stream name, consumer group, entry id) at claim time inside
// the processing transaction; ok=false when the consumer never claimed the
// entry. event_inbox is baseline schema, so this works on both trees.
func (s *stand) oracleEventInboxClaim(t *testing.T, source, consumer, eventID string) (time.Time, bool) {
	t.Helper()
	var createdAt time.Time
	err := s.oracleDB.db.QueryRow(`
		SELECT created_at FROM event_inbox
		WHERE source = $1 AND consumer = $2 AND event_id = $3`,
		source, consumer, eventID).Scan(&createdAt)
	if err == sql.ErrNoRows {
		return time.Time{}, false
	}
	if err != nil {
		t.Fatalf("harness: oracle event_inbox claim query: %v", err)
	}
	return createdAt, true
}

// oracleExec runs one operator-level write (stand configuration or fault
// injection). Observation queries never go through it.
func (s *stand) oracleExec(t *testing.T, what string, query string, args ...any) {
	t.Helper()
	if _, err := s.oracleDB.db.Exec(query, args...); err != nil {
		t.Fatalf("harness: %s: %v", what, err)
	}
}

// oracleQueryRowString scans one string column.
func (s *stand) oracleQueryRowString(t *testing.T, query string, args ...any) (string, bool) {
	t.Helper()
	var v string
	err := s.oracleDB.db.QueryRow(query, args...).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		t.Fatalf("harness: oracle query %q: %v", query, err)
	}
	return v, true
}

// oracleTableExists reports whether a table exists in the public schema.
func (s *stand) oracleTableExists(t *testing.T, name string) bool {
	t.Helper()
	return s.oracleCount(t, `SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = $1`, name) == 1
}

// admissionRow is the persisted admission state for one client
// correlation id: the server-minted invocation identity, the lifecycle
// state and, once terminal, why it left the admitted state.
type admissionRow struct {
	InvocationID  string
	State         string
	ResolvedAt    sql.NullTime
	ResolveReason sql.NullString
}

// oracleAdmission observes the persisted admission rows for a request in
// the given organization. request_admissions.org_id is TEXT in the
// candidate schema (unlike request_logs' uuid), so the org parameter is
// bound without a cast — a cast would silently never match. Absent table
// yields no rows; the state vocabulary is observed, never assumed.
func (s *stand) oracleAdmissions(t *testing.T, rid, orgID string) []admissionRow {
	t.Helper()
	if !s.oracleTableExists(t, "request_admissions") {
		return nil
	}
	rows, err := s.oracleDB.db.Query(`
		SELECT invocation_id::text, state, resolved_at, resolve_reason
		FROM request_admissions WHERE client_request_id = $1 AND org_id = $2
		ORDER BY admitted_at`, rid, orgID)
	if err != nil {
		t.Fatalf("harness: oracle admissions query: %v", err)
	}
	defer rows.Close()
	var out []admissionRow
	for rows.Next() {
		var r admissionRow
		if err := rows.Scan(&r.InvocationID, &r.State, &r.ResolvedAt, &r.ResolveReason); err != nil {
			t.Fatalf("harness: oracle admissions scan: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("harness: oracle admissions rows: %v", err)
	}
	return out
}

// oracleAdmissionState returns the (first) admission state for a request.
// ok=false when no admission row exists.
func (s *stand) oracleAdmissionState(t *testing.T, rid, orgID string) (state string, ok bool) {
	t.Helper()
	rs := s.oracleAdmissions(t, rid, orgID)
	if len(rs) == 0 {
		return "", false
	}
	return rs[0].State, true
}

// oracleAdmissionRowCount counts admission rows bound to the given org and
// client correlation id.
func (s *stand) oracleAdmissionRowCount(t *testing.T, rid, orgID string) int {
	t.Helper()
	if !s.oracleTableExists(t, "request_admissions") {
		return 0
	}
	return s.oracleCount(t,
		`SELECT count(*) FROM request_admissions WHERE client_request_id = $1 AND org_id = $2`,
		rid, orgID)
}

// oracleAdmissionByInvocation fetches one admission row by its
// server-minted invocation id, org-bound.
func (s *stand) oracleAdmissionByInvocation(t *testing.T, invocationID, orgID string) (admissionRow, bool) {
	t.Helper()
	if !s.oracleTableExists(t, "request_admissions") {
		return admissionRow{}, false
	}
	var r admissionRow
	err := s.oracleDB.db.QueryRow(`
		SELECT invocation_id::text, state, resolved_at, resolve_reason
		FROM request_admissions WHERE invocation_id = $1::uuid AND org_id = $2`,
		invocationID, orgID).Scan(&r.InvocationID, &r.State, &r.ResolvedAt, &r.ResolveReason)
	if err == sql.ErrNoRows {
		return admissionRow{}, false
	}
	if err != nil {
		t.Fatalf("harness: oracle admission by invocation: %v", err)
	}
	return r, true
}

// ageAdmissionPastGrace moves ONLY the target admission's admitted_at to
// beyond the reconciler's 15-minute grace window (the consumer contract's
// default), scoped to one org + correlation id + still-admitted state. It
// fails when no row was aged: aging a still-live control instead of the
// target, or aging nothing at all, would invalidate the case. This is a
// deterministic-test control for time that the product does not expose as
// configuration; it never touches terminal admissions.
func (s *stand) ageAdmissionPastGrace(t *testing.T, rid, orgID string) {
	t.Helper()
	res, err := s.oracleDB.db.Exec(`
		UPDATE request_admissions SET admitted_at = now() - interval '16 minutes'
		WHERE client_request_id = $1 AND org_id = $2 AND state = 'admitted'`,
		rid, orgID)
	if err != nil {
		t.Fatalf("harness: age admission: %v", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		t.Fatalf("harness: age admission: aged %d rows for %s, want exactly 1 (the target, still admitted)", n, rid)
	}
	t.Logf("harness: target admission for %s aged past the 15m grace window", rid)
}

// oracleTerminalFactsCount counts the terminal-facts projection rows for a
// client correlation id in the given organization. The facts row is the
// durable completion evidence the reconciler recovers from when no live
// event will ever arrive.
func (s *stand) oracleTerminalFactsCount(t *testing.T, rid, orgID string) int {
	t.Helper()
	if !s.oracleTableExists(t, "request_terminal_facts") {
		return 0
	}
	return s.oracleCount(t,
		`SELECT count(*) FROM request_terminal_facts WHERE client_request_id = $1 AND org_id = $2`,
		rid, orgID)
}

// oracleWalletBalance reads the org's current wallet balance in cents.
// ok=false when the org has no wallet row.
func (s *stand) oracleWalletBalance(t *testing.T, orgID string) (cents int64, ok bool) {
	t.Helper()
	err := s.oracleDB.db.QueryRow(`SELECT balance_cents FROM org_credits WHERE org_id = $1`, orgID).Scan(&cents)
	if err == sql.ErrNoRows {
		return 0, false
	}
	if err != nil {
		t.Fatalf("harness: wallet balance: %v", err)
	}
	return cents, true
}

// requireWalletChargedExactlyOnce asserts the candidate wallet contract
// for one request in one org: exactly one usage transaction, signed
// negative (a debit), matching the independently computed fixture cost
// under the operator-installed zero-markup rates (32 micro-USD), and no
// topups riding on the request.
func (s *stand) requireWalletChargedExactlyOnce(t *testing.T, rid, orgID, phase string) {
	t.Helper()
	c := s.oracleCreditTotals(t, rid, orgID)
	if c.UsageRows != 1 {
		t.Fatalf("%s: wallet: %d usage transactions for %s, want exactly 1", phase, c.UsageRows, rid)
	}
	const wantMicro = int64(-fixtureMicroUSDCost)
	if c.SumMicroUSD != wantMicro {
		t.Errorf("%s: wallet: usage transaction for %s sums to %d micro-USD, want the signed debit %d (zero-markup resale of %d input + %d output tokens at %v/%v per M)",
			phase, rid, c.SumMicroUSD, wantMicro, fixturePromptTokens, fixtureCompletionTokens, s.pricingInputPerM, s.pricingOutputPerM)
	}
	if c.SumCents > 0 {
		t.Errorf("%s: wallet: usage transaction for %s carries positive cents %d — a debit must not be positive", phase, rid, c.SumCents)
	}
}

// oracleUsageByInvocation counts usage transactions carrying one
// server-minted invocation id — the invocation-scoped exact-once surface
// that survives shared client correlation ids and event redelivery.
func (s *stand) oracleUsageByInvocation(t *testing.T, invocationID, orgID string) creditTotals {
	t.Helper()
	var c creditTotals
	rows, err := s.oracleDB.db.Query(`
		SELECT type, amount_cents, coalesce(amount_micro_usd, 0)
		FROM credit_transactions WHERE invocation_id = $1::uuid AND org_id = $2`,
		invocationID, orgID)
	if err != nil {
		if strings.Contains(err.Error(), "invocation_id") {
			t.Fatalf("harness: usage by invocation query: %v (candidate column missing?)", err)
		}
		t.Fatalf("harness: usage by invocation query: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var typ string
		var cents, micro int64
		if err := rows.Scan(&typ, &cents, &micro); err != nil {
			t.Fatalf("harness: usage by invocation scan: %v", err)
		}
		switch typ {
		case "usage":
			c.UsageRows++
		case "topup":
			c.TopupRows++
		}
		c.SumCents += cents
		c.SumMicroUSD += micro
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("harness: usage by invocation rows: %v", err)
	}
	return c
}

// expectedFixtureCostUSD is the independently known cost of one fixture
// completion under the rates the harness installs (see
// stand.pricingInputPerM / pricingOutputPerM): 7 input + 3 output tokens.
func (s *stand) expectedFixtureCostUSD() float64 {
	return (float64(fixturePromptTokens)/1e6)*s.pricingInputPerM +
		(float64(fixtureCompletionTokens)/1e6)*s.pricingOutputPerM
}

// requireBilledRow validates a durable request row that carries usage
// against the independently known fixture usage and the operator-installed
// rates — never against values reported by the gateway response. Under the
// harness's zero-markup resale provisioning the durable cost also equals
// the wallet debit basis.
func (s *stand) requireBilledRow(t *testing.T, rid, orgID, phase string) {
	t.Helper()
	row, ok := s.oracleRequestRow(t, rid, orgID)
	if !ok {
		t.Fatalf("%s: request %s has no durable row", phase, rid)
	}
	if row.OrgID != orgID {
		t.Fatalf("%s: request %s durable row is bound to org %s, not org %s",
			phase, rid, row.OrgID, orgID)
	}
	if row.TokensIn != fixturePromptTokens || row.TokensOut != fixtureCompletionTokens {
		t.Errorf("%s: request %s usage tokens in/out = %d/%d, fixture independently reported %d/%d",
			phase, rid, row.TokensIn, row.TokensOut, fixturePromptTokens, fixtureCompletionTokens)
	}
	const tol = 1e-9
	if diff := row.CostUSD - s.expectedFixtureCostUSD(); diff > tol || diff < -tol {
		t.Errorf("%s: request %s cost %v does not match independently computed %v (rates input=%v/M output=%v/M, usage %d+%d tokens)",
			phase, rid, row.CostUSD, s.expectedFixtureCostUSD(), s.pricingInputPerM, s.pricingOutputPerM,
			fixturePromptTokens, fixtureCompletionTokens)
	}
}
