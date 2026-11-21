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
// id inside this stand's organization.
func (s *stand) oracleRequestLogCount(t *testing.T, rid string) int {
	t.Helper()
	return s.oracleCount(t, `SELECT count(*) FROM request_logs WHERE request_id = $1 AND org_id = $2::uuid`, rid, s.oracleDB.orgID)
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
// this stand's organization. ok=false when no row exists.
func (s *stand) oracleRequestRow(t *testing.T, rid string) (requestRow, bool) {
	t.Helper()
	var r requestRow
	err := s.oracleDB.db.QueryRow(`
		SELECT status_code, tokens_in, tokens_out, cost_in_usd, error, created_at, org_id::text
		FROM request_logs WHERE request_id = $1 AND org_id = $2::uuid`, rid, s.oracleDB.orgID).
		Scan(&r.Status, &r.TokensIn, &r.TokensOut, &r.CostUSD, &r.Err, &r.CreatedAt, &r.OrgID)
	if err == sql.ErrNoRows {
		return r, false
	}
	if err != nil {
		t.Fatalf("harness: oracle request row: %v", err)
	}
	return r, true
}

// creditTotals summarizes the charge surface for one request id.
type creditTotals struct {
	UsageRows   int
	TopupRows   int
	SumMicroUSD int64
	SumCents    int64
}

// oracleCreditTotals reads the credit ledger position for one request,
// org-bound.
func (s *stand) oracleCreditTotals(t *testing.T, rid string) creditTotals {
	t.Helper()
	var c creditTotals
	rows, err := s.oracleDB.db.Query(`
		SELECT type, amount_cents, coalesce(amount_micro_usd, 0)
		FROM credit_transactions WHERE request_id = $1 AND org_id = $2`, rid, s.oracleDB.orgID)
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

// oracleSettlementJobs counts settlement jobs for one request id,
// org-bound.
func (s *stand) oracleSettlementJobs(t *testing.T, rid string) int {
	t.Helper()
	return s.oracleCount(t, `SELECT count(*) FROM settlement_jobs WHERE request_id = $1 AND org_id = $2`, rid, s.oracleDB.orgID)
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

// admissionState observes the persisted admission state for a request in
// the candidate schema's public.request_admissions table (invocation_id,
// org_id, client_request_id, state). The client-supplied correlation id
// maps to client_request_id; org binding is enforced in the query. Absent
// table or row yields ("", false). The state vocabulary is observed, never
// assumed: assertions treat it as evidence.
func (s *stand) oracleAdmissionState(t *testing.T, rid string) (state string, ok bool) {
	t.Helper()
	if !s.oracleTableExists(t, "request_admissions") {
		return "", false
	}
	return s.oracleQueryRowString(t,
		`SELECT state FROM request_admissions WHERE client_request_id = $1 AND org_id = $2::uuid`,
		rid, s.oracleDB.orgID)
}

// oracleAdmissionRowCount counts admission rows bound to this org and
// client correlation id. This stand sends each correlation id at most once,
// so more than one admission row for it is duplication by this stand's
// traffic; distinguishing multiple legitimate invocations that share one
// client-supplied id is a product capability outside this case's scope.
func (s *stand) oracleAdmissionRowCount(t *testing.T, rid string) int {
	t.Helper()
	if !s.oracleTableExists(t, "request_admissions") {
		return 0
	}
	return s.oracleCount(t,
		`SELECT count(*) FROM request_admissions WHERE client_request_id = $1 AND org_id = $2::uuid`,
		rid, s.oracleDB.orgID)
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
// rates — never against values reported by the gateway response.
func (s *stand) requireBilledRow(t *testing.T, rid, phase string) {
	t.Helper()
	row, ok := s.oracleRequestRow(t, rid)
	if !ok {
		t.Fatalf("%s: request %s has no durable row", phase, rid)
	}
	if row.OrgID != s.oracleDB.orgID {
		t.Fatalf("%s: request %s durable row is bound to org %s, not this stand's org %s",
			phase, rid, row.OrgID, s.oracleDB.orgID)
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
