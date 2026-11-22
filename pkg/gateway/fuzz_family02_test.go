package cli

// Fuzz seeds for gateway FAMILY-02: JWT bearer auth (auth_jwt.go), the
// legacy auth middleware (auth.go), and the session-key API surface
// (sessionkeys_api.go) — task gateway-corpus-fam02. Case IDs and expected
// outcomes are frozen below (F02-*); upstreams are loopback httptest JWKS
// servers; DB rows and SQL oracles come from f02RecordingDB (a recording
// wrapper over the established scriptDB fixture).
//
// Frozen case table (mirrors the FROZEN-CASE-TABLE.md convention of the
// A2A/toolgate seeds — the table lives in this comment):
//
//	F02-01 JW-VALID        valid RS256+ES256 → 200; X-Org-Id; locked key-label
//	                        source; key-label claim shapes; metric ok; wiring
//	                        disabled → nil authenticator
//	F02-02 JW-INVALID      expired/nbf/aud/iss/missing-exp/org-claim rejections
//	                        → 401 reason + metric per reason
//	F02-03 JW-MALFORMED    2/4-segment, empty segment, bad base64, non-JSON
//	                        header, header without kid → 401 form; middleware
//	                        renders legacy 401; missing header; non-Bearer
//	F02-04 JW-ALGCONFUSION alg none + HS256 → 401 alg BEFORE any JWKS fetch
//	                        (fetch count 0); ES256 token vs RSA-only kid → 401
//	                        signature
//	F02-05 JW-TENANT       two orgs, same kid + same sub, distinct key
//	                        material AND distinct issuer policy: own-org 200
//	                        with own org id; cross-org 401 signature; same
//	                        material + foreign issuer → 401 issuer
//	F02-06 JW-BURST        cold concurrent JWKS burst (24 goroutines): all
//	                        authenticated, EXACTLY ONE fetch; jittered
//	                        refreshDue == fetchedAt + ttl + 10% jitter
//	F02-07 JW-FAILCLOSED   JWKS down: warm cache + unknown kid → 401
//	                        unknown_kid; empty cache → 503; aged past
//	                        max-stale → 503 (middleware status + JSON envelope)
//	F02-08 JW-ALGLESS-KEYS JWKS keys without explicit alg: RSA type switch
//	                        verifies RS256; EC P-256 verifies ES256; use:"enc"
//	                        key skipped → 401 signature
//	F02-09 SK-MINT         mint happy: 201 ybs_ key; expires window; INSERT
//	                        args oracle (own org + parent + labels jsonb, no
//	                        reserved keys); rate counter consumed; logs never
//	                        contain the secret
//	F02-10 SK-MINT-DENIED  no CanMintSessions / agent / session principal →
//	                        403; invalid ttl/name/limits/unknown field → 400;
//	                        expired parent key → 400 parent_key_expired;
//	                        rate-limited → 429
//	F02-11 SK-REVOKE       revoke own → 204 + one UPDATE (revoked_at IS NULL)
//	                        + one cache Del; idempotent second revoke → 204
//	                        with NO second UPDATE/Del (no stale cache);
//	                        foreign/unknown → 404; exec failure → 500
//	F02-12 SK-FINISH       finish own → 204 with outcome/exit/duration args +
//	                        finished_at + revoked_at COALESCE; second finish →
//	                        204 without a second UPDATE; invalid status → 400;
//	                        foreign → 404
//	F02-13 SK-USAGE        usage own → 200 totals + by_model rows; SQL oracle
//	                        `org_id = $1 AND session_key_id = $2` with own
//	                        tenant args; Complete=false; foreign/unknown → 404;
//	                        lookup store failure → 503 usage_unavailable (not
//	                        404); totals or by-model query/row failure → 503
//	                        usage_unavailable, no totals leaked
//	F02-14 SK-OWNUSAGE     without CanReadUsage → 403; with flag → 200 +
//	                        api_key-scoped SQL oracle + label filter args;
//	                        bad from/to, >31d span, invalid label key → 400;
//	                        group_by=bogus → 400; group_by=model SQL recorded;
//	                        group_by=label:team → quoteLiteral labels->>'team';
//	                        totals/group/by-model read failure → 503
//	                        usage_unavailable, no totals leaked; NULL group
//	                        value renders "" at 200; empty groups omitted
//	F02-15 SK-UNAVAILABLE  no DB: all five endpoints 501 session_keys_unavailable;
//	                        label policy → 200 default policy JSON (query
//	                        recorded); empty org → 401
//	F02-16 SK-LIFECYCLE    mint → revoke → use on the minted id: INSERT hook
//	                        registers the row; revoke 204 + purge Del exactly
//	                        once; usage rows carry ONLY the minting tenant's
//	                        org + session id; foreign → 404
//	F02-17 AUTH-LEGACY     strict/header modes; client-spoofed identity
//	                        headers stripped; x-api-key promotion; resolver
//	                        sets X-Org-Id/X-API-Key-Id + principal; expired
//	                        key → 401 code key_expired; SetLastUsedTracker
//	                        flushes the async UPDATE; authMiddlewareFunc wiring
//	F02-18 BROKEN-CONTROL  deliberately broken variants must be caught by the
//	                        oracles: cross-tenant wiring, tampered payload,
//	                        corrupted session principal (oracle discrimination)
//	F02-19..23 BOOT         real-server lifecycle / authorized / negative /
//	                        admin-surface / JWT boots live in
//	                        fuzz_family02_boot_test.go
//	                        (FuzzFamily02BootLifecycle); binding notes there.
//
// Generated-input behavior (else branch of the dispatch): JWT space
// (org × signer × mutation) and session space (op × principal × id) drive
// the real handlers; the expected status is derived independently in
// f02jwtGenExpect/f02sessGenExpect from the fixture contract only.

// Documented-unreachable singles (kept honest, not hidden): the mint
// crypto/rand and INSERT-returning failures, fetch's mid-stream read error is
// driven via truncation (F02-07), the validateClaims default arm,
// serveJWT's non-typed-error fallback, claimsString with an unset OrgClaim
// (the constructor defaults it), and sessions()' dbPool fallback (needs a
// live Postgres; the nil-pool boot shape is F02-19).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/auth"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/labels"
)

// --- fixtures -------------------------------------------------------------------

// f02Stmt is one recorded statement (SQL + args) against the session DB.
type f02Stmt struct {
	kind string // "row" (QueryRow), "rows" (Query), "exec" (Exec)
	sql  string
	args []any
}

// f02RecordingDB wraps the established scriptDB and records every statement
// so the seeds get an independent SQL oracle (own-tenant filters, idempotent
// UPDATEs, group expressions) on top of the HTTP status/body oracles. The
// INSERT hook registers the minted row in scriptDB.loads, making a real
// mint → revoke → use lifecycle observable.
type f02RecordingDB struct {
	*scriptDB

	mu    sync.Mutex
	stmts []f02Stmt

	// failNext, when non-empty, makes the NEXT statement whose SQL contains
	// the substring fail once (injected failure oracle).
	failNext string
	// modelRows / groupRows are canned result rows served by Query for
	// "GROUP BY model_used" / "GROUP BY 1" statements; nil falls through to
	// scriptDB's empty result set. Inject query failures with failNext and
	// row failures with failModelScan / failGroupScan.
	modelRows [][]any
	groupRows [][]any
	// policyRaw, when non-nil, answers the label_policies QueryRow with a
	// canned raw policy JSON column.
	policyRaw []byte
	// failModelScan / failGroupScan inject a Scan error at that canned row
	// index (-1 = off) to exercise the skip-and-continue branches.
	failModelScan int
	failGroupScan int
}

func f02DB() *f02RecordingDB {
	return &f02RecordingDB{scriptDB: &scriptDB{loads: map[string]sessionRow{}},
		failModelScan: -1, failGroupScan: -1}
}

func (d *f02RecordingDB) record(kind, sql string, args []any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stmts = append(d.stmts, f02Stmt{kind: kind, sql: sql, args: args})
}

// f02Find returns the recorded statements of the given kind whose SQL
// contains sub.
func (d *f02RecordingDB) f02Find(kind, sub string) []f02Stmt {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []f02Stmt
	for _, s := range d.stmts {
		if s.kind == kind && strings.Contains(s.sql, sub) {
			out = append(out, s)
		}
	}
	return out
}

func (d *f02RecordingDB) shouldFail(sql string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failNext != "" && strings.Contains(sql, d.failNext) {
		d.failNext = ""
		return true
	}
	return false
}

func (d *f02RecordingDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	d.record("row", sql, args)
	if d.policyRaw != nil && strings.Contains(sql, "label_policies") {
		return f02RawRow{raw: d.policyRaw}
	}
	if strings.Contains(sql, "INSERT INTO session_keys") && len(args) >= 3 {
		// Register the minted row (hash, org, parent from the INSERT args)
		// so revoke/finish/usage operate on the freshly minted session.
		hash, _ := args[0].(string)
		org, _ := args[1].(string)
		parent, _ := args[2].(string)
		d.scriptDB.loads["sess-new"] = sessionRow{id: "sess-new", parentID: parent, keyHash: hash, orgID: org}
	}
	if d.shouldFail(sql) {
		return scanRow{err: errors.New("f02 injected row failure")}
	}
	return d.scriptDB.QueryRow(ctx, sql, args...)
}

func (d *f02RecordingDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	d.record("rows", sql, args)
	if d.shouldFail(sql) {
		return nil, errors.New("f02 injected query failure")
	}
	switch {
	case strings.Contains(sql, "GROUP BY model_used") && d.modelRows != nil:
		return &f02Rows{idx: -1, rows: d.modelRows, failScanIdx: d.failModelScan}, nil
	case strings.Contains(sql, "GROUP BY 1") && d.groupRows != nil:
		return &f02Rows{idx: -1, rows: d.groupRows, failScanIdx: d.failGroupScan}, nil
	}
	return d.scriptDB.Query(ctx, sql, args...)
}

func (d *f02RecordingDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	d.record("exec", sql, args)
	if d.shouldFail(sql) {
		return pgconn.NewCommandTag(""), errors.New("f02 injected exec failure")
	}
	return d.scriptDB.Exec(ctx, sql, args...)
}

// f02Rows is a canned pgx.Rows over [][]any (success path of the usage
// by-model / group queries). failScanIdx (-1 = off) injects a Scan error at
// that row to drive the handlers' skip-and-continue branches.
type f02Rows struct {
	rows        [][]any
	idx         int // -1 = before first
	failScanIdx int
}

func (r *f02Rows) TypeMap() *pgtype.Map                         { return nil }
func (r *f02Rows) Conn() *pgx.Conn                              { return nil }
func (r *f02Rows) RawValues() [][]byte                          { return nil }
func (r *f02Rows) Close()                                       {}
func (r *f02Rows) Err() error                                   { return nil }
func (r *f02Rows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT 1") }
func (r *f02Rows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *f02Rows) Values() ([]any, error) {
	if r.idx < 0 || r.idx >= len(r.rows) {
		return nil, nil
	}
	return r.rows[r.idx], nil
}

func (r *f02Rows) Next() bool {
	r.idx++
	return r.idx < len(r.rows)
}

func (r *f02Rows) Scan(dest ...any) error {
	if r.idx < 0 || r.idx >= len(r.rows) {
		return errors.New("f02Rows: scan past end")
	}
	if r.idx == r.failScanIdx {
		return errors.New("f02Rows: injected scan failure")
	}
	cur := r.rows[r.idx]
	for i, d := range dest {
		if i >= len(cur) {
			break
		}
		switch d := d.(type) {
		case *string:
			*d, _ = cur[i].(string)
		case *int64:
			*d, _ = cur[i].(int64)
		case *float64:
			*d, _ = cur[i].(float64)
		case **string:
			if s, ok := cur[i].(string); ok {
				v := s
				*d = &v
			}
		default:
			return fmt.Errorf("f02Rows: unsupported dest %T", d)
		}
	}
	return nil
}

// f02RawRow answers one raw []byte column (the label_policies policy row).
type f02RawRow struct{ raw []byte }

func (r f02RawRow) Scan(dest ...any) error {
	for _, d := range dest {
		if b, ok := d.(*[]byte); ok {
			*b = r.raw
			return nil
		}
	}
	return errors.New("f02RawRow: no []byte dest")
}

// f02FailingKV wraps memSessionKV with injectable command failures: Incr
// failure documents allowSessionMint's fail-open soft limit, Del failure
// documents purgeSessionCache's warn-only path.
type f02FailingKV struct {
	*memSessionKV
	failIncr bool
	failDel  bool
}

func (f *f02FailingKV) Incr(ctx context.Context, key string) *redis.IntCmd {
	if f.failIncr {
		return redis.NewIntResult(0, errors.New("f02 kv incr down"))
	}
	return f.memSessionKV.Incr(ctx, key)
}

func (f *f02FailingKV) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	if f.failDel {
		return redis.NewIntResult(0, errors.New("f02 kv del down"))
	}
	return f.memSessionKV.Del(ctx, keys...)
}

// f02SessionResolveRow fills resolver.go's session-key scan (13 columns) so
// the legacy middleware's session principal + label-source wiring (auth.go)
// runs against a session-shaped resolve result.
type f02SessionResolveRow struct{}

func (f02SessionResolveRow) Scan(dest ...any) error {
	strs := []string{"sess-9", "org-s", "parent-9"} // first three *string dests
	si := 0
	for _, d := range dest {
		switch d := d.(type) {
		case *string:
			if si < 3 {
				*d = strs[si]
				si++
			} else {
				*d = "" // team/user/etc stay blank
			}
		case *[]byte:
			if si == 3 {
				*d = []byte(`null`) // session labels: nil → empty-set branch
				si++
			} else {
				*d = []byte(`{}`)
			}
		case *bool:
			*d = false
		case *time.Time:
			*d = time.Now().Add(time.Hour).UTC()
		case **int64, **string, **time.Time:
			// optional columns stay unset
		default:
			return fmt.Errorf("f02SessionResolveRow: unexpected dest %T", d)
		}
	}
	return nil
}

// f02SessionGW mirrors the established mintGW composition but installs the
// recording DB (gatewayCore is set with the nested literal — the
// toolchain-portable form for promoted fields).
func f02SessionGW(db *f02RecordingDB, kv sessionRedis, logs *bytes.Buffer) *gateway {
	logger := slog.New(fuzzDiscardLogger().Handler())
	if logs != nil {
		logger = slog.New(slog.NewTextHandler(logs, nil))
	}
	return &gateway{gatewayCore: gatewayCore{sessionDB: db, sessionKV: kv, log: logger}}
}

// f02Router mounts the session-key endpoints exactly like the ordinary
// revoke/finish/usage test does.
func f02Router(gw *gateway) chi.Router {
	r := chi.NewRouter()
	r.Delete("/session-keys/{id}", gw.revokeSessionKey)
	r.Post("/session-keys/{id}/finish", gw.finishSessionKey)
	r.Get("/session-keys/{id}/usage", gw.sessionKeyUsage)
	return r
}

// f02Call drives one session-key endpoint through the router with the given
// principal installed.
func f02Call(t *testing.T, r chi.Router, method, path, body string, p principal) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req = req.WithContext(withPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// f02OrgClaims builds base claims for a given tenant (issuer, audience, org
// id); the subject is shared so tenant identity is carried ONLY by the key
// material and the issuer policy.
func f02OrgClaims(iss, aud, org string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":    iss,
		"sub":    "svc-shared",
		"aud":    aud,
		"iat":    now.Unix(),
		"nbf":    now.Add(-time.Minute).Unix(),
		"exp":    now.Add(time.Hour).Unix(),
		"org_id": org,
	}
}

// f02LastUsedStore records the async last-used UPDATEs.
type f02LastUsedStore struct {
	mu    sync.Mutex
	sql   string
	batch [][]any
}

func (s *f02LastUsedStore) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sql == "" {
		s.sql = sql
	}
	s.batch = append(s.batch, args)
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

// --- fuzz target ------------------------------------------------------------------

func FuzzFamily02AuthSessionKeys(f *testing.F) {
	for id := 1; id <= 18; id++ {
		f.Add([]byte{byte(id)}) // frozen regression corpus
	}
	// Generated-request seeds: own-org valid, cross-org signer, expired
	// mutation, session mint ok, session foreign principal.
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x40, 0x01, 0x00, 0x01, 0x03, 0x00})
	f.Add([]byte{0x80, 0x00, 0x01, 0x02, 0x00, 0x01})
	fixture := f02GenFixture(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 1 && data[0] >= 1 && data[0] <= 18 {
			fuzzF02Cases[int(data[0])](t)
			return
		}
		f02Generated(t, data, fixture)
	})
}

var fuzzF02Cases = map[int]func(*testing.T){
	1:  fuzzF0201,
	2:  fuzzF0202,
	3:  fuzzF0203,
	4:  fuzzF0204,
	5:  fuzzF0205,
	6:  fuzzF0206,
	7:  fuzzF0207,
	8:  fuzzF0208,
	9:  fuzzF0209,
	10: fuzzF0210,
	11: fuzzF0211,
	12: fuzzF0212,
	13: fuzzF0213,
	14: fuzzF0214,
	15: fuzzF0215,
	16: fuzzF0216,
	17: fuzzF0217,
	18: fuzzF0218,
}

// --- generated-input behavior -------------------------------------------------------

// f02GenJWT is the lazily built fixture for the generated JWT space: two
// orgs with the same kid and subject but distinct key material and issuer
// policy; six tokens (org × mutation) minted once.
type f02GenJWT struct {
	mw  [2]*AuthMiddleware
	tok [2][3]string
	org [2]string
}

func f02GenFixture(t testing.TB) *f02GenJWT {
	t.Helper()
	g := &f02GenJWT{org: [2]string{"org-a", "org-b"}}
	iss := [2]string{"https://idp-a.example", "https://idp-b.example"}
	aud := [2]string{"aud-a", "aud-b"}
	for i := range g.mw {
		k := mustRSAJWK(t, "shared-kid")
		srv := newJWKSServer(t, k)
		a := newTestJWTAuth(t, srv, func(w *JWTWiring) {
			w.Issuer = iss[i]
			w.Audience = aud[i]
		})
		g.mw[i] = jwtMiddleware(a)
		muts := [3]func(map[string]any){
			func(map[string]any) {}, // valid
			func(c map[string]any) { c["exp"] = time.Now().Add(-2 * time.Minute).Unix() }, // expired
			func(c map[string]any) { c["iss"] = "https://evil.example" },                  // wrong issuer
		}
		for m, mut := range muts {
			c := f02OrgClaims(iss[i], aud[i], g.org[i])
			mut(c)
			g.tok[i][m] = signToken(t, k, c)
		}
	}
	return g
}

// f02jwtGenExpect derives the expected status independently of the handler:
// only the org's OWN signer with the valid mutation authenticates.
func f02jwtGenExpect(ownKey bool, mut int) int {
	if ownKey && mut == 0 {
		return http.StatusOK
	}
	return http.StatusUnauthorized
}

// f02sessGenExpect derives the expected status from the fixture contract:
// mint requires the mint-ok parent; revoke/finish/usage require the parent
// that owns the row or the session itself; unknown ids are 404 for everyone.
func f02sessGenExpect(op, pIdx int, idKnown bool) int {
	if op == 0 { // mint
		if pIdx == 0 {
			return http.StatusCreated
		}
		return http.StatusForbidden
	}
	// Both parent fixtures own this key; the mint grant controls only creation.
	visible := idKnown && (pIdx == 0 || pIdx == 1 || pIdx == 2)
	if !visible {
		return http.StatusNotFound
	}
	if op == 3 { // usage
		return http.StatusOK
	}
	return http.StatusNoContent // revoke / finish
}

// f02Generated drives the real handlers with generated inputs and asserts
// the independently derived outcomes on both domains.
func f02Generated(t *testing.T, data []byte, g *f02GenJWT) {
	t.Helper()
	p := data
	if len(p) < 6 {
		p = append(append([]byte{}, p...), 0, 1, 2, 3, 4, 5)
	}

	// JWT domain: org × signer × mutation → middleware status + org header.
	orgIdx, signerIdx, mut := int(p[0])%2, int(p[1])%2, int(p[2])%3
	var gotOrg string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get("X-Org-Id")
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+g.tok[signerIdx][mut])
	rec := httptest.NewRecorder()
	g.mw[orgIdx].ServeHTTP(next).ServeHTTP(rec, req)
	if want := f02jwtGenExpect(orgIdx == signerIdx, mut); rec.Code != want {
		t.Fatalf("F02 gen jwt: org=%d signer=%d mut=%d: want %d got %d %q",
			orgIdx, signerIdx, mut, want, rec.Code, rec.Body.String())
	}
	if rec.Code == http.StatusOK && gotOrg != g.org[orgIdx] {
		t.Fatalf("F02 gen jwt: X-Org-Id %q, want %q", gotOrg, g.org[orgIdx])
	}

	// Session domain: op × principal × id → handler status.
	op, pIdx, idSel := int(p[3])%4, int(p[4])%4, int(p[5])%2
	principals := []principal{
		{APIKeyID: "parent-1", CanMintSessions: true}, // mint-ok owner
		{APIKeyID: "parent-1"},                        // no mint grant
		{SessionKeyID: "sess-1"},                      // the session itself
		{APIKeyID: "attacker"},                        // foreign key
	}
	ids := []string{"sess-1", "sess-x"}
	db := f02DB()
	db.scriptDB.loads["sess-1"] = sessionRow{id: "sess-1", parentID: "parent-1", keyHash: "hash-1", orgID: "org-1"}
	kv := &memSessionKV{}
	gw := f02SessionGW(db, kv, nil)
	want := f02sessGenExpect(op, pIdx, idSel == 0)

	var rec2 *httptest.ResponseRecorder
	switch op {
	case 0:
		rec2 = httptest.NewRecorder()
		gw.mintSessionKey(rec2, mintReq(t, principals[pIdx], `{}`))
	case 1:
		rec2 = f02Call(t, f02Router(gw), http.MethodDelete, "/session-keys/"+ids[idSel], "", principals[pIdx])
	case 2:
		rec2 = f02Call(t, f02Router(gw), http.MethodPost, "/session-keys/"+ids[idSel]+"/finish", `{"status":"success"}`, principals[pIdx])
	default:
		rec2 = f02Call(t, f02Router(gw), http.MethodGet, "/session-keys/"+ids[idSel]+"/usage", "", principals[pIdx])
	}
	if rec2.Code != want {
		t.Fatalf("F02 gen session: op=%d principal=%d id=%q: want %d got %d %q",
			op, pIdx, ids[idSel], want, rec2.Code, rec2.Body.String())
	}
}

// --- frozen cases -------------------------------------------------------------------

// F02-01 valid RS256/ES256 through the middleware; org + locked key-label
// source reach downstream; wiring disabled → nil authenticator; metric.
func fuzzF0201(t *testing.T) {
	t.Helper()
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	a := newTestJWTAuth(t, srv, nil)
	mw := jwtMiddleware(a)

	if NewJWTAuthenticator(JWTWiring{}, nil) != nil {
		t.Fatal("F02-01: disabled wiring must yield a nil authenticator")
	}

	c := baseClaims()
	c["key_labels"] = map[string]any{"env": "prod"}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+signToken(t, k, c))

	var gotOrg string
	var srcs []struct {
		name    string
		locked  bool
		envTeam string
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get("X-Org-Id")
		for _, s := range principalLabelSources(r.Context()) {
			if s.Name == "key" {
				srcs = append(srcs, struct {
					name    string
					locked  bool
					envTeam string
				}{s.Name, s.Locked, s.Labels["env"]})
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	before := jwtValidations("ok")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("F02-01: status %d body %s", rec.Code, rec.Body.String())
	}
	if gotOrg != "org-42" {
		t.Fatalf("F02-01: X-Org-Id %q", gotOrg)
	}
	if len(srcs) != 1 || !srcs[0].locked || srcs[0].envTeam != "prod" {
		t.Fatalf("F02-01: key label source %+v", srcs)
	}
	if got := jwtValidations("ok"); got < before+1 {
		t.Fatalf("F02-01: validations(ok) delta %v", got-before)
	}

	// ES256 + key-label claim shapes through Authenticate.
	ec := mustESJWK(t, "ec1")
	ecSrv := newJWKSServer(t, ec)
	ecAuth := newTestJWTAuth(t, ecSrv, nil)
	p, err := ecAuth.Authenticate(context.Background(), signToken(t, ec, baseClaims()))
	if err != nil || p.OrgID != "org-42" || p.Subject != "svc-account-1" {
		t.Fatalf("F02-01: es256 principal %+v err %v", p, err)
	}
	shapes := []struct {
		claim any
		want  []string
	}{
		{"prod", []string{"prod"}},
		{[]any{"prod", "team-a"}, []string{"prod", "team-a"}},
		{map[string]any{"env": "prod"}, []string{"env"}},
		{[]any{1, 2}, nil},
	}
	for _, tc := range shapes {
		c := baseClaims()
		c["key_labels"] = tc.claim
		p, err := a.Authenticate(context.Background(), signToken(t, k, c))
		if err != nil {
			t.Fatalf("F02-01: shape %v: %v", tc.claim, err)
		}
		for _, want := range tc.want {
			if _, ok := p.KeyLabels[want]; !ok {
				t.Fatalf("F02-01: shape %v: labels %v missing %q", tc.claim, p.KeyLabels, want)
			}
		}
		if tc.want == nil && len(p.KeyLabels) != 0 {
			t.Fatalf("F02-01: shape %v: labels %v", tc.claim, p.KeyLabels)
		}
	}

	// Constructor defaults: a wiring with only the JWKS URL enables the
	// path, defaults the org claim to org_id, and enforces no iss/aud.
	ctor := NewJWTAuthenticator(JWTWiring{JWKSURL: srv.srv.URL}, nil)
	pc, err := ctor.Authenticate(context.Background(), signToken(t, k, baseClaims()))
	if err != nil || pc.OrgID != "org-42" || pc.Subject != "svc-account-1" {
		t.Fatalf("F02-01: constructor defaults: %+v err %v", pc, err)
	}
}

// F02-02 claim rejections: reason + metric per case.
func fuzzF0202(t *testing.T) {
	t.Helper()
	k := mustRSAJWK(t, "k1")
	other := mustRSAJWK(t, "k1") // same kid, different material
	srv := newJWKSServer(t, k)
	a := newTestJWTAuth(t, srv, nil)

	mut := func(f func(map[string]any)) map[string]any {
		c := baseClaims()
		f(c)
		return c
	}
	cases := []struct {
		name   string
		token  string
		reason string
	}{
		{"expired", signToken(t, k, mut(func(c map[string]any) { c["exp"] = time.Now().Add(-2 * time.Minute).Unix() })), "expired"},
		{"nbf future", signToken(t, k, mut(func(c map[string]any) { c["nbf"] = time.Now().Add(2 * time.Minute).Unix() })), "not_yet_valid"},
		{"iat future", signToken(t, k, mut(func(c map[string]any) { c["iat"] = time.Now().Add(2 * time.Minute).Unix() })), "not_yet_valid"},
		{"wrong aud", signToken(t, k, mut(func(c map[string]any) { c["aud"] = "other-service" })), "audience"},
		{"wrong iss", signToken(t, k, mut(func(c map[string]any) { c["iss"] = "https://evil.example" })), "issuer"},
		{"missing exp", signToken(t, k, mut(func(c map[string]any) { delete(c, "exp") })), "missing_exp"},
		{"missing org claim", signToken(t, k, mut(func(c map[string]any) { delete(c, "org_id") })), "org_claim"},
		{"blank org claim", signToken(t, k, mut(func(c map[string]any) { c["org_id"] = "  " })), "org_claim"},
		{"non-string org claim", signToken(t, k, mut(func(c map[string]any) { c["org_id"] = 42 })), "org_claim"},
		{"same-kid other material", signToken(t, other, baseClaims()), "signature"},
	}
	for _, tc := range cases {
		before := jwtErrors(tc.reason)
		_, err := a.Authenticate(context.Background(), tc.token)
		ae, ok := err.(*jwtAuthError)
		if !ok || ae.status != http.StatusUnauthorized || ae.reason != tc.reason {
			t.Fatalf("F02-02 %s: want 401/%s, got %+v (%v)", tc.name, tc.reason, ae, err)
		}
		if got := jwtErrors(tc.reason); got < before+1 {
			t.Fatalf("F02-02 %s: errors(%s) delta %v", tc.name, tc.reason, got-before)
		}
		if ae.Error() == "" {
			t.Fatalf("F02-02 %s: typed error renders an empty message", tc.name)
		}
	}
}

// F02-03 malformed forms fail at the gate; the middleware renders the legacy
// 401 for non-JWT shapes; missing header and non-Bearer scheme stay legacy.
func fuzzF0203(t *testing.T) {
	t.Helper()
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	a := newTestJWTAuth(t, srv, nil)
	mw := jwtMiddleware(a)

	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	badHdr, _ := json.Marshal(map[string]string{"alg": "RS256"}) // no kid
	malformed := []string{
		"not-a-jwt",
		"a.b",
		"a.b.c.d",
		"..",
		"***.b.c",
		b64("notjson") + ".b.c",
		b64(string(badHdr)) + ".b.c",
	}
	for _, tok := range malformed {
		_, err := a.Authenticate(context.Background(), tok)
		ae, ok := err.(*jwtAuthError)
		if !ok || ae.status != http.StatusUnauthorized || ae.reason != "form" {
			t.Fatalf("F02-03: %q: want 401/form, got %+v (%v)", tok, ae, err)
		}
	}

	// Well-formed header, garbage payload: the kid lookup succeeds and the
	// parse fails → signature reason (not "form").
	goodHdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1"})
	garbagePayload := b64(string(goodHdr)) + "." + b64("not-json") + "." + b64("c2ln")
	_, gpErr := a.Authenticate(context.Background(), garbagePayload)
	gpAe, gpOK := gpErr.(*jwtAuthError)
	if !gpOK || gpAe.status != http.StatusUnauthorized || gpAe.reason != "signature" {
		t.Fatalf("F02-03: garbage payload: want 401/signature, got %+v (%v)", gpAe, gpErr)
	}

	// Middleware: non-JWT shapes fall to the legacy path → "invalid API key".
	for _, tok := range []string{"not-a-jwt", "a.b", b64("notjson") + ".b.c"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next reached") })).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid API key") {
			t.Fatalf("F02-03: %q: %d %s", tok, rec.Code, rec.Body.String())
		}
	}

	// No Authorization at all → missing-header 401.
	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(http.NotFound)).ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("F02-03: missing header: %d", rec.Code)
	}

	// Non-Bearer scheme must not trigger the JWT fork.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Basic "+signToken(t, k, baseClaims()))
	rec = httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next reached") })).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("F02-03: basic scheme: %d", rec.Code)
	}
}

// F02-04 algorithm confusion: none and HS256 are rejected BEFORE any JWKS
// fetch; an ES token claiming an RSA kid dies at key-type filtering.
func fuzzF0204(t *testing.T) {
	t.Helper()
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	a := newTestJWTAuth(t, srv, nil)

	// Unsupported headers must fail before a claim or a signature is consumed.
	for _, alg := range []string{"none", "HS256"} {
		header, err := json.Marshal(map[string]string{"alg": alg, "kid": "k1"})
		if err != nil {
			t.Fatal(err)
		}
		tok := base64.RawURLEncoding.EncodeToString(header) + ".e30.AA"
		_, err = a.Authenticate(context.Background(), tok)
		ae, ok := err.(*jwtAuthError)
		if !ok || ae.status != http.StatusUnauthorized || ae.reason != "alg" {
			t.Fatalf("F02-04: want 401/alg, got %+v (%v)", ae, err)
		}
	}
	if got := srv.fetchCount(); got != 0 {
		t.Fatalf("F02-04: confusion attempts must not fetch the JWKS, fetches = %d", got)
	}

	ec := mustESJWK(t, "k1") // RSA key's kid, EC material
	_, err := a.Authenticate(context.Background(), signToken(t, ec, baseClaims()))
	ae, ok := err.(*jwtAuthError)
	if !ok || ae.status != http.StatusUnauthorized || ae.reason != "signature" {
		t.Fatalf("F02-04: want 401/signature for ES-vs-RSA kid, got %+v (%v)", ae, err)
	}
}

// F02-05 tenant isolation: same kid + subject, distinct material and policy.
func fuzzF0205(t *testing.T) {
	t.Helper()
	keyA := mustRSAJWK(t, "shared-kid")
	keyB := mustRSAJWK(t, "shared-kid")
	srvA := newJWKSServer(t, keyA)
	srvB := newJWKSServer(t, keyB)

	authA := newTestJWTAuth(t, srvA, func(w *JWTWiring) {
		w.Issuer = "https://idp-a.example"
		w.Audience = "aud-a"
	})
	authB := newTestJWTAuth(t, srvB, func(w *JWTWiring) {
		w.Issuer = "https://idp-b.example"
		w.Audience = "aud-b"
	})
	tokA := signToken(t, keyA, f02OrgClaims("https://idp-a.example", "aud-a", "org-a"))
	tokB := signToken(t, keyB, f02OrgClaims("https://idp-b.example", "aud-b", "org-b"))

	// Own-org: authenticated with the own org id and shared subject.
	p, err := authA.Authenticate(context.Background(), tokA)
	if err != nil || p.OrgID != "org-a" || p.Subject != "svc-shared" {
		t.Fatalf("F02-05: own-org principal %+v err %v", p, err)
	}
	if _, err := authB.Authenticate(context.Background(), tokB); err != nil {
		t.Fatalf("F02-05: org-b own token: %v", err)
	}

	// Cross-org: same kid + sub, other org's material → signature failure,
	// and the victim JWKS is consulted exactly once.
	_, err = authB.Authenticate(context.Background(), tokA)
	ae, ok := err.(*jwtAuthError)
	if !ok || ae.status != http.StatusUnauthorized || ae.reason != "signature" {
		t.Fatalf("F02-05: cross-org want 401/signature, got %+v (%v)", ae, err)
	}
	if got := srvB.fetchCount(); got != 1 {
		t.Fatalf("F02-05: victim JWKS fetches = %d, want 1", got)
	}

	// Policy isolation with material held constant: same JWKS, other
	// issuer policy → issuer failure.
	authA2 := newTestJWTAuth(t, srvA, func(w *JWTWiring) {
		w.Issuer = "https://idp-b.example"
		w.Audience = "aud-a"
	})
	_, err = authA2.Authenticate(context.Background(), tokA)
	ae, ok = err.(*jwtAuthError)
	if !ok || ae.status != http.StatusUnauthorized || ae.reason != "issuer" {
		t.Fatalf("F02-05: foreign issuer want 401/issuer, got %+v (%v)", ae, err)
	}

	// Middleware: own org flows as X-Org-Id; cross-org token is rejected on
	// the JWT path (not the legacy body).
	var gotOrg string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get("X-Org-Id")
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+tokA)
	rec := httptest.NewRecorder()
	jwtMiddleware(authA).ServeHTTP(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotOrg != "org-a" {
		t.Fatalf("F02-05: middleware own-org %d org %q", rec.Code, gotOrg)
	}
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req2.Header.Set("Authorization", "Bearer "+tokA)
	rec2 := httptest.NewRecorder()
	jwtMiddleware(authB).ServeHTTP(http.HandlerFunc(http.NotFound)).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized ||
		!strings.Contains(rec2.Body.String(), "invalid bearer token") ||
		strings.Contains(rec2.Body.String(), "invalid API key") {
		t.Fatalf("F02-05: middleware cross-org %d %s", rec2.Code, rec2.Body.String())
	}
}

// F02-06 cold concurrent burst: 24 goroutines, exactly one fetch, all
// authenticated; jittered refresh deadline verified.
func fuzzF0206(t *testing.T) {
	t.Helper()
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	a := newTestJWTAuth(t, srv, nil)
	a.cache.jitter = func(n int) int { return n } // jittered branch: +n

	tok := signToken(t, k, baseClaims())
	before := jwtValidations("ok")
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Authenticate(context.Background(), tok); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("F02-06: burst auth: %v", err)
	}
	if got := srv.fetchCount(); got != 1 {
		t.Fatalf("F02-06: cold burst fetches = %d, want exactly 1", got)
	}
	if got := jwtValidations("ok"); got < before+24 {
		t.Fatalf("F02-06: validations(ok) delta %v", got-before)
	}
	a.cache.mu.RLock()
	defer a.cache.mu.RUnlock()
	// ttl 10m + jitter int(600*0.1)=60s.
	if got := a.cache.refreshDue.Sub(a.cache.fetchedAt); got != 660*time.Second {
		t.Fatalf("F02-06: jittered refresh delta %s, want 660s", got)
	}
}

// F02-07 JWKS-down fail-closed matrix.
func fuzzF0207(t *testing.T) {
	t.Helper()
	k := mustRSAJWK(t, "k1")
	srv := newJWKSServer(t, k)
	a := newTestJWTAuth(t, srv, nil)
	tok := signToken(t, k, baseClaims())

	if _, err := a.Authenticate(context.Background(), tok); err != nil {
		t.Fatalf("F02-07: warm: %v", err)
	}
	srv.srv.Close()

	// Unknown kid with a warm live cache → 401 (cache is the truth).
	unknown := mustRSAJWK(t, "never-seen")
	_, err := a.Authenticate(context.Background(), signToken(t, unknown, baseClaims()))
	ae, ok := err.(*jwtAuthError)
	if !ok || ae.status != http.StatusUnauthorized || ae.reason != "unknown_kid" {
		t.Fatalf("F02-07: want 401/unknown_kid, got %+v (%v)", ae, err)
	}

	// Past max-stale → fail closed 503.
	a.cache.mu.Lock()
	a.cache.fetchedAt = a.cache.now().Add(-a.cache.maxStale - time.Minute)
	a.cache.mu.Unlock()
	_, err = a.Authenticate(context.Background(), tok)
	ae, ok = err.(*jwtAuthError)
	if !ok || ae.status != http.StatusServiceUnavailable || ae.reason != "jwks_unavailable" {
		t.Fatalf("F02-07: want 503/jwks_unavailable, got %+v (%v)", ae, err)
	}

	// Empty cache + dead endpoint → 503; the middleware renders the status
	// and the JSON envelope (status + header oracles).
	deadSrv := newJWKSServer(t)
	deadSrv.srv.Close()
	a2 := newTestJWTAuth(t, deadSrv, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+signToken(t, k, baseClaims()))
	rec := httptest.NewRecorder()
	jwtMiddleware(a2).ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next reached") })).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("F02-07: middleware empty cache: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("F02-07: Content-Type %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "temporarily unavailable") ||
		!strings.Contains(rec.Body.String(), apierrors.ErrorCodeAuthentication) {
		t.Fatalf("F02-07: 503 body %s", rec.Body.String())
	}

	// Invalid JWKS URL: fetch cannot even build the request → fail closed.
	badURL := NewJWTAuthenticator(JWTWiring{JWKSURL: "http://[::1]:namedport"}, nil)
	_, err = badURL.Authenticate(context.Background(), signToken(t, k, baseClaims()))
	buAe, buOK := err.(*jwtAuthError)
	if !buOK || buAe.status != http.StatusServiceUnavailable || buAe.reason != "jwks_unavailable" {
		t.Fatalf("F02-07: bad URL: want 503/jwks_unavailable, got %+v (%v)", buAe, err)
	}

	// Malformed JWKS bodies: non-200, garbage JSON, oversize (>1MiB),
	// empty key set, and a truncated stream all fail closed on an empty
	// cache.
	modes := 0
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch modes {
		case 0:
			w.WriteHeader(http.StatusInternalServerError)
		case 1:
			_, _ = w.Write([]byte("<html>not json</html>"))
		case 2:
			_, _ = w.Write(bytes.Repeat([]byte("x"), (1<<20)+2))
		case 3:
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case 4:
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn, _, cerr := hj.Hijack()
			if cerr != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"))
			_ = conn.Close()
		}
	}))
	defer badSrv.Close()
	for m := 0; m < 5; m++ {
		modes = m
		ba := NewJWTAuthenticator(JWTWiring{
			JWKSURL: badSrv.URL, Issuer: "https://idp.example", Audience: "yabanin-gateway",
			OrgClaim: "org_id", KeyLabelClaim: "key_labels",
		}, nil)
		_, err := ba.Authenticate(context.Background(), signToken(t, k, baseClaims()))
		ae, ok := err.(*jwtAuthError)
		if !ok || ae.status != http.StatusServiceUnavailable || ae.reason != "jwks_unavailable" {
			t.Fatalf("F02-07: bad JWKS mode %d: want 503/jwks_unavailable, got %+v (%v)", m, ae, err)
		}
	}
	modes = 0

	// refreshSync: success stores a fresh set; a dead endpoint errors.
	live := newJWKSServer(t, k)
	la := newTestJWTAuth(t, live, nil)
	if err := la.cache.refreshSync(context.Background()); err != nil {
		t.Fatalf("F02-07: refreshSync live: %v", err)
	}
	live.srv.Close()
	if err := la.cache.refreshSync(context.Background()); err == nil {
		t.Fatal("F02-07: refreshSync against a dead endpoint must error")
	}

	// Aged-but-live cache schedules ONE background refresh; the request
	// path keeps serving stale keys while it runs.
	la2 := newTestJWTAuth(t, newJWKSServer(t, k), nil)
	if _, err := la2.Authenticate(context.Background(), tok); err != nil {
		t.Fatalf("F02-07: warm2: %v", err)
	}
	la2.cache.mu.Lock()
	beforeFetch := la2.cache.fetchedAt
	la2.cache.refreshDue = la2.cache.now().Add(-time.Minute)
	la2.cache.mu.Unlock()
	if _, err := la2.Authenticate(context.Background(), tok); err != nil {
		t.Fatalf("F02-07: stale-serving: %v", err)
	}
	refreshed := false
	deadline := time.Now().Add(3 * time.Second)
	for !refreshed && time.Now().Before(deadline) {
		la2.cache.mu.RLock()
		refreshed = la2.cache.fetchedAt.After(beforeFetch)
		la2.cache.mu.RUnlock()
		if !refreshed {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !refreshed {
		t.Fatal("F02-07: background refresh never stored a fresh set")
	}
}

// F02-08 JWKS keys without explicit alg: the type switch admits RSA for
// RS256 and EC P-256 for ES256; a use:"enc" key is never a candidate.
func fuzzF0208(t *testing.T) {
	t.Helper()
	rsaKey := mustRSAJWK(t, "k1")
	algless := rsaKey
	algless.pub.Algorithm = ""
	algless.pub.Use = ""
	srv := newJWKSServer(t, algless)
	a := newTestJWTAuth(t, srv, nil)
	if _, err := a.Authenticate(context.Background(), signToken(t, rsaKey, baseClaims())); err != nil {
		t.Fatalf("F02-08: algless RSA: %v", err)
	}

	ecKey := mustESJWK(t, "ec1")
	alglessEC := ecKey
	alglessEC.pub.Algorithm = ""
	alglessEC.pub.Use = ""
	ecSrv := newJWKSServer(t, alglessEC)
	ecAuth := newTestJWTAuth(t, ecSrv, nil)
	if _, err := ecAuth.Authenticate(context.Background(), signToken(t, ecKey, baseClaims())); err != nil {
		t.Fatalf("F02-08: algless EC: %v", err)
	}

	encKey := mustRSAJWK(t, "k2")
	encKey.pub.Use = "enc"
	encSrv := newJWKSServer(t, encKey)
	encAuth := newTestJWTAuth(t, encSrv, nil)
	_, err := encAuth.Authenticate(context.Background(), signToken(t, encKey, baseClaims()))
	ae, ok := err.(*jwtAuthError)
	if !ok || ae.status != http.StatusUnauthorized || ae.reason != "signature" {
		t.Fatalf("F02-08: use:enc key must not verify, got %+v (%v)", ae, err)
	}

	// An oct (symmetric) JWKS key with no explicit alg/use never becomes a
	// candidate for an RS256 token: the keyMatchesAlg type switch rejects
	// it and verification fails closed.
	octTok := mustRSAJWK(t, "k9") // RS256 signer carrying the oct key's kid
	octSrv := newJWKSServer(t, jwkPair{pub: jose.JSONWebKey{
		Key:   []byte("0123456789abcdef0123456789abcdef"),
		KeyID: "k9",
	}})
	octAuth := newTestJWTAuth(t, octSrv, nil)
	_, err = octAuth.Authenticate(context.Background(), signToken(t, octTok, baseClaims()))
	ae, ok = err.(*jwtAuthError)
	if !ok || ae.status != http.StatusUnauthorized || ae.reason != "signature" {
		t.Fatalf("F02-08: oct key must not verify, got %+v (%v)", ae, err)
	}
}

// F02-09 mint happy path: status, body, INSERT args, rate counter, log hygiene.
func fuzzF0209(t *testing.T) {
	t.Helper()
	db := f02DB()
	kv := &memSessionKV{}
	var logs bytes.Buffer
	gw := f02SessionGW(db, kv, &logs)

	before := time.Now().UTC()
	rec := httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, principal{APIKeyID: "parent-1", CanMintSessions: true},
		`{"labels":{"yabanin.secret":"1","team":"other","project":"preview"}}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("F02-09: %d %s", rec.Code, rec.Body.String())
	}
	after := time.Now().UTC()

	body := struct {
		ID        string `json:"id"`
		Key       string `json:"key"`
		ExpiresAt string `json:"expires_at"`
	}{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("F02-09: body %s: %v", rec.Body.String(), err)
	}
	if body.ID != "sess-new" || !strings.HasPrefix(body.Key, "ybs_") {
		t.Fatalf("F02-09: id/key %q/%q", body.ID, body.Key)
	}
	if !strings.Contains(rec.Body.String(), "dropped") || !strings.Contains(rec.Body.String(), "reserved") {
		t.Fatalf("F02-09: dropped-reserved oracle missing: %s", rec.Body.String())
	}
	expires, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		t.Fatalf("F02-09: expires %q: %v", body.ExpiresAt, err)
	}
	if expires.Sub(before) < 7140*time.Second || expires.Sub(after) > 7260*time.Second {
		t.Fatalf("F02-09: expires %s outside default TTL window", body.ExpiresAt)
	}

	ins := db.f02Find("row", "INSERT INTO session_keys")
	if len(ins) != 1 {
		t.Fatalf("F02-09: INSERT statements %d", len(ins))
	}
	args := ins[0].args
	if args[1] != "org-1" || args[2] != "parent-1" || args[3] != "" || args[5] != false {
		t.Fatalf("F02-09: INSERT tenant/parent args %+v", args)
	}
	raw, _ := args[4].([]byte)
	if string(raw) != `{"project":"preview"}` {
		t.Fatalf("F02-09: unexpected stored session labels %s", raw)
	}
	if expArg, ok := args[8].(time.Time); !ok || expArg.Sub(before) < 7140*time.Second || expArg.Sub(after) > 7260*time.Second {
		t.Fatalf("F02-09: INSERT expires arg %+v", args[8])
	}
	if hash, ok := args[0].(string); !ok || hash == "" || hash == body.Key {
		t.Fatalf("F02-09: INSERT hash arg %+v", args[0])
	}

	// Rate limiter consumed exactly one slot for the current minute.
	kv.mu.Lock()
	found := false
	for k, n := range kv.n {
		if strings.HasPrefix(k, "yb:skey:mint:parent-1:") {
			if n != 1 {
				kv.mu.Unlock()
				t.Fatalf("F02-09: rate counter %s = %d", k, n)
			}
			found = true
		}
	}
	kv.mu.Unlock()
	if !found {
		t.Fatal("F02-09: no rate counter recorded")
	}

	// The secret must never reach the logs.
	if strings.Contains(logs.String(), "ybs_") {
		t.Fatal("F02-09: session secret leaked into logs")
	}
}

// F02-10 mint denials and validation failures (fail closed).
func fuzzF0210(t *testing.T) {
	t.Helper()
	parent := principal{APIKeyID: "parent-1", CanMintSessions: true}
	bad := []struct {
		name string
		p    principal
		body string
		code int
		want string
	}{
		{"no mint grant", principal{APIKeyID: "parent-1"}, `{}`, http.StatusForbidden, "session_mint_not_allowed"},
		{"agent principal", principal{APIKeyID: "parent-1", AgentID: "agent-1", CanMintSessions: true}, `{}`, http.StatusForbidden, "session_mint_not_allowed"},
		{"session principal", principal{APIKeyID: "parent-1", SessionKeyID: "sess", CanMintSessions: true}, `{}`, http.StatusForbidden, "session_mint_not_allowed"},
		{"invalid ttl", parent, `{"ttl_seconds":10}`, http.StatusBadRequest, "invalid_ttl"},
		{"invalid name", parent, `{"name":"bad name!"}`, http.StatusBadRequest, "invalid_name"},
		{"invalid max_tokens", parent, `{"max_tokens":0}`, http.StatusBadRequest, "invalid_limits"},
		{"invalid max_cost_usd", parent, `{"max_cost_usd":0}`, http.StatusBadRequest, "invalid_limits"},
		{"unknown field", parent, `{"bogus":1}`, http.StatusBadRequest, "invalid_request"},
		{"expired parent", principal{APIKeyID: "parent-1", CanMintSessions: true, KeyExpiresAt: time.Now().Add(-time.Hour)}, `{}`, http.StatusBadRequest, "parent_key_expired"},
	}
	for _, tc := range bad {
		gw := f02SessionGW(f02DB(), &memSessionKV{}, nil)
		rec := httptest.NewRecorder()
		gw.mintSessionKey(rec, mintReq(t, tc.p, tc.body))
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("F02-10 %s: want %d/%s, got %d %s", tc.name, tc.code, tc.want, rec.Code, rec.Body.String())
		}
	}

	// Rate limited: the limiter is at the per-minute cap.
	kv := &memSessionKV{n: map[string]int64{}}
	kv.n["yb:skey:mint:parent-1:"+strconv.FormatInt(time.Now().Unix()/60, 10)] = 60
	gw := f02SessionGW(f02DB(), kv, nil)
	rec := httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, parent, `{}`))
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "rate_limited") {
		t.Fatalf("F02-10 rate limit: %d %s", rec.Code, rec.Body.String())
	}

	// Oversized body (>16KiB) is rejected at the read gate.
	gwBig := f02SessionGW(f02DB(), &memSessionKV{}, nil)
	recBig := httptest.NewRecorder()
	gwBig.mintSessionKey(recBig, mintReq(t, parent, strings.Repeat("x", 17*1024)))
	if recBig.Code != http.StatusBadRequest || !strings.Contains(recBig.Body.String(), "invalid_request") {
		t.Fatalf("F02-10 oversized: %d %s", recBig.Code, recBig.Body.String())
	}

	// Mint rate-limiter KV failure is fail-open (soft limit): mint succeeds.
	gwKv := f02SessionGW(f02DB(), &f02FailingKV{memSessionKV: &memSessionKV{}, failIncr: true}, nil)
	recKv := httptest.NewRecorder()
	gwKv.mintSessionKey(recKv, mintReq(t, parent, `{}`))
	if recKv.Code != http.StatusCreated {
		t.Fatalf("F02-10 kv-down: want fail-open 201, got %d %s", recKv.Code, recKv.Body.String())
	}
}

// F02-11 revoke: UPDATE + purge oracles, idempotence, visibility, exec failure.
func fuzzF0211(t *testing.T) {
	t.Helper()
	db := f02DB()
	db.scriptDB.loads["sess-1"] = sessionRow{id: "sess-1", parentID: "parent-1", keyHash: "hash-1", orgID: "org-1"}
	kv := &memSessionKV{}
	gw := f02SessionGW(db, kv, nil)
	r := f02Router(gw)

	// Foreign and unknown ids never reach the UPDATE.
	if rec := f02Call(t, r, http.MethodDelete, "/session-keys/sess-1", "", principal{APIKeyID: "attacker"}); rec.Code != http.StatusNotFound {
		t.Fatalf("F02-11: foreign: %d", rec.Code)
	}
	if rec := f02Call(t, r, http.MethodDelete, "/session-keys/sess-x", "", principal{APIKeyID: "parent-1"}); rec.Code != http.StatusNotFound {
		t.Fatalf("F02-11: unknown: %d", rec.Code)
	}
	if got := len(db.f02Find("exec", "SET revoked_at")); got != 0 {
		t.Fatalf("F02-11: premature UPDATEs %d", got)
	}

	// Own revoke → 204, one UPDATE, one cache purge.
	if rec := f02Call(t, r, http.MethodDelete, "/session-keys/sess-1", "", principal{APIKeyID: "parent-1"}); rec.Code != http.StatusNoContent {
		t.Fatalf("F02-11: own: %d %s", rec.Code, rec.Body.String())
	}
	ups := db.f02Find("exec", "SET revoked_at = now()")
	if len(ups) != 1 || !strings.Contains(ups[0].sql, "AND revoked_at IS NULL") || len(ups[0].args) != 1 || ups[0].args[0] != "sess-1" {
		t.Fatalf("F02-11: UPDATE oracle %+v", ups)
	}
	kv.mu.Lock()
	dels := append([]string(nil), kv.dels...)
	kv.mu.Unlock()
	if len(dels) != 1 || dels[0] != "org:resolve:hash-1" {
		t.Fatalf("F02-11: purge dels %v", dels)
	}

	// Idempotent second revoke: 204, NO second UPDATE, NO second purge
	// (no stale resolver cache churn).
	if rec := f02Call(t, r, http.MethodDelete, "/session-keys/sess-1", "", principal{APIKeyID: "parent-1"}); rec.Code != http.StatusNoContent {
		t.Fatalf("F02-11: idempotent: %d", rec.Code)
	}
	if got := len(db.f02Find("exec", "SET revoked_at")); got != 1 {
		t.Fatalf("F02-11: second revoke issued %d UPDATEs", got)
	}
	kv.mu.Lock()
	n := len(kv.dels)
	kv.mu.Unlock()
	if n != 1 {
		t.Fatalf("F02-11: second purge recorded, dels = %d", n)
	}

	// Exec failure → 500.
	db2 := f02DB()
	db2.scriptDB.loads["sess-2"] = sessionRow{id: "sess-2", parentID: "parent-1", keyHash: "hash-2", orgID: "org-1"}
	db2.failNext = "SET revoked_at"
	gw2 := f02SessionGW(db2, &memSessionKV{}, nil)
	rec := f02Call(t, f02Router(gw2), http.MethodDelete, "/session-keys/sess-2", "", principal{APIKeyID: "parent-1"})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "session_revoke_failed") {
		t.Fatalf("F02-11: exec failure: %d %s", rec.Code, rec.Body.String())
	}

	// KV purge failure is soft: revoke still succeeds and warns.
	db3 := f02DB()
	db3.scriptDB.loads["sess-3"] = sessionRow{id: "sess-3", parentID: "parent-1", keyHash: "hash-3", orgID: "org-1"}
	var logs3 bytes.Buffer
	gw3 := f02SessionGW(db3, &f02FailingKV{memSessionKV: &memSessionKV{}, failDel: true}, &logs3)
	rec3 := f02Call(t, f02Router(gw3), http.MethodDelete, "/session-keys/sess-3", "", principal{APIKeyID: "parent-1"})
	if rec3.Code != http.StatusNoContent {
		t.Fatalf("F02-11: kv-down revoke: %d %s", rec3.Code, rec3.Body.String())
	}
	if !strings.Contains(logs3.String(), "session resolver cache purge failed") {
		t.Fatalf("F02-11: purge failure warning missing: %s", logs3.String())
	}
}

// F02-12 finish: UPDATE oracle, idempotence, validation, visibility.
func fuzzF0212(t *testing.T) {
	t.Helper()
	db := f02DB()
	db.scriptDB.loads["sess-2"] = sessionRow{id: "sess-2", parentID: "parent-1", keyHash: "hash-2", orgID: "org-1"}
	gw := f02SessionGW(db, &memSessionKV{}, nil)
	r := f02Router(gw)
	self := principal{SessionKeyID: "sess-2"}

	if rec := f02Call(t, r, http.MethodPost, "/session-keys/sess-2/finish", "", principal{APIKeyID: "attacker"}); rec.Code != http.StatusNotFound {
		t.Fatalf("F02-12: foreign: %d", rec.Code)
	}
	if rec := f02Call(t, r, http.MethodPost, "/session-keys/sess-2/finish", `{"status":"bogus"}`, self); rec.Code != http.StatusBadRequest {
		t.Fatalf("F02-12: invalid status: %d", rec.Code)
	}
	if rec := f02Call(t, r, http.MethodPost, "/session-keys/sess-2/finish", `{"bogus":1}`, self); rec.Code != http.StatusBadRequest {
		t.Fatalf("F02-12: unknown field: %d", rec.Code)
	}
	if got := len(db.f02Find("exec", "finished_at IS NULL")); got != 0 {
		t.Fatalf("F02-12: premature UPDATEs %d", got)
	}

	if rec := f02Call(t, r, http.MethodPost, "/session-keys/sess-2/finish",
		`{"status":"success","exit_code":0,"duration_ms":5}`, self); rec.Code != http.StatusNoContent {
		t.Fatalf("F02-12: own: %d %s", rec.Code, rec.Body.String())
	}
	ups := db.f02Find("exec", "finished_at IS NULL")
	if len(ups) != 1 ||
		!strings.Contains(ups[0].sql, "finished_at = now()") ||
		!strings.Contains(ups[0].sql, "revoked_at = COALESCE(revoked_at, now())") ||
		len(ups[0].args) != 4 || ups[0].args[0] != "sess-2" || ups[0].args[1] != "success" {
		t.Fatalf("F02-12: UPDATE oracle %+v", ups)
	}

	// Second finish: 204 without another UPDATE.
	if rec := f02Call(t, r, http.MethodPost, "/session-keys/sess-2/finish", `{"status":"failed"}`, self); rec.Code != http.StatusNoContent {
		t.Fatalf("F02-12: idempotent: %d", rec.Code)
	}
	if got := len(db.f02Find("exec", "finished_at IS NULL")); got != 1 {
		t.Fatalf("F02-12: second finish issued %d UPDATEs", got)
	}

	// Oversized finish body → 400 at the read gate (unfinished session).
	db3 := f02DB()
	db3.scriptDB.loads["sess-3"] = sessionRow{id: "sess-3", parentID: "parent-1", keyHash: "hash-3", orgID: "org-1"}
	r3 := f02Router(f02SessionGW(db3, &memSessionKV{}, nil))
	self3 := principal{SessionKeyID: "sess-3"}
	if rec := f02Call(t, r3, http.MethodPost, "/session-keys/sess-3/finish", strings.Repeat("x", 17*1024), self3); rec.Code != http.StatusBadRequest {
		t.Fatalf("F02-12: oversized body: %d", rec.Code)
	}

	// UPDATE failure → 500 with the stable code.
	db3.failNext = "finished_at IS NULL"
	if rec := f02Call(t, r3, http.MethodPost, "/session-keys/sess-3/finish", `{"status":"success"}`, self3); rec.Code != http.StatusInternalServerError ||
		!strings.Contains(rec.Body.String(), "session_finish_failed") {
		t.Fatalf("F02-12: exec failure: %d %s", rec.Code, rec.Body.String())
	}
}

// F02-13 session usage: totals + by-model + own-tenant SQL oracle.
func fuzzF0213(t *testing.T) {
	t.Helper()
	db := f02DB()
	db.scriptDB.loads["sess-1"] = sessionRow{id: "sess-1", parentID: "parent-1", keyHash: "hash-1", orgID: "org-1"}
	db.modelRows = [][]any{{"gpt-x", int64(3), int64(30), int64(20), 0.25}}
	gw := f02SessionGW(db, &memSessionKV{}, nil)
	r := f02Router(gw)

	if rec := f02Call(t, r, http.MethodGet, "/session-keys/sess-1/usage", "", principal{APIKeyID: "attacker"}); rec.Code != http.StatusNotFound {
		t.Fatalf("F02-13: foreign: %d", rec.Code)
	}
	if rec := f02Call(t, r, http.MethodGet, "/session-keys/sess-x/usage", "", principal{APIKeyID: "parent-1"}); rec.Code != http.StatusNotFound {
		t.Fatalf("F02-13: unknown: %d", rec.Code)
	}

	rec := f02Call(t, r, http.MethodGet, "/session-keys/sess-1/usage", "", principal{APIKeyID: "parent-1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("F02-13: own: %d %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`"requests":2`, `"model":"gpt-x"`, `"complete":false`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("F02-13: body missing %s: %s", want, rec.Body.String())
		}
	}
	rows := db.f02Find("row", "session_key_id = $2")
	if len(rows) != 1 ||
		!strings.Contains(rows[0].sql, "org_id = $1 AND session_key_id = $2") ||
		strings.Contains(rows[0].sql, "api_key_id") ||
		len(rows[0].args) != 2 || rows[0].args[0] != "org-1" || rows[0].args[1] != "sess-1" {
		t.Fatalf("F02-13: own-tenant SQL oracle %+v", rows)
	}

	// Required totals read failure → 503 usage_unavailable; no totals leak.
	db2 := f02DB()
	db2.scriptDB.loads["sess-1"] = sessionRow{id: "sess-1", parentID: "parent-1", keyHash: "hash-1", orgID: "org-1"}
	db2.failNext = "count(*)"
	gw2 := f02SessionGW(db2, &memSessionKV{}, nil)
	rec2 := f02Call(t, f02Router(gw2), http.MethodGet, "/session-keys/sess-1/usage", "", principal{APIKeyID: "parent-1"})
	if rec2.Code != http.StatusServiceUnavailable || !strings.Contains(rec2.Body.String(), "usage_unavailable") ||
		strings.Contains(rec2.Body.String(), `"requests"`) {
		t.Fatalf("F02-13: failed totals: %d %s", rec2.Code, rec2.Body.String())
	}

	// Session lookup store failure is 503 usage_unavailable, not 404.
	db5 := f02DB()
	db5.failNext = "FROM session_keys"
	gw5 := f02SessionGW(db5, &memSessionKV{}, nil)
	rec5 := f02Call(t, f02Router(gw5), http.MethodGet, "/session-keys/sess-1/usage", "", principal{APIKeyID: "parent-1"})
	if rec5.Code != http.StatusServiceUnavailable || !strings.Contains(rec5.Body.String(), "usage_unavailable") {
		t.Fatalf("F02-13: lookup outage: %d %s", rec5.Code, rec5.Body.String())
	}

	// Broken by-model row delivery aborts the report → 503; neither totals
	// nor the healthy later row may leak.
	db3 := f02DB()
	db3.scriptDB.loads["sess-1"] = sessionRow{id: "sess-1", parentID: "parent-1", keyHash: "hash-1", orgID: "org-1"}
	db3.failModelScan = 0
	db3.modelRows = [][]any{{"broken", int64(9), int64(9), int64(9), 9.0}, {"gpt-x", int64(3), int64(30), int64(20), 0.25}}
	rec3 := f02Call(t, f02Router(f02SessionGW(db3, &memSessionKV{}, nil)), http.MethodGet, "/session-keys/sess-1/usage", "", principal{APIKeyID: "parent-1"})
	if rec3.Code != http.StatusServiceUnavailable || !strings.Contains(rec3.Body.String(), "usage_unavailable") ||
		strings.Contains(rec3.Body.String(), `"requests"`) || strings.Contains(rec3.Body.String(), "gpt-x") {
		t.Fatalf("F02-13: malformed model rows: %d %s", rec3.Code, rec3.Body.String())
	}

	// Zero model rows → empty by_model array, not null.
	db4 := f02DB()
	db4.scriptDB.loads["sess-1"] = sessionRow{id: "sess-1", parentID: "parent-1", keyHash: "hash-1", orgID: "org-1"}
	db4.modelRows = [][]any{}
	rec4 := f02Call(t, f02Router(f02SessionGW(db4, &memSessionKV{}, nil)), http.MethodGet, "/session-keys/sess-1/usage", "", principal{APIKeyID: "parent-1"})
	if rec4.Code != http.StatusOK || !strings.Contains(rec4.Body.String(), `"by_model":[]`) {
		t.Fatalf("F02-13: empty model rows: %d %s", rec4.Code, rec4.Body.String())
	}
}

// F02-14 own-key usage: permission, SQL oracles, validation, grouping.
func fuzzF0214(t *testing.T) {
	t.Helper()
	gw := f02SessionGW(f02DB(), &memSessionKV{}, nil)

	serve := func(p principal, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage"+query, nil)
		req = req.WithContext(withPrincipal(req.Context(), p))
		req.Header.Set("X-Org-Id", "org-1")
		rec := httptest.NewRecorder()
		gw.ownUsage(rec, req)
		return rec
	}

	// Without the grant → 403.
	if rec := serve(principal{APIKeyID: "parent-1"}, ""); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "usage_read_not_allowed") {
		t.Fatalf("F02-14: no grant: %d %s", rec.Code, rec.Body.String())
	}

	ok := principal{APIKeyID: "parent-1", CanReadUsage: true}
	bad := []struct {
		name, query, want string
	}{
		{"bad from", "?from=not-rfc3339", "from must be RFC3339"},
		{"bad to", "?to=yesterday", "to must be RFC3339"},
		{"span too wide", "?from=" + time.Now().Add(-32*24*time.Hour).UTC().Format(time.RFC3339), "range must be at most 31 days"},
		{"invalid encoding", "?label.bad%key=x", "invalid usage query encoding"},
		{"invalid label key", "?label.bad%25key=x", "label filter key is not valid"},
		{"invalid group", "?group_by=bogus", "group_by must be model or label:<key>"},
	}
	for _, tc := range bad {
		rec := serve(ok, tc.query)
		var body struct{ Error struct{ Message string } }
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusBadRequest || body.Error.Message != tc.want {
			t.Fatalf("F02-14 %s: %d %s", tc.name, rec.Code, rec.Body.String())
		}
	}

	// Happy path + label filter SQL oracle.
	db := f02DB()
	gw2 := f02SessionGW(db, &memSessionKV{}, nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage?label.team=x", nil)
	req = req.WithContext(withPrincipal(req.Context(), ok))
	req.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()
	gw2.ownUsage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("F02-14: happy: %d %s", rec.Code, rec.Body.String())
	}
	rows := db.f02Find("row", "api_key_id = $2")
	if len(rows) < 1 {
		t.Fatalf("F02-14: no api-key-scoped row query recorded")
	}
	q := rows[0]
	if !strings.Contains(q.sql, "org_id = $1 AND api_key_id = $2") ||
		!strings.Contains(q.sql, "created_at >= $3 AND created_at < $4") ||
		!strings.Contains(q.sql, "labels @> $5::jsonb") {
		t.Fatalf("F02-14: SQL oracle %s", q.sql)
	}
	if len(q.args) != 5 || q.args[0] != "org-1" || q.args[1] != "parent-1" {
		t.Fatalf("F02-14: args %+v", q.args)
	}
	if raw, ok := q.args[4].([]byte); !ok || string(raw) != `{"team":"x"}` {
		t.Fatalf("F02-14: filter arg %v", q.args[4])
	}

	// group_by=model: model_used expression recorded (empty canned groups).
	dbM := f02DB()
	dbM.groupRows = [][]any{}
	gwM := f02SessionGW(dbM, &memSessionKV{}, nil)
	reqM := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage?group_by=model", nil)
	reqM = reqM.WithContext(withPrincipal(reqM.Context(), ok))
	reqM.Header.Set("X-Org-Id", "org-1")
	recM := httptest.NewRecorder()
	gwM.ownUsage(recM, reqM)
	if recM.Code != http.StatusOK {
		t.Fatalf("F02-14: group model: %d %s", recM.Code, recM.Body.String())
	}
	if gs := dbM.f02Find("rows", "GROUP BY 1"); len(gs) != 1 || !strings.Contains(gs[0].sql, "model_used") {
		t.Fatalf("F02-14: group model SQL %+v", dbM.f02Find("rows", "GROUP BY 1"))
	}

	// group_by=label:team: quoteLiteral renders labels->>'team'; canned
	// group rows reach the body.
	dbL := f02DB()
	dbL.groupRows = [][]any{{"payments", int64(3), int64(30), int64(20), 0.25}}
	gwL := f02SessionGW(dbL, &memSessionKV{}, nil)
	reqL := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage?group_by=label:team", nil)
	reqL = reqL.WithContext(withPrincipal(reqL.Context(), ok))
	reqL.Header.Set("X-Org-Id", "org-1")
	recL := httptest.NewRecorder()
	gwL.ownUsage(recL, reqL)
	if recL.Code != http.StatusOK {
		t.Fatalf("F02-14: group label: %d %s", recL.Code, recL.Body.String())
	}
	if gs := dbL.f02Find("rows", "labels->>'team'"); len(gs) != 1 || !strings.Contains(gs[0].sql, "GROUP BY 1") {
		t.Fatalf("F02-14: quoteLiteral SQL oracle %+v", dbL.f02Find("rows", "labels->>'team'"))
	}
	if !strings.Contains(recL.Body.String(), "payments") {
		t.Fatalf("F02-14: groups missing from body: %s", recL.Body.String())
	}

	// Explicit from/to window flows into the SQL args; unknown params
	// (limit, bogus) are ignored.
	dbW := f02DB()
	dbW.scriptDB.usage = []any{int64(5), int64(50), int64(20), int64(2), 1.5, int64(0)}
	gwW := f02SessionGW(dbW, &memSessionKV{}, nil)
	fromW := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	toW := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	reqW := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/v1/yabanin/usage?from="+fromW.Format(time.RFC3339)+"&to="+toW.Format(time.RFC3339)+"&limit=25&bogus=1", nil)
	reqW = reqW.WithContext(withPrincipal(reqW.Context(), ok))
	reqW.Header.Set("X-Org-Id", "org-1")
	recW := httptest.NewRecorder()
	gwW.ownUsage(recW, reqW)
	if recW.Code != http.StatusOK {
		t.Fatalf("F02-14: window: %d %s", recW.Code, recW.Body.String())
	}
	rowsW := dbW.f02Find("row", "api_key_id = $2")
	if len(rowsW) != 1 {
		t.Fatalf("F02-14: window row queries %d", len(rowsW))
	}
	if gt, gok := rowsW[0].args[2].(time.Time); !gok || !gt.Equal(fromW) {
		t.Fatalf("F02-14: from arg %+v", rowsW[0].args[2])
	}
	if gt, gok := rowsW[0].args[3].(time.Time); !gok || !gt.Equal(toW) {
		t.Fatalf("F02-14: to arg %+v", rowsW[0].args[3])
	}

	// Required totals read failure → 503 usage_unavailable; no totals leak.
	dbF := f02DB()
	dbF.failNext = "count(*)"
	gwF := f02SessionGW(dbF, &memSessionKV{}, nil)
	reqF := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage", nil)
	reqF = reqF.WithContext(withPrincipal(reqF.Context(), ok))
	reqF.Header.Set("X-Org-Id", "org-1")
	recF := httptest.NewRecorder()
	gwF.ownUsage(recF, reqF)
	if recF.Code != http.StatusServiceUnavailable || !strings.Contains(recF.Body.String(), "usage_unavailable") ||
		strings.Contains(recF.Body.String(), `"requests"`) {
		t.Fatalf("F02-14: totals failure: %d %s", recF.Code, recF.Body.String())
	}

	// Group read failure → 503 usage_unavailable; neither the old stable
	// 400 message nor partial totals may appear. The failure is injected on
	// the "GROUP BY 1" groups statement (scriptDB itself answers empty rows).
	dbG := f02DB()
	dbG.failNext = "GROUP BY 1"
	gwG := f02SessionGW(dbG, &memSessionKV{}, nil)
	reqG := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage?group_by=model", nil)
	reqG = reqG.WithContext(withPrincipal(reqG.Context(), ok))
	reqG.Header.Set("X-Org-Id", "org-1")
	recG := httptest.NewRecorder()
	gwG.ownUsage(recG, reqG)
	if recG.Code != http.StatusServiceUnavailable || !strings.Contains(recG.Body.String(), "usage_unavailable") ||
		strings.Contains(recG.Body.String(), "cost_usd") {
		t.Fatalf("F02-14: group failure: %d %s", recG.Code, recG.Body.String())
	}

	// A NULL group value is a legitimate group: it renders "" at 200.
	dbN := f02DB()
	dbN.groupRows = [][]any{{nil, int64(2), int64(2), int64(2), 0.2}}
	gwN := f02SessionGW(dbN, &memSessionKV{}, nil)
	reqN := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage?group_by=label:team", nil)
	reqN = reqN.WithContext(withPrincipal(reqN.Context(), ok))
	reqN.Header.Set("X-Org-Id", "org-1")
	recN := httptest.NewRecorder()
	gwN.ownUsage(recN, reqN)
	if recN.Code != http.StatusOK {
		t.Fatalf("F02-14: nil group value: %d %s", recN.Code, recN.Body.String())
	}
	if n := strings.Count(recN.Body.String(), `"value"`); n != 1 {
		t.Fatalf("F02-14: want exactly one group, values = %d body %s", n, recN.Body.String())
	}
	if !strings.Contains(recN.Body.String(), `"value":""`) {
		t.Fatalf("F02-14: NULL group value must render empty: %s", recN.Body.String())
	}

	// Broken group row delivery aborts the report → 503; no groups or
	// totals may leak.
	dbS := f02DB()
	dbS.groupRows = [][]any{{"team-a", int64(1), int64(1), int64(1), 0.1}, {nil, int64(2), int64(2), int64(2), 0.2}}
	dbS.failGroupScan = 0
	gwS := f02SessionGW(dbS, &memSessionKV{}, nil)
	reqS := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage?group_by=label:team", nil)
	reqS = reqS.WithContext(withPrincipal(reqS.Context(), ok))
	reqS.Header.Set("X-Org-Id", "org-1")
	recS := httptest.NewRecorder()
	gwS.ownUsage(recS, reqS)
	if recS.Code != http.StatusServiceUnavailable || !strings.Contains(recS.Body.String(), "usage_unavailable") ||
		strings.Contains(recS.Body.String(), `"value"`) || strings.Contains(recS.Body.String(), `"requests"`) {
		t.Fatalf("F02-14: broken group rows: %d %s", recS.Code, recS.Body.String())
	}

	// Zero group rows → the groups field is omitted (omitempty), not null.
	dbE := f02DB()
	dbE.groupRows = [][]any{}
	gwE := f02SessionGW(dbE, &memSessionKV{}, nil)
	reqE := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage?group_by=label:team", nil)
	reqE = reqE.WithContext(withPrincipal(reqE.Context(), ok))
	reqE.Header.Set("X-Org-Id", "org-1")
	recE := httptest.NewRecorder()
	gwE.ownUsage(recE, reqE)
	if recE.Code != http.StatusOK || strings.Contains(recE.Body.String(), "groups") {
		t.Fatalf("F02-14: empty groups must omit the field: %d %s", recE.Code, recE.Body.String())
	}
}

// F02-15 no DB → 501 on every endpoint; label policy default + auth gate.
func fuzzF0215(t *testing.T) {
	t.Helper()
	gw := &gateway{gatewayCore: gatewayCore{log: fuzzDiscardLogger()}}

	unavailable := func(rec *httptest.ResponseRecorder, want string) {
		t.Helper()
		if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), "session_keys_unavailable") {
			t.Fatalf("F02-15 %s: %d %s", want, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	gw.mintSessionKey(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/yabanin/session-keys", nil))
	unavailable(rec, "mint")
	rec = httptest.NewRecorder()
	gw.revokeSessionKey(rec, httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/session-keys/sess-1", nil))
	unavailable(rec, "revoke")
	rec = httptest.NewRecorder()
	gw.finishSessionKey(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/session-keys/sess-1/finish", nil))
	unavailable(rec, "finish")
	rec = httptest.NewRecorder()
	gw.sessionKeyUsage(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/session-keys/sess-1/usage", nil))
	unavailable(rec, "usage")
	rec = httptest.NewRecorder()
	gw.ownUsage(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage", nil))
	unavailable(rec, "own usage")
	rec = httptest.NewRecorder()
	gw.sessionLabelPolicy(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/label-policy", nil))
	unavailable(rec, "label policy")

	// With a DB: org gate first (401), then the default policy (200).
	db := f02DB()
	gw2 := f02SessionGW(db, &memSessionKV{}, nil)
	rec = httptest.NewRecorder()
	gw2.sessionLabelPolicy(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/label-policy", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("F02-15: no org: %d", rec.Code)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/label-policy", nil)
	req.Header.Set("X-Org-Id", "org-1")
	rec = httptest.NewRecorder()
	gw2.sessionLabelPolicy(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("F02-15: default policy: %d %s", rec.Code, rec.Body.String())
	}
	if got := len(db.f02Find("row", "label_policies")); got != 1 {
		t.Fatalf("F02-15: label_policies queries %d", got)
	}

	// Stored policy shapes: malformed JSON and an empty column both fall
	// back to the default policy; a valid custom policy renders.
	policyReq := func() (*httptest.ResponseRecorder, *http.Request) {
		reqP := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/label-policy", nil)
		reqP.Header.Set("X-Org-Id", "org-1")
		return httptest.NewRecorder(), reqP
	}
	dbBad := f02DB()
	dbBad.policyRaw = []byte("{not-json")
	recBad, reqBad := policyReq()
	f02SessionGW(dbBad, &memSessionKV{}, nil).sessionLabelPolicy(recBad, reqBad)
	if recBad.Code != http.StatusOK || strings.Contains(recBad.Body.String(), "not-json") {
		t.Fatalf("F02-15: malformed policy must fall back to default: %d %s", recBad.Code, recBad.Body.String())
	}
	dbBad.policyRaw = []byte{}
	recBad, reqBad = policyReq()
	f02SessionGW(dbBad, &memSessionKV{}, nil).sessionLabelPolicy(recBad, reqBad)
	if recBad.Code != http.StatusOK {
		t.Fatalf("F02-15: empty policy column: %d %s", recBad.Code, recBad.Body.String())
	}

	dbPol := f02DB()
	dbPol.policyRaw = []byte(`{"allowed_keys":["f02team","env"],"denied_keys":[],"required_keys":[],"on_invalid":"drop","on_missing":"allow","aliases":{},"derive":[],"rollup_keys":["f02team"],"max_labels":8,"value_max_len":64}`)
	recPol, reqPol := policyReq()
	f02SessionGW(dbPol, &memSessionKV{}, nil).sessionLabelPolicy(recPol, reqPol)
	if recPol.Code != http.StatusOK || !strings.Contains(recPol.Body.String(), "f02team") {
		t.Fatalf("F02-15: stored policy must render: %d %s", recPol.Code, recPol.Body.String())
	}
}

// F02-16 mint → revoke → use lifecycle on the freshly minted row.
func fuzzF0216(t *testing.T) {
	t.Helper()
	db := f02DB()
	db.modelRows = [][]any{{"gpt-x", int64(1), int64(1), int64(1), 0.0}}
	kv := &memSessionKV{}
	var logs bytes.Buffer
	gw := f02SessionGW(db, kv, &logs)

	rec := httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, principal{APIKeyID: "parent-1", CanMintSessions: true}, `{}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("F02-16: mint: %d %s", rec.Code, rec.Body.String())
	}
	ins := db.f02Find("row", "INSERT INTO session_keys")
	if len(ins) != 1 {
		t.Fatalf("F02-16: INSERT oracle %d", len(ins))
	}
	hash, _ := ins[0].args[0].(string)
	if hash == "" {
		t.Fatalf("F02-16: INSERT hash arg %+v", ins[0].args[0])
	}
	if strings.Contains(logs.String(), "ybs_") {
		t.Fatal("F02-16: secret leaked into logs")
	}

	r := f02Router(gw)
	if rec := f02Call(t, r, http.MethodDelete, "/session-keys/sess-new", "", principal{APIKeyID: "parent-1"}); rec.Code != http.StatusNoContent {
		t.Fatalf("F02-16: revoke minted: %d %s", rec.Code, rec.Body.String())
	}
	kv.mu.Lock()
	dels := append([]string(nil), kv.dels...)
	kv.mu.Unlock()
	if len(dels) != 1 || dels[0] != "org:resolve:"+hash {
		t.Fatalf("F02-16: purge dels %v (hash %q)", dels, hash)
	}

	rec2 := f02Call(t, r, http.MethodGet, "/session-keys/sess-new/usage", "", principal{APIKeyID: "parent-1"})
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), `"requests":2`) {
		t.Fatalf("F02-16: usage minted: %d %s", rec2.Code, rec2.Body.String())
	}
	rows := db.f02Find("row", "session_key_id = $2")
	if len(rows) != 1 || rows[0].args[0] != "org-1" || rows[0].args[1] != "sess-new" {
		t.Fatalf("F02-16: own-tenant usage rows %+v", rows)
	}

	if rec := f02Call(t, r, http.MethodDelete, "/session-keys/sess-new", "", principal{APIKeyID: "attacker"}); rec.Code != http.StatusNotFound {
		t.Fatalf("F02-16: foreign: %d", rec.Code)
	}
}

// F02-17 legacy auth middleware: modes, header hygiene, resolver, expired
// key, last-used tracker, authMiddlewareFunc.
func fuzzF0217(t *testing.T) {
	t.Helper()
	strict := NewAuthMiddleware(newGatewayConfig("strict", "sk-static", ""), nil)

	// Client-spoofed identity headers are stripped; the static key passes.
	var org, agent, session string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		org = r.Header.Get("X-Org-Id")
		agent = r.Header.Get("X-Agent-Id")
		session = r.Header.Get("X-Session-Key-Id")
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-static")
	req.Header.Set("X-Org-Id", "org-hacker")
	req.Header.Set("X-Agent-Id", "yag_spoof")
	req.Header.Set("X-Session-Key-Id", "ybs_spoof")
	rec := httptest.NewRecorder()
	strict.ServeHTTP(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || org != "" || agent != "" || session != "" {
		t.Fatalf("F02-17: strict spoof: %d org=%q agent=%q session=%q", rec.Code, org, agent, session)
	}

	// x-api-key promotion.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("x-api-key", "sk-static")
	rec = httptest.NewRecorder()
	strict.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "" {
			t.Fatal("x-api-key must be removed before forwarding")
		}
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("F02-17: x-api-key promotion: %d", rec.Code)
	}

	// Bad key in strict mode → 401.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-wrong")
	rec = httptest.NewRecorder()
	strict.ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next reached") })).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid API key") {
		t.Fatalf("F02-17: strict reject: %d %s", rec.Code, rec.Body.String())
	}

	// Resolver path: org + key id headers, principal, last-used UPDATE.
	store := &f02LastUsedStore{}
	tracker := auth.NewLastUsedTracker(context.Background(), store, 1, 1, time.Minute)
	res := NewAuthMiddleware(newGatewayConfig("header", "", ""), newTestResolver("org-res", nil))
	res.SetLastUsedTracker(tracker)
	var p principal
	var havePrincipal bool
	nextRes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, havePrincipal = principalFrom(r.Context())
		if r.Header.Get("X-Org-Id") != "org-res" || r.Header.Get("X-API-Key-Id") != "org-res" {
			t.Fatalf("F02-17: resolver headers org=%q key=%q", r.Header.Get("X-Org-Id"), r.Header.Get("X-API-Key-Id"))
		}
	})
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer ypk_whatever")
	rec = httptest.NewRecorder()
	res.ServeHTTP(nextRes).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !havePrincipal || p.APIKeyID != "org-res" {
		t.Fatalf("F02-17: resolver principal: %d ok=%v %+v", rec.Code, havePrincipal, p)
	}
	tracker.Close()
	store.mu.Lock()
	sql, batches := store.sql, store.batch
	store.mu.Unlock()
	if sql != "UPDATE api_keys SET last_used_at = now() WHERE id = ANY($1)" || len(batches) != 1 {
		t.Fatalf("F02-17: last-used tracker sql %q batches %d", sql, len(batches))
	}

	// Expired key → 401 with stable code key_expired.
	expiredPool := &mockDBForGateway{queryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
		if !strings.Contains(query, "FROM api_keys") {
			return scanRow{err: pgx.ErrNoRows}
		}
		return scanRow{vals: []any{"expired-id", "org-1", "", "", time.Now().Add(-time.Hour)}}
	}}
	exp := NewAuthMiddleware(newGatewayConfig("header", "", ""), auth.NewResolver(expiredPool, nil, 300, nil))
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer ypk_expired")
	rec = httptest.NewRecorder()
	exp.ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next reached") })).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), apierrors.CodeKeyExpired) ||
		!strings.Contains(rec.Body.String(), "API key has expired") {
		t.Fatalf("F02-17: expired key: %d %s", rec.Code, rec.Body.String())
	}

	// authMiddlewareFunc delegates to gw.auth.
	gw := &gateway{gatewayCore: gatewayCore{log: fuzzDiscardLogger(), auth: strict}}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-static")
	rec = httptest.NewRecorder()
	gw.authMiddlewareFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("F02-17: authMiddlewareFunc: %d", rec.Code)
	}

	// Unknown auth mode behaves as strict (fail-closed): the static key
	// still works, any other token is rejected.
	bogus := NewAuthMiddleware(newGatewayConfig("bogus-mode", "sk-bogus", ""), nil)
	reqB := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	reqB.Header.Set("Authorization", "Bearer sk-bogus")
	recB := httptest.NewRecorder()
	bogus.ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Fatalf("F02-17: bogus mode static key: %d", recB.Code)
	}
	reqB2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	reqB2.Header.Set("Authorization", "Bearer sk-other")
	recB2 := httptest.NewRecorder()
	bogus.ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next reached") })).ServeHTTP(recB2, reqB2)
	if recB2.Code != http.StatusUnauthorized || !strings.Contains(recB2.Body.String(), "invalid API key") {
		t.Fatalf("F02-17: bogus mode reject: %d %s", recB2.Code, recB2.Body.String())
	}

	// Resolver failure under an unknown mode → "org resolution failed".
	bogusRes := NewAuthMiddleware(newGatewayConfig("bogus-mode", "", ""), newTestResolver("", errors.New("f02 resolver down")))
	reqBR := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	reqBR.Header.Set("Authorization", "Bearer ypk_whatever")
	recBR := httptest.NewRecorder()
	bogusRes.ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next reached") })).ServeHTTP(recBR, reqBR)
	if recBR.Code != http.StatusUnauthorized || !strings.Contains(recBR.Body.String(), "org resolution failed") {
		t.Fatalf("F02-17: bogus mode resolver failure: %d %s", recBR.Code, recBR.Body.String())
	}

	// Session-key resolution: the session label source is appended (with
	// the empty-set default for a NULL session labels column).
	pool := &mockDBForGateway{queryRowFn: func(_ context.Context, query string, _ ...interface{}) pgx.Row {
		if !strings.Contains(query, "FROM session_keys s") {
			return scanRow{err: pgx.ErrNoRows}
		}
		return f02SessionResolveRow{}
	}}
	sres := auth.NewResolver(pool, &mockRedisForGateway{getFn: func(ctx context.Context, _ string) *redis.StringCmd {
		cmd := redis.NewStringCmd(ctx)
		cmd.SetErr(redis.Nil)
		return cmd
	}}, 300, nil)
	sm := NewAuthMiddleware(newGatewayConfig("header", "", ""), sres)
	var sources []labels.Source
	var sessHdr, keyHdr string
	nextS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sources = principalLabelSources(r.Context())
		sessHdr = r.Header.Get("X-Session-Key-Id")
		keyHdr = r.Header.Get("X-API-Key-Id")
	})
	reqS := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	sessionKey, err := auth.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	reqS.Header.Set("Authorization", "Bearer "+sessionKey)
	recS := httptest.NewRecorder()
	sm.ServeHTTP(nextS).ServeHTTP(recS, reqS)
	if recS.Code != http.StatusOK || sessHdr != "sess-9" || keyHdr != "parent-9" {
		t.Fatalf("F02-17: session resolve: %d sess=%q key=%q", recS.Code, sessHdr, keyHdr)
	}
	if len(sources) != 2 || sources[0].Name != "key" || sources[1].Name != "session" || sources[1].Labels == nil || len(sources[1].Labels) != 0 {
		t.Fatalf("F02-17: session label sources %+v", sources)
	}
}

// F02-18 deliberately broken variants: the oracles must catch each one
// (control against vacuous expectations).
func fuzzF0218(t *testing.T) {
	t.Helper()
	keyA := mustRSAJWK(t, "k1")
	srvA := newJWKSServer(t, keyA)
	authA := newTestJWTAuth(t, srvA, nil)

	// (a) Cross-tenant wiring: the token is valid for org A but presented to
	// a middleware wired with another org's authenticator. The oracle for
	// org A (200) must NOT be satisfied — the request fails with the JWT
	// signature error, proving tenant discrimination.
	tokA := signToken(t, keyA, baseClaims())
	srvB := newJWKSServer(t, mustRSAJWK(t, "k1"))
	authB := newTestJWTAuth(t, srvB, func(w *JWTWiring) { w.Issuer = "https://idp-b.example" })
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+tokA)
	jwtMiddleware(authB).ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("broken variant accepted") })).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("F02-18: cross-tenant wiring not caught: %d", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req2.Header.Set("Authorization", "Bearer "+tokA)
	jwtMiddleware(authA).ServeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("F02-18: correct twin must pass: %d", rec2.Code)
	}

	// (b) Tampered payload: all claims valid, but the signature no longer
	// covers the bytes — must fail closed on signature.
	parts := strings.Split(tokA, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["org_id"] = "org-evil"
	evil, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(evil) + "." + parts[2]
	_, err = authA.Authenticate(context.Background(), tampered)
	ae, ok := err.(*jwtAuthError)
	if !ok || ae.status != http.StatusUnauthorized || ae.reason != "signature" {
		t.Fatalf("F02-18: tampered payload not caught: %+v (%v)", ae, err)
	}

	// (c) Corrupted session principal: a foreign parent id on an owned
	// session — the visibility oracle must 404 (the correct twin 204s).
	db := f02DB()
	db.scriptDB.loads["sess-1"] = sessionRow{id: "sess-1", parentID: "parent-1", keyHash: "hash-1", orgID: "org-1"}
	gw := f02SessionGW(db, &memSessionKV{}, nil)
	r := f02Router(gw)
	if rec := f02Call(t, r, http.MethodDelete, "/session-keys/sess-1", "", principal{APIKeyID: "attacker"}); rec.Code != http.StatusNotFound {
		t.Fatalf("F02-18: corrupted principal not caught: %d", rec.Code)
	}
	if rec := f02Call(t, r, http.MethodDelete, "/session-keys/sess-1", "", principal{APIKeyID: "parent-1"}); rec.Code != http.StatusNoContent {
		t.Fatalf("F02-18: correct twin must revoke: %d", rec.Code)
	}
}
