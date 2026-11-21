package cli

// N1-ROWS-ERR: deterministic mid-result-set interruption for
// queryEnabledModels over the REAL disposable PostgreSQL stand. MC-26
// documented this arm as having "no deterministic seam on a healthy stand";
// rowsErrProxy is that seam: a real loopback TCP proxy that speaks the
// PostgreSQL v3 wire protocol, forwards startup/auth/queries untouched, and
// after forwarding exactly ONE DataRow message on the first connection closes
// both directions — pgx sees the result stream die before CommandComplete
// and before the remaining rows. Later connections forward cleanly, so a
// variant that suppresses rows.Err() cannot hide behind a dead pool: its
// alias query opens another proxy connection and is directly observable.
//
// Instrumentation contract (owner dispatch on the r3 review): every
// connection is classified INDEPENDENTLY in both directions — query-class
// client->server messages ('Q' simple Query / 'P' Parse) with SQL-table
// booleans (models_registry / model_aliases), and server->client DataRow /
// CommandComplete counts — so the report can explicitly show whether any
// later connection repeats the enabled-models query, sends the alias query,
// or is an otherwise idle reconnect. Raw bytes, SQL text and
// startup/authentication material are NEVER printed or persisted beyond the
// live test process: analysis reduces each direction to counts and booleans.
//
// FROZEN INVARIANT under interruption: non-nil error (type logged), NO
// partial-success list (length logged), NO alias query after the interrupted
// first result. Extra physical connections are diagnostic evidence, never an
// asserted production contract by themselves. Coverage closure for the
// EXISTING rows.Err() check: current production is expected to pass; the
// isolated broken variant must fail behaviorally.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// pgConnReport is the reduced, printable form of one proxy connection's
// traffic: counts and SQL-table booleans only.
type pgConnReport struct {
	Index       int
	QueryClass  int // 'Q' simple-Query + 'P' Parse messages (client->server)
	ModelSQL    bool
	AliasSQL    bool
	DataRows    int // 'D' server->client
	CmdComplete int // 'C' server->client
	C2SBytes    int
	S2CBytes    int
}

type connCapture struct {
	client []byte
	server []byte
}

type rowsErrProxy struct {
	ln         net.Listener
	backend    string
	truncAfter int
	ctx        context.Context

	mu               sync.Mutex
	conns            int
	dataRowsConn1    int
	cmdCompleteConn1 bool
	truncated        bool
	captures         []*connCapture
	openConns        []net.Conn
	wg               sync.WaitGroup
}

func startRowsErrProxy(t *testing.T, backend string, truncAfter int) *rowsErrProxy {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("rows-err proxy listen: %v", err)
	}
	p := &rowsErrProxy{ln: ln, backend: backend, truncAfter: truncAfter, ctx: t.Context()}
	t.Cleanup(func() {
		_ = ln.Close()
		p.mu.Lock()
		for _, c := range p.openConns {
			_ = c.Close()
		}
		p.mu.Unlock()
		done := make(chan struct{})
		go func() { p.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Log("rows-err proxy: handlers did not drain within 5s")
		}
	})
	p.wg.Add(1)
	go p.acceptLoop()
	return p
}

func (p *rowsErrProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.conns++
		n := p.conns
		cap := &connCapture{}
		p.captures = append(p.captures, cap)
		p.openConns = append(p.openConns, c)
		p.mu.Unlock()
		p.wg.Add(1)
		go p.serve(c, n, cap)
	}
}

func (p *rowsErrProxy) track(c net.Conn) {
	p.mu.Lock()
	p.openConns = append(p.openConns, c)
	p.mu.Unlock()
}

func (p *rowsErrProxy) appendCapture(cap *connCapture, dir func(*connCapture) *[]byte, chunk []byte) {
	p.mu.Lock()
	*dir(cap) = append(*dir(cap), chunk...)
	p.mu.Unlock()
}

func clientBufOf(c *connCapture) *[]byte { return &c.client }
func serverBufOf(c *connCapture) *[]byte { return &c.server }

// forwardClientToServer is the client->server half of one proxied
// connection: plain forward with per-connection capture for offline
// query-class classification (bytes never leave the test).
func (p *rowsErrProxy) forwardClientToServer(client, server net.Conn, cap *connCapture) {
	defer p.wg.Done()
	buf := make([]byte, 32*1024)
	for {
		r, rerr := client.Read(buf)
		if r > 0 {
			p.appendCapture(cap, clientBufOf, buf[:r])
			if _, werr := server.Write(buf[:r]); werr != nil {
				_ = client.Close()
				_ = server.Close()
				return
			}
		}
		if rerr != nil {
			_ = client.Close()
			_ = server.Close()
			return
		}
	}
}

// forwardServerToClient is the server->client half on later (or healthy)
// connections: capture + forward until either side fails.
func (p *rowsErrProxy) forwardServerToClient(client, server net.Conn, cap *connCapture) {
	buf := make([]byte, 32*1024)
	for {
		r, rerr := server.Read(buf)
		if r > 0 {
			p.appendCapture(cap, serverBufOf, buf[:r])
			if _, werr := client.Write(buf[:r]); werr != nil {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
}

func (p *rowsErrProxy) serve(client net.Conn, n int, cap *connCapture) {
	defer p.wg.Done()
	var dialer net.Dialer
	server, err := dialer.DialContext(p.ctx, "tcp", p.backend)
	if err != nil {
		_ = client.Close()
		return
	}
	defer func() { _ = server.Close() }()
	p.track(server)

	p.wg.Add(1)
	go p.forwardClientToServer(client, server, cap)

	if n == 1 && p.truncAfter > 0 {
		p.serveTruncated(client, server, cap)
		return
	}
	p.forwardServerToClient(client, server, cap)
	_ = client.Close()
	_ = server.Close()
}

// serveTruncated forwards complete PostgreSQL messages one at a time. After
// truncAfter DataRow ('D') messages have been forwarded on this first
// connection, both sockets are closed: the client has seen startup, auth,
// RowDescription and exactly truncAfter DataRows — never CommandComplete,
// never the remaining rows. Inline DataRow counting (unchanged, proven
// deterministic) drives the truncation; the capture feeds per-connection
// evidence.
func (p *rowsErrProxy) serveTruncated(client, server net.Conn, cap *connCapture) {
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(server, header); err != nil {
			return
		}
		// PostgreSQL v3 framing: 1 type byte + 4 length bytes (the length
		// counts itself, not the type byte) + (length-4) payload.
		msgLen := binary.BigEndian.Uint32(header[1:]) - 4
		body := make([]byte, msgLen)
		if _, err := io.ReadFull(server, body); err != nil {
			return
		}
		p.appendCapture(cap, serverBufOf, header)
		p.appendCapture(cap, serverBufOf, body)
		if _, err := client.Write(append(header, body...)); err != nil {
			return
		}
		if header[0] == 'D' {
			p.mu.Lock()
			p.dataRowsConn1++
			dr := p.dataRowsConn1
			p.mu.Unlock()
			if dr >= p.truncAfter {
				p.mu.Lock()
				p.truncated = true
				p.mu.Unlock()
				return // close both: mid-result-set interruption
			}
		}
		if header[0] == 'C' {
			p.mu.Lock()
			p.cmdCompleteConn1 = true
			p.mu.Unlock()
		}
	}
}

// report reduces every connection's captured traffic to counts and
// SQL-table booleans. Raw bytes, statement text and startup/auth material
// are never exposed: pgClientAnalyze inspects bytes only for classification.
func (p *rowsErrProxy) report() []pgConnReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]pgConnReport, 0, len(p.captures))
	for i, cap := range p.captures {
		qc, modelSQL, aliasSQL := pgClientAnalyze(cap.client)
		dr, cc := pgServerAnalyze(cap.server)
		out = append(out, pgConnReport{
			Index: i + 1, QueryClass: qc, ModelSQL: modelSQL, AliasSQL: aliasSQL,
			DataRows: dr, CmdComplete: cc,
			C2SBytes: len(cap.client), S2CBytes: len(cap.server),
		})
	}
	return out
}

func (p *rowsErrProxy) snapshot() (conns, dataRows int, cmdComplete, truncated bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conns, p.dataRowsConn1, p.cmdCompleteConn1, p.truncated
}

// pgClientState accumulates one connection's reduced client->server
// traffic: a query-class count plus the two SQL-table booleans. Nothing is
// kept that could leak startup or authentication material.
type pgClientState struct {
	queryClass int
	modelSQL   bool
	aliasSQL   bool
}

// classifyQueryMsg folds one query-class client message ('Q' simple Query /
// 'P' Parse) into the connection's reduced traffic state.
func (s *pgClientState) classifyQueryMsg(typ byte, payload []byte) {
	s.queryClass++
	sql := pgQueryText(typ, payload)
	s.modelSQL = s.modelSQL || strings.Contains(sql, "models_registry")
	s.aliasSQL = s.aliasSQL || strings.Contains(sql, "model_aliases")
}

// pgFrame decodes the standard PostgreSQL v3 message framing at pos — 1
// type byte + 4 length bytes (counting themselves) + payload — returning
// the type and the framed length. ok is false when the buffer holds no
// complete well-formed message at pos.
func pgFrame(b []byte, pos int) (typ byte, frameLen int, ok bool) {
	if len(b)-pos < 5 {
		return 0, 0, false
	}
	typ = b[pos]
	n := int(binary.BigEndian.Uint32(b[pos+1 : pos+5]))
	if n < 4 || pos+1+n > len(b) {
		return 0, 0, false
	}
	return typ, n, true
}

// pgSkipStartup steps over the connection's first packet — the startup
// message ([int32 len][payload], no type byte) — returning the position of
// the first standard-framed message, or -1 when malformed.
func pgSkipStartup(b []byte) int {
	if len(b) < 4 {
		return -1
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if n < 4 || n > len(b) {
		return -1
	}
	return n
}

// pgClientAnalyze classifies one connection's client->server byte stream.
// The first message is the startup packet ([int32 len][payload], no type
// byte); everything after uses standard framing. Only 'Q' (simple Query)
// and 'P' (Parse) carry SQL text — counted as query-class, reduced to the
// two table booleans. Nothing is returned that could leak startup or
// authentication material.
func pgClientAnalyze(b []byte) (queryClass int, modelSQL, aliasSQL bool) {
	pos := pgSkipStartup(b)
	if pos < 0 {
		return
	}
	var st pgClientState
	for pos < len(b) {
		typ, n, ok := pgFrame(b, pos)
		if !ok {
			return st.queryClass, st.modelSQL, st.aliasSQL
		}
		if typ == 'Q' || typ == 'P' {
			st.classifyQueryMsg(typ, b[pos+5:pos+1+n])
		}
		pos += 1 + n
	}
	return st.queryClass, st.modelSQL, st.aliasSQL
}

// pgQueryText extracts the SQL text from a simple-Query ('Q') or Parse
// ('P') payload: 'Q' = [query cstring]; 'P' = [stmt name cstring][query
// cstring] (pgx names cached statements "stmtcache_<hex>"). Returns "" when
// no NUL-terminated string is present — never any other payload bytes.
func pgQueryText(typ byte, payload []byte) string {
	off := 0
	if typ == 'P' {
		nameLen := cstringLen(payload, 0)
		if nameLen <= 0 {
			return ""
		}
		off = nameLen
	}
	sql, ok := cstringAt(payload, off)
	if !ok {
		return ""
	}
	return sql
}

// pgServerAnalyze counts DataRow ('D') and CommandComplete ('C') messages in
// one connection's server->client byte stream (standard framing throughout).
func pgServerAnalyze(b []byte) (dataRows, cmdComplete int) {
	pos := 0
	for pos < len(b) {
		if len(b)-pos < 5 {
			return
		}
		typ := b[pos]
		n := int(binary.BigEndian.Uint32(b[pos+1 : pos+5]))
		if n < 4 || pos+1+n > len(b) {
			return
		}
		switch typ {
		case 'D':
			dataRows++
		case 'C':
			cmdComplete++
		}
		pos += 1 + n
	}
	return
}

// cstringAt returns the NUL-terminated string starting at off. cstringLen
// returns its byte length including the NUL. cstringLen is a RELATIVE
// length, so the slice must be [off, off+len-1) — using end-1 as an
// absolute bound truncates every cstring that does not start at 0.
func cstringAt(b []byte, off int) (string, bool) {
	n := cstringLen(b, off)
	if n <= 0 {
		return "", false
	}
	return string(b[off : off+n-1]), true
}

func cstringLen(b []byte, off int) int {
	for i := off; i < len(b); i++ {
		if b[i] == 0 {
			return i - off + 1
		}
	}
	return -1
}

// standAddr returns the disposable stand's dial address (host:port) from the
// parsed pool config. Never the DSN/URI itself — net.Dial needs host:port and
// credentials must not be logged.
func standAddr(pool *pgxpool.Pool) string {
	cc := pool.Config().ConnConfig
	return net.JoinHostPort(cc.Host, fmt.Sprint(cc.Port))
}

// proxiedPool returns a fresh pgxpool whose connections dial the proxy (and
// only through it reach the stand), plus nothing else changed from the
// stand DSN: startup, auth and queries traverse the real wire.
func proxiedPool(t *testing.T, p *rowsErrProxy) *pgxpool.Pool {
	t.Helper()
	return testdb.PostgresPool(t, func(pc *pgxpool.Config) {
		_, portStr, err := net.SplitHostPort(p.ln.Addr().String())
		if err != nil {
			t.Fatalf("rows-err proxy address: %v", err)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			t.Fatalf("rows-err proxy port %q: %v", portStr, err)
		}
		pc.ConnConfig.Host = "127.0.0.1"
		pc.ConnConfig.Port = uint16(port)
	})
}

// rowsErrSeed inserts two enabled models with independently known names, one
// disabled model and one alias targeting the first enabled model; everything
// is removed in cleanup (the stand is shared by the package run).
func rowsErrSeed(t *testing.T, pool *pgxpool.Pool) (on1, on2, off, alias string) {
	t.Helper()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	on1, on2 = "rowserr-a-"+suffix, "rowserr-b-"+suffix
	off, alias = "rowserr-off-"+suffix, "rowserr-alias-"+suffix
	ctx := context.Background()
	for _, stmt := range []string{
		`INSERT INTO models_registry (model_name, display_name, tier, provider, enabled)
		 VALUES ('` + on1 + `', 'RowsErr One', 'smart', 'openai-compat', true)`,
		`INSERT INTO models_registry (model_name, display_name, tier, provider, enabled)
		 VALUES ('` + on2 + `', 'RowsErr Two', 'smart', 'openai-compat', true)`,
		`INSERT INTO models_registry (model_name, display_name, tier, provider, enabled)
		 VALUES ('` + off + `', 'RowsErr Off', 'smart', 'openai-compat', false)`,
		`INSERT INTO model_aliases (alias, target_model) VALUES ('` + alias + `', '` + on1 + `')`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("rows-err seed insert: %v", err)
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM model_aliases WHERE alias = $1`, alias)
		_, _ = pool.Exec(c, `DELETE FROM models_registry WHERE model_name IN ($1, $2, $3)`, on1, on2, off)
	})
	return on1, on2, off, alias
}

func logConnReports(t *testing.T, tag string, reps []pgConnReport) {
	t.Helper()
	for _, r := range reps {
		t.Logf("%s conn %d: queryClass=%d modelSQL=%v aliasSQL=%v dataRows=%d cmdComplete=%d bytes(c2s=%d s2c=%d)",
			tag, r.Index, r.QueryClass, r.ModelSQL, r.AliasSQL, r.DataRows, r.CmdComplete, r.C2SBytes, r.S2CBytes)
	}
}

// assertRowsErrHealthyList checks the healthy positive control's expected
// effect: both seeded enabled models returned, the disabled one absent, and
// the alias joined to its target's provider.
func assertRowsErrHealthyList(t *testing.T, got []modelEntry, on1, on2, off, alias string) {
	t.Helper()
	ids := map[string]modelEntry{}
	for _, e := range got {
		ids[e.ID] = e
	}
	for _, want := range []string{on1, on2} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("rows-err healthy control: %s missing from %v", want, got)
		}
	}
	if _, ok := ids[off]; ok {
		t.Fatalf("rows-err healthy control: disabled %s must be absent", off)
	}
	ae, ok := ids[alias]
	if !ok || ae.AliasOf != on1 || ae.Provider != "openai-compat" {
		t.Fatalf("rows-err healthy control: alias join wrong: %+v", ae)
	}
}

// assertRowsErrDetectorSelfProof proves the query-class detector itself on
// the healthy connection: some connection carried BOTH queries, received
// the enabled rows back as DataRows, and saw CommandComplete.
func assertRowsErrDetectorSelfProof(t *testing.T, reps []pgConnReport) {
	t.Helper()
	joined := false
	for _, r := range reps {
		if r.ModelSQL && r.AliasSQL && r.DataRows >= 3 && r.CmdComplete >= 2 {
			joined = true
		}
	}
	if !joined {
		t.Fatalf("rows-err healthy control: no healthy connection observed both queries through the proxy")
	}
}

// TestQueryEnabledModels_HealthyStandThroughProxy is the healthy POSITIVE
// control on the REAL stand THROUGH the same proxy (untruncated): both
// independently seeded enabled models are returned, the disabled one is not,
// and the alias joins with its target's provider. Per-connection reports
// also prove the query-class detector itself works: the healthy connection
// carries the models_registry query AND the model_aliases query, receives
// the enabled rows back as DataRows, and sees CommandComplete.
func TestQueryEnabledModels_HealthyStandThroughProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("disposable stands are skipped in -short mode")
	}
	if !fuzzDockerUp() {
		t.Fatal("N1-ROWS-ERR needs the disposable PostgreSQL stand (tests gate)")
	}
	stand := testdb.Postgres(t)
	on1, on2, off, alias := rowsErrSeed(t, stand)
	proxy := startRowsErrProxy(t, standAddr(stand), 0)
	pool := proxiedPool(t, proxy)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := queryEnabledModels(ctx, pool)
	if err != nil {
		t.Fatalf("rows-err healthy control: %v", err)
	}
	time.Sleep(150 * time.Millisecond) // let handler goroutines finish capture
	reps := proxy.report()
	logConnReports(t, "rows-err healthy", reps)

	assertRowsErrHealthyList(t, got, on1, on2, off, alias)
	assertRowsErrDetectorSelfProof(t, reps)
}

// assertRowsErrProxyEvidence enforces the harness prerequisites: the
// interruption really happened, exactly one DataRow was forwarded, the
// server never completed the command, and conn 1 carried the
// enabled-models query. A broken interruption is a harness failure, not a
// pass.
func assertRowsErrProxyEvidence(t *testing.T, truncated bool, dataRows int, cmdComplete bool, reps []pgConnReport) {
	t.Helper()
	if !truncated || dataRows != 1 {
		t.Fatalf("rows-err proxy evidence: truncated=%v dataRows=%d, want truncated after exactly 1 DataRow", truncated, dataRows)
	}
	if cmdComplete {
		t.Fatalf("rows-err proxy evidence: CommandComplete reached conn 1 — truncation too late")
	}
	if len(reps) < 1 || !reps[0].ModelSQL {
		t.Fatalf("rows-err proxy evidence: conn 1 never carried the enabled-models query")
	}
}

// assertRowsErrInterruptionInvariants enforces the FROZEN behavioral
// invariant, Errorf on every observed fact, so a suppressed-rows.Err
// variant shows each violation in the failure log: non-nil error, NO
// partial-success list, NO alias query after the interrupted first result,
// and no later connection repeating the enabled-models query. Extra
// physical connections are diagnostic: each is classified explicitly — the
// oracle is what a connection CARRIES, not how many exist.
func assertRowsErrInterruptionInvariants(t *testing.T, got []modelEntry, err error, reps []pgConnReport) {
	t.Helper()
	if err == nil {
		t.Errorf("rows-err interrupted: queryEnabledModels returned nil error; got list %+v (partial success)", got)
	} else if len(got) != 0 {
		t.Errorf("rows-err interrupted: non-nil error must carry NO partial list, got %d entries", len(got))
	}
	for _, r := range reps {
		if r.AliasSQL {
			t.Errorf("rows-err interrupted: alias query on conn %d after the interrupted first result", r.Index)
		}
		if r.Index > 1 && r.ModelSQL {
			t.Errorf("rows-err interrupted: conn %d repeats the enabled-models query (models_registry SQL)", r.Index)
		}
	}
}

// TestQueryEnabledModels_RowStreamInterruptedAfterFirstRow drives the real
// interruption: first connection dies after exactly one forwarded DataRow,
// before CommandComplete and before the second row. FROZEN INVARIANT on the
// corrected path: non-nil error (type logged), NO partial-success list
// (length logged), NO alias query after the interrupted first result — and
// no later connection may repeat the enabled-models query. Assertions use
// Errorf so a suppressed-rows.Err variant shows every observed fact (wrong
// success, partial list, forbidden alias query) in the failure log;
// proxy-evidence prerequisites stay Fatalf — a broken interruption is a
// harness failure, not a pass.
func TestQueryEnabledModels_RowStreamInterruptedAfterFirstRow(t *testing.T) {
	if testing.Short() {
		t.Skip("disposable stands are skipped in -short mode")
	}
	if !fuzzDockerUp() {
		t.Fatal("N1-ROWS-ERR needs the disposable PostgreSQL stand (tests gate)")
	}
	stand := testdb.Postgres(t)
	rowsErrSeed(t, stand) // alias row exists: a suppressed variant WOULD query it
	proxy := startRowsErrProxy(t, standAddr(stand), 1)
	pool := proxiedPool(t, proxy)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := queryEnabledModels(ctx, pool)

	// Harness prerequisites: the interruption really happened, exactly one
	// DataRow was forwarded, and the server never completed the command.
	time.Sleep(150 * time.Millisecond) // let handler goroutines settle
	conns, dataRows, cmdComplete, truncated := proxy.snapshot()
	reps := proxy.report()
	logConnReports(t, "rows-err interrupted", reps)
	t.Logf("rows-err interrupted result: errType=%T listLen=%d", err, len(got))
	assertRowsErrProxyEvidence(t, truncated, dataRows, cmdComplete, reps)

	// Behavioral invariant (Errorf on every fact); extra physical
	// connections are diagnostic evidence classified per connection.
	assertRowsErrInterruptionInvariants(t, got, err, reps)
	_ = conns // logged via per-connection reports; not an invariant by itself
}
