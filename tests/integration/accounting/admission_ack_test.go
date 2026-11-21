//go:build integration

package accounting

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The barrier holds only PostgreSQL replies. Requests keep reaching the
// server, and the independent oracle uses its own direct connection.
type ackBarrier struct {
	sync.RWMutex
	generation atomic.Uint64
	dropped    atomic.Uint64
}

func (b *ackBarrier) reply(dst io.Writer, p []byte, generation uint64) (int, error) {
	b.RLock()
	defer b.RUnlock()
	if b.generation.Load() != generation {
		b.dropped.Add(1)
		return 0, net.ErrClosed
	}
	return dst.Write(p)
}

type ackReplyWriter struct {
	barrier    *ackBarrier
	client     net.Conn
	generation uint64
}

func (w ackReplyWriter) Write(p []byte) (int, error) {
	return w.barrier.reply(w.client, p, w.generation)
}

func gatewayAckRelay(t *testing.T, upstream string) (string, *ackBarrier) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := new(ackBarrier)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			generation := b.generation.Load()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer client.Close()
				dialer := net.Dialer{Timeout: 3 * time.Second}
				backend, err := dialer.DialContext(ctx, "tcp", upstream)
				if err != nil {
					return
				}
				defer backend.Close()
				stop := context.AfterFunc(ctx, func() { client.Close(); backend.Close() })
				defer stop()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(backend, client); backend.Close(); close(done) }()
				_, _ = io.Copy(ackReplyWriter{b, client, generation}, backend)
				client.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() { cancel(); ln.Close(); workers.Wait() })
	return ln.Addr().String(), b
}

func TestAccountingCommittedStartLostAck(t *testing.T) {
	s := startStand(t)
	dsn, err := url.Parse(s.appDSN)
	if err != nil {
		t.Fatal(err)
	}
	relay, b := gatewayAckRelay(t, dsn.Host)
	s.killGatewaySIGKILL()
	dsn.Host = relay
	q := dsn.Query()
	q.Set("application_name", "acceptance_ack_gateway")
	dsn.RawQuery = q.Encode()
	updated := false
	for i, v := range s.gatewayEnv {
		if strings.HasPrefix(v, "YABANIN_PG_URI=") {
			s.gatewayEnv[i] = "YABANIN_PG_URI=" + dsn.String()
			updated = true
		}
	}
	if !updated {
		t.Fatal("gateway database environment missing")
	}
	s.restartGateway()
	s.controlRequest(t, "ack-pre")
	rid := s.reqPrefix + "ack"
	db := s.oracleDB.db
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	// The stand owns this database. Filtering on this request prevents a
	// concurrent health check or another admission from opening the barrier.
	literal := "'" + strings.ReplaceAll(rid, "'", "''") + "'"
	_, err = db.ExecContext(ctx, `CREATE FUNCTION acc_hold_start() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM pg_advisory_xact_lock(1921,112); RETURN NEW; END $$;
 CREATE TRIGGER acc_hold_start AFTER INSERT ON request_admissions
 FOR EACH ROW WHEN (NEW.client_request_id = `+literal+`) EXECUTE FUNCTION acc_hold_start()`)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, "SELECT pg_advisory_xact_lock(1921,112)"); err != nil {
		t.Fatal(err)
	}
	before := s.fixture.Snapshot()
	type response struct {
		status int
		body   string
		err    error
	}
	result := make(chan response, 1)
	go func() { status, body, err := s.chat(t, rid, 35*time.Second); result <- response{status, body, err} }()
	waitCount := func(query string, args ...any) {
		t.Helper()
		for {
			var n int
			if err := db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n == 1 {
				return
			}
			select {
			case r := <-result:
				t.Fatalf("client returned before commit acknowledgement fault: status=%d err=%v", r.status, r.err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	waitCount(`SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING(pid)
 WHERE a.application_name='acceptance_ack_gateway' AND l.locktype='advisory'
 AND l.classid=1921 AND l.objid=112 AND NOT l.granted`)
	func() {
		b.Lock()
		defer b.Unlock()
		if err := lock.Commit(); err != nil {
			t.Fatal(err)
		}
		waitCount(`SELECT count(*) FROM request_admissions WHERE client_request_id=$1 AND org_id=$2`, rid, s.oracleDB.orgID)
		b.generation.Add(1)
	}()
	var r response
	select {
	case r = <-result:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	code, ok := decodeErrorCode(r.body)
	if r.err != nil || r.status != 503 || !ok || code != "history_unavailable" || b.dropped.Load() == 0 {
		t.Fatalf("committed start with discarded reply: status=%d code=%q transport=%v discarded=%d", r.status, code, r.err, b.dropped.Load())
	}
	s.fixture.VerifyEvidence()
	if d := s.fixture.Since(before); d.arrivals != 0 || d.dispatches != 0 || d.receipts != 0 {
		t.Fatalf("provider activity after lost start acknowledgement: %+v", d)
	}
	s.controlRequest(t, "ack-post")
	for _, table := range []string{"request_terminal_facts", "settlement_jobs", "credit_transactions"} {
		var count int
		query := fmt.Sprintf("SELECT count(*) FROM %s WHERE invocation_id IN (SELECT invocation_id FROM request_admissions WHERE org_id=$1 AND client_request_id=$2)", table)
		if err := db.QueryRowContext(ctx, query, s.oracleDB.orgID, rid).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s rows=%d err=%v", table, count, err)
		}
	}
	if d := s.fixture.Since(before); d.arrivals != 1 || d.dispatches != 1 || d.receipts != 1 {
		t.Fatalf("only the healthy post-control should reach upstream: %+v", d)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM settlement_jobs WHERE org_id=$1 AND request_id=$2) +
  (SELECT count(*) FROM credit_transactions WHERE org_id=$1 AND request_id=$2 AND type='usage')`, s.oracleDB.orgID, rid).Scan(&count); err != nil || count != 0 {
		t.Fatalf("correlation-keyed charges or jobs=%d err=%v", count, err)
	}

}

func TestAccountingAckRelayControl(t *testing.T) {
	server, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	observed := make(chan byte, 3)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := server.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var p [1]byte
				for {
					if _, err := io.ReadFull(c, p[:]); err != nil {
						return
					}
					observed <- p[0]
					if _, err := c.Write(p[:]); err != nil {
						return
					}
				}
			}()
		}
	}()
	addr, b := gatewayAckRelay(t, server.Addr().String())
	dial := func() net.Conn {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		return c
	}
	send := func(c net.Conn, value byte) {
		if _, err := c.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
		select {
		case seen := <-observed:
			if seen != value {
				t.Fatalf("upstream saw %d, want %d", seen, value)
			}
		case <-time.After(time.Second):
			t.Fatal("upstream did not observe request")
		}
	}
	receive := func(c net.Conn, value byte) {
		var p [1]byte
		if _, err := io.ReadFull(c, p[:]); err != nil || p[0] != value {
			t.Fatalf("received %d err=%v want %d", p[0], err, value)
		}
	}
	first := dial()
	send(first, 1)
	receive(first, 1)
	func() { b.Lock(); defer b.Unlock(); send(first, 2); b.generation.Add(1) }()
	var p [1]byte
	if _, err := first.Read(p[:]); err != io.EOF {
		t.Fatalf("old client received %d err=%v, want EOF", p[0], err)
	}
	if b.dropped.Load() != 1 {
		t.Fatalf("discarded writes %d, want 1", b.dropped.Load())
	}
	fresh := dial()
	send(fresh, 3)
	receive(fresh, 3)
}
