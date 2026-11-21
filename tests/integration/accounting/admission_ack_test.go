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

	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
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

func (s *stand) installGatewayAckRelay(t *testing.T) *ackBarrier {
	t.Helper()
	dsn, err := url.Parse(s.appDSN)
	require.NoError(t, err)
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
	require.True(t, updated, "gateway database environment missing")
	s.restartGateway()
	return b
}

func TestAccountingCommittedStartLostAck(t *testing.T) {
	s := startStand(t)
	b := s.installGatewayAckRelay(t)
	s.controlRequest(t, "ack-pre")
	rid := s.reqPrefix + "ack"
	db := s.oracleDB.db
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	// The stand owns this database. Filtering on this request prevents a
	// concurrent health check or another admission from opening the barrier.
	literal := "'" + strings.ReplaceAll(rid, "'", "''") + "'"
	_, err := db.ExecContext(ctx, `CREATE FUNCTION acc_hold_start() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM pg_advisory_xact_lock(1921,112); RETURN NEW; END $$;
 CREATE TRIGGER acc_hold_start AFTER INSERT ON request_admissions
 FOR EACH ROW WHEN (NEW.client_request_id = `+literal+`) EXECUTE FUNCTION acc_hold_start()`)
	require.NoError(t, err)
	lock, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer lock.Rollback()
	_, err = lock.ExecContext(ctx, "SELECT pg_advisory_xact_lock(1921,112)")
	require.NoError(t, err)
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
			require.NoError(t, db.QueryRowContext(ctx, query, args...).Scan(&n))
			require.LessOrEqual(t, n, 1)
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
		require.NoError(t, lock.Commit())
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
	require.NoError(t, r.err)
	require.Equal(t, 503, r.status, r.body)
	require.True(t, ok, "structured error missing")
	require.Equal(t, "history_unavailable", code)
	require.Positive(t, b.dropped.Load(), "gateway received no discarded reply")
	s.fixture.VerifyEvidence()
	require.Equal(t, fixtureTotals{}, s.fixture.Since(before))
	s.controlRequest(t, "ack-post")
	require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1, receipts: 1}, s.fixture.Since(before), "only the healthy post-control should reach upstream")
	for _, table := range []string{"request_terminal_facts", "settlement_jobs", "credit_transactions"} {
		var count int
		query := fmt.Sprintf("SELECT count(*) FROM %s WHERE invocation_id IN (SELECT invocation_id FROM request_admissions WHERE org_id=$1 AND client_request_id=$2)", table)
		require.NoError(t, db.QueryRowContext(ctx, query, s.oracleDB.orgID, rid).Scan(&count))
		require.Zero(t, count, table)
	}
	var count int
	err = db.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM settlement_jobs WHERE org_id=$1 AND request_id=$2) +
  (SELECT count(*) FROM credit_transactions WHERE org_id=$1 AND request_id=$2 AND type='usage')`, s.oracleDB.orgID, rid).Scan(&count)
	require.NoError(t, err)
	require.Zero(t, count, "correlation-keyed charges or jobs")

}

func TestAccountingAckRelayControl(t *testing.T) {
	server, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
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
		require.NoError(t, err)
		t.Cleanup(func() { c.Close() })
		require.NoError(t, c.SetDeadline(time.Now().Add(3*time.Second)))
		return c
	}
	send := func(c net.Conn, value byte) {
		_, err := c.Write([]byte{value})
		require.NoError(t, err)
		select {
		case seen := <-observed:
			require.Equal(t, value, seen)
		case <-time.After(time.Second):
			t.Fatal("upstream did not observe request")
		}
	}
	receive := func(c net.Conn, value byte) {
		var p [1]byte
		_, err := io.ReadFull(c, p[:])
		require.NoError(t, err)
		require.Equal(t, value, p[0])
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
