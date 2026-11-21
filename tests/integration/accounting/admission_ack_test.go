//go:build integration

package accounting

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type ackCut struct {
	held      chan string
	forward   chan bool
	discarded chan time.Time
}

// The disposable PostgreSQL stand uses plaintext loopback. BackendKeyData
// identifies a connection and ReadyForQuery('I') ends its transaction.
type ackRelay struct {
	sync.Mutex
	cuts map[uint32]*ackCut
}

func (r *ackRelay) arm(pid uint32) *ackCut {
	r.Lock()
	defer r.Unlock()
	cut := &ackCut{make(chan string, 1), make(chan bool, 1), make(chan time.Time, 1)}
	r.cuts[pid] = cut
	return cut
}
func (r *ackRelay) take(pid uint32) *ackCut {
	r.Lock()
	defer r.Unlock()
	cut := r.cuts[pid]
	delete(r.cuts, pid)
	return cut
}
func (r *ackRelay) copyReplies(ctx context.Context, client net.Conn, backend io.Reader) error {
	var pid uint32
	var command string
	var header [5]byte
	for {
		if _, err := io.ReadFull(backend, header[:]); err != nil {
			return err
		}
		size := int(binary.BigEndian.Uint32(header[1:])) - 4
		if size < 0 || size > 64<<20 {
			return errors.New("invalid stand PostgreSQL reply length")
		}
		frame := make([]byte, 5+size)
		copy(frame, header[:])
		if _, err := io.ReadFull(backend, frame[5:]); err != nil {
			return err
		}
		if header[0] == 'K' && size == 8 {
			pid = binary.BigEndian.Uint32(frame[5:9])
		}
		if header[0] == 'C' {
			command = strings.TrimSuffix(string(frame[5:]), "\x00")
		}
		if header[0] == 'Z' && size == 1 && frame[5] == 'I' {
			if cut := r.take(pid); cut != nil {
				if err := cut.deliver(ctx, client, command); err != nil {
					return err
				}
			}
		}
		if err := client.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		if _, err := client.Write(frame); err != nil {
			return err
		}
	}
}
func (c *ackCut) deliver(ctx context.Context, client net.Conn, command string) error {
	c.held <- command
	select {
	case forward := <-c.forward:
		if forward {
			return nil
		}
		err := client.Close()
		if err != nil {
			return err
		}
		c.discarded <- time.Now()
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return errors.New("unreleased commit acknowledgement")
	}
}

func gatewayAckRelay(t *testing.T, upstream string) (string, *ackRelay) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	relay := &ackRelay{cuts: make(map[uint32]*ackCut)}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() { defer workers.Done(); relay.bridge(ctx, c, upstream) }()
		}
	}()
	t.Cleanup(func() { cancel(); ln.Close(); workers.Wait() })
	return ln.Addr().String(), relay
}
func (r *ackRelay) bridge(ctx context.Context, client net.Conn, upstream string) {
	defer client.Close()
	d := net.Dialer{Timeout: 3 * time.Second}
	backend, err := d.DialContext(ctx, "tcp", upstream)
	if err != nil {
		return
	}
	defer backend.Close()
	stop := context.AfterFunc(ctx, func() { client.Close(); backend.Close() })
	defer stop()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(backend, client); backend.Close() }()
	_ = r.copyReplies(ctx, client, backend)
	client.Close()
	<-done
}

func (s *stand) installGatewayAckRelay(t *testing.T) (*ackRelay, string) {
	t.Helper()
	dsn, err := url.Parse(s.appDSN)
	require.NoError(t, err)
	addr, b := gatewayAckRelay(t, dsn.Host)
	s.killGatewaySIGKILL()
	dsn.Host = addr
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
	return b, dsn.String()
}

type ackResponse struct {
	status int
	body   string
	err    error
	at     time.Time
}

func (s *stand) ackRequest(ctx context.Context, rid string) ackResponse {
	var out ackResponse
	trace := httptrace.ClientTrace{GotFirstResponseByte: func() { out.at = time.Now() }}
	payload := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}]}`, s.model, rid)
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, &trace), http.MethodPost, s.gatewayURL+"/v1/chat/completions", strings.NewReader(payload))
	if err != nil {
		out.err = err
		return out
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", rid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		out.err = err
		return out
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out.status, out.body, out.err = resp.StatusCode, string(body), err
	return out
}

func (s *stand) exerciseStartAck(t *testing.T, relay *ackRelay, other *sql.Conn, rid string, forward bool) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	db := s.oracleDB.db
	lock, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer lock.Rollback()
	_, err = lock.ExecContext(ctx, "SELECT pg_advisory_xact_lock(1921,112)")
	require.NoError(t, err)
	result := make(chan ackResponse, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- s.ackRequest(ctx, rid)
	}()
	defer func() { cancel(); <-done }()
	var pid uint32
	require.Eventually(t, func() bool {
		err := db.QueryRowContext(ctx, `SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a USING(pid)
   WHERE a.application_name='acceptance_ack_gateway' AND l.locktype='advisory'
   AND l.classid=1921 AND l.objid=112 AND NOT l.granted`).Scan(&pid)
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}
		return err == nil && pid > 0
	}, 8*time.Second, 10*time.Millisecond, "gateway did not reach the admission trigger")
	t.Logf("holding transaction-ready acknowledgement for request %s backend %d", rid, pid)
	cut := relay.arm(pid)
	require.NoError(t, lock.Commit())
	select {
	case command := <-cut.held:
		require.Contains(t, []string{"INSERT 0 1", "COMMIT"}, command, "expected the completion exchange for this admission")
		t.Logf("gateway backend %d completed %s and its transaction-ready reply is held", pid, command)
	case r := <-result:
		t.Fatalf("client returned before commit reply: %d %v", r.status, r.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var id string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT invocation_id::text FROM request_admissions WHERE client_request_id=$1 AND org_id=$2`, rid, s.oracleDB.orgID).Scan(&id))
	t.Logf("independent database observation confirmed invocation %s for request %s", id, rid)
	// A second, already-established connection through the same relay must
	// still be live while the selected gateway session is parked.
	pingCtx, stop := context.WithTimeout(ctx, time.Second)
	err = other.PingContext(pingCtx)
	stop()
	require.NoError(t, err)
	require.Empty(t, result, "client finished while its commit reply was held")
	cut.forward <- forward
	var resp ackResponse
	select {
	case resp = <-result:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.NoError(t, resp.err)
	if forward {
		require.Equal(t, httpOK, resp.status, resp.body)
		require.Contains(t, resp.body, fixtureAssistantContent)
		return id
	}
	select {
	case at := <-cut.discarded:
		require.False(t, resp.at.IsZero(), "missing HTTP first-byte observation")
		require.False(t, resp.at.Before(at), "HTTP response began before the selected connection was closed")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	code, ok := decodeErrorCode(resp.body)
	require.Equal(t, 503, resp.status, resp.body)
	require.True(t, ok)
	require.Equal(t, "history_unavailable", code)
	return id
}

func TestAccountingCommittedStartLostAck(t *testing.T) {
	s := startStand(t)
	b, dsn := s.installGatewayAckRelay(t)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer db.Close()
	other, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer other.Close()
	require.NoError(t, other.PingContext(t.Context()))
	s.controlRequest(t, "ack-pre")
	forwardRID, dropRID := s.reqPrefix+"ack-forward", s.reqPrefix+"ack-lost"
	// Only this temporary stand's two named requests enter the barrier.
	quoted := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }
	_, err = s.oracleDB.db.ExecContext(t.Context(), `CREATE FUNCTION acc_hold_start() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM pg_advisory_xact_lock(1921,112); RETURN NEW; END $$;
 CREATE TRIGGER acc_hold_start AFTER INSERT ON request_admissions FOR EACH ROW WHEN (NEW.client_request_id IN (`+quoted(forwardRID)+","+quoted(dropRID)+`)) EXECUTE FUNCTION acc_hold_start()`)
	require.NoError(t, err)
	before := s.fixture.Snapshot()
	s.exerciseStartAck(t, b, other, forwardRID, true)
	require.Equal(t, fixtureTotals{1, 1, 1}, s.fixture.Since(before))
	a, d, r := s.fixture.Counts(forwardRID)
	require.Equal(t, []int{1, 1, 1}, []int{a, d, r})
	before = s.fixture.Snapshot()
	id := s.exerciseStartAck(t, b, other, dropRID, false)
	s.fixture.VerifyEvidence()
	require.Equal(t, fixtureTotals{}, s.fixture.Since(before))
	s.controlRequest(t, "ack-post")
	require.Equal(t, fixtureTotals{1, 1, 1}, s.fixture.Since(before))
	a, d, r = s.fixture.Counts(s.reqPrefix + "ctl-ack-post")
	require.Equal(t, []int{1, 1, 1}, []int{a, d, r})
	var count int
	require.NoError(t, s.oracleDB.db.QueryRowContext(t.Context(), "SELECT count(*) FROM request_admissions WHERE invocation_id=$1 AND org_id=$2 AND client_request_id=$3", id, s.oracleDB.orgID, dropRID).Scan(&count))
	require.Equal(t, 1, count)
	for _, table := range []string{"request_terminal_facts", "settlement_jobs", "credit_transactions"} {
		query := fmt.Sprintf("SELECT count(*) FROM %s WHERE invocation_id=$1", table)
		require.NoError(t, s.oracleDB.db.QueryRowContext(t.Context(), query, id).Scan(&count))
		require.Zero(t, count, table)
	}
	require.NoError(t, s.oracleDB.db.QueryRowContext(t.Context(), `SELECT
  (SELECT count(*) FROM settlement_jobs WHERE org_id=$1 AND request_id=$2) +
  (SELECT count(*) FROM credit_transactions WHERE org_id=$1 AND request_id=$2 AND type='usage')`, s.oracleDB.orgID, dropRID).Scan(&count))
	require.Zero(t, count, "correlation-keyed jobs or charges")
}

func TestAccountingAckRelayControl(t *testing.T) {
	relay := &ackRelay{cuts: make(map[uint32]*ackCut)}
	// Drive real net.Conn writes through PostgreSQL backend frames. The
	// sibling connection remains usable throughout the target's held reply.
	open := func(pid uint32) (net.Conn, net.Conn) {
		input, producer := net.Pipe()
		relaySide, reader := net.Pipe()
		t.Cleanup(func() { producer.Close(); reader.Close() })
		go func() {
			defer input.Close()
			defer relaySide.Close()
			_ = relay.copyReplies(t.Context(), relaySide, input)
		}()
		key := []byte{'K', 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(key[5:9], pid)
		_, err := producer.Write(key)
		require.NoError(t, err)
		buf := make([]byte, len(key))
		_, err = io.ReadFull(reader, buf)
		require.NoError(t, err)
		require.Equal(t, key, buf)
		return producer, reader
	}
	target, client := open(17)
	sibling, healthy := open(19)
	ready := []byte{'Z', 0, 0, 0, 5, 'I'}
	readReady := func(conn net.Conn) {
		buf := make([]byte, len(ready))
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
		_, err := io.ReadFull(conn, buf)
		require.NoError(t, err)
		require.Equal(t, ready, buf)
	}
	for _, forward := range []bool{true, false} {
		cut := relay.arm(17)
		_, err := target.Write(ready)
		require.NoError(t, err)
		select {
		case <-cut.held:
		case <-time.After(time.Second):
			t.Fatal("target reply not held")
		}
		_, err = sibling.Write(ready)
		require.NoError(t, err)
		readReady(healthy)
		require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
		cut.forward <- forward
		if forward {
			readReady(client)
			continue
		}
		var v [1]byte
		_, err = client.Read(v[:])
		require.ErrorIs(t, err, io.EOF)
	}
}
