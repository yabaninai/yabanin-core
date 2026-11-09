package mcpserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sessionSigner issues and validates stateless Mcp-Session-Id values:
// "<expiry-unix>.<nonce>.<hmac>". Stateless by design — the gateway runs
// multiple replicas with no shared session store, and a signed id needs no
// storage at all (each replica holds a fresh per-process HMAC key, so only
// the issuing process accepts its own ids; any foreign id validates as
// unknown and the client re-initializes). The HMAC key is per-process; a
// restart rotates it, which just makes clients re-initialize (the spec's
// prescribed recovery for a 404 session).
//
// Revocation (client-initiated session termination) is process-local by the
// same argument: a cancelled id is recorded in a bounded in-process set, and
// the only process that could ever accept that id is the one holding the
// revocation record. A session id is a bearer credential — revocation
// requires presenting it — so revocation authority equals possession.
// Entries are dropped once their session's embedded expiry passes (an
// expired id is rejected before any registry consultation — and validate
// re-checks freshness inside the pruner's lock, so deleting a record can
// never be the step that lets a cancelled id through), keeping the set
// bounded by live-cancelled sessions; exhaustion refuses new terminations
// (fail-closed: a cancel that cannot be recorded is reported as failed, not
// acknowledged falsely).
type sessionSigner struct {
	key []byte
	ttl time.Duration
	now func() time.Time

	// mu guards the revocation registry and makes validate's accept/reject
	// decision atomic against pruning (AUDIT-P2-09): validate runs its
	// freshness check and its revocation lookup together in ONE read-locked
	// critical section, and a read section never overlaps the pruner's
	// write section on the same mutex. issue/revoke take the write side
	// only when the registry needs pruning or insertion.
	mu            sync.RWMutex
	revoked       map[string]int64 // session id → embedded expiry (unix seconds)
	revocationCap int              // hard bound on registry entries
}

// defaultRevocationCap bounds the revocation registry: enough for every
// session a single process could realistically hold live plus cancelled
// ones, while capping memory (~2 MB worst case at ~200 B per entry).
const defaultRevocationCap = 10000

// errRevocationExhausted reports that the revocation registry is at capacity
// with no prunable entries: the termination is refused instead of silently
// acknowledged.
var errRevocationExhausted = errors.New("mcp session revocation registry exhausted")

func newSessionSigner(secret []byte, ttl time.Duration) *sessionSigner {
	if len(secret) == 0 {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &sessionSigner{key: secret, ttl: ttl, now: time.Now,
		revoked: make(map[string]int64), revocationCap: defaultRevocationCap}
}

// sessionDomain separates this HMAC's inputs from any other HMAC sharing the
// same key material.
const sessionDomain = "yabanin/mcpserver:session:v1"

// macEncoding is the only base64 variant used for the Mcp-Session-Id HMAC
// segment, for signing and for verification. Strict mode rejects
// non-canonical spellings (non-zero discarded trailing bits in the final
// base64 character): lenient decoding accepted ~1/1024 of re-spelled ids
// whose decoded MAC bytes were identical (segment suffix "XU" re-spelled
// "XX"), so a session id could validate under a second text form. Signature
// verification must accept only the exact issued spelling; all issued ids
// are canonical. (AUTHSTR2, sibling of AUTHFLAKESEC1, 2026-11-02.)
var macEncoding = base64.RawURLEncoding.Strict()

// issue returns a fresh signed session id. When the revocation registry is
// at capacity it is pruned first, so long-lived processes shed entries for
// sessions that have since expired.
func (s *sessionSigner) issue() string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	expiry := s.now().Add(s.ttl).Unix()
	s.maybePrune()
	return s.sign(expiry, nonce)
}

func (s *sessionSigner) sign(expiry int64, nonce []byte) string {
	payload := strconv.FormatInt(expiry, 36) + "." + base64.RawURLEncoding.EncodeToString(nonce)
	return payload + "." + macEncoding.EncodeToString(s.mac(payload))
}

func (s *sessionSigner) mac(payload string) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(sessionDomain))
	h.Write([]byte{0})
	h.Write([]byte(payload))
	return h.Sum(nil)
}

var errInvalidSession = errors.New("invalid mcp session id")

// revoke terminates a live session: the id is recorded so every later
// validate() fails exactly like an unknown one (the spec's 404 →
// re-initialize recovery). Only a currently-valid, not-yet-cancelled id
// can be revoked — a dead or already-cancelled id is rejected the same way
// validate() rejects it, so a second DELETE of the same session is 404,
// not a second success. Capacity exhaustion returns errRevocationExhausted
// (the caller must not acknowledge the termination) rather than dropping
// the cancel on the floor. verify() runs outside the lock: an id expiring
// inside that gap gets recorded as harmless dead weight — it can never
// validate (freshness is re-checked inside validate's locked checkpoint)
// and the record is pruned on pressure.
func (s *sessionSigner) revoke(sid string) error {
	expiry, err := s.verify(sid)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dead := s.revoked[sid]; dead {
		return errInvalidSession
	}
	if len(s.revoked) >= s.revocationCap {
		s.pruneLocked()
		if len(s.revoked) >= s.revocationCap {
			return errRevocationExhausted
		}
	}
	s.revoked[sid] = expiry
	return nil
}

// validate checks the signature and expiry (constant-time compare) and the
// revocation registry. An expired, forged or cancelled session is as good
// as unknown — the client must re-initialize — and the three are
// indistinguishable from the outside (no oracle).
//
// The accept/reject decision is ONE coherent checkpoint: the expiry
// comparison and the revocation lookup both happen inside a single
// s.mu.RLock critical section — the same mutex pruneLocked holds for
// writing — so the decision is atomic against pruning. This closes the
// TOCTOU the Codex audit (AUDIT-P2-09) proved on the earlier layout, where
// freshness was decided by verify() outside the lock and the revocation
// lookup ran as a second, separate locked step: with the registry at
// capacity, a pruner could run in the gap (verify read the clock at exactly
// the expiry second — still fresh under the now > expiry predicate — the
// pruner saw expiry+1 and deleted the cancelled id's record, and the
// subsequent lookup had nothing left to reject). Mutual exclusion gives the
// repaired invariant in both directions: a critical section running after
// such a delete necessarily reads a clock strictly past expiry and rejects
// on freshness; one running before it still sees the record and rejects on
// revocation. The pre-lock verify() call stays as a fast path only — it
// rejects forged ids without lock contention and yields the embedded
// expiry — never as an authoritative freshness answer for acceptance.
func (s *sessionSigner) validate(sid string) error {
	expiry, err := s.verify(sid)
	if err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.now().Unix() > expiry {
		return errInvalidSession
	}
	if _, dead := s.revoked[sid]; dead {
		return errInvalidSession
	}
	return nil
}

// verify parses a session id and checks the signature and freshness,
// returning the embedded expiry. revoke() needs the expiry and must reject
// dead ids; validate() uses it as its lock-free fast path (forged ids never
// reach the registry lock) and re-checks freshness inside its critical
// section with the same now > expiry predicate the pruner applies — the
// value returned here is advisory for validate, never authoritative for
// acceptance.
func (s *sessionSigner) verify(sid string) (int64, error) {
	parts := strings.Split(sid, ".")
	if len(parts) != 3 {
		return 0, errInvalidSession
	}
	payload := parts[0] + "." + parts[1]
	got, err := macEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(got, s.mac(payload)) {
		return 0, errInvalidSession
	}
	expiry, err := strconv.ParseInt(parts[0], 36, 64)
	if err != nil || s.now().Unix() > expiry {
		return 0, errInvalidSession
	}
	return expiry, nil
}

// maybePrune sheds expired registry entries once the set reaches capacity
// (amortized housekeeping on the issue/revoke paths).
func (s *sessionSigner) maybePrune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.revoked) >= s.revocationCap {
		s.pruneLocked()
	}
}

// pruneLocked drops entries whose sessions have expired — `now > expiry`,
// the exact predicate validate's in-lock freshness check applies, under the
// same write lock. Such ids are dead weight: they are rejected before any
// registry consultation, so deleting the record cannot be the step that
// turns a cancelled id back into a valid one (AUDIT-P2-09 invariant).
// Callers hold the write lock.
func (s *sessionSigner) pruneLocked() {
	now := s.now().Unix()
	for sid, expiry := range s.revoked {
		if now > expiry {
			delete(s.revoked, sid)
		}
	}
}
