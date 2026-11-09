package adminstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RequestPayloadGrant is a durable, one-time authorization for one request.
type RequestPayloadGrant struct {
	ID        string
	Token     string `json:"-"`
	OrgID     string
	RequestID string
	RootID    string
	ExpiresAt time.Time
	Scope     string
}

const (
	// MaxRequestPayloadGrantTTL bounds root self-grants.
	MaxRequestPayloadGrantTTL = 15 * time.Minute
	// MaxActiveRequestGrants limits concurrent grants per root identity.
	MaxActiveRequestGrants = 10
	// RequestPayloadScopeRead grants processed payload access.
	RequestPayloadScopeRead = "payload.read"
	// RequestPayloadScopeOriginals grants access to retained original payloads.
	RequestPayloadScopeOriginals = "payload.read_originals"
	requestPayloadGrantCacheTTL  = 30 * time.Second
	requestPayloadGrantCacheCap  = 1024
)

var (
	// ErrInvalidRequestPayloadGrant indicates invalid scope, identity, or TTL.
	ErrInvalidRequestPayloadGrant = errors.New("invalid request payload grant")
	// ErrRequestPayloadGrantUnavailable indicates durable storage is unavailable.
	ErrRequestPayloadGrantUnavailable = errors.New("request payload grant store unavailable")
)

type requestPayloadGrantCacheEntry struct {
	expiresAt time.Time
	consumed  bool
}

// CreateRequestPayloadGrant stores the grant before returning its bearer token.
// The database is authoritative; no process-local grant can authorize a read.
func (s *Store) CreateRequestPayloadGrant(orgID, requestID, rootID string, ttl time.Duration, now time.Time) (RequestPayloadGrant, error) {
	return s.CreateRequestPayloadGrantScope(orgID, requestID, rootID, RequestPayloadScopeRead, ttl, now)
}

// CreateRequestPayloadGrantScope stores a one-time grant for exactly one
// payload scope. Original access is a distinct capability and is never
// implied by payload.read.
func (s *Store) CreateRequestPayloadGrantScope(orgID, requestID, rootID, scope string, ttl time.Duration, now time.Time) (RequestPayloadGrant, error) {
	if orgID == "" || requestID == "" || rootID == "" || ttl <= 0 || ttl > MaxRequestPayloadGrantTTL {
		return RequestPayloadGrant{}, ErrInvalidRequestPayloadGrant
	}
	if scope != RequestPayloadScopeRead && scope != RequestPayloadScopeOriginals {
		return RequestPayloadGrant{}, ErrInvalidRequestPayloadGrant
	}
	if s == nil || s.db == nil {
		return RequestPayloadGrant{}, ErrRequestPayloadGrantUnavailable
	}
	var raw [48]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return RequestPayloadGrant{}, fmt.Errorf("generate payload grant: %w", err)
	}
	grant := RequestPayloadGrant{ID: hex.EncodeToString(raw[:16]), Token: hex.EncodeToString(raw[16:]), OrgID: orgID, RequestID: requestID, RootID: rootID, ExpiresAt: now.Add(ttl), Scope: scope}
	hash := sha256.Sum256([]byte(grant.Token))
	ctx := context.Background()
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return RequestPayloadGrant{}, fmt.Errorf("begin payload grant transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, rootID); err != nil {
		return RequestPayloadGrant{}, fmt.Errorf("lock payload grants: %w", err)
	}
	var active int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM request_payload_grants WHERE grantor_root=$1::uuid AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at > $2`, rootID, now).Scan(&active); err != nil {
		return RequestPayloadGrant{}, fmt.Errorf("count active payload grants: %w", err)
	}
	if active >= MaxActiveRequestGrants {
		return RequestPayloadGrant{}, ErrInvalidRequestPayloadGrant
	}
	_, err = tx.Exec(ctx, `INSERT INTO request_payload_grants (id, token_hash, grantor_root, grantee, org_id, request_id, scope, expires_at, created_at) VALUES ($1::uuid, $2, $3::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8)`, grant.ID, hash[:], rootID, orgID, requestID, grant.Scope, grant.ExpiresAt, now)
	if err != nil {
		return RequestPayloadGrant{}, fmt.Errorf("persist payload grant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return RequestPayloadGrant{}, fmt.Errorf("commit payload grant: %w", err)
	}
	if err := s.auditRequestPayloadGrant(ctx, "request_payload.grant_issued", grant, now); err != nil {
		_, _ = s.db.Exec(ctx, `UPDATE request_payload_grants SET revoked_at=$2 WHERE id=$1::uuid AND revoked_at IS NULL`, grant.ID, now)
		return RequestPayloadGrant{}, fmt.Errorf("audit payload grant: %w", err)
	}
	s.cacheRequestPayloadGrant(hash, grant.ExpiresAt, now)
	return grant, nil
}

// ConsumeRequestPayloadGrant atomically consumes a matching active grant. Any
// database error, expiration, revocation, reuse, or scope mismatch denies.
func (s *Store) ConsumeRequestPayloadGrant(token, orgID, requestID, rootID string, now time.Time) bool {
	return s.ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, RequestPayloadScopeRead, now) == nil
}

// ConsumeRequestPayloadGrantScope is the detailed fail-closed consume path.
func (s *Store) ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope string, now time.Time) error {
	if s == nil || s.db == nil || token == "" {
		return ErrRequestPayloadGrantUnavailable
	}
	hash := sha256.Sum256([]byte(token))
	if s.cachedRequestPayloadGrantConsumed(hash, now) {
		return ErrInvalidRequestPayloadGrant
	}
	ctx := context.Background()
	var grant RequestPayloadGrant
	err := s.db.QueryRow(ctx, `UPDATE request_payload_grants SET consumed_at=$5 WHERE token_hash=$1 AND org_id=$2::uuid AND request_id=$3 AND grantee=$4::uuid AND scope=$6 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at > $5 RETURNING id::text, org_id::text, request_id, grantor_root::text, expires_at, scope`, hash[:], orgID, requestID, rootID, now, scope).Scan(&grant.ID, &grant.OrgID, &grant.RequestID, &grant.RootID, &grant.ExpiresAt, &grant.Scope)
	if err != nil {
		return fmt.Errorf("consume payload grant: %w", err)
	}
	s.cacheConsumedRequestPayloadGrant(hash, now)
	if err := s.auditRequestPayloadGrant(ctx, "request_payload.grant_used", grant, now); err != nil {
		return fmt.Errorf("audit payload grant use: %w", err)
	}
	return nil
}

// RevokeRequestPayloadGrant revokes a grant by bearer token, failing closed on
// database or mandatory-audit errors.
func (s *Store) RevokeRequestPayloadGrant(token, rootID string) error {
	if s == nil || s.db == nil || token == "" || rootID == "" {
		return ErrRequestPayloadGrantUnavailable
	}
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	ctx := context.Background()
	var grant RequestPayloadGrant
	err := s.db.QueryRow(ctx, `UPDATE request_payload_grants SET revoked_at=$3 WHERE token_hash=$1 AND grantor_root=$2::uuid AND revoked_at IS NULL AND consumed_at IS NULL RETURNING id::text, org_id::text, request_id, grantor_root::text, expires_at, scope`, hash[:], rootID, now).Scan(&grant.ID, &grant.OrgID, &grant.RequestID, &grant.RootID, &grant.ExpiresAt, &grant.Scope)
	if err != nil {
		return fmt.Errorf("revoke payload grant: %w", err)
	}
	s.invalidateRequestPayloadGrant(hash)
	if err := s.auditRequestPayloadGrant(ctx, "request_payload.grant_revoked", grant, now); err != nil {
		return fmt.Errorf("audit payload grant revocation: %w", err)
	}
	return nil
}

// cacheRequestPayloadGrant keeps only a short-lived process-local hint. Every
// redemption still performs the durable conditional UPDATE above.
func (s *Store) cacheRequestPayloadGrant(hash [32]byte, expiresAt, now time.Time) {
	s.requestPayloadGrantMu.Lock()
	defer s.requestPayloadGrantMu.Unlock()
	if s.requestPayloadGrantCache == nil {
		s.requestPayloadGrantCache = make(map[[32]byte]requestPayloadGrantCacheEntry)
	}
	for cachedHash, entry := range s.requestPayloadGrantCache {
		if !now.Before(entry.expiresAt) {
			delete(s.requestPayloadGrantCache, cachedHash)
		}
	}
	cacheUntil := now.Add(requestPayloadGrantCacheTTL)
	if expiresAt.Before(cacheUntil) {
		cacheUntil = expiresAt
	}
	if len(s.requestPayloadGrantCache) >= requestPayloadGrantCacheCap {
		return
	}
	s.requestPayloadGrantCache[hash] = requestPayloadGrantCacheEntry{expiresAt: cacheUntil}
}

func (s *Store) invalidateRequestPayloadGrant(hash [32]byte) {
	s.requestPayloadGrantMu.Lock()
	delete(s.requestPayloadGrantCache, hash)
	s.requestPayloadGrantMu.Unlock()
}

func (s *Store) cachedRequestPayloadGrantConsumed(hash [32]byte, now time.Time) bool {
	s.requestPayloadGrantMu.Lock()
	defer s.requestPayloadGrantMu.Unlock()
	entry, ok := s.requestPayloadGrantCache[hash]
	if !ok {
		return false
	}
	if !now.Before(entry.expiresAt) {
		delete(s.requestPayloadGrantCache, hash)
		return false
	}
	return entry.consumed
}

func (s *Store) cacheConsumedRequestPayloadGrant(hash [32]byte, now time.Time) {
	s.requestPayloadGrantMu.Lock()
	defer s.requestPayloadGrantMu.Unlock()
	if s.requestPayloadGrantCache == nil {
		s.requestPayloadGrantCache = make(map[[32]byte]requestPayloadGrantCacheEntry)
	}
	for cachedHash, entry := range s.requestPayloadGrantCache {
		if !now.Before(entry.expiresAt) {
			delete(s.requestPayloadGrantCache, cachedHash)
		}
	}
	if len(s.requestPayloadGrantCache) >= requestPayloadGrantCacheCap {
		return
	}
	s.requestPayloadGrantCache[hash] = requestPayloadGrantCacheEntry{
		expiresAt: now.Add(requestPayloadGrantCacheTTL), consumed: true,
	}
}

func (s *Store) auditRequestPayloadGrant(ctx context.Context, action string, grant RequestPayloadGrant, now time.Time) error {
	details := fmt.Sprintf(`{"grant_id":%q,"org_id":%q,"request_id":%q,"scope":%q,"expires_at":%q}`, grant.ID, grant.OrgID, grant.RequestID, grant.Scope, grant.ExpiresAt.UTC().Format(time.RFC3339Nano))
	// One grant, one audit-ID prefix: issuance audits the compact hex id the
	// issuer minted, while consume/revoke read the id back through the uuid
	// column (dashed rendering). Canonicalize so every lifecycle entry of a
	// grant is correlatable by id.
	grantID := strings.ReplaceAll(grant.ID, "-", "")
	return s.InsertAuditLogEntry(ctx, AuditLogEntryRecord{ID: grantID + "-" + action, Action: action, Resource: "request:" + grant.RequestID, Details: details, AdminID: grant.RootID, CreatedAt: now})
}

// ListRequestPayloadGrants returns metadata only; bearer secrets are never
// persisted in or returned from the grant table.
func (s *Store) ListRequestPayloadGrants(ctx context.Context, rootID string) ([]RequestPayloadGrant, error) {
	if s == nil || s.db == nil {
		return nil, ErrRequestPayloadGrantUnavailable
	}
	rows, err := s.db.Query(ctx, `SELECT id::text, org_id::text, COALESCE(request_id,''), grantor_root::text, expires_at, scope FROM request_payload_grants WHERE grantor_root=$1::uuid ORDER BY created_at DESC`, rootID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := []RequestPayloadGrant{}
	for rows.Next() {
		var g RequestPayloadGrant
		if err := rows.Scan(&g.ID, &g.OrgID, &g.RequestID, &g.RootID, &g.ExpiresAt, &g.Scope); err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}
