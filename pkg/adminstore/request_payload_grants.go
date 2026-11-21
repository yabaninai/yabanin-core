package adminstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/auditlog"
)

// RequestPayloadGrant is a durable, one-time authorization for one request.
// RowKey pins the one physical request_logs row the grant addresses. Zero
// marks a legacy grant issued before the binding existed: its original row
// is not provable, so it is permanently unusable at redemption (conservative
// deny, no burn) instead of being retargeted to whatever row the
// correlation currently names.
type RequestPayloadGrant struct {
	ID        string
	Token     string `json:"-"`
	OrgID     string
	RequestID string
	RootID    string
	RowKey    int64
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
	// ErrRequestPayloadGrantTargetMissing indicates the correlation has no
	// carrier row in the org, so no physical row can be bound or resolved.
	ErrRequestPayloadGrantTargetMissing = errors.New("request payload grant target missing")
	// ErrRequestPayloadGrantTargetAmbiguous indicates several physical rows
	// carry the correlation (legitimate per 0028), so no single row may be
	// addressed by the grant: fail closed.
	ErrRequestPayloadGrantTargetAmbiguous = errors.New("request payload grant target ambiguous")
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
// validateRequestPayloadGrantIssue enforces the static issue contract:
// non-empty parties, a bounded TTL and a known scope.
func validateRequestPayloadGrantIssue(orgID, requestID, rootID, scope string, ttl time.Duration) error {
	if orgID == "" || requestID == "" || rootID == "" || ttl <= 0 || ttl > MaxRequestPayloadGrantTTL {
		return ErrInvalidRequestPayloadGrant
	}
	if scope != RequestPayloadScopeRead && scope != RequestPayloadScopeOriginals {
		return ErrInvalidRequestPayloadGrant
	}
	return nil
}

// enforceActiveRequestGrantCap denies issuance past the per-root active
// budget, counted inside the issuance transaction.
func enforceActiveRequestGrantCap(ctx context.Context, tx auditTx, rootID string, now time.Time) error {
	var active int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM request_payload_grants WHERE grantor_root=$1::uuid AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at > $2`, rootID, now).Scan(&active); err != nil {
		return fmt.Errorf("count active payload grants: %w", err)
	}
	if active >= MaxActiveRequestGrants {
		return ErrInvalidRequestPayloadGrant
	}
	return nil
}

// resolveRequestPayloadGrantTarget binds a new grant to exactly one physical
// request_logs row: the client correlation alone is not row identity (0028
// allows two invocations to share it), so issuance resolves the carrier
// inside the same locked transaction and refuses fail-closed when the
// target is gone or ambiguous rather than minting an addressable-wider
// grant.
func resolveRequestPayloadGrantTarget(ctx context.Context, tx auditTx, orgID, requestID string) (int64, error) {
	var carriers int
	var rowKey int64
	if err := tx.QueryRow(ctx, `SELECT count(*), COALESCE(MIN(id), 0) FROM request_logs WHERE org_id=$1::uuid AND request_id=$2`, orgID, requestID).Scan(&carriers, &rowKey); err != nil {
		return 0, fmt.Errorf("resolve payload grant target: %w", err)
	}
	switch {
	case carriers == 0:
		return 0, ErrRequestPayloadGrantTargetMissing
	case carriers > 1:
		return 0, ErrRequestPayloadGrantTargetAmbiguous
	}
	return rowKey, nil
}

// CreateRequestPayloadGrantScope issues a durable single-request bearer
// grant bound to exactly one physical request_logs row. Issuance refuses
// fail-closed when the target is gone or ambiguous rather than minting an
// addressable-wider grant.
func (s *Store) CreateRequestPayloadGrantScope(orgID, requestID, rootID, scope string, ttl time.Duration, now time.Time) (RequestPayloadGrant, error) {
	if err := validateRequestPayloadGrantIssue(orgID, requestID, rootID, scope, ttl); err != nil {
		return RequestPayloadGrant{}, err
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
	if err := enforceActiveRequestGrantCap(ctx, tx, rootID, now); err != nil {
		return RequestPayloadGrant{}, err
	}
	if grant.RowKey, err = resolveRequestPayloadGrantTarget(ctx, tx, orgID, requestID); err != nil {
		return RequestPayloadGrant{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO request_payload_grants (id, token_hash, grantor_root, grantee, org_id, request_id, request_row_key, scope, expires_at, created_at) VALUES ($1::uuid, $2, $3::uuid, $3::uuid, $4::uuid, $5, $6::bigint, $7, $8, $9)`, grant.ID, hash[:], rootID, orgID, requestID, grant.RowKey, grant.Scope, grant.ExpiresAt, now); err != nil {
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

// ConsumeRequestPayloadGrant atomically consumes a matching active grant,
// resolving the bound row key first. Any database error, expiration,
// revocation, reuse, or scope mismatch denies; a legacy unbound grant is
// permanently unusable and denies without state change.
func (s *Store) ConsumeRequestPayloadGrant(token, orgID, requestID, rootID string, now time.Time) bool {
	rowKey, err := s.PeekRequestPayloadGrantTarget(context.Background(), token, orgID, requestID, rootID, now)
	if err != nil {
		return false
	}
	_, err = s.ConsumeRequestPayloadGrantScope(token, orgID, requestID, rowKey, rootID, RequestPayloadScopeRead, now)
	return err == nil
}

// PeekRequestPayloadGrantTarget resolves, without consuming, the one physical
// row a currently redeemable grant addresses: the issuance-time bound row key.
// It discloses nothing beyond steering the pre-consume decision — an unknown,
// expired, revoked, replayed, mismatched, or legacy-unbound token is one
// indistinguishable generic error (the conservative treatment: a grant whose
// original row is not provable is never retargeted to the correlation's
// current carrier), and disclosure still requires the atomic consume. A bound
// row purged after issuance surfaces as the caller's read-by-key 404, not
// here.
func (s *Store) PeekRequestPayloadGrantTarget(ctx context.Context, token, orgID, requestID, rootID string, now time.Time) (int64, error) {
	if s == nil || s.db == nil || token == "" {
		return 0, ErrRequestPayloadGrantUnavailable
	}
	hash := sha256.Sum256([]byte(token))
	if s.cachedRequestPayloadGrantConsumed(hash, now) {
		return 0, ErrInvalidRequestPayloadGrant
	}
	var bound *int64
	err := s.db.QueryRow(ctx, `
		SELECT request_row_key
		FROM request_payload_grants
		WHERE token_hash=$1 AND org_id=$2::uuid AND request_id=$3 AND grantee=$4::uuid
		  AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at > $5
		LIMIT 1`, hash[:], orgID, requestID, rootID, now).Scan(&bound)
	if err != nil {
		if IsNotFound(err) {
			return 0, ErrInvalidRequestPayloadGrant
		}
		return 0, fmt.Errorf("peek payload grant target: %w", err)
	}
	if bound == nil || *bound <= 0 {
		// Legacy pre-binding grant: the original row is not provable, so it
		// stays unusable instead of retargeting the correlation's current
		// carrier.
		return 0, ErrInvalidRequestPayloadGrant
	}
	return *bound, nil
}

// ConsumeRequestPayloadGrantScope is the detailed fail-closed consume path.
// rowKey is the physical row the redemption addresses: the atomic predicate
// matches only a grant bound to exactly that row, so a concurrent sibling, a
// replaced target, or a legacy unbound grant denies without burning the
// token.
func (s *Store) ConsumeRequestPayloadGrantScope(token, orgID, requestID string, rowKey int64, rootID, scope string, now time.Time) (RequestPayloadGrant, error) {
	if s == nil || s.db == nil || token == "" || rowKey <= 0 {
		return RequestPayloadGrant{}, ErrInvalidRequestPayloadGrant
	}
	hash := sha256.Sum256([]byte(token))
	if s.cachedRequestPayloadGrantConsumed(hash, now) {
		return RequestPayloadGrant{}, ErrInvalidRequestPayloadGrant
	}
	ctx := context.Background()
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return RequestPayloadGrant{}, fmt.Errorf("begin payload grant consume: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var grant RequestPayloadGrant
	err = tx.QueryRow(ctx, `
		UPDATE request_payload_grants SET consumed_at=$5
		WHERE token_hash=$1 AND org_id=$2::uuid AND request_id=$3 AND grantee=$4::uuid AND scope=$6
		  AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at > $5
		  AND request_row_key = $7::bigint
		RETURNING id::text, org_id::text, request_id, grantor_root::text, COALESCE(request_row_key, 0), expires_at, scope`,
		hash[:], orgID, requestID, rootID, now, scope, rowKey).Scan(&grant.ID, &grant.OrgID, &grant.RequestID, &grant.RootID, &grant.RowKey, &grant.ExpiresAt, &grant.Scope)
	if err != nil {
		if IsNotFound(err) {
			return RequestPayloadGrant{}, ErrInvalidRequestPayloadGrant
		}
		return RequestPayloadGrant{}, fmt.Errorf("consume payload grant: %w", err)
	}
	// The mandatory use-audit row joins the consume in ONE transaction: a
	// failed or lost audit rolls the consume back too, so the token is never
	// destroyed by an infrastructure failure (a retry of the same token then
	// succeeds once the journal is reachable again).
	if err := appendRequestPayloadGrantAudit(ctx, tx, "request_payload.grant_used", grant, now); err != nil {
		return RequestPayloadGrant{}, fmt.Errorf("audit payload grant use: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return RequestPayloadGrant{}, fmt.Errorf("commit payload grant consume: %w", err)
	}
	// Only a committed consume enters the replay cache.
	s.cacheConsumedRequestPayloadGrant(hash, now)
	return grant, nil
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
	err := s.db.QueryRow(ctx, `UPDATE request_payload_grants SET revoked_at=$3 WHERE token_hash=$1 AND grantor_root=$2::uuid AND revoked_at IS NULL AND consumed_at IS NULL RETURNING id::text, org_id::text, request_id, grantor_root::text, COALESCE(request_row_key, 0), expires_at, scope`, hash[:], rootID, now).Scan(&grant.ID, &grant.OrgID, &grant.RequestID, &grant.RootID, &grant.RowKey, &grant.ExpiresAt, &grant.Scope)
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

// requestPayloadGrantAuditDetail is the journal payload shared by every
// grant lifecycle entry (issue, use, revoke).
type requestPayloadGrantAuditDetail struct {
	GrantID   string `json:"grant_id"`
	OrgID     string `json:"org_id"`
	RequestID string `json:"request_id"`
	RowKey    int64  `json:"row_key"`
	Scope     string `json:"scope"`
	ExpiresAt string `json:"expires_at"`
}

// requestPayloadGrantAuditDetails renders the lifecycle journal details for
// a grant. encoding/json is mandatory: fmt %q emits \x.. byte escapes —
// invalid JSON — for request ids carrying control bytes or invalid UTF-8,
// and the journal must never hold malformed JSON.
func requestPayloadGrantAuditDetails(grant RequestPayloadGrant) (string, error) {
	details, err := json.Marshal(requestPayloadGrantAuditDetail{
		GrantID:   grant.ID,
		OrgID:     grant.OrgID,
		RequestID: grant.RequestID,
		RowKey:    grant.RowKey,
		Scope:     grant.Scope,
		ExpiresAt: grant.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return "", fmt.Errorf("marshal payload grant audit details: %w", err)
	}
	return string(details), nil
}

// auditRequestPayloadGrant journals a grant lifecycle entry through the
// standalone synchronous append (own transaction). Issuance uses it after
// commit with a compensating revoke on failure; consume instead appends via
// appendRequestPayloadGrantAudit inside the consume transaction.
func (s *Store) auditRequestPayloadGrant(ctx context.Context, action string, grant RequestPayloadGrant, now time.Time) error {
	details, err := requestPayloadGrantAuditDetails(grant)
	if err != nil {
		return err
	}
	// One grant, one audit-ID prefix: issuance audits the compact hex id the
	// issuer minted, while consume/revoke read the id back through the uuid
	// column (dashed rendering). Canonicalize so every lifecycle entry of a
	// grant is correlatable by id.
	grantID := strings.ReplaceAll(grant.ID, "-", "")
	return s.InsertAuditLogEntry(ctx, AuditLogEntryRecord{ID: grantID + "-" + action, Action: action, Resource: "request:" + grant.RequestID, Details: details, AdminID: grant.RootID, CreatedAt: now})
}

// appendRequestPayloadGrantAudit appends the same lifecycle entry inside an
// open transaction, coupling the journal row to the state change it records.
func appendRequestPayloadGrantAudit(ctx context.Context, tx auditTx, action string, grant RequestPayloadGrant, now time.Time) error {
	details, err := requestPayloadGrantAuditDetails(grant)
	if err != nil {
		return err
	}
	grantID := strings.ReplaceAll(grant.ID, "-", "")
	return auditlog.AppendInTx(ctx, pgxAppendTx{tx}, auditlog.Entry{
		ID: grantID + "-" + action, Action: action, Resource: "request:" + grant.RequestID,
		Details: details, AdminID: grant.RootID, CreatedAt: now,
	})
}

// ListRequestPayloadGrants returns metadata only; bearer secrets are never
// persisted in or returned from the grant table.
func (s *Store) ListRequestPayloadGrants(ctx context.Context, rootID string) ([]RequestPayloadGrant, error) {
	if s == nil || s.db == nil {
		return nil, ErrRequestPayloadGrantUnavailable
	}
	rows, err := s.db.Query(ctx, `SELECT id::text, org_id::text, COALESCE(request_id,''), grantor_root::text, COALESCE(request_row_key, 0), expires_at, scope FROM request_payload_grants WHERE grantor_root=$1::uuid ORDER BY created_at DESC`, rootID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := []RequestPayloadGrant{}
	for rows.Next() {
		var g RequestPayloadGrant
		if err := rows.Scan(&g.ID, &g.OrgID, &g.RequestID, &g.RootID, &g.RowKey, &g.ExpiresAt, &g.Scope); err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}
