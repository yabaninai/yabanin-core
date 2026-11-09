// Persistent store for the observable asset registry (E02-P01 W01-C02).
//
// The production home of the table DDL is migration
// 0022_inventory_assets (migrations/ and pkg/migrate/migrations/);
// EnsureSchema below is the idempotent bootstrap for SPI and test stands
// and is a no-op once the migration has run (its DDL mirrors migration
// 0022 plus IF NOT EXISTS) — the same posture as pkg/secevents.
//
// Import semantics: UpsertAssets classifies every row of one import batch
// atomically (single transaction) into created/updated/unchanged — the
// WHERE clause on the conflict arm fires only when payload, source,
// confidence or last_seen actually differ (or the row was tombstoned), so
// a re-import of identical upstream state reports unchanged and touches
// nothing. first_seen is monotonic (LEAST) and last_seen monotonic
// (GREATEST): a re-import never moves the discovery stamp backwards. A
// pure first_seen refinement with everything else identical counts as
// unchanged — counts describe observable registry change, not internal
// stamp bookkeeping.
//
// Absence of observations is NOT absence of the asset: nothing here
// deletes or tombstones rows; tombstones happen only through the explicit
// TombstoneAssets signal of an import adapter (a tool missing from a
// listing), and a later re-import resurrects the row (tombstone cleared,
// classified as updated).

package inventory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// DB is the minimal database surface Store needs. It is satisfied
// directly by *pgxpool.Pool and *pgx.Tx (the production connection
// surfaces) without a wrapper.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// schemaSQL creates the registry table. The production home is migration
// 0022_inventory_assets; this bootstrap (with IF NOT EXISTS) serves SPI
// and test stands.
const schemaSQL = `CREATE TABLE IF NOT EXISTS inventory_assets (
	org_id        TEXT        NOT NULL,
	asset_key     TEXT        NOT NULL,
	kind          TEXT        NOT NULL,
	payload       JSONB       NOT NULL,
	source        TEXT        NOT NULL,
	confidence    TEXT        NOT NULL,
	first_seen    TIMESTAMPTZ NOT NULL,
	last_seen     TIMESTAMPTZ NOT NULL,
	tombstone     BOOLEAN     NOT NULL DEFAULT false,
	tombstoned_at TIMESTAMPTZ,
	PRIMARY KEY (org_id, asset_key, kind),
	CONSTRAINT chk_inventory_assets_kind CHECK (kind = ANY (ARRAY['agent'::text, 'service'::text, 'mcp_server'::text, 'tool'::text, 'model'::text, 'provider'::text])),
	CONSTRAINT chk_inventory_assets_confidence CHECK (confidence = ANY (ARRAY['high'::text, 'low'::text])),
	CONSTRAINT chk_inventory_assets_tombstone CHECK (NOT tombstone OR tombstoned_at IS NOT NULL)
)`

const liveIndexSQL = `CREATE INDEX IF NOT EXISTS idx_inventory_assets_live ON inventory_assets (org_id, kind, last_seen DESC) WHERE NOT tombstone`

// upsertSQL is the classified import write: one statement per row. On
// conflict the update arm fires only for a real change (see the WHERE);
// xmax = 0 identifies a freshly inserted row (created) versus an updated
// one, and no returned row at all means unchanged.
const upsertSQL = `INSERT INTO inventory_assets
	(org_id, asset_key, kind, payload, source, confidence, first_seen, last_seen)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	ON CONFLICT (org_id, asset_key, kind) DO UPDATE SET
		payload        = EXCLUDED.payload,
		source         = EXCLUDED.source,
		confidence     = EXCLUDED.confidence,
		first_seen     = LEAST(inventory_assets.first_seen, EXCLUDED.first_seen),
		last_seen      = GREATEST(inventory_assets.last_seen, EXCLUDED.last_seen),
		tombstone      = false,
		tombstoned_at  = NULL
	WHERE inventory_assets.payload IS DISTINCT FROM EXCLUDED.payload
	   OR inventory_assets.source IS DISTINCT FROM EXCLUDED.source
	   OR inventory_assets.confidence IS DISTINCT FROM EXCLUDED.confidence
	   OR inventory_assets.last_seen IS DISTINCT FROM EXCLUDED.last_seen
	   OR inventory_assets.tombstone
	RETURNING (xmax = 0) AS created`

const tombstoneSQL = `UPDATE inventory_assets
	SET tombstone = true, tombstoned_at = $4
	WHERE org_id = $1 AND kind = $2 AND asset_key = ANY($3) AND NOT tombstone
	RETURNING 1`

const listSQL = `SELECT org_id, asset_key, kind, payload, source, confidence, first_seen, last_seen,
		tombstone, COALESCE(tombstoned_at, 'epoch'::timestamptz)
	FROM inventory_assets
	WHERE org_id = $1
	  AND ($2::text IS NULL OR kind = $2::text)
	  AND ($3::text IS NULL OR (kind, asset_key) > ($3::text, $4::text))
	  AND ($5::bool OR NOT tombstone)
	ORDER BY kind, asset_key
	LIMIT $6`

const getSQL = `SELECT org_id, asset_key, kind, payload, source, confidence, first_seen, last_seen,
		tombstone, COALESCE(tombstoned_at, 'epoch'::timestamptz)
	FROM inventory_assets
	WHERE org_id = $1 AND asset_key = $2 AND kind = $3`

// ImportCounts reports what an import batch did. Created+Updated+Unchanged
// equals the number of input rows on success.
type ImportCounts struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
}

// ListParams controls ListAssets. Zero Limit means the default page; the
// limit is clamped to MaxPageSize. After is an opaque cursor from a
// previous page (empty string starts from the beginning). IncludeTombstoned
// adds tombstoned rows to the page (the default listing is the live
// registry).
type ListParams struct {
	Kind              AssetKind
	After             string
	Limit             int
	IncludeTombstoned bool
}

// MaxPageSize is the hard upper bound for one listing page.
const MaxPageSize = 500

const defaultPageSize = 100

// cursorSep separates kind and asset_key inside a cursor. Asset keys
// reject control characters (Validate), so the separator cannot occur
// inside either part.
const cursorSep = "\x1f"

// Row is one registry row as read back: the Asset write model plus the
// tombstone state (zero time = live row).
type Row struct {
	Asset
	Tombstone    bool      `json:"tombstone"`
	TombstonedAt time.Time `json:"tombstoned_at,omitempty"`
}

// Store persists registry assets. Safe for concurrent use when the DB is
// (pools and transactions are).
type Store struct {
	db DB
}

// NewStore wraps db with the registry access layer.
func NewStore(db DB) *Store { return &Store{db: db} }

// EnsureSchema creates the registry table if it is missing. In production
// the table comes from migration 0022_inventory_assets; this bootstrap is
// for SPI and test stands.
func (s *Store) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("inventory: ensure schema: %w", err)
	}
	if _, err := s.db.Exec(ctx, liveIndexSQL); err != nil {
		return fmt.Errorf("inventory: ensure schema index: %w", err)
	}
	return nil
}

// UpsertAssets imports one batch atomically: every row is validated first
// (all-or-nothing on model contract violations), then written in a single
// transaction, each classified as created/updated/unchanged.
func (s *Store) UpsertAssets(ctx context.Context, assets []Asset) (ImportCounts, error) {
	var counts ImportCounts
	if len(assets) == 0 {
		return counts, nil // empty upstream: no-op success, registry untouched
	}
	for i := range assets {
		if err := assets[i].Validate(); err != nil {
			return counts, fmt.Errorf("inventory: import batch row %d: %w", i, err)
		}
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return counts, fmt.Errorf("inventory: import begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for i := range assets {
		a := &assets[i]
		rows, err := tx.Query(ctx, upsertSQL,
			a.OrgID, a.AssetKey, string(a.Kind), []byte(a.Payload), string(a.Source),
			string(a.Confidence), a.FirstSeen, a.LastSeen)
		if err != nil {
			return counts, fmt.Errorf("inventory: import row %d (%s): %w", i, a.AssetKey, err)
		}
		created, seen := false, false
		for rows.Next() {
			seen = true
			if err := rows.Scan(&created); err != nil {
				rows.Close()
				return counts, fmt.Errorf("inventory: import row %d (%s): scan: %w", i, a.AssetKey, err)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return counts, fmt.Errorf("inventory: import row %d (%s): %w", i, a.AssetKey, err)
		}
		rows.Close()
		switch {
		case !seen:
			counts.Unchanged++
		case created:
			counts.Created++
		default:
			counts.Updated++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return counts, fmt.Errorf("inventory: import commit: %w", err)
	}
	return counts, nil
}

// TombstoneAssets marks the listed keys of one org+kind tombstoned at the
// given time. Rows already tombstoned (or absent) are no-ops; the return
// is how many rows flipped this call. Resurrection happens by re-import
// (UpsertAssets clears tombstone).
func (s *Store) TombstoneAssets(ctx context.Context, orgID string, kind AssetKind, at time.Time, keys []string) (int, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	rows, err := s.db.Query(ctx, tombstoneSQL, orgID, string(kind), keys, at)
	if err != nil {
		return 0, fmt.Errorf("inventory: tombstone: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	if err := rows.Err(); err != nil {
		return n, fmt.Errorf("inventory: tombstone: %w", err)
	}
	return n, nil
}

// ListAssets returns one deterministic page of the org registry in
// (kind, asset_key) order, plus the cursor for the next page (empty when
// the end is reached).
func (s *Store) ListAssets(ctx context.Context, orgID string, p ListParams) ([]Row, string, error) {
	if orgID == "" {
		return nil, "", errors.New("inventory: list: org_id is required")
	}
	limit := p.Limit
	if limit <= 0 {
		limit = defaultPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}
	var kindPtr *string
	if p.Kind != "" {
		if !ValidAssetKind(p.Kind) {
			return nil, "", fmt.Errorf("inventory: list: unknown kind %q", p.Kind)
		}
		k := string(p.Kind)
		kindPtr = &k
	}
	var afterKind, afterKey *string
	if p.After != "" {
		k, key, err := decodeCursor(p.After)
		if err != nil {
			return nil, "", fmt.Errorf("inventory: list: cursor: %w", err)
		}
		afterKind, afterKey = &k, &key
	}
	rows, err := s.db.Query(ctx, listSQL, orgID, kindPtr, afterKind, afterKey, p.IncludeTombstoned, limit+1)
	if err != nil {
		return nil, "", fmt.Errorf("inventory: list: %w", err)
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		var kind string
		var payload []byte
		if err := rows.Scan(&r.OrgID, &r.AssetKey, &kind, &payload, &r.Source, &r.Confidence,
			&r.FirstSeen, &r.LastSeen, &r.Tombstone, &r.TombstonedAt); err != nil {
			return nil, "", fmt.Errorf("inventory: list: scan: %w", err)
		}
		r.Kind = AssetKind(kind)
		r.Payload = payload
		if !r.Tombstone {
			r.TombstonedAt = time.Time{}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("inventory: list: %w", err)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		next = encodeCursor(string(last.Kind), last.AssetKey)
	}
	return out, next, nil
}

// GetAsset fetches one asset by its full key. found is false when the
// (org, key, kind) triple has no row — including tombstoned rows, which
// are returned with their tombstone state.
func (s *Store) GetAsset(ctx context.Context, orgID string, kind AssetKind, assetKey string) (Row, bool, error) {
	var r Row
	var k string
	var payload []byte
	err := s.db.QueryRow(ctx, getSQL, orgID, assetKey, string(kind)).
		Scan(&r.OrgID, &r.AssetKey, &k, &payload, &r.Source, &r.Confidence,
			&r.FirstSeen, &r.LastSeen, &r.Tombstone, &r.TombstonedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Row{}, false, nil
	}
	if err != nil {
		return Row{}, false, fmt.Errorf("inventory: get: %w", err)
	}
	r.Kind = AssetKind(k)
	r.Payload = payload
	if !r.Tombstone {
		r.TombstonedAt = time.Time{}
	}
	return r, true, nil
}

func encodeCursor(kind, key string) string { return kind + cursorSep + key }

func decodeCursor(c string) (kind, key string, err error) {
	i := strings.Index(c, cursorSep)
	if i <= 0 || i == len(c)-1 {
		return "", "", errors.New("malformed cursor")
	}
	return c[:i], c[i+len(cursorSep):], nil
}
