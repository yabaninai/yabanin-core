// Package dataclass — persistent org-scoped taxonomies (store).
//
// The taxonomy store keeps one row per organization in
// dataclass_taxonomies (migration 0025_dataclass_taxonomies). Reads and
// writes run inside one transaction whose app.current_org GUC is pinned
// to the target org (the pkg/toolpolicy Store.withOrgTx parity): pooled
// connections never leak the binding, and under the non-owner
// application role (yabanin_app, NOBYPASSRLS) the table's org_isolation
// RLS policy makes foreign rows invisible and cross-tenant writes
// rejected — defense in depth under the app-level WHERE org_id = $1
// every statement keeps. The org id is validated (non-empty, UUID)
// BEFORE any database call: the policy casts the GUC to uuid, so a
// malformed id would otherwise surface as a confusing per-row cast
// error instead of a typed refusal.
package dataclass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// DB is the database surface (pgx pool satisfies it; tests mock it).
type DB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Store is the dataclass_taxonomies registry.
type Store struct{ db DB }

// NewStore builds a Store over the DB interface.
func NewStore(db DB) *Store { return &Store{db: db} }

// Typed refusals for org-id problems (checked before any DB call).
var (
	// ErrEmptyOrgID — the caller passed a blank org scope.
	ErrEmptyOrgID = errors.New("dataclass: org id is empty")
	// ErrInvalidOrgID — the org scope is not a UUID (the RLS policy casts
	// app.current_org to uuid; a malformed id can never match a row).
	ErrInvalidOrgID = errors.New("dataclass: org id is not a uuid")
)

// withOrgTx runs fn inside one transaction whose app.current_org GUC is
// pinned to orgID (transaction-local: set_config ... true). Mirrors
// pkg/toolpolicy.Store.withOrgTx — see the package comment.
func (s *Store) withOrgTx(ctx context.Context, orgID string, fn func(tx pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("dataclass: begin org tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID); err != nil {
		return fmt.Errorf("dataclass: bind org rls context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// requireOrgID validates the org scope up front (non-empty, UUID).
func requireOrgID(orgID string) error {
	if orgID == "" {
		return ErrEmptyOrgID
	}
	if _, err := uuid.Parse(orgID); err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidOrgID, orgID)
	}
	return nil
}

// GetTaxonomy returns the org's stored taxonomy. A never-written org gets
// its empty taxonomy (valid by W02-C01's fixed choice) with Version 0
// and found=false — callers distinguish "nothing stored yet" from an
// explicitly stored empty list.
func (s *Store) GetTaxonomy(ctx context.Context, orgID string) (Taxonomy, bool, error) {
	if err := requireOrgID(orgID); err != nil {
		return Taxonomy{}, false, err
	}
	var out Taxonomy
	found := false
	err := s.withOrgTx(ctx, orgID, func(tx pgx.Tx) error {
		var raw []byte
		var version int64
		err := tx.QueryRow(ctx,
			`SELECT labels, version FROM dataclass_taxonomies WHERE org_id = $1`, orgID).
			Scan(&raw, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("dataclass: read taxonomy: %w", err)
		}
		labels, err := unmarshalLabels(raw)
		if err != nil {
			return err
		}
		out = Taxonomy{OrgID: orgID, Labels: labels, Version: version}
		found = true
		return nil
	})
	if err != nil {
		return Taxonomy{}, false, err
	}
	return out, found, nil
}

// PutTaxonomy stores the taxonomy (validated first). The write is
// idempotent: an unchanged label set keeps the stored row and its
// version untouched (changed=false); a real change bumps version by
// exactly one. updated_by records the actor verbatim (the handler passes
// the caller identity; the store does not judge it).
func (s *Store) PutTaxonomy(ctx context.Context, orgID string, t Taxonomy, updatedBy string) (Taxonomy, bool, error) {
	if err := requireOrgID(orgID); err != nil {
		return Taxonomy{}, false, err
	}
	t.OrgID = orgID
	if err := t.Validate(); err != nil {
		return Taxonomy{}, false, err
	}
	stored := t.Canonical()
	raw, err := marshalLabels(stored.Labels)
	if err != nil {
		return Taxonomy{}, false, err
	}

	var out Taxonomy
	var changed bool
	err = s.withOrgTx(ctx, orgID, func(tx pgx.Tx) error {
		var perr error
		out, changed, perr = putTaxonomyTx(ctx, tx, orgID, stored, raw, updatedBy)
		return perr
	})
	if err != nil {
		return Taxonomy{}, false, err
	}
	return out, changed, nil
}

// putTaxonomyTx implements the row's read-compare-write inside the
// caller's org transaction. The initial SELECT ... FOR UPDATE serializes
// concurrent writers per org; the INSERT ... ON CONFLICT DO NOTHING keeps
// the never-written → written race honest (the loser re-reads under the
// row lock and takes the compare path instead of failing).
func putTaxonomyTx(ctx context.Context, tx pgx.Tx, orgID string, t Taxonomy, raw []byte, updatedBy string) (Taxonomy, bool, error) {
	existing, found, err := lockedTaxonomy(ctx, tx, orgID)
	if err != nil {
		return Taxonomy{}, false, err
	}
	if !found {
		var version int64
		err := tx.QueryRow(ctx, `
			INSERT INTO dataclass_taxonomies (org_id, labels, updated_by)
			VALUES ($1, $2, $3)
			ON CONFLICT (org_id) DO NOTHING
			RETURNING version`, orgID, raw, updatedBy).Scan(&version)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// Lost the insert race: the winner's row exists now — fall
			// through to the locked compare path below.
			if existing, found, err = lockedTaxonomy(ctx, tx, orgID); err != nil || !found {
				if err == nil {
					err = fmt.Errorf("dataclass: taxonomy row vanished after insert conflict for org %s", orgID)
				}
				return Taxonomy{}, false, err
			}
		case err != nil:
			return Taxonomy{}, false, fmt.Errorf("dataclass: insert taxonomy: %w", err)
		default:
			return Taxonomy{OrgID: orgID, Labels: t.Labels, Version: version}, true, nil
		}
	}

	// Idempotence: an unchanged label set (canonical compare — W02-C01
	// Taxonomy.Equal ignores Version) keeps the stored row untouched.
	if existing.Equal(t) {
		return existing, false, nil
	}
	var version int64
	if err := tx.QueryRow(ctx, `
		UPDATE dataclass_taxonomies
		SET labels = $2, version = version + 1, updated_at = now(), updated_by = $3
		WHERE org_id = $1
		RETURNING version`, orgID, raw, updatedBy).Scan(&version); err != nil {
		return Taxonomy{}, false, fmt.Errorf("dataclass: update taxonomy: %w", err)
	}
	return Taxonomy{OrgID: orgID, Labels: t.Labels, Version: version}, true, nil
}

// lockedTaxonomy reads the org's row under FOR UPDATE (the row lock that
// serializes the compare-then-bump path).
func lockedTaxonomy(ctx context.Context, tx pgx.Tx, orgID string) (Taxonomy, bool, error) {
	var raw []byte
	var version int64
	err := tx.QueryRow(ctx,
		`SELECT labels, version FROM dataclass_taxonomies WHERE org_id = $1 FOR UPDATE`, orgID).
		Scan(&raw, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Taxonomy{}, false, nil
	}
	if err != nil {
		return Taxonomy{}, false, fmt.Errorf("dataclass: lock taxonomy: %w", err)
	}
	labels, err := unmarshalLabels(raw)
	if err != nil {
		return Taxonomy{}, false, err
	}
	return Taxonomy{OrgID: orgID, Labels: labels, Version: version}, true, nil
}

// marshalLabels renders the label set as the row's jsonb payload.
func marshalLabels(labels []Label) ([]byte, error) {
	if labels == nil {
		labels = []Label{}
	}
	raw, err := json.Marshal(labels)
	if err != nil {
		return nil, fmt.Errorf("dataclass: encode labels: %w", err)
	}
	return raw, nil
}

// unmarshalLabels parses the row's jsonb payload back into labels; a
// NULL column is an empty set (never written through this path).
func unmarshalLabels(raw []byte) ([]Label, error) {
	if len(raw) == 0 {
		return []Label{}, nil
	}
	var labels []Label
	if err := json.Unmarshal(raw, &labels); err != nil {
		return nil, fmt.Errorf("dataclass: decode labels: %w", err)
	}
	if labels == nil {
		labels = []Label{}
	}
	return labels, nil
}
