package adminstore

// CM-00-02 persistence leaf: additive per-request dimensional cost-component
// storage and scoped reads over the validated pkg/dimensions contract
// (plans/ui-delivery-20261110/MULTIDIMENSIONAL-ACCOUNTING.md). Leaf scope:
// persist every validated component field and read it back exactly. Dedup
// semantics and correction lineage application are CM-00-03; analytics, API
// wiring and UI are later packets, so this store has no production caller
// yet by design.
//
// Scope policy (IP-SCOPE): the org is server-selected storage scope — the
// caller passes the authenticated org id and every statement runs inside
// withPolicyTx (org GUC + explicit WHERE org_id, the policydecisions.go
// contract; migration 0035 RLS org_isolation is the fail-closed safety
// net). Components carry no org field, so a payload can never choose its
// own storage scope, and no caller input can widen a read: the tenant id is
// a required filter, never an optional one, and reads return only that
// tenant's rows within the org scope.
//
// Decimal carrier policy (IP-METER): quantities and bounds travel as
// canonical decimal text (dimensions.Decimal.String ⇄ ParseDecimal, the
// documented lossless roundtrip). NULL means absent/unknown and can never
// read as zero; an explicit zero is stored as '0'. No float ever touches
// the path.
//
// Replay policy: the (org_id, tenant_id, event_id, component_id) primary
// key makes delivery identity stable, so a duplicate delivery fails loudly
// on the unique key instead of double-counting. Silent dedup semantics are
// CM-00-03.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/reireirei/yabanin/pkg/dimensions"
)

// DimensionalComponentFilters narrows the org+tenant read. Empty strings
// mean "no filter"; values are bound placeholders, never interpolated.
type DimensionalComponentFilters struct {
	EventID     string
	RequestID   string
	ComponentID string
	Meter       string

	PageFilter
}

// withDefaultPage normalizes the page the same way PolicyDecisionFilters
// does, so an unset page cannot turn into a zero LIMIT.
func (f DimensionalComponentFilters) withDefaultPage() DimensionalComponentFilters {
	if f.PageSize > 0 {
		return f
	}
	f.PageFilter = NewPageFilter(f.Page, f.PageSize)
	return f
}

// dimensionalComponentColumns is the canonical explicit SELECT list (the
// explicit-column compatibility pattern: a later migration can never rewrite
// these readers' positional contract). created_at is storage metadata the
// component contract does not carry, so it stays out of the list.
const dimensionalComponentColumns = `tenant_id, event_id, component_id, request_id, task_id,
	meter, unit, quantity_text, bounds_lower_text, bounds_upper_text,
	source_kind, source_ref, method, formula, factor_version,
	event_time, effective_time, boundary, allocation_basis,
	precision_kind, lifecycle, corrects_component_id, coverage_meters`

// dimensionalInsertSQL binds one validated component row, org scope first.
const dimensionalInsertSQL = `INSERT INTO dimensional_components (
	org_id, tenant_id, event_id, component_id, request_id, task_id,
	meter, unit, quantity_text, bounds_lower_text, bounds_upper_text,
	source_kind, source_ref, method, formula, factor_version,
	event_time, effective_time, boundary, allocation_basis,
	precision_kind, lifecycle, corrects_component_id, coverage_meters
) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
	$15, $16, $17, $18, $19, $20, $21, $22, $23, $24)`

// decimalToText maps a component decimal to its stored canonical text; nil
// stays nil (absent/unknown), an explicit zero becomes '0'.
func decimalToText(d *dimensions.Decimal) *string {
	if d == nil {
		return nil
	}
	s := d.String()
	return &s
}

// decimalFromText parses stored canonical text back into an exact Decimal.
// A nil column is absent/unknown; a stored value that no longer parses is a
// corrupted-row error, never a silent zero.
func decimalFromText(s *string) (*dimensions.Decimal, error) {
	if s == nil {
		return nil, nil
	}
	d, err := dimensions.ParseDecimal(*s)
	if err != nil {
		return nil, fmt.Errorf("stored decimal %q: %w", *s, err)
	}
	return &d, nil
}

// dimensionalBoundText extracts one side of the validated bounds; nil bounds
// stay nil on both sides.
func dimensionalBoundText(b *dimensions.Bounds, lower bool) *string {
	if b == nil {
		return nil
	}
	if lower {
		return decimalToText(b.Lower)
	}
	return decimalToText(b.Upper)
}

// dimensionalBounds maps the stored bound texts back. Validated rows always
// carry both sides, so a one-sided stored row surfaces as a one-sided bounds
// value that the component contract's Validate rejects at the end of the
// scan, instead of reading as a silent range.
func dimensionalBounds(lo, hi *string) (*dimensions.Bounds, error) {
	if lo == nil && hi == nil {
		return nil, nil
	}
	lower, err := decimalFromText(lo)
	if err != nil {
		return nil, fmt.Errorf("bounds lower: %w", err)
	}
	upper, err := decimalFromText(hi)
	if err != nil {
		return nil, fmt.Errorf("bounds upper: %w", err)
	}
	return &dimensions.Bounds{Lower: lower, Upper: upper}, nil
}

// coverageOrEmpty maps nil/empty coverage onto the empty-array carrier so a
// non-coverage row never trips the NOT NULL coverage column.
func coverageOrEmpty(m []string) []string {
	if len(m) == 0 {
		return []string{}
	}
	return m
}

// dimensionalInsertArgs binds the org scope followed by the validated
// fields, in the INSERT statement's column order.
func dimensionalInsertArgs(orgID string, c dimensions.Component) []any {
	return []any{
		orgID, c.TenantID, c.EventID, c.ComponentID, c.RequestID, c.TaskID,
		c.Meter, c.Unit, decimalToText(c.Quantity),
		dimensionalBoundText(c.Bounds, true), dimensionalBoundText(c.Bounds, false),
		c.SourceKind, c.SourceRef, c.Method, c.Formula, c.FactorVersion,
		c.EventTime, c.EffectiveTime, c.Boundary, c.AllocationBasis,
		c.Precision, c.Lifecycle, c.CorrectsComponentID, coverageOrEmpty(c.CoverageMeters),
	}
}

// dimensionalWhere renders the always org+tenant-scoped filter clause with
// bound placeholders. The tenant predicate is not optional: a read without
// it is a contract violation, so the builder takes the tenant as a required
// argument rather than as a filter.
func dimensionalWhere(orgID, tenantID string, filters DimensionalComponentFilters) (string, []any) {
	args := []any{orgID, tenantID}
	conditions := []string{"org_id = $1", "tenant_id = $2"}
	add := func(column, value string) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	for _, f := range []struct{ column, value string }{
		{"event_id", filters.EventID},
		{"request_id", filters.RequestID},
		{"component_id", filters.ComponentID},
		{"meter", filters.Meter},
	} {
		if f.value != "" {
			add(f.column, f.value)
		}
	}
	clause := " WHERE org_id = $1 AND tenant_id = $2"
	for _, c := range conditions[2:] {
		clause += " AND " + c
	}
	return clause, args
}

// StoreDimensionalComponents persists every component in one org-scoped
// transaction. Validation happens before any statement: a malformed
// component refuses the whole batch with the named problem and no
// transaction is opened. A statement failure rolls the whole batch back
// (withPolicyTx), so partial persistence is impossible; a replayed delivery
// fails loudly on the unique key.
func (s *Store) StoreDimensionalComponents(ctx context.Context, orgID string, components []dimensions.Component) error {
	if orgID == "" {
		return fmt.Errorf("org id is required")
	}
	for i := range components {
		if err := components[i].Validate(); err != nil {
			return fmt.Errorf("component %d: %w", i, err)
		}
	}
	return s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		for i := range components {
			if err := storeDimensionalComponent(ctx, tx, orgID, components[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

// storeDimensionalComponent inserts one validated component.
func storeDimensionalComponent(ctx context.Context, tx auditTx, orgID string, c dimensions.Component) error {
	if _, err := tx.Exec(ctx, dimensionalInsertSQL, dimensionalInsertArgs(orgID, c)...); err != nil {
		return fmt.Errorf("store dimensional component %q: %w", c.ComponentID, err)
	}
	return nil
}

// ListDimensionalComponents returns one page of the requested tenant's
// components inside the org scope, newest event first, plus the tenant's
// total row count (page metadata like PolicyDecisions).
func (s *Store) ListDimensionalComponents(ctx context.Context, orgID, tenantID string, filters DimensionalComponentFilters) ([]dimensions.Component, int64, error) {
	if orgID == "" || tenantID == "" {
		return nil, 0, fmt.Errorf("org and tenant ids are required")
	}
	filters = filters.withDefaultPage()
	var components []dimensions.Component
	var total int64
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		where, args := dimensionalWhere(orgID, tenantID, filters)
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM dimensional_components`+where, args...).Scan(&total); err != nil {
			return fmt.Errorf("count dimensional components: %w", err)
		}
		return listDimensionalComponents(ctx, tx, where, args, filters, &components)
	})
	if err != nil {
		return nil, 0, err
	}
	if components == nil {
		components = []dimensions.Component{}
	}
	return components, total, nil
}

// listDimensionalComponents pages through the scoped rows in stable order.
func listDimensionalComponents(ctx context.Context, tx auditTx, where string, args []any, filters DimensionalComponentFilters, out *[]dimensions.Component) error {
	listArgs := append(append([]any{}, args...), filters.PageSize, filters.Offset()) //nolint:gocritic // appendCombine: bound filter args stay last by contract
	rows, err := tx.Query(ctx, dimensionalListSQL(where, len(args)), listArgs...)
	if err != nil {
		return fmt.Errorf("list dimensional components: %w", err)
	}
	return collectDimensionalComponents(rows, out)
}

// dimensionalListSQL renders the explicit-column page query; the ORDER BY
// completes the in-scope primary key so page boundaries are deterministic,
// and the LIMIT and OFFSET placeholders follow the bound filter args.
func dimensionalListSQL(where string, boundArgs int) string {
	return `SELECT ` + dimensionalComponentColumns + ` FROM dimensional_components` + where +
		` ORDER BY event_time DESC, event_id DESC, component_id DESC LIMIT $` + fmt.Sprint(boundArgs+1) +
		` OFFSET $` + fmt.Sprint(boundArgs+2)
}

// collectDimensionalComponents scans the page rows.
func collectDimensionalComponents(rows pgx.Rows, out *[]dimensions.Component) error {
	defer rows.Close()
	for rows.Next() {
		c, err := scanDimensionalComponent(rows)
		if err != nil {
			return err
		}
		*out = append(*out, c)
	}
	return rows.Err()
}

// scanDimensionalComponent reconstructs a component from the explicit
// column list; absent quantity/bounds stay nil and coverage normalizes the
// empty array back to nil so the roundtrip preserves absence.
func scanDimensionalComponent(row pgx.Row) (dimensions.Component, error) {
	var c dimensions.Component
	var quantity, lower, upper *string
	var coverage []string
	if err := row.Scan(&c.TenantID, &c.EventID, &c.ComponentID, &c.RequestID, &c.TaskID,
		&c.Meter, &c.Unit, &quantity, &lower, &upper,
		&c.SourceKind, &c.SourceRef, &c.Method, &c.Formula, &c.FactorVersion,
		&c.EventTime, &c.EffectiveTime, &c.Boundary, &c.AllocationBasis,
		&c.Precision, &c.Lifecycle, &c.CorrectsComponentID, &coverage); err != nil {
		return dimensions.Component{}, fmt.Errorf("scan dimensional component: %w", err)
	}
	return buildDimensionalComponent(c, quantity, lower, upper, coverage)
}

// buildDimensionalComponent reassembles the decimal carrier and re-validates
// the reconstructed row against the component contract, so a stored value
// that no longer parses (or a corrupted closed-set value) surfaces as a
// named integrity error instead of reading as a plausible component.
func buildDimensionalComponent(c dimensions.Component, quantity, lower, upper *string, coverage []string) (dimensions.Component, error) {
	q, err := decimalFromText(quantity)
	if err != nil {
		return dimensions.Component{}, err
	}
	c.Quantity = q
	bounds, err := dimensionalBounds(lower, upper)
	if err != nil {
		return dimensions.Component{}, err
	}
	c.Bounds = bounds
	if len(coverage) == 0 {
		coverage = nil
	}
	c.CoverageMeters = coverage
	if err := c.Validate(); err != nil {
		return dimensions.Component{}, fmt.Errorf("stored row fails the component contract: %w", err)
	}
	return c, nil
}
