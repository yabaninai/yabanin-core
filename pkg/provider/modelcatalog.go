package provider

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// This file defines the versioned model catalog: the per-model data model for
// capabilities, limits, pricing and aliases, each carried by an explicit
// effective-dated sell window. The catalog is the single place that decides
// whether a (provider, model) pair is currently sellable, so a model
// withdrawn by its vendor stops being green the moment its window closes —
// even if some static surface (a config fallback, a bundled snapshot, a
// cached picker list) still names it.
//
// Data-model rules:
//   - A snapshot (ModelCatalog) is immutable once built; updates replace the
//     whole snapshot atomically. Readers never see a half-updated catalog.
//   - Every entry is effective-dated with a half-open window
//     [EffectiveFrom, EffectiveTo): a model is pending before the window
//     opens, active inside it, retired from EffectiveTo on. Zero bounds mean
//     "no opinion" on that side.
//   - Pricing reuses the pricing.Price unit semantics (USD per 1M tokens)
//     instead of defining a second price vocabulary; the billing-side price
//     store stays authoritative, the catalog carries the vendor-published
//     list price for sellability and display.
//   - Aliases resolve to a canonical model inside the same provider and
//     inherit the target's window: an alias can never outlive its target.
//
// With no catalog installed every predicate answers "no opinion" and the
// existing behavior (whitelist-driven) is preserved unchanged.

// ModelCapabilities states what a model can do. The vocabulary mirrors the
// owner's modality requirements: image and PDF input, image generation,
// speech transcription and synthesis are release-required modalities;
// realtime audio and video are intentionally absent because they are out of
// release scope, not because they default to false. Extend this struct (and
// the catalog schema version) together — never by repurposing a field.
type ModelCapabilities struct {
	// Chat: text chat / completions served at all.
	Chat bool
	// Streaming: incremental (SSE) output supported.
	Streaming bool
	// Tools: function/tool calling supported upstream.
	Tools bool
	// VisionInput: image parts accepted as input.
	VisionInput bool
	// PDFInput: PDF documents accepted as input parts.
	PDFInput bool
	// AudioInput: audio parts accepted (transcription/understanding).
	AudioInput bool
	// ImageGeneration: the model generates images.
	ImageGeneration bool
	// SpeechTranscription: the model transcribes speech.
	SpeechTranscription bool
	// SpeechSynthesis: the model synthesizes speech.
	SpeechSynthesis bool
	// Embeddings: the model serves embedding vectors.
	Embeddings bool
}

// ModelLimits carries the documented per-model bounds. Zero always means
// "unset in the catalog", never a zero-size limit; negative values are
// rejected at construction.
type ModelLimits struct {
	// ContextWindowTokens: maximum input (prompt) tokens.
	ContextWindowTokens int64
	// MaxOutputTokens: maximum completion tokens per request.
	MaxOutputTokens int64
	// MaxTPM: default tokens-per-minute ceiling (0 = unset).
	MaxTPM int64
	// MaxRPM: default requests-per-minute ceiling (0 = unset).
	MaxRPM int64
}

// ModelCatalogEntry is one versioned catalog row: a (provider, model) pair
// with its aliases, attributes and sell window. Entries are copied into the
// snapshot at construction; later edits to the caller's slices do not affect
// the catalog.
type ModelCatalogEntry struct {
	// Provider is the registry provider name ("openai", "anthropic", ...).
	Provider string
	// Model is the canonical served model name.
	Model string
	// Aliases are alternative names resolving to Model within Provider.
	Aliases []string
	// Capabilities and Limits are the versioned attribute payload.
	Capabilities ModelCapabilities
	Limits       ModelLimits
	// Price is the vendor list price (USD per 1M tokens). PriceListed
	// distinguishes "catalog lists a price" (possibly zero for a free
	// model) from "pricing is owned by the billing-side price store".
	Price       pricing.Price
	PriceListed bool
	// EffectiveFrom/EffectiveTo bound the sell window (half-open).
	// Zero EffectiveFrom = pending-open; zero EffectiveTo = no scheduled
	// retirement.
	EffectiveFrom time.Time
	EffectiveTo   time.Time
	// DeprecatedAt is the announced end-of-life instant: from it on (and
	// while the sell window is still open) the model stays sellable but is
	// flagged deprecated — surfaces must not present it as a plain green
	// recommendation. Zero = not deprecated. A deprecated model is not an
	// unavailable model: requests keep working until EffectiveTo.
	DeprecatedAt time.Time
	// Custom marks a row the vendor snapshot did not carry: it was
	// introduced by a custom override (an org-local or self-hosted model
	// added on top of the vendor catalog). Vendor rows overridden in place
	// stay Custom=false — their identity is still the vendor row.
	Custom bool
}

// Withdrawal records that a provider (all of its models) stops being
// admitted for new traffic at WithdrawnAt. It is the provider-level analog
// of a retired model entry and is enforced at the adapter factory boundary.
type Withdrawal struct {
	Provider    string
	WithdrawnAt time.Time
}

// ModelStatus is the catalog's opinion about a (provider, model) pair at a
// point in time.
type ModelStatus int

const (
	// StatusUnknown reports that the catalog has no row for the pair —
	// no opinion. Callers keep whatever policy they already apply
	// (e.g. whitelists).
	StatusUnknown ModelStatus = iota
	// StatusPending reports that a row exists but its sell window opens
	// in the future.
	StatusPending
	// StatusActive reports that the sell window covers the queried
	// instant.
	StatusActive
	// StatusRetired reports that the sell window has closed — the model
	// is withdrawn and must not be shown as available by any surface.
	StatusRetired
)

func (s ModelStatus) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusActive:
		return "active"
	case StatusRetired:
		return "retired"
	default:
		return "unknown"
	}
}

// ModelCatalogSpec is the input to NewModelCatalog.
type ModelCatalogSpec struct {
	// Version is the operator-assigned catalog revision (opaque string,
	// e.g. a date-based revision or an upstream commit pin).
	Version string
	// SchemaVersion pins the data vocabulary (capabilities fields, price
	// layout). Consumers must refuse snapshots whose schema they do not
	// understand; bump when the vocabulary changes.
	SchemaVersion int
	// Source names where the snapshot came from (for provenance reports).
	Source string
	// AsOf is the snapshot publication instant (zero = unset).
	AsOf time.Time
	// Entries are the per-model rows.
	Entries []ModelCatalogEntry
	// Withdrawals are the provider-level delist rows.
	Withdrawals []Withdrawal
}

// ModelCatalog is an immutable, validated catalog snapshot. All lookup
// methods are safe for concurrent use and nil-receiver safe: a nil
// *ModelCatalog behaves like "no catalog installed" (no opinion, no
// rejection).
type ModelCatalog struct {
	version       string
	schemaVersion int
	source        string
	asOf          time.Time

	entries     []ModelCatalogEntry
	byExact     map[string]int // provider:model -> entries index
	byAlias     map[string]int // provider:alias -> entries index
	withdrawals map[string]time.Time
}

// NewModelCatalog validates spec and returns an immutable snapshot. The
// validation is strict on purpose: ambiguous snapshots (duplicate models or
// aliases, aliases shadowing model names, duplicate provider withdrawals,
// inverted windows, negative bounds) are rejected instead of resolved
// silently.
func NewModelCatalog(spec ModelCatalogSpec) (*ModelCatalog, error) {
	if strings.TrimSpace(spec.Version) == "" {
		return nil, fmt.Errorf("model catalog: version is required")
	}
	if spec.SchemaVersion < 1 {
		return nil, fmt.Errorf("model catalog: schema version must be >= 1, got %d", spec.SchemaVersion)
	}
	if strings.TrimSpace(spec.Source) == "" {
		return nil, fmt.Errorf("model catalog: source is required")
	}

	cat := &ModelCatalog{
		version:       strings.TrimSpace(spec.Version),
		schemaVersion: spec.SchemaVersion,
		source:        strings.TrimSpace(spec.Source),
		asOf:          spec.AsOf,
		byExact:       make(map[string]int, len(spec.Entries)),
		byAlias:       make(map[string]int),
		withdrawals:   make(map[string]time.Time, len(spec.Withdrawals)),
	}
	if spec.Entries != nil {
		cat.entries = make([]ModelCatalogEntry, 0, len(spec.Entries))
	}

	for i, e := range spec.Entries {
		e.Provider = strings.TrimSpace(e.Provider)
		e.Model = strings.TrimSpace(e.Model)
		if e.Provider == "" || e.Model == "" {
			return nil, fmt.Errorf("model catalog: entries[%d]: provider and model are required", i)
		}
		if !e.EffectiveFrom.IsZero() && !e.EffectiveTo.IsZero() && e.EffectiveTo.Before(e.EffectiveFrom) {
			return nil, fmt.Errorf("model catalog: entries[%d] (%s:%s): sell window closes before it opens",
				i, e.Provider, e.Model)
		}
		if err := validateDeprecation(e); err != nil {
			return nil, fmt.Errorf("model catalog: entries[%d] (%s:%s): %w", i, e.Provider, e.Model, err)
		}
		if err := validateLimits(e.Limits); err != nil {
			return nil, fmt.Errorf("model catalog: entries[%d] (%s:%s): %w", i, e.Provider, e.Model, err)
		}
		if err := validatePrice(e.Price, e.PriceListed); err != nil {
			return nil, fmt.Errorf("model catalog: entries[%d] (%s:%s): %w", i, e.Provider, e.Model, err)
		}

		key := e.Provider + ":" + e.Model
		if _, dup := cat.byExact[key]; dup {
			return nil, fmt.Errorf("model catalog: entries[%d]: duplicate entry for %s", i, key)
		}
		aliases := make([]string, 0, len(e.Aliases))
		for _, a := range e.Aliases {
			a = strings.TrimSpace(a)
			if a == "" {
				return nil, fmt.Errorf("model catalog: entries[%d] (%s): empty alias", i, key)
			}
			if a == e.Model {
				return nil, fmt.Errorf("model catalog: entries[%d] (%s): alias %q shadows the model name", i, key, a)
			}
			aliasKey := e.Provider + ":" + a
			if _, dup := cat.byAlias[aliasKey]; dup {
				return nil, fmt.Errorf("model catalog: entries[%d] (%s): duplicate alias %q", i, key, a)
			}
			if _, dup := cat.byExact[aliasKey]; dup {
				return nil, fmt.Errorf("model catalog: entries[%d] (%s): alias %q collides with an existing model name", i, key, a)
			}
			cat.byAlias[aliasKey] = len(cat.entries)
			aliases = append(aliases, a)
		}
		e.Aliases = aliases
		cat.byExact[key] = len(cat.entries)
		cat.entries = append(cat.entries, e)
	}

	// The per-entry alias checks above cannot see model names declared
	// later in the spec, so every alias is re-checked against the complete
	// name set once all rows are registered.
	for i, e := range cat.entries {
		for _, a := range e.Aliases {
			if _, clash := cat.byExact[e.Provider+":"+a]; clash {
				return nil, fmt.Errorf("model catalog: entries[%d] (%s:%s): alias %q collides with an existing model name", i, e.Provider, e.Model, a)
			}
		}
	}

	for i, w := range spec.Withdrawals {
		w.Provider = strings.TrimSpace(w.Provider)
		if w.Provider == "" {
			return nil, fmt.Errorf("model catalog: withdrawals[%d]: provider is required", i)
		}
		if w.WithdrawnAt.IsZero() {
			return nil, fmt.Errorf("model catalog: withdrawals[%d] (%s): withdrawal date is required", i, w.Provider)
		}
		if _, dup := cat.withdrawals[w.Provider]; dup {
			return nil, fmt.Errorf("model catalog: withdrawals[%d]: duplicate withdrawal for provider %s", i, w.Provider)
		}
		cat.withdrawals[w.Provider] = w.WithdrawnAt
	}
	return cat, nil
}

// Withdrawal validation and attribute validation report findings in a fixed
// field order: the slices below are the single source of that order, so the
// same broken spec always produces the same first error (map iteration
// order must never decide which finding an operator sees).
var limitFields = []struct {
	name  string
	value func(ModelLimits) int64
}{
	{"context_window_tokens", func(l ModelLimits) int64 { return l.ContextWindowTokens }},
	{"max_output_tokens", func(l ModelLimits) int64 { return l.MaxOutputTokens }},
	{"max_tpm", func(l ModelLimits) int64 { return l.MaxTPM }},
	{"max_rpm", func(l ModelLimits) int64 { return l.MaxRPM }},
}

var priceFields = []struct {
	name  string
	value func(pricing.Price) float64
}{
	{"input", func(p pricing.Price) float64 { return p.InputPerM }},
	{"output", func(p pricing.Price) float64 { return p.OutputPerM }},
	{"cache_write", func(p pricing.Price) float64 { return p.CacheWritePerM }},
	{"cache_read", func(p pricing.Price) float64 { return p.CacheReadPerM }},
}

func validateLimits(l ModelLimits) error {
	for _, f := range limitFields {
		if v := f.value(l); v < 0 {
			return fmt.Errorf("limit %s must not be negative (%d)", f.name, v)
		}
	}
	return nil
}

// validateDeprecation keeps the deprecation instant a meaningful phase
// *inside* the sell window: announcing end-of-life before the window opens
// (the model would be born deprecated) or after it closed (the flag could
// never be observed) is rejected instead of silently accepted. The half-open
// window puts DeprecatedAt == EffectiveTo outside the observable range, so
// that too is rejected.
func validateDeprecation(e ModelCatalogEntry) error {
	if e.DeprecatedAt.IsZero() {
		return nil
	}
	if !e.EffectiveFrom.IsZero() && e.DeprecatedAt.Before(e.EffectiveFrom) {
		return fmt.Errorf("deprecation instant %s precedes the sell window opening %s",
			e.DeprecatedAt.Format(time.RFC3339), e.EffectiveFrom.Format(time.RFC3339))
	}
	if !e.EffectiveTo.IsZero() && !e.DeprecatedAt.Before(e.EffectiveTo) {
		return fmt.Errorf("deprecation instant %s is not before the sell window closing %s",
			e.DeprecatedAt.Format(time.RFC3339), e.EffectiveTo.Format(time.RFC3339))
	}
	return nil
}

func validatePrice(p pricing.Price, listed bool) error {
	if !listed {
		return nil
	}
	for _, f := range priceFields {
		v := f.value(p)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("price %s must be a finite number (%v)", f.name, v)
		}
		if v < 0 {
			return fmt.Errorf("price %s must not be negative (%v)", f.name, v)
		}
	}
	return nil
}

// Version reports the operator-assigned catalog revision ("" without a
// catalog). SchemaVersion, Source and AsOf expose the remaining snapshot
// metadata. Like every other method Version is nil-receiver safe: a nil
// *ModelCatalog reports the zero value, consistent with "no catalog
// installed".
func (c *ModelCatalog) Version() string {
	if c == nil {
		return ""
	}
	return c.version
}

// SchemaVersion reports the pinned data vocabulary version (0 without a
// catalog).
func (c *ModelCatalog) SchemaVersion() int {
	if c == nil {
		return 0
	}
	return c.schemaVersion
}

// Source reports where the snapshot came from ("" without a catalog).
func (c *ModelCatalog) Source() string {
	if c == nil {
		return ""
	}
	return c.source
}

// AsOf reports the snapshot publication instant (zero time without a
// catalog).
func (c *ModelCatalog) AsOf() time.Time {
	if c == nil {
		return time.Time{}
	}
	return c.asOf
}

// EntryCount reports the number of model rows (0 without a catalog).
func (c *ModelCatalog) EntryCount() int {
	if c == nil {
		return 0
	}
	return len(c.entries)
}

// resolve returns the entry for the pair, following aliases, plus the index
// used. Exact names win over aliases.
func (c *ModelCatalog) resolve(provider, model string) (ModelCatalogEntry, bool) {
	if c == nil || provider == "" || model == "" {
		return ModelCatalogEntry{}, false
	}
	if idx, ok := c.byExact[provider+":"+model]; ok {
		return c.entries[idx], true
	}
	if idx, ok := c.byAlias[provider+":"+model]; ok {
		return c.entries[idx], true
	}
	return ModelCatalogEntry{}, false
}

// statusAt classifies an entry against a half-open sell window.
func statusAt(e ModelCatalogEntry, at time.Time) ModelStatus {
	if !e.EffectiveFrom.IsZero() && at.Before(e.EffectiveFrom) {
		return StatusPending
	}
	if !e.EffectiveTo.IsZero() && !at.Before(e.EffectiveTo) {
		return StatusRetired
	}
	return StatusActive
}

// Lookup returns the entry for (provider, model) — exact name first, then
// alias — together with its status at the given instant. An unknown pair
// yields StatusUnknown and a zero entry. An alias resolves to its target
// entry, so a retired target reports StatusRetired through any of its
// aliases: an alias cannot resurrect a withdrawn model.
func (c *ModelCatalog) Lookup(provider, model string, at time.Time) (ModelCatalogEntry, ModelStatus) {
	e, ok := c.resolve(provider, model)
	if !ok {
		return ModelCatalogEntry{}, StatusUnknown
	}
	return e, statusAt(e, at)
}

// Status reports the model status at the given instant (Lookup without the
// entry payload).
func (c *ModelCatalog) Status(provider, model string, at time.Time) ModelStatus {
	_, st := c.Lookup(provider, model, at)
	return st
}

// ResolveAlias maps an alias to its canonical model name and reports the
// target's status. Unknown aliases yield an empty name and StatusUnknown.
func (c *ModelCatalog) ResolveAlias(provider, alias string, at time.Time) (string, ModelStatus) {
	e, st := c.Lookup(provider, alias, at)
	if st == StatusUnknown {
		return "", StatusUnknown
	}
	return e.Model, st
}

// Capabilities returns the capability set when the model is active at the
// given instant; otherwise ok is false (pending, retired and unknown models
// expose no capabilities).
func (c *ModelCatalog) Capabilities(provider, model string, at time.Time) (ModelCapabilities, bool) {
	e, st := c.Lookup(provider, model, at)
	if st != StatusActive {
		return ModelCapabilities{}, false
	}
	return e.Capabilities, true
}

// PricingKey returns the canonical (provider, model) pair to feed into a
// pricing lookup once the model is active at the given instant. The
// billing-side price store stays authoritative for costs; this only resolves
// aliases so price lookups land on the canonical name. The returned provider
// is the registry name — the pricing layer applies its own catalog-namespace
// aliases on miss.
func (c *ModelCatalog) PricingKey(provider, model string, at time.Time) (string, string, bool) {
	e, st := c.Lookup(provider, model, at)
	if st != StatusActive {
		return "", "", false
	}
	return e.Provider, e.Model, true
}

// Deprecated reports whether the model is in its announced end-of-life
// phase at the given instant: the deprecation instant has arrived, the sell
// window is still open, and the provider is not withdrawn. A deprecated
// model is still sellable — it must keep working — but it is flagged, and
// surfaces must render the flag instead of a plain green recommendation.
// A retired model is never "deprecated": retirement dominates.
func (c *ModelCatalog) Deprecated(provider, model string, at time.Time) bool {
	e, st := c.Lookup(provider, model, at)
	if st != StatusActive || e.DeprecatedAt.IsZero() {
		return false
	}
	return !at.Before(e.DeprecatedAt) && c.ProviderAdmitted(provider, at)
}

// PickerVisible decides picker visibility for one model, combining the
// catalog opinion with the visibility the existing per-key policy (e.g. the
// whitelist) already computed:
//   - StatusRetired → never visible, even when the static/key policy says
//     visible. Withdrawal from the catalog wins over every static list.
//   - StatusPending → not visible: the catalog knows the model is not
//     sellable yet.
//   - StatusActive and StatusUnknown → defer to keyVisible. The catalog
//     never widens visibility the key policy denied, and it never fabricates
//     an opinion about models it has no row for (custom and org-local
//     models stay governed by their own policy).
func (c *ModelCatalog) PickerVisible(provider, model string, at time.Time, keyVisible bool) bool {
	switch c.Status(provider, model, at) {
	case StatusRetired, StatusPending:
		return false
	default:
		return keyVisible
	}
}

// PickerRow is one picker candidate: the model identity plus the visibility
// the per-key policy already assigned.
type PickerRow struct {
	Provider   string
	Model      string
	KeyVisible bool
	// Deprecated is filled in by FilterVisible for rows it keeps: the
	// model is sellable but inside its announced end-of-life phase. A
	// deprecated row stays visible (hiding it would break working
	// clients) — the flag lets the picker render it as deprecated instead
	// of green. Retired and pending rows never survive the filter.
	Deprecated bool
}

// FilterVisible applies PickerVisible to a row set, preserving order, and
// annotates the surviving rows with their deprecation flag. With no catalog
// installed (nil receiver) the rows pass through unchanged.
func (c *ModelCatalog) FilterVisible(rows []PickerRow, at time.Time) []PickerRow {
	if c == nil {
		return rows
	}
	out := make([]PickerRow, 0, len(rows))
	for _, r := range rows {
		if c.PickerVisible(r.Provider, r.Model, at, r.KeyVisible) {
			r.Deprecated = c.Deprecated(r.Provider, r.Model, at)
			out = append(out, r)
		}
	}
	return out
}

// ProviderAdmitted reports whether the provider may still be instantiated at
// the given instant. Providers without a withdrawal row are admitted: the
// catalog records exits, not memberships, so adding a provider never
// requires a catalog edit.
func (c *ModelCatalog) ProviderAdmitted(name string, at time.Time) bool {
	if c == nil {
		return true
	}
	w, ok := c.withdrawals[strings.TrimSpace(name)]
	if !ok {
		return true
	}
	return at.Before(w)
}

// ModelLifecycle is the four-state lifecycle vocabulary for surfaces that
// present model availability: discovered, configured, tested, unavailable.
// Its purpose is anti-drift: instead of one collapsed "available" bit, a
// surface renders which distinct state a (provider, model) pair is in, so a
// name the vendor withdrew shows up as unavailable even when every static
// surface still lists it as green.
type ModelLifecycle int

const (
	// LifecycleDiscovered means the catalog knows the name, but the
	// installation neither configures nor serves it yet.
	LifecycleDiscovered ModelLifecycle = iota
	// LifecycleConfigured means the installation lists the model for
	// serving; no verification result is recorded.
	LifecycleConfigured
	// LifecycleTested means the installation serves the model and its
	// latest verification passed.
	LifecycleTested
	// LifecycleUnavailable means the model is not sellable now — its sell
	// window has not opened yet or has closed, or its provider carries an
	// active withdrawal.
	LifecycleUnavailable
)

func (l ModelLifecycle) String() string {
	switch l {
	case LifecycleDiscovered:
		return "discovered"
	case LifecycleConfigured:
		return "configured"
	case LifecycleTested:
		return "tested"
	case LifecycleUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// Lifecycle classifies one (provider, model) pair into the four-state
// lifecycle vocabulary at the given instant, given the installation facts:
// configured (the installation lists it for serving) and tested (its latest
// verification passed).
//
// Catalog withdrawal dominates every installation fact: a pair whose sell
// window is pending or closed, or whose provider carries an active
// withdrawal, reports LifecycleUnavailable even when configured and tested —
// a delisted model never stays green because a static list still names it.
// For a pair the catalog has no row for, the installation facts decide
// (tested over configured over discovered), so custom and org-local models
// keep the pre-catalog behavior. Asking about a name with no catalog row and
// no installation fact yields LifecycleDiscovered; such a name carries no
// facts and belongs in no report — callers filter it out.
//
// Nil-receiver safe: without a catalog installed the facts decide.
func (c *ModelCatalog) Lifecycle(provider, model string, at time.Time, configured, tested bool) ModelLifecycle {
	if !c.ProviderAdmitted(provider, at) {
		return LifecycleUnavailable
	}
	switch c.Status(provider, model, at) {
	case StatusPending, StatusRetired:
		return LifecycleUnavailable
	default:
		switch {
		case tested:
			return LifecycleTested
		case configured:
			return LifecycleConfigured
		default:
			return LifecycleDiscovered
		}
	}
}

// Entry returns a copy of the entry stored under (provider, model), following
// aliases, without a status evaluation. Ok is false for unknown pairs.
func (c *ModelCatalog) Entry(provider, model string) (ModelCatalogEntry, bool) {
	e, ok := c.resolve(provider, model)
	if !ok {
		return ModelCatalogEntry{}, false
	}
	e.Aliases = append([]string(nil), e.Aliases...)
	return e, true
}

// Entries returns copies of every entry in construction order. Without a
// catalog installed it returns nil.
func (c *ModelCatalog) Entries() []ModelCatalogEntry {
	if c == nil {
		return nil
	}
	out := make([]ModelCatalogEntry, len(c.entries))
	for i, e := range c.entries {
		e.Aliases = append([]string(nil), e.Aliases...)
		out[i] = e
	}
	return out
}

// Withdrawals returns copies of the provider-level delist rows, sorted by
// provider name so repeated calls observe one order. Without a catalog
// installed it returns nil.
func (c *ModelCatalog) Withdrawals() []Withdrawal {
	if c == nil {
		return nil
	}
	out := make([]Withdrawal, 0, len(c.withdrawals))
	for name, at := range c.withdrawals {
		out = append(out, Withdrawal{Provider: name, WithdrawnAt: at})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

// ModelOverride is one custom-catalog row applied on top of an installed
// vendor snapshot. It is how an installation reconciles vendor drift with
// local reality without forking the vendor data:
//
//   - an override for a (provider, model) pair the vendor catalog knows
//     adjusts that row: capabilities, limits and aliases are replaced when
//     present (the operator's explicit set is authoritative — restate what
//     must survive), and the sell window can only be narrowed;
//   - an override for a pair the vendor catalog does not know introduces a
//     custom model (org-local, self-hosted proxy, vendor-undocumented
//     name): it defines its own attributes and window and is marked
//     Custom in the merged snapshot.
//
// Narrowing is the load-bearing rule: the merged window is the intersection
// of the vendor window and the override window (EffectiveFrom moves only
// later, EffectiveTo only earlier), and a deprecation instant can only move
// earlier. A vendor snapshot that has retired a model therefore stays
// retired under any override — a stale custom override cannot resurrect a
// model the vendor withdrew, which is the drift the catalog exists to kill.
//
// Overrides never touch pricing: the billing-side price store stays
// authoritative for costs (Price/PriceListed always come from the vendor
// row, and custom rows list no price).
type ModelOverride struct {
	// Provider and Model name the pair (or the new custom model). Required.
	Provider string
	Model    string
	// Aliases: nil keeps the vendor aliases; a non-nil slice replaces
	// them. Custom rows take them as their alias set.
	Aliases []string
	// Capabilities: nil keeps the vendor set; non-nil replaces it.
	Capabilities *ModelCapabilities
	// Limits: nil keeps the vendor limits; non-nil replaces them.
	Limits *ModelLimits
	// EffectiveFrom/EffectiveTo narrow the vendor window (zero = no
	// opinion on that side); on a custom row they define the window.
	EffectiveFrom time.Time
	EffectiveTo   time.Time
	// DeprecatedAt flags end-of-life from this instant. It can only move
	// a deprecation earlier: when the vendor row already carries a
	// deprecation, the earlier instant wins.
	DeprecatedAt time.Time
}

// ApplyOverrides merges the overrides onto the vendor snapshot and returns a
// new immutable catalog; the base snapshot is left untouched. Installation
// stays atomic: install the returned snapshot with SetModelCatalog when the
// whole set is accepted. The merged snapshot inherits the base metadata
// (version, source, schema, as-of); the identity of what was merged on top
// is carried by the deployment (e.g. the document fingerprint).
//
// The merge is validated with the same strictness as NewModelCatalog, over
// the merged name space: duplicate overrides for one pair, aliases colliding
// with model names (vendor or custom), inverted or empty-window overrides on
// custom rows, and deprecation instants outside the merged window are all
// errors — nothing is silently repaired. The base catalog must not be nil:
// a purely custom catalog (no vendor snapshot) is a plain NewModelCatalog
// construction.
func ApplyOverrides(base *ModelCatalog, ovs []ModelOverride) (*ModelCatalog, error) {
	if base == nil {
		return nil, fmt.Errorf("model catalog: ApplyOverrides requires a base catalog")
	}

	entries := base.Entries() // deep copies; the base cannot be mutated
	index := make(map[string]int, len(entries))
	for i, e := range entries {
		index[e.Provider+":"+e.Model] = i
	}

	seen := make(map[string]struct{}, len(ovs))
	for i, ov := range ovs {
		ov.Provider = strings.TrimSpace(ov.Provider)
		ov.Model = strings.TrimSpace(ov.Model)
		if ov.Provider == "" || ov.Model == "" {
			return nil, fmt.Errorf("model catalog: overrides[%d]: provider and model are required", i)
		}
		key := ov.Provider + ":" + ov.Model
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("model catalog: overrides[%d]: duplicate override for %s", i, key)
		}
		seen[key] = struct{}{}
		if !ov.EffectiveFrom.IsZero() && !ov.EffectiveTo.IsZero() && ov.EffectiveTo.Before(ov.EffectiveFrom) {
			return nil, fmt.Errorf("model catalog: overrides[%d] (%s): override window closes before it opens", i, key)
		}

		idx, known := index[key]
		if !known {
			// Custom model: the override defines the row outright.
			e := ModelCatalogEntry{
				Provider:      ov.Provider,
				Model:         ov.Model,
				Aliases:       ov.Aliases,
				DeprecatedAt:  ov.DeprecatedAt,
				EffectiveFrom: ov.EffectiveFrom,
				EffectiveTo:   ov.EffectiveTo,
				Custom:        true,
			}
			if ov.Capabilities != nil {
				e.Capabilities = *ov.Capabilities
			}
			if ov.Limits != nil {
				e.Limits = *ov.Limits
			}
			if err := validateDeprecation(e); err != nil {
				return nil, fmt.Errorf("model catalog: overrides[%d] (%s): %w", i, key, err)
			}
			entries = append(entries, e)
			index[key] = len(entries) - 1
			continue
		}

		// Vendor row: replace explicit attributes, narrow the window.
		e := entries[idx]
		if ov.Aliases != nil {
			e.Aliases = ov.Aliases
		}
		if ov.Capabilities != nil {
			e.Capabilities = *ov.Capabilities
		}
		if ov.Limits != nil {
			e.Limits = *ov.Limits
		}
		if !ov.EffectiveFrom.IsZero() && ov.EffectiveFrom.After(e.EffectiveFrom) {
			e.EffectiveFrom = ov.EffectiveFrom
		}
		if !ov.EffectiveTo.IsZero() && (e.EffectiveTo.IsZero() || ov.EffectiveTo.Before(e.EffectiveTo)) {
			e.EffectiveTo = ov.EffectiveTo
		}
		if !ov.DeprecatedAt.IsZero() && (e.DeprecatedAt.IsZero() || ov.DeprecatedAt.Before(e.DeprecatedAt)) {
			e.DeprecatedAt = ov.DeprecatedAt
		}
		if err := validateDeprecation(e); err != nil {
			return nil, fmt.Errorf("model catalog: overrides[%d] (%s): merged row violates the deprecation window: %w", i, key, err)
		}
		entries[idx] = e
	}

	merged, err := NewModelCatalog(ModelCatalogSpec{
		Version:       base.Version(),
		SchemaVersion: base.SchemaVersion(),
		Source:        base.Source(),
		AsOf:          base.AsOf(),
		Entries:       entries,
		Withdrawals:   base.Withdrawals(),
	})
	if err != nil {
		return nil, fmt.Errorf("model catalog: merged catalog with %d override(s): %w", len(ovs), err)
	}
	return merged, nil
}

// currentModelCatalog holds the installed process-wide snapshot. The pointer
// type is stable, so atomic.Value can carry successive snapshots directly.
var currentModelCatalog atomic.Value // *ModelCatalog

// SetModelCatalog installs (or, with nil, removes) the process-wide catalog
// snapshot. Installation is atomic: concurrent readers observe either the
// old or the new snapshot, never a mix.
func SetModelCatalog(c *ModelCatalog) {
	currentModelCatalog.Store(c)
}

// CurrentModelCatalog returns the installed snapshot or nil when none is
// installed.
func CurrentModelCatalog() *ModelCatalog {
	c, _ := currentModelCatalog.Load().(*ModelCatalog)
	return c
}

// ProviderAdmitted consults the installed catalog (time.Now). With no
// catalog installed it answers true, preserving pre-catalog behavior at the
// factory boundary.
func ProviderAdmitted(name string) bool { //nolint:revive // the package-level stutter mirrors the (*ModelCatalog).ProviderAdmitted predicate; the name is published API consumed by the factory, renaming is deferred to the API-stability review
	return CurrentModelCatalog().ProviderAdmitted(name, time.Now())
}
