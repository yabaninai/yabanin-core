package pricing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Yabanin-local reference catalog schema (CORE-REF-01, status
// authorized_preview).
//
// This file defines the typed vocabulary for a Yabanin-owned reference
// snapshot of model prices and metering units. The built-in Catalog is
// independently assembled by Yabanin from primary
// provider sources and verified contractual rates, never invented and never a
// rename of someone else's catalog.
//
// Design contracts (from plans/enterprise-beta-next-5000h/
// REFERENCE-MATERIALS-AUDIT.md §Целевая модель):
//
//   - Missing ≠ free. A rate is one of: absent (the entry does not price
//     this axis), explicitly unpriced (Amount=nil: the axis is known but no
//     verified price exists), or a number (0 is a legitimate explicit free).
//     Nothing in the schema may collapse these states into a silent 0.
//   - Every entry is effective-dated with a half-open window
//     [EffectiveFrom, EffectiveTo). Empty bound = open on that side.
//   - Every entry carries provenance: at least one primary source (provider
//     URL or internal evidence ID), a verification instant and a reviewer.
//   - Source conflicts are explicit: disagreeing observations are kept as
//     Evidence on the rate and must be resolved by recording which source
//     was chosen and why; validation refuses an unresolved conflict.
//   - Deactivation is a first-class status (retired); an entry can also be
//     draft (not yet serveable) before its window opens.
//   - The snapshot carries schema version, catalog version and a digest over
//     its canonical form; Supersedes links the rollback chain to the
//     snapshot it replaces.
//   - Public list prices are the only thing this schema describes. Client
//     actuals (quotes, ledger) and contractual overrides (reseller_pricing)
//     are separate data planes and deliberately have no fields here.
//
// The bundled snapshots are NOT rewritten by this file — the schema, its
// validation, conversion adapters and the consumer inventory are CORE-REF-01;
// populating a real Yabanin catalog is CORE-REF-02 and later.
// pkg/pricing/SCHEMA.md is the normative prose for this vocabulary.

// RefSchemaVersion is the schema version of the reference-catalog vocabulary.
// Bump on any non-additive change; consumers must refuse snapshots whose
// schema they do not understand.
const RefSchemaVersion = 1

// Entry lifecycle statuses (RefModel.Status).
const (
	// RefStatusDraft: assembled but not reviewed/released; never serveable.
	RefStatusDraft = "draft"
	// RefStatusActive: reviewed and released; serveable inside its window.
	RefStatusActive = "active"
	// RefStatusRetired: deactivated by Yabanin (or the vendor exit);
	// never serveable regardless of the window.
	RefStatusRetired = "retired"
)

// Metering axes (RefRate.Axis). The set is closed: an unknown axis is a
// validation error, never silently dropped — a silently ignored axis would
// price a billable dimension at zero (parity with unitKinds).
const (
	// AxisInput / AxisOutput / AxisCacheWrite / AxisCacheRead are the token
	// axes, priced per 1M tokens.
	AxisInput      = "input"
	AxisOutput     = "output"
	AxisCacheWrite = "cache_write"
	AxisCacheRead  = "cache_read"
	// AxisAudioSecond is input audio duration (transcription).
	AxisAudioSecond = "audio_second"
	// AxisCharacter is input character count (text-to-speech).
	AxisCharacter = "character"
	// AxisImage is generated image count (images API).
	AxisImage = "image"
)

// Unit denominators (RefRate.Unit). Values are byte-compatible with the
// existing snapshot vocabulary ("per_1m_tokens", UnitPerAudioSecond, ...)
// so conversion adapters stay 1:1.
const (
	// RefUnitPer1MTokens is the token-axis denominator. gosec G101 flags
	// the identifier's "Token" substring; this is a metering-unit
	// vocabulary string, not a credential.
	RefUnitPer1MTokens    = "per_1m_tokens"    // #nosec G101
	RefUnitPerAudioSecond = UnitPerAudioSecond // "per_second_audio"
	RefUnitPerCharacter   = UnitPerCharacter   // "per_character"
	RefUnitPerImage       = UnitPerImage       // "per_image"
)

// axisUnits pairs every axis with the single unit that may price it. The
// pairing is part of the schema contract: a rate whose unit does not match
// its axis is a validation error (mixed units are expressed as multiple
// rates on one entry, not as one rate with a foreign unit).
var axisUnits = map[string]string{
	AxisInput:       RefUnitPer1MTokens,
	AxisOutput:      RefUnitPer1MTokens,
	AxisCacheWrite:  RefUnitPer1MTokens,
	AxisCacheRead:   RefUnitPer1MTokens,
	AxisAudioSecond: RefUnitPerAudioSecond,
	AxisCharacter:   RefUnitPerCharacter,
	AxisImage:       RefUnitPerImage,
}

// CanonicalAxes is the stable axis order used for canonical rendering and
// digesting (token axes first, then non-token axes, matching the canonical
// QuoteLine order input → output → cache_write → cache_read).
var CanonicalAxes = []string{
	AxisInput, AxisOutput, AxisCacheWrite, AxisCacheRead,
	AxisAudioSecond, AxisCharacter, AxisImage,
}

// RefAxisUnit returns the unit that may price the axis and whether the axis
// is part of the closed vocabulary at all.
func RefAxisUnit(axis string) (unit string, ok bool) {
	unit, ok = axisUnits[axis]
	return unit, ok
}

// RefSourceKind distinguishes where a piece of evidence came from.
const (
	// RefSourceURL: a primary provider source reachable by URL.
	RefSourceURL = "url"
	// RefSourceInternalEvidence: a Yabanin-internal evidence record
	// (contract, verified screenshot archive, support ticket digest).
	RefSourceInternalEvidence = "internal_evidence"
)

// Catalog is one immutable reference snapshot: a complete, reviewed set of
// model entries plus the metadata that makes it auditable and revertible.
// A Catalog value must be treated as read-only after validation; the digest
// is computed over the canonical form (CanonicalCatalogJSON) so any content
// change invalidates the fingerprint.
type Catalog struct {
	// SchemaVersion must equal RefSchemaVersion for this consumer.
	SchemaVersion int `json:"schema_version"`
	// Version is the operator-assigned catalog revision (opaque string).
	Version string `json:"version"`
	// GeneratedAt is the assembly instant (RFC 3339 or YYYY-MM-DD).
	GeneratedAt string `json:"generated_at"`
	// Supersedes is the digest of the snapshot this one replaces (rollback
	// chain). Empty for a genesis snapshot. Validated by
	// ValidateCatalogChain against the previous snapshot's actual digest.
	Supersedes string `json:"supersedes,omitempty"`
	// Digest is the SHA256 hex over CanonicalCatalogJSON of this snapshot
	// (with Digest itself excluded). Computed by the producer; loaders must
	// verify it instead of trusting the field.
	Digest string `json:"digest,omitempty"`
	// Source names how the snapshot was assembled (tool, operator, run).
	Source string `json:"source"`
	// Reviewer names the human who approved the snapshot ("" = unreviewed,
	// draft only).
	Reviewer string `json:"reviewer,omitempty"`
	// ReviewSLADays is the maximum age a model's VerifiedAt may reach
	// before re-review is due (0 = no SLA configured). Entries past the SLA
	// are reported by StaleModels but are not automatically invalid.
	ReviewSLADays int `json:"review_sla_days,omitempty"`
	// Models are the per-model entries, canonical order (provider, model).
	Models []RefModel `json:"models"`
}

// RefModel is one reference entry: a stable (provider, model) identity with
// its aliases, applicability bounds, priced axes and provenance.
type RefModel struct {
	// Provider is the stable provider ID (registry namespace, e.g. "openai").
	Provider string `json:"provider"`
	// Model is the stable canonical model ID (the served name).
	Model string `json:"model"`
	// Aliases are alternative names that resolve to Model within Provider.
	// Aliases never carry their own rates: an alias lookup resolves to the
	// target entry's identity (an identical model never inherits a price
	// through an alias of a different entry).
	Aliases []string `json:"aliases,omitempty"`
	// Region scopes the entry ("" = global). A provider may quote different
	// list prices per region; each region is its own entry.
	Region string `json:"region,omitempty"`
	// Tier scopes the entry within provider/region ("" = standard tier).
	Tier string `json:"tier,omitempty"`
	// ContextBand is the coarse context-size class the entry applies to
	// ("" = unclassified / single band). Providers that price by context
	// size get one entry per band.
	ContextBand string `json:"context_band,omitempty"`
	// Currency is the ISO-4217 code of every rate in this entry.
	Currency string `json:"currency"`
	// Rates are the priced axes. At most one rate per axis; absent axis =
	// not priced by this entry.
	Rates []RefRate `json:"rates,omitempty"`
	// EffectiveFrom opens the applicability window (RFC 3339 or YYYY-MM-DD;
	// "" = open / no lower bound). Half-open [EffectiveFrom, EffectiveTo).
	EffectiveFrom string `json:"effective_from,omitempty"`
	// EffectiveTo closes the applicability window ("" = no scheduled end).
	EffectiveTo string `json:"effective_to,omitempty"`
	// VerifiedAt is the instant the entry's facts were last verified
	// against its sources (RFC 3339 or YYYY-MM-DD; "" = never verified,
	// draft only).
	VerifiedAt string `json:"verified_at,omitempty"`
	// Sources are the primary-source evidence records backing the entry.
	// At least one is required for an active entry.
	Sources []RefSource `json:"sources"`
	// Reviewer names who verified/approved this entry ("" = unreviewed).
	Reviewer string `json:"reviewer,omitempty"`
	// Status is the lifecycle status (draft/active/retired).
	Status string `json:"status"`
	// Conflicts record resolved source disagreements (one per axis).
	Conflicts []RefConflict `json:"conflicts,omitempty"`
}

// RefRate is one priced axis of an entry.
type RefRate struct {
	// Axis is the metering axis (closed vocabulary, see CanonicalAxes).
	Axis string `json:"axis"`
	// Unit is the rate denominator; must be the axis's paired unit.
	Unit string `json:"unit"`
	// Amount is the unit price in the entry's Currency. nil = explicitly
	// unpriced (the axis is known but no verified price exists — never
	// treated as free). A present value must be finite and non-negative;
	// 0 is a legitimate explicit free.
	Amount *float64 `json:"amount"`
	// Evidence records the per-source observations backing the amount.
	// Two observations of the same axis with different amounts are a
	// conflict: validation requires the conflict to be resolved by choosing
	// Amount equal to one observation and recording a RefConflict.
	Evidence []RefEvidence `json:"evidence,omitempty"`
}

// RefEvidence is one source's observation of a rate.
type RefEvidence struct {
	// Ref is the source reference (URL or internal evidence ID) and must
	// match one of the entry's Sources.
	Ref string `json:"ref"`
	// Amount is the value that source stated (entry Currency, rate Unit).
	Amount float64 `json:"amount"`
	// At is when the observation was made (RFC 3339 or YYYY-MM-DD).
	At string `json:"at,omitempty"`
}

// RefSource is a primary-source record for an entry.
type RefSource struct {
	// Kind is RefSourceURL or RefSourceInternalEvidence.
	Kind string `json:"kind"`
	// Ref is the URL or internal evidence ID.
	Ref string `json:"ref"`
	// VerifiedAt is when this source was consulted (RFC 3339 or YYYY-MM-DD).
	VerifiedAt string `json:"verified_at,omitempty"`
	// Note is an optional human annotation.
	Note string `json:"note,omitempty"`
}

// RefConflict records the resolution of a source disagreement on one axis.
type RefConflict struct {
	// Axis is the disagreeing axis.
	Axis string `json:"axis"`
	// Ref is the evidence reference whose amount was chosen. Must match one
	// of the entry's Sources and one Evidence amount on the axis.
	Ref string `json:"ref"`
	// Reason is the human justification for the choice (required).
	Reason string `json:"reason"`
}

// refTimeLayouts are the accepted instant formats: exact timestamps and
// bare dates (operator-authored snapshots), parity with the upstream
// catalog document.
var refTimeLayouts = []string{time.RFC3339, "2006-01-02"}

// parseRefTime accepts RFC 3339 or a bare YYYY-MM-DD date.
func parseRefTime(s string) (time.Time, error) {
	for _, layout := range refTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("not an RFC 3339 instant or YYYY-MM-DD date")
}

// ValidateRefTime reports whether s is empty or a well-formed schema instant.
func ValidateRefTime(s string) error {
	if s == "" {
		return nil
	}
	if _, err := parseRefTime(s); err != nil {
		return err
	}
	return nil
}

// CatalogProblem is one validation finding, located by JSON pointer-ish
// path (models[3].rates[0]).
type CatalogProblem struct {
	Path    string
	Message string
}

func (p CatalogProblem) Error() string { return p.Path + ": " + p.Message }

// CatalogError aggregates every validation finding so an operator fixes the
// whole snapshot at once. The snapshot is rejected if any finding exists.
type CatalogError struct {
	Problems []CatalogProblem
}

func (e *CatalogError) Error() string {
	parts := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		parts[i] = p.Error()
	}
	return fmt.Sprintf("invalid reference catalog: %s", strings.Join(parts, "; "))
}

// refProblemCollector accumulates findings in declaration order.
type refProblemCollector struct {
	problems []CatalogProblem
}

func (c *refProblemCollector) add(path, format string, args ...any) {
	c.problems = append(c.problems, CatalogProblem{Path: path, Message: fmt.Sprintf(format, args...)})
}

func (c *refProblemCollector) err() error {
	if len(c.problems) == 0 {
		return nil
	}
	return &CatalogError{Problems: c.problems}
}

// ValidateCatalog checks structural and semantic soundness of a reference
// snapshot. Everything is reported at once; any finding rejects the whole
// snapshot. A snapshot that passes validation is still not automatically
// serveable: entries additionally need Status=active, an in-force window and
// (for production traffic) a non-stale review.
func ValidateCatalog(c Catalog) error {
	var pc refProblemCollector

	if c.SchemaVersion != RefSchemaVersion {
		pc.add("schema_version", "must be %d, got %d", RefSchemaVersion, c.SchemaVersion)
	}
	if strings.TrimSpace(c.Version) == "" {
		pc.add("version", "catalog version is required")
	}
	if strings.TrimSpace(c.Source) == "" {
		pc.add("source", "assembly source is required")
	}
	if err := ValidateRefTime(c.GeneratedAt); err != nil {
		pc.add("generated_at", "%v", err)
	}
	if c.Supersedes != "" && !isDigestHex(c.Supersedes) {
		pc.add("supersedes", "must be a 64-hex digest, got %q", c.Supersedes)
	}
	if c.Digest != "" && !isDigestHex(c.Digest) {
		pc.add("digest", "must be a 64-hex digest, got %q", c.Digest)
	}
	if c.Digest != "" {
		want, err := CatalogDigest(c)
		if err != nil {
			pc.add("digest", "canonical form: %v", err)
		} else if want != c.Digest {
			pc.add("digest", "does not match content (want %s)", want)
		}
	}
	if c.ReviewSLADays < 0 {
		pc.add("review_sla_days", "must not be negative (%d)", c.ReviewSLADays)
	}

	seenIdentity := make(map[string]int, len(c.Models))
	seenAlias := make(map[string]int, len(c.Models))
	for i := range c.Models {
		validateModel(&pc, i, &c.Models[i], seenIdentity, seenAlias)
	}
	return pc.err()
}

// validateModel checks one model entry and registers its identity and
// aliases in the catalog-wide namespaces (first occurrence wins). The
// per-concern helpers must run in this exact order: problems are reported
// in declaration order and the identity namespaces are order-sensitive.
func validateModel(pc *refProblemCollector, i int, m *RefModel, seenIdentity, seenAlias map[string]int) {
	where := fmt.Sprintf("models[%d]", i)
	if strings.TrimSpace(m.Provider) == "" {
		pc.add(where+".provider", "provider is required")
	}
	if strings.TrimSpace(m.Model) == "" {
		pc.add(where+".model", "model is required")
	}
	if m.Provider == "" || m.Model == "" {
		return
	}
	validateModelIdentity(pc, where, i, m, seenIdentity, seenAlias)
	validateModelStatus(pc, where, m)
	validateModelWindow(pc, where, m)
	validateModelReview(pc, where, m)
	validateModelAliases(pc, where, i, m, seenIdentity, seenAlias)
	seenAxis := make(map[string]int, len(m.Rates))
	for j := range m.Rates {
		validateRate(pc, fmt.Sprintf("%s.rates[%d]", where, j), j, &m.Rates[j], seenAxis)
	}
	seenSource := validateModelSources(pc, where, m)
	validateModelConflicts(pc, where, m, seenSource)
	validateConflictCompleteness(pc, where, m)
}

// validateModelIdentity registers (or rejects) the entry's identity in the
// catalog-wide namespace. An identity that duplicates an earlier entry or
// collides with an earlier alias is reported and NOT registered, so the
// first occurrence keeps serving later checks.
func validateModelIdentity(pc *refProblemCollector, where string, i int, m *RefModel, seenIdentity, seenAlias map[string]int) {
	key := m.Provider + "\x00" + m.Model
	if prev, dup := seenIdentity[key]; dup {
		pc.add(where, "duplicate entry for %s:%s (first at models[%d])", m.Provider, m.Model, prev)
	} else if _, aliasOf := seenAlias[key]; aliasOf {
		pc.add(where, "model name %q collides with an existing alias in %s", m.Model, m.Provider)
	} else {
		seenIdentity[key] = i
	}
}

// validateModelStatus checks the lifecycle status and the currency scope.
func validateModelStatus(pc *refProblemCollector, where string, m *RefModel) {
	switch m.Status {
	case RefStatusDraft, RefStatusActive, RefStatusRetired:
	default:
		pc.add(where+".status", "must be draft, active or retired, got %q", m.Status)
	}
	if strings.ToUpper(strings.TrimSpace(m.Currency)) != "USD" {
		// v1 scope: the reference vocabulary is USD-only until multi-currency
		// resource accounting lands; refusing other codes now prevents a
		// silent unit mismatch later.
		pc.add(where+".currency", "must be USD, got %q", m.Currency)
	}
}

// validateModelWindow checks the applicability window: both bounds must be
// well-formed schema instants, and a closed window must open strictly
// before it closes (half-open [EffectiveFrom, EffectiveTo)).
func validateModelWindow(pc *refProblemCollector, where string, m *RefModel) {
	if err := ValidateRefTime(m.EffectiveFrom); err != nil {
		pc.add(where+".effective_from", "%v", err)
	}
	if err := ValidateRefTime(m.EffectiveTo); err != nil {
		pc.add(where+".effective_to", "%v", err)
	}
	if from, errFrom := parseRefTime(m.EffectiveFrom); errFrom == nil {
		if to, errTo := parseRefTime(m.EffectiveTo); errTo == nil && !to.After(from) {
			pc.add(where, "effective window closes at or before it opens (%s >= %s)", m.EffectiveTo, m.EffectiveFrom)
		}
	}
}

// validateModelReview checks the review provenance an active entry must
// carry: a verification instant and at least one primary source. Draft and
// retired entries are exempt.
func validateModelReview(pc *refProblemCollector, where string, m *RefModel) {
	if err := ValidateRefTime(m.VerifiedAt); err != nil {
		pc.add(where+".verified_at", "%v", err)
	}
	if m.VerifiedAt == "" && m.Status == RefStatusActive {
		pc.add(where+".verified_at", "an active entry must carry a verification instant")
	}
	if m.Status == RefStatusActive && len(m.Sources) == 0 {
		pc.add(where+".sources", "an active entry needs at least one primary source")
	}
}

// validateModelAliases checks and registers the entry's aliases in the
// provider namespace. Aliases resolve by exact string match (ResolveModel),
// so what validates is exactly what resolves: no padding, no shadowing the
// model's own name, no collisions with earlier models or aliases.
func validateModelAliases(pc *refProblemCollector, where string, i int, m *RefModel, seenIdentity, seenAlias map[string]int) {
	for j, a := range m.Aliases {
		apath := fmt.Sprintf("%s.aliases[%d]", where, j)
		trimmed := strings.TrimSpace(a)
		if trimmed == "" {
			pc.add(apath, "alias is empty")
			continue
		}
		if trimmed != a {
			// A stored " x" would validate as "x" yet never resolve as
			// "x". Reject instead of normalizing the caller's slice.
			pc.add(apath, "alias %q must not have leading or trailing whitespace", a)
			continue
		}
		if a == m.Model {
			pc.add(apath, "alias %q shadows the model name", a)
			continue
		}
		aliasKey := m.Provider + "\x00" + a
		if prev, dup := seenAlias[aliasKey]; dup {
			pc.add(apath, "duplicate alias %q for %s (first at models[%d])", a, m.Provider, prev)
			continue
		}
		if _, collides := seenIdentity[aliasKey]; collides {
			pc.add(apath, "alias %q collides with an existing model name in %s", a, m.Provider)
			continue
		}
		seenAlias[aliasKey] = i
	}
}

// validateModelSources checks the primary-source records and returns the
// set of source refs the entry declared (conflict resolutions must name one
// of them).
func validateModelSources(pc *refProblemCollector, where string, m *RefModel) map[string]struct{} {
	seenSource := make(map[string]struct{}, len(m.Sources))
	for j, s := range m.Sources {
		spath := fmt.Sprintf("%s.sources[%d]", where, j)
		switch s.Kind {
		case RefSourceURL, RefSourceInternalEvidence:
		default:
			pc.add(spath+".kind", "must be %q or %q, got %q", RefSourceURL, RefSourceInternalEvidence, s.Kind)
		}
		if strings.TrimSpace(s.Ref) == "" {
			pc.add(spath+".ref", "source ref is required")
			continue
		}
		if _, dup := seenSource[s.Ref]; dup {
			pc.add(spath+".ref", "duplicate source ref %q", s.Ref)
		}
		seenSource[s.Ref] = struct{}{}
		if err := ValidateRefTime(s.VerifiedAt); err != nil {
			pc.add(spath+".verified_at", "%v", err)
		}
	}
	return seenSource
}

// validateModelConflicts checks the declared conflict resolutions: known
// axis, a reason, and a ref naming one of the entry's declared sources.
func validateModelConflicts(pc *refProblemCollector, where string, m *RefModel, seenSource map[string]struct{}) {
	for j, cf := range m.Conflicts {
		cpath := fmt.Sprintf("%s.conflicts[%d]", where, j)
		if _, known := axisUnits[cf.Axis]; !known {
			pc.add(cpath+".axis", "unknown axis %q", cf.Axis)
		}
		if strings.TrimSpace(cf.Ref) == "" {
			pc.add(cpath+".ref", "conflict resolution needs the chosen source ref")
		} else if _, ok := seenSource[cf.Ref]; !ok {
			pc.add(cpath+".ref", "chosen source %q is not one of the entry's sources", cf.Ref)
		}
		if strings.TrimSpace(cf.Reason) == "" {
			pc.add(cpath+".reason", "conflict resolution needs a reason")
		}
	}
}

// validateConflictCompleteness enforces that every axis whose evidence
// disagrees carries a resolution naming an amount the evidence actually
// observed.
func validateConflictCompleteness(pc *refProblemCollector, where string, m *RefModel) {
	for j := range m.Rates {
		r := &m.Rates[j]
		if !rateEvidenceConflicts(r) {
			continue
		}
		if rateConflictResolved(r, m.Conflicts) {
			continue
		}
		pc.add(fmt.Sprintf("%s.rates[%d]", where, j),
			"conflicting evidence on axis %q without a resolution choosing one observed amount", r.Axis)
	}
}

// rateConflictResolved reports whether one of the declared resolutions
// chooses the rate's amount from an observation on the conflicting axis.
func rateConflictResolved(r *RefRate, conflicts []RefConflict) bool {
	for _, cf := range conflicts {
		if cf.Axis != r.Axis || r.Amount == nil {
			continue
		}
		for _, ev := range r.Evidence {
			if ev.Ref == cf.Ref && sameRefAmount(ev.Amount, *r.Amount) {
				return true
			}
		}
	}
	return false
}

func validateRate(pc *refProblemCollector, where string, idx int, r *RefRate, seenAxis map[string]int) {
	unit, known := axisUnits[r.Axis]
	if !known {
		pc.add(where+".axis", "unknown axis %q", r.Axis)
	} else if r.Unit != unit {
		pc.add(where+".unit", "axis %q must use unit %q, got %q", r.Axis, unit, r.Unit)
	}
	if prev, dup := seenAxis[r.Axis]; dup {
		pc.add(where+".axis", "duplicate rate for axis %q (first at rates[%d])", r.Axis, prev)
	} else {
		seenAxis[r.Axis] = idx
	}
	if r.Amount != nil {
		v := *r.Amount
		if math.IsNaN(v) || math.IsInf(v, 0) {
			pc.add(where+".amount", "not a finite number (%v)", v)
		} else if v < 0 {
			pc.add(where+".amount", "negative price %v", v)
		}
	}
	seenEvidence := make(map[string]struct{}, len(r.Evidence))
	for k, ev := range r.Evidence {
		epath := fmt.Sprintf("%s.evidence[%d]", where, k)
		if strings.TrimSpace(ev.Ref) == "" {
			pc.add(epath+".ref", "evidence ref is required")
		}
		if _, dup := seenEvidence[ev.Ref]; dup {
			pc.add(epath+".ref", "duplicate evidence ref %q", ev.Ref)
		}
		seenEvidence[ev.Ref] = struct{}{}
		if math.IsNaN(ev.Amount) || math.IsInf(ev.Amount, 0) {
			pc.add(epath+".amount", "not a finite number (%v)", ev.Amount)
		} else if ev.Amount < 0 {
			pc.add(epath+".amount", "negative price %v", ev.Amount)
		}
		if err := ValidateRefTime(ev.At); err != nil {
			pc.add(epath+".at", "%v", err)
		}
	}
}

// rateEvidenceConflicts reports whether the evidence set contains two
// observations of the same axis with different amounts.
func rateEvidenceConflicts(r *RefRate) bool {
	for i := 0; i < len(r.Evidence); i++ {
		for j := i + 1; j < len(r.Evidence); j++ {
			if !sameRefAmount(r.Evidence[i].Amount, r.Evidence[j].Amount) {
				return true
			}
		}
	}
	return false
}

// sameRefAmount compares two observed amounts at the schema's storage
// precision (1e-12, mirroring roundUnitPrice): sources that differ only by
// sub-picodollar rounding noise agree.
func sameRefAmount(a, b float64) bool {
	return math.Round(a*1e12) == math.Round(b*1e12)
}

func isDigestHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// RateAmount returns the priced amount for an axis and whether the entry
// prices it at all. ok=false covers both "axis absent" and "explicitly
// unpriced (Amount=nil)" — callers must treat unpriced as unknown, never as
// free. Use Rate for the full distinction.
func RateAmount(m RefModel, axis string) (amount float64, priced bool) {
	r, ok := Rate(m, axis)
	if !ok || r.Amount == nil {
		return 0, false
	}
	return *r.Amount, true
}

// Rate returns the entry's rate record for an axis. ok=false when the axis
// is absent from the entry.
func Rate(m RefModel, axis string) (RefRate, bool) {
	for _, r := range m.Rates {
		if r.Axis == axis {
			return r, true
		}
	}
	return RefRate{}, false
}

// EntryEffective reports whether the entry's half-open window
// [EffectiveFrom, EffectiveTo) covers the instant. Empty bounds are open on
// that side.
func EntryEffective(m RefModel, at time.Time) bool {
	if from, err := parseRefTime(m.EffectiveFrom); err == nil && at.Before(from) {
		return false
	}
	if to, err := parseRefTime(m.EffectiveTo); err == nil && !at.Before(to) {
		return false
	}
	return true
}

// EntryServeable reports whether the entry may price production traffic at
// the instant: status active AND window in force. Draft entries are never
// serveable (unreviewed); retired entries are never serveable regardless of
// a still-open window (deactivation dominates the window).
func EntryServeable(m RefModel, at time.Time) bool {
	return m.Status == RefStatusActive && EntryEffective(m, at)
}

// ResolveModel maps (provider, name) to the canonical entry, exact name
// first, then alias. An alias yields its target entry: aliases never carry
// their own rates, so the identical model keeps one identity's price.
func ResolveModel(c Catalog, provider, name string) (RefModel, bool) {
	for i := range c.Models {
		if c.Models[i].Provider == provider && c.Models[i].Model == name {
			return c.Models[i], true
		}
	}
	for i := range c.Models {
		if c.Models[i].Provider != provider {
			continue
		}
		for _, a := range c.Models[i].Aliases {
			if a == name {
				return c.Models[i], true
			}
		}
	}
	return RefModel{}, false
}

// StaleModels returns the active entries whose VerifiedAt is older than the
// catalog's review SLA (or that never carry a verification instant). An
// empty SLA means no re-review is due and the result is empty. Staleness is
// an operational signal, not a validation failure.
func StaleModels(c Catalog, now time.Time) []string {
	if c.ReviewSLADays <= 0 {
		return nil
	}
	var stale []string
	for _, m := range c.Models {
		if m.Status != RefStatusActive {
			continue
		}
		if m.VerifiedAt == "" {
			stale = append(stale, m.Provider+":"+m.Model)
			continue
		}
		v, err := parseRefTime(m.VerifiedAt)
		if err != nil || v.AddDate(0, 0, c.ReviewSLADays).Before(now) {
			stale = append(stale, m.Provider+":"+m.Model)
		}
	}
	return stale
}

// canonicalCatalog is the digest input form: the catalog with its Digest
// field cleared and every ordering normalized (models by (provider, model,
// region, tier, context_band); aliases, rates by canonical axis order,
// sources and conflicts by ref/axis).
type canonicalCatalog Catalog

// CanonicalCatalogJSON renders the catalog in its canonical form: a stable,
// sorted JSON document. Identical content produces byte-identical output,
// which is what the digest and the Supersedes rollback chain fingerprint.
func CanonicalCatalogJSON(c Catalog) ([]byte, error) {
	n := canonicalizeCatalog(c)
	b, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("canonical catalog json: %w", err)
	}
	return b, nil
}

// CatalogDigest returns the SHA256 hex over the canonical form of the
// catalog (Digest field excluded from the input).
func CatalogDigest(c Catalog) (string, error) {
	b, err := CanonicalCatalogJSON(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalizeCatalog(c Catalog) canonicalCatalog {
	models := make([]RefModel, len(c.Models))
	copy(models, c.Models)
	for i := range models {
		m := &models[i]
		m.Aliases = append([]string(nil), m.Aliases...)
		sort.Strings(m.Aliases)
		rates := append([]RefRate(nil), m.Rates...)
		sort.Slice(rates, func(a, b int) bool {
			return refAxisRank(rates[a].Axis) < refAxisRank(rates[b].Axis)
		})
		for k := range rates {
			ev := append([]RefEvidence(nil), rates[k].Evidence...)
			sort.Slice(ev, func(x, y int) bool { return ev[x].Ref < ev[y].Ref })
			rates[k].Evidence = ev
		}
		m.Rates = rates
		src := append([]RefSource(nil), m.Sources...)
		sort.Slice(src, func(a, b int) bool { return src[a].Ref < src[b].Ref })
		m.Sources = src
		cf := append([]RefConflict(nil), m.Conflicts...)
		sort.Slice(cf, func(a, b int) bool {
			if cf[a].Axis != cf[b].Axis {
				return cf[a].Axis < cf[b].Axis
			}
			return cf[a].Ref < cf[b].Ref
		})
		m.Conflicts = cf
	}
	sort.Slice(models, func(a, b int) bool {
		x, y := models[a], models[b]
		if x.Provider != y.Provider {
			return x.Provider < y.Provider
		}
		if x.Model != y.Model {
			return x.Model < y.Model
		}
		if x.Region != y.Region {
			return x.Region < y.Region
		}
		if x.Tier != y.Tier {
			return x.Tier < y.Tier
		}
		return x.ContextBand < y.ContextBand
	})
	out := canonicalCatalog(c)
	out.Models = models
	out.Digest = ""
	return out
}

func refAxisRank(axis string) int {
	for i, a := range CanonicalAxes {
		if a == axis {
			return i
		}
	}
	return len(CanonicalAxes)
}

// SealCatalog computes and stores the digest of the snapshot. The input is
// not modified; the sealed copy is returned.
func SealCatalog(c Catalog) (Catalog, error) {
	d, err := CatalogDigest(c)
	if err != nil {
		return Catalog{}, err
	}
	c.Digest = d
	return c, nil
}

// ValidateCatalogChain verifies that next supersedes prev: next.Supersedes
// must equal the actual digest of prev. This is the rollback-chain check a
// loader runs when switching snapshots — a chain break means the "previous"
// snapshot is not the one next claims to replace, and switching (or rolling
// back) would silently rewrite history.
func ValidateCatalogChain(prev, next Catalog) error {
	if next.Supersedes == "" {
		return fmt.Errorf("catalog chain: next snapshot does not declare a predecessor")
	}
	d, err := CatalogDigest(prev)
	if err != nil {
		return fmt.Errorf("catalog chain: digest of previous snapshot: %w", err)
	}
	if next.Supersedes != d {
		return fmt.Errorf("catalog chain: next supersedes %s but previous snapshot digests to %s",
			next.Supersedes, d)
	}
	return nil
}
