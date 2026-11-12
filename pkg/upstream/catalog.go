package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// The upstream catalog document is the versioned, self-describing transport
// format for the model catalog: schema pin, revision, source, per-model
// capabilities/limits/pricing/aliases with sell windows, and provider-level
// withdrawals. It mirrors the pricing snapshot pattern (validated document,
// SHA256 provenance, offline-installable), but owns the model attributes the
// price snapshot deliberately refuses: context windows, request bounds and
// the modality vocabulary.
//
// Documents are untrusted input: every structural or semantic problem is a
// validation error listing all findings; nothing is silently repaired,
// dropped or defaulted except fields documented as optional.

// CatalogSchemaV1 is the base catalog document schema: sell windows,
// capabilities, limits, prices, aliases and provider withdrawals.
const CatalogSchemaV1 = 1

// CatalogSchemaV2 extends v1 with model deprecation instants
// (deprecated_at) and the customizations section (custom overrides /
// custom models). Both additions are optional in a v2 document; a v1
// document carrying them is a validation error, so an old document can
// never lose its deprecation or override data silently.
const CatalogSchemaV2 = 2

// CatalogSchemaCurrent is the schema version new documents should declare.
const CatalogSchemaCurrent = CatalogSchemaV2

// catalogTimeLayouts are the accepted instant formats: RFC 3339 for exact
// timestamps and bare dates for operator-authored snapshots.
var catalogTimeLayouts = []string{time.RFC3339, "2006-01-02"}

// CatalogDocument is the parsed document shape.
type CatalogDocument struct {
	// SchemaVersion must equal CatalogSchemaV1 for this parser; other
	// versions are rejected with a precise error so an older binary never
	// misreads a newer vocabulary.
	SchemaVersion int `json:"schema_version"`
	// Version is the operator-assigned catalog revision.
	Version string `json:"version"`
	// Source names where the snapshot originated.
	Source string `json:"source"`
	// AsOf is the optional publication instant (RFC 3339 or YYYY-MM-DD).
	AsOf string `json:"as_of,omitempty"`
	// Models are the per-model rows. A document may legitimately carry
	// only provider withdrawals, so an empty list is valid.
	Models []CatalogModelEntry `json:"models,omitempty"`
	// WithdrawnProviders are provider-level delist rows.
	WithdrawnProviders []CatalogWithdrawal `json:"withdrawn_providers,omitempty"`
	// Customizations are the custom-catalog rows (schema v2): overrides
	// of vendor rows and introductions of custom models. Absent in a v1
	// document.
	Customizations []CatalogOverride `json:"customizations,omitempty"`
}

// CatalogModelEntry is one document row. All optional fields are additive:
// absent means "unset", never zero-capacity.
type CatalogModelEntry struct {
	Provider string   `json:"provider"`
	Model    string   `json:"model"`
	Aliases  []string `json:"aliases,omitempty"`
	// Capabilities keys come from the pinned vocabulary returned by
	// CatalogCapabilityFields; unknown keys are validation errors.
	Capabilities  map[string]bool `json:"capabilities,omitempty"`
	Limits        *CatalogLimits  `json:"limits,omitempty"`
	Price         *CatalogPrice   `json:"price,omitempty"`
	EffectiveFrom string          `json:"effective_from,omitempty"`
	EffectiveTo   string          `json:"effective_to,omitempty"`
	// DeprecatedAt is the announced end-of-life instant (schema v2): the
	// model stays sellable but flagged from it on, until the sell window
	// closes.
	DeprecatedAt string `json:"deprecated_at,omitempty"`
}

// CatalogOverride is one custom-catalog row (schema v2): an override of a
// vendor row, or the introduction of a custom model the vendor snapshot
// does not carry. Field semantics mirror provider.ModelOverride: explicit
// attributes replace the vendor set, sell windows can only narrow on a
// vendor row (a retired model cannot be resurrected), deprecation can only
// move earlier, and pricing is never overridden (the price store stays
// authoritative).
type CatalogOverride struct {
	Provider string   `json:"provider"`
	Model    string   `json:"model"`
	Aliases  []string `json:"aliases,omitempty"`
	// Capabilities keys come from the pinned vocabulary returned by
	// CatalogCapabilityFields; unknown keys are validation errors.
	Capabilities  map[string]bool `json:"capabilities,omitempty"`
	Limits        *CatalogLimits  `json:"limits,omitempty"`
	EffectiveFrom string          `json:"effective_from,omitempty"`
	EffectiveTo   string          `json:"effective_to,omitempty"`
	DeprecatedAt  string          `json:"deprecated_at,omitempty"`
}

// CatalogLimits carries the documented per-model bounds; zero means unset.
type CatalogLimits struct {
	ContextWindowTokens int64 `json:"context_window_tokens,omitempty"`
	MaxOutputTokens     int64 `json:"max_output_tokens,omitempty"`
	MaxTPM              int64 `json:"max_tpm,omitempty"`
	MaxRPM              int64 `json:"max_rpm,omitempty"`
}

// CatalogPrice is the vendor list price in USD per 1M tokens, using the same
// unit semantics as the pricing snapshot (input/output/cache-write/cache-read).
type CatalogPrice struct {
	Input  float64 `json:"input,omitempty"`
	Output float64 `json:"output,omitempty"`
	CacheW float64 `json:"cache_w,omitempty"`
	CacheR float64 `json:"cache_r,omitempty"`
}

// CatalogWithdrawal delists a whole provider at WithdrawnAt.
type CatalogWithdrawal struct {
	Provider    string `json:"provider"`
	WithdrawnAt string `json:"withdrawn_at"`
}

// CatalogDocumentError aggregates every validation problem in document order
// so the operator can fix the whole file at once.
type CatalogDocumentError struct {
	Problems []string
}

func (e *CatalogDocumentError) Error() string {
	return fmt.Sprintf("invalid catalog document: %s", strings.Join(e.Problems, "; "))
}

// CatalogCapabilityFields returns the pinned capability vocabulary: the
// exact document keys Capabilities accepts and what each toggles. The map is
// a copy; extend it (and the schema version) together with
// provider.ModelCapabilities.
func CatalogCapabilityFields() map[string]string {
	return map[string]string{
		"chat":                 "Chat",
		"streaming":            "Streaming",
		"tools":                "Tools",
		"vision_input":         "VisionInput",
		"pdf_input":            "PDFInput",
		"audio_input":          "AudioInput",
		"image_generation":     "ImageGeneration",
		"speech_transcription": "SpeechTranscription",
		"speech_synthesis":     "SpeechSynthesis",
		"embeddings":           "Embeddings",
	}
}

// catalogLimitFields and catalogPriceFields pin the field order of limit
// and price validation findings, so the same broken document always yields
// the same problem list regardless of Go map iteration order.
var catalogLimitFields = []struct {
	name  string
	value func(*CatalogLimits) int64
}{
	{"context_window_tokens", func(l *CatalogLimits) int64 { return l.ContextWindowTokens }},
	{"max_output_tokens", func(l *CatalogLimits) int64 { return l.MaxOutputTokens }},
	{"max_tpm", func(l *CatalogLimits) int64 { return l.MaxTPM }},
	{"max_rpm", func(l *CatalogLimits) int64 { return l.MaxRPM }},
}

var catalogPriceFields = []string{"input", "output", "cache_w", "cache_r"}

func catalogPriceField(p *CatalogPrice, name string) float64 {
	switch name {
	case "input":
		return p.Input
	case "output":
		return p.Output
	case "cache_w":
		return p.CacheW
	default:
		return p.CacheR
	}
}

func applyCatalogCapabilities(raw map[string]bool) (provider.ModelCapabilities, error) {
	if unknown := unknownCapabilityKeys(raw); len(unknown) > 0 {
		return provider.ModelCapabilities{}, fmt.Errorf("unknown capability keys: %s", strings.Join(unknown, ", "))
	}
	var caps provider.ModelCapabilities
	caps.Chat = raw["chat"]
	caps.Streaming = raw["streaming"]
	caps.Tools = raw["tools"]
	caps.VisionInput = raw["vision_input"]
	caps.PDFInput = raw["pdf_input"]
	caps.AudioInput = raw["audio_input"]
	caps.ImageGeneration = raw["image_generation"]
	caps.SpeechTranscription = raw["speech_transcription"]
	caps.SpeechSynthesis = raw["speech_synthesis"]
	caps.Embeddings = raw["embeddings"]
	return caps, nil
}

// unknownCapabilityKeys returns the sorted capability keys outside the
// pinned vocabulary.
func unknownCapabilityKeys(raw map[string]bool) []string {
	vocabulary := CatalogCapabilityFields()
	var unknown []string
	for k := range raw {
		if _, ok := vocabulary[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	sortStrings(unknown)
	return unknown
}

// sortStrings is a small insertion sort so validation messages stay
// deterministic without importing sort for one call site.
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// parseCatalogTime parses an optional instant; empty yields the zero time.
func parseCatalogTime(field, value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	for _, layout := range catalogTimeLayouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%s: not an RFC 3339 or YYYY-MM-DD instant (%q)", field, value)
}

// deprecationWindowProblem reports the deprecation-instant violations
// against a sell window, or "" when the instant is a valid phase inside it
// (mirrors provider.validateDeprecation): a deprecation announced before the
// window opens or not before it closes is dead or contradictory data and is
// rejected.
func deprecationWindowProblem(from, to, dep time.Time) string {
	if dep.IsZero() {
		return ""
	}
	if !from.IsZero() && dep.Before(from) {
		return fmt.Sprintf("deprecated_at %s precedes the sell window opening %s",
			dep.Format(time.RFC3339), from.Format(time.RFC3339))
	}
	if !to.IsZero() && !dep.Before(to) {
		return fmt.Sprintf("deprecated_at %s is not before the sell window closing %s",
			dep.Format(time.RFC3339), to.Format(time.RFC3339))
	}
	return ""
}

// paddedNameProblem reports leading or trailing whitespace in a namespace
// name, or "". The checks below compare trimmed spellings, and the runtime
// snapshot layers (provider.NewModelCatalog, ApplyOverrides) trim again
// before installing — so a padded form that passed validation would be
// silently repaired into an identity other than the one the document wrote,
// contradicting the contract that nothing in a catalog document is silently
// repaired. Padded names are therefore rejected loudly at the boundary.
// Internal whitespace stays legal: names are opaque strings.
func paddedNameProblem(where, key, kind, value string) string {
	if strings.TrimSpace(value) == value {
		return ""
	}
	if key == "" {
		return fmt.Sprintf("%s: whitespace-padded %s name %q", where, kind, value)
	}
	return fmt.Sprintf("%s (%s): whitespace-padded %s name %q", where, key, kind, value)
}

// catalogProblems is the append-and-format callback shared by the section
// validators, so findings stay in document order.
type catalogProblems func(format string, args ...any)

// ValidateCatalogDocument checks structural and semantic soundness:
//   - schema_version must equal CatalogSchemaV1 or CatalogSchemaV2; a v1
//     document must not carry v2 data (deprecated_at, customizations) —
//     the precise error tells the operator to bump schema_version;
//   - version and source are required; as_of, when present, must parse;
//   - every model row needs a provider and model; (provider, model) pairs
//     are unique; aliases are unique per provider and never shadow a model
//     name; sell windows must not close before they open; a deprecated_at
//     instant, when present, must fall inside the sell window;
//   - capability keys must come from the pinned vocabulary;
//   - limits and prices must be non-negative and finite;
//   - provider, model and alias names must not carry leading or trailing
//     whitespace: a padded form is rejected, never silently trimmed;
//   - every withdrawal names a provider and a parseable instant, and a
//     provider carries at most one withdrawal row;
//   - every customization names a provider and model; one pair is
//     customized at most once; its aliases, capabilities, limits, window
//     and deprecated_at obey the same rules as a model row.
func ValidateCatalogDocument(doc CatalogDocument) error {
	var problems []string
	add := catalogProblems(func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	})

	validateCatalogHeader(doc, add)
	models := validateCatalogModels(doc, add)
	catalogAliasModelCollisions(doc.Models, models, add)
	validateCatalogCustomizations(doc, add)
	validateCatalogWithdrawals(doc.WithdrawnProviders, add)

	if len(problems) > 0 {
		return &CatalogDocumentError{Problems: problems}
	}
	return nil
}

// validateCatalogHeader checks the header fields; its findings precede any
// row finding.
func validateCatalogHeader(doc CatalogDocument, add catalogProblems) {
	if doc.SchemaVersion == 0 {
		add("schema_version is required")
	} else if doc.SchemaVersion != CatalogSchemaV1 && doc.SchemaVersion != CatalogSchemaV2 {
		add("unsupported schema_version %d (this parser understands %d and %d)",
			doc.SchemaVersion, CatalogSchemaV1, CatalogSchemaV2)
	}
	if strings.TrimSpace(doc.Version) == "" {
		add("version is required")
	}
	if strings.TrimSpace(doc.Source) == "" {
		add("source is required")
	}
	if _, err := parseCatalogTime("as_of", doc.AsOf); err != nil {
		add("%v", err)
	}
}

// validateCatalogModels walks the model rows in document order and returns
// the trimmed model namespace (provider:model) that the deferred alias
// collision pass checks against.
func validateCatalogModels(doc CatalogDocument, add catalogProblems) map[string]struct{} {
	models := make(map[string]struct{}, len(doc.Models))
	aliases := make(map[string]struct{})
	for i, m := range doc.Models {
		validateCatalogModelRow(i, m, doc.SchemaVersion, models, aliases, add)
	}
	return models
}

// validateCatalogModelRow validates one model row. A row missing either
// name contributes only the required-name finding: without both names
// there is no identity to check the remaining fields against.
func validateCatalogModelRow(i int, m CatalogModelEntry, schema int, models, aliases map[string]struct{}, add catalogProblems) {
	where := fmt.Sprintf("models[%d]", i)
	providerName := strings.TrimSpace(m.Provider)
	model := strings.TrimSpace(m.Model)
	if providerName == "" || model == "" {
		add("%s: provider and model are required", where)
		return
	}
	key := providerName + ":" + model
	addCatalogPaddedNames(where, key, m.Provider, m.Model, add)
	if _, dup := models[key]; dup {
		add("%s: duplicate entry for %s", where, key)
	}
	models[key] = struct{}{}

	catalogAliasProblems(where, key, providerName, model, m.Aliases, aliases, "in this provider", add)
	addCatalogCapabilityProblems(where, key, m.Capabilities, add)
	if m.Limits != nil {
		addCatalogLimitProblems(where, key, m.Limits, add)
	}
	if m.Price != nil {
		addCatalogPriceProblems(where, key, m.Price, add)
	}
	validateCatalogModelWindow(where, key, m, schema, add)
}

// addCatalogPaddedNames reports whitespace-padded provider and model
// spellings: the checks below compare trimmed spellings and the runtime
// snapshot layers trim again before installing, so a padded form that
// passed validation would be silently repaired into an identity other than
// the one the document wrote.
func addCatalogPaddedNames(where, key, providerRaw, modelRaw string, add catalogProblems) {
	if p := paddedNameProblem(where, key, "provider", providerRaw); p != "" {
		add("%s", p)
	}
	if p := paddedNameProblem(where, key, "model", modelRaw); p != "" {
		add("%s", p)
	}
}

// catalogAliasProblems validates one row's alias list in listed order.
// owner is the provider-scoped alias namespace of the section;
// usedByNote completes the already-used finding ("in this provider" for
// vendor rows, "by another override in this provider" for overrides).
func catalogAliasProblems(where, key, providerName, model string, rawAliases []string, owner map[string]struct{}, usedByNote string, add catalogProblems) {
	seen := make(map[string]struct{}, len(rawAliases))
	for _, rawAlias := range rawAliases {
		a := strings.TrimSpace(rawAlias)
		if a == "" {
			add("%s (%s): empty alias", where, key)
			continue
		}
		if p := paddedNameProblem(where, key, "alias", rawAlias); p != "" {
			add("%s", p)
			continue
		}
		if a == model {
			add("%s (%s): alias %q shadows the model name", where, key, a)
			continue
		}
		if _, dup := seen[a]; dup {
			add("%s (%s): duplicate alias %q", where, key, a)
			continue
		}
		seen[a] = struct{}{}
		aliasKey := providerName + ":" + a
		if _, dup := owner[aliasKey]; dup {
			add("%s (%s): alias %q is already used %s", where, key, a, usedByNote)
			continue
		}
		owner[aliasKey] = struct{}{}
	}
}

// addCatalogCapabilityProblems reports capability keys outside the pinned
// vocabulary, sorted for deterministic messages.
func addCatalogCapabilityProblems(where, key string, caps map[string]bool, add catalogProblems) {
	if unknown := unknownCapabilityKeys(caps); len(unknown) > 0 {
		add("%s (%s): unknown capability keys: %s", where, key, strings.Join(unknown, ", "))
	}
}

// addCatalogLimitProblems reports negative limits in the pinned field
// order (catalogLimitFields), so identical documents always produce
// identical problem lists.
func addCatalogLimitProblems(where, key string, l *CatalogLimits, add catalogProblems) {
	for _, f := range catalogLimitFields {
		if v := f.value(l); v < 0 {
			add("%s (%s): limits.%s must not be negative (%d)", where, key, f.name, v)
		}
	}
}

// addCatalogPriceProblems walks the price fields in the pinned order
// (catalogPriceFields): non-finite values (reachable only through the
// struct API — JSON cannot spell them) are rejected before negativity.
func addCatalogPriceProblems(where, key string, p *CatalogPrice, add catalogProblems) {
	for _, name := range catalogPriceFields {
		v := catalogPriceField(p, name)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			add("%s (%s): price.%s must be a finite number (%v)", where, key, name, v)
		} else if v < 0 {
			add("%s (%s): price.%s must not be negative (%v)", where, key, name, v)
		}
	}
}

// catalogWindowTimes parses the optional sell-window endpoints, reporting
// parse findings; an endpoint that fails to parse (or is absent) yields
// the zero instant, which the inversion checks treat as unset.
func catalogWindowTimes(where, fromStr, toStr string, add catalogProblems) (from, to time.Time) {
	from, errFrom := parseCatalogTime(where+".effective_from", fromStr)
	to, errTo := parseCatalogTime(where+".effective_to", toStr)
	if errFrom != nil {
		add("%v", errFrom)
	}
	if errTo != nil {
		add("%v", errTo)
	}
	return from, to
}

// validateCatalogModelWindow checks the sell window and, when present, the
// deprecation instant of a model row (the v1 schema guard's message names
// the row key).
func validateCatalogModelWindow(where, key string, m CatalogModelEntry, schema int, add catalogProblems) {
	from, to := catalogWindowTimes(where, m.EffectiveFrom, m.EffectiveTo, add)
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		add("%s (%s): sell window closes before it opens", where, key)
	}
	if m.DeprecatedAt == "" {
		return
	}
	if schema == CatalogSchemaV1 {
		add("%s (%s): deprecated_at requires schema_version %d", where, key, CatalogSchemaV2)
	}
	addCatalogDeprecationProblems(where, key, m.DeprecatedAt, from, to, add)
}

// addCatalogDeprecationProblems parses a present deprecated_at instant and
// checks it against the row's parsed sell window. The v1 schema guard is
// emitted by the callers because its message differs per section.
func addCatalogDeprecationProblems(where, key, dep string, from, to time.Time, add catalogProblems) {
	depTime, err := parseCatalogTime(where+".deprecated_at", dep)
	if err != nil {
		add("%v", err)
		return
	}
	if p := deprecationWindowProblem(from, to, depTime); p != "" {
		add("%s (%s): %s", where, key, p)
	}
}

// catalogAliasModelCollisions re-checks every alias against the full model
// namespace after all rows: an alias may not shadow any model name of the
// same provider, including names declared later in the document.
func catalogAliasModelCollisions(rows []CatalogModelEntry, models map[string]struct{}, add catalogProblems) {
	for _, m := range rows {
		providerName := strings.TrimSpace(m.Provider)
		model := strings.TrimSpace(m.Model)
		for _, a := range m.Aliases {
			a = strings.TrimSpace(a)
			if a == "" || a == model {
				continue
			}
			if _, clash := models[providerName+":"+a]; clash {
				add("models (%s:%s): alias %q collides with an existing model name", providerName, model, a)
			}
		}
	}
}

// validateCatalogCustomizations walks the customization rows (they obey
// the same rules as model rows) and enforces the v2 schema requirement for
// the section as a whole. Override aliases are checked for
// self-consistency and cross-override uniqueness only — an override alias
// may legitimately restate an alias of the vendor row it replaces, so
// collisions against the vendor name space are left to the merge
// (BuildModelCatalog), which validates the merged name space as a whole.
func validateCatalogCustomizations(doc CatalogDocument, add catalogProblems) {
	overridden := make(map[string]struct{}, len(doc.Customizations))
	overrideAliases := make(map[string]struct{})
	for i, o := range doc.Customizations {
		validateCatalogOverrideRow(i, o, doc.SchemaVersion, overridden, overrideAliases, add)
	}
	if len(doc.Customizations) > 0 && doc.SchemaVersion == CatalogSchemaV1 {
		add("customizations require schema_version %d", CatalogSchemaV2)
	}
}

// validateCatalogOverrideRow validates one customization row; like a model
// row, a row missing either name contributes only the required-name
// finding. One (provider, model) pair may be customized at most once.
func validateCatalogOverrideRow(i int, o CatalogOverride, schema int, overridden, overrideAliases map[string]struct{}, add catalogProblems) {
	where := fmt.Sprintf("customizations[%d]", i)
	providerName := strings.TrimSpace(o.Provider)
	model := strings.TrimSpace(o.Model)
	if providerName == "" || model == "" {
		add("%s: provider and model are required", where)
		return
	}
	key := providerName + ":" + model
	addCatalogPaddedNames(where, key, o.Provider, o.Model, add)
	if _, dup := overridden[key]; dup {
		add("%s: duplicate override for %s", where, key)
	}
	overridden[key] = struct{}{}

	catalogAliasProblems(where, key, providerName, model, o.Aliases, overrideAliases, "by another override in this provider", add)
	addCatalogCapabilityProblems(where, key, o.Capabilities, add)
	if o.Limits != nil {
		addCatalogLimitProblems(where, key, o.Limits, add)
	}
	validateCatalogOverrideWindow(where, key, o, schema, add)
}

// validateCatalogOverrideWindow mirrors validateCatalogModelWindow for a
// customization row (the v1 schema guard's message omits the row key).
func validateCatalogOverrideWindow(where, key string, o CatalogOverride, schema int, add catalogProblems) {
	from, to := catalogWindowTimes(where, o.EffectiveFrom, o.EffectiveTo, add)
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		add("%s (%s): override window closes before it opens", where, key)
	}
	if o.DeprecatedAt == "" {
		return
	}
	if schema == CatalogSchemaV1 {
		add("%s: deprecated_at requires schema_version %d", where, CatalogSchemaV2)
	}
	addCatalogDeprecationProblems(where, key, o.DeprecatedAt, from, to, add)
}

// validateCatalogWithdrawals checks the provider-level delist rows: a
// named provider with a parseable instant, at most one row per provider.
func validateCatalogWithdrawals(rows []CatalogWithdrawal, add catalogProblems) {
	withdrawn := make(map[string]struct{}, len(rows))
	for i, w := range rows {
		where := fmt.Sprintf("withdrawn_providers[%d]", i)
		name := strings.TrimSpace(w.Provider)
		if name == "" {
			add("%s: provider is required", where)
		} else if p := paddedNameProblem(where, "", "provider", w.Provider); p != "" {
			add("%s", p)
		} else if _, dup := withdrawn[name]; dup {
			add("%s: duplicate withdrawal for provider %s", where, name)
		} else {
			withdrawn[name] = struct{}{}
		}
		t, err := parseCatalogTime(where+".withdrawn_at", w.WithdrawnAt)
		if err != nil {
			add("%v", err)
		} else if t.IsZero() {
			add("%s: withdrawn_at is required", where)
		}
	}
}

// ParseCatalogDocument reads, decodes and validates a document. The returned
// SHA256 hex fingerprints the exact raw bytes, so an installation can cite
// the snapshot it was built from.
func ParseCatalogDocument(r io.Reader) (CatalogDocument, string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return CatalogDocument{}, "", fmt.Errorf("read catalog document: %w", err)
	}
	var doc CatalogDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return CatalogDocument{}, "", fmt.Errorf("parse catalog document: %w", err)
	}
	if err := ValidateCatalogDocument(doc); err != nil {
		return CatalogDocument{}, "", err
	}
	sum := sha256.Sum256(data)
	return doc, hex.EncodeToString(sum[:]), nil
}

// BuildModelCatalog validates the document again (defensively, the same way
// NewFilePricer re-validates a price file) and materializes the immutable
// runtime snapshot. Customizations, when the document carries them, are
// merged on top of the vendor rows through provider.ApplyOverrides — a
// model the vendor retired therefore stays retired no matter what a
// customization claims.
func BuildModelCatalog(doc CatalogDocument) (*provider.ModelCatalog, error) {
	if err := ValidateCatalogDocument(doc); err != nil {
		return nil, err
	}
	asOf, err := parseCatalogTime("as_of", doc.AsOf)
	if err != nil {
		return nil, err
	}
	spec := provider.ModelCatalogSpec{
		Version:       doc.Version,
		SchemaVersion: doc.SchemaVersion,
		Source:        doc.Source,
		AsOf:          asOf,
		Entries:       make([]provider.ModelCatalogEntry, 0, len(doc.Models)),
		Withdrawals:   make([]provider.Withdrawal, 0, len(doc.WithdrawnProviders)),
	}
	for _, m := range doc.Models {
		from, err := parseCatalogTime("effective_from", m.EffectiveFrom)
		if err != nil {
			return nil, err
		}
		to, err := parseCatalogTime("effective_to", m.EffectiveTo)
		if err != nil {
			return nil, err
		}
		dep, err := parseCatalogTime("deprecated_at", m.DeprecatedAt)
		if err != nil {
			return nil, err
		}
		caps, err := applyCatalogCapabilities(copyBoolMap(m.Capabilities))
		if err != nil {
			return nil, fmt.Errorf("models (%s:%s): %w", m.Provider, m.Model, err)
		}
		entry := provider.ModelCatalogEntry{
			Provider:      m.Provider,
			Model:         m.Model,
			Aliases:       m.Aliases,
			Capabilities:  caps,
			EffectiveFrom: from,
			EffectiveTo:   to,
			DeprecatedAt:  dep,
		}
		if m.Limits != nil {
			entry.Limits = provider.ModelLimits{
				ContextWindowTokens: m.Limits.ContextWindowTokens,
				MaxOutputTokens:     m.Limits.MaxOutputTokens,
				MaxTPM:              m.Limits.MaxTPM,
				MaxRPM:              m.Limits.MaxRPM,
			}
		}
		if m.Price != nil {
			entry.Price = pricingPrice(*m.Price)
			entry.PriceListed = true
		}
		spec.Entries = append(spec.Entries, entry)
	}
	for _, w := range doc.WithdrawnProviders {
		at, err := parseCatalogTime("withdrawn_at", w.WithdrawnAt)
		if err != nil {
			return nil, err
		}
		spec.Withdrawals = append(spec.Withdrawals, provider.Withdrawal{
			Provider:    w.Provider,
			WithdrawnAt: at,
		})
	}
	base, err := provider.NewModelCatalog(spec)
	if err != nil {
		return nil, err
	}
	ovs, err := overridesFromDocument(doc)
	if err != nil {
		return nil, err
	}
	if len(ovs) == 0 {
		return base, nil
	}
	return provider.ApplyOverrides(base, ovs)
}

// overridesFromDocument converts the customizations section into runtime
// overrides. Instant parse errors are already excluded by the validation
// BuildModelCatalog runs first.
func overridesFromDocument(doc CatalogDocument) ([]provider.ModelOverride, error) {
	if len(doc.Customizations) == 0 {
		return nil, nil
	}
	ovs := make([]provider.ModelOverride, 0, len(doc.Customizations))
	for _, o := range doc.Customizations {
		from, err := parseCatalogTime("effective_from", o.EffectiveFrom)
		if err != nil {
			return nil, err
		}
		to, err := parseCatalogTime("effective_to", o.EffectiveTo)
		if err != nil {
			return nil, err
		}
		dep, err := parseCatalogTime("deprecated_at", o.DeprecatedAt)
		if err != nil {
			return nil, err
		}
		ov := provider.ModelOverride{
			Provider:      o.Provider,
			Model:         o.Model,
			Aliases:       o.Aliases,
			EffectiveFrom: from,
			EffectiveTo:   to,
			DeprecatedAt:  dep,
		}
		if o.Capabilities != nil {
			caps, err := applyCatalogCapabilities(copyBoolMap(o.Capabilities))
			if err != nil {
				return nil, fmt.Errorf("customizations (%s:%s): %w", o.Provider, o.Model, err)
			}
			ov.Capabilities = &caps
		}
		if o.Limits != nil {
			lim := provider.ModelLimits{
				ContextWindowTokens: o.Limits.ContextWindowTokens,
				MaxOutputTokens:     o.Limits.MaxOutputTokens,
				MaxTPM:              o.Limits.MaxTPM,
				MaxRPM:              o.Limits.MaxRPM,
			}
			ov.Limits = &lim
		}
		ovs = append(ovs, ov)
	}
	return ovs, nil
}

func copyBoolMap(src map[string]bool) map[string]bool {
	out := make(map[string]bool, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func pricingPrice(p CatalogPrice) pricing.Price {
	return pricing.Price{
		InputPerM:      p.Input,
		OutputPerM:     p.Output,
		CacheWritePerM: p.CacheW,
		CacheReadPerM:  p.CacheR,
	}
}

// InstallCatalog parses, builds and installs the snapshot process-wide.
// Installation is atomic; on error the previously installed catalog (if any)
// stays in place. The returned SHA256 fingerprints the raw document bytes.
func InstallCatalog(r io.Reader) (*provider.ModelCatalog, string, error) {
	doc, sum, err := ParseCatalogDocument(r)
	if err != nil {
		return nil, "", err
	}
	cat, err := BuildModelCatalog(doc)
	if err != nil {
		return nil, "", err
	}
	provider.SetModelCatalog(cat)
	return cat, sum, nil
}

// StaticModelRef is one name a static surface (config fallback, effort
// list, bundled snapshot, cached picker payload) still claims to offer.
type StaticModelRef struct {
	Provider string
	Model    string
}

// StaticModelStatus pairs the static claim with the catalog's opinion.
type StaticModelStatus struct {
	Ref    StaticModelRef
	Status provider.ModelStatus
}

// ReconcileStaticNames classifies static names against the catalog sell
// windows, preserving input order. This is the delist primitive: a name a
// vendor withdrew comes back StatusRetired even though the static list still
// contains it, and names the catalog has no row for come back StatusUnknown
// so policy scope stays explicit instead of being silently inherited.
func ReconcileStaticNames(c *provider.ModelCatalog, refs []StaticModelRef, at time.Time) []StaticModelStatus {
	out := make([]StaticModelStatus, len(refs))
	for i, ref := range refs {
		out[i] = StaticModelStatus{
			Ref:    ref,
			Status: c.Status(ref.Provider, ref.Model, at),
		}
	}
	return out
}

// LifecycleFact is one installation-side observation about a model name:
// whether the installation lists it for serving (Configured) and whether its
// latest verification passed (Tested). Facts are inputs; the catalog stays
// the single authority on sellability. Several facts about one name merge by
// union of the flags.
type LifecycleFact struct {
	Provider   string
	Model      string
	Configured bool
	Tested     bool
}

// ModelLifecycleRow shows one model's lifecycle facts separately: where the
// name is known from (Discovered: a catalog row exists), what the
// installation does with it (Configured, Tested), whether it is currently
// sellable (Available), the catalog's own opinion (CatalogStatus) and the
// single derived label a surface renders (State). The facts stay visible
// even when the label is unavailable, so a configured-and-tested name the
// vendor withdrew is inspectable as drift instead of silently green.
type ModelLifecycleRow struct {
	Provider string
	Model    string
	// Aliases are the catalog aliases of the canonical name, sorted.
	Aliases    []string
	Discovered bool
	Configured bool
	Tested     bool
	Available  bool
	// CatalogStatus is the catalog's opinion (StatusUnknown for a name the
	// catalog has no row for).
	CatalogStatus provider.ModelStatus
	// Deprecated reports the announced end-of-life phase: the model is
	// sellable (Available) but its deprecation instant has arrived, so it
	// must not be presented as a plain green recommendation. DeprecatedAt
	// is non-zero exactly when Deprecated is true. Deprecation is a
	// distinct state from unavailability: a deprecated model keeps
	// serving, a retired or pending one does not — the row shows both
	// facts instead of collapsing them.
	Deprecated   bool
	DeprecatedAt time.Time
	// State is the derived lifecycle label: the single value a picker or
	// ops surface renders for the row.
	State provider.ModelLifecycle
}

// LifecycleSummary counts rows per lifecycle state. Fixed fields (not a map)
// keep the serialization order stable.
type LifecycleSummary struct {
	Discovered  int
	Configured  int
	Tested      int
	Unavailable int
}

// LifecycleReport is the four-state availability view over the union of the
// catalog rows and the installation facts. Rows are sorted by
// (provider, model); Rows is never nil so an empty report serializes as []
// (honest empty).
type LifecycleReport struct {
	At      time.Time
	Rows    []ModelLifecycleRow
	Summary LifecycleSummary
}

// BuildLifecycleReport merges the catalog with the installation facts into a
// deterministic four-state report:
//
//   - every catalog entry contributes a Discovered row (aliases attached);
//   - every fact contributes its Configured/Tested flags to the row of the
//     canonical name it resolves to, so a configured alias never forks a
//     second row;
//   - a fact the catalog has no row for contributes a facts-only row with
//     CatalogStatus StatusUnknown: installation drift stays visible instead
//     of being silently inherited, and a withdrawal of the provider still
//     makes the row unavailable;
//   - names with no facts at all (no catalog row, not configured, not
//     tested) are not part of the report.
//
// Row states are derived through (*provider.ModelCatalog).Lifecycle, so the
// report and the per-name classifier can never disagree.
func BuildLifecycleReport(c *provider.ModelCatalog, facts []LifecycleFact, at time.Time) LifecycleReport {
	rows := make(map[string]*ModelLifecycleRow)
	addRow := func(r *ModelLifecycleRow) { rows[r.Provider+":"+r.Model] = r }

	for _, e := range c.Entries() {
		aliases := append([]string(nil), e.Aliases...)
		sortStrings(aliases)
		status := c.Status(e.Provider, e.Model, at)
		deprecated := !e.DeprecatedAt.IsZero() && status == provider.StatusActive &&
			c.ProviderAdmitted(e.Provider, at) && !at.Before(e.DeprecatedAt)
		row := &ModelLifecycleRow{
			Provider:      e.Provider,
			Model:         e.Model,
			Aliases:       aliases,
			Discovered:    true,
			Available:     status == provider.StatusActive && c.ProviderAdmitted(e.Provider, at),
			CatalogStatus: status,
			Deprecated:    deprecated,
		}
		if deprecated {
			row.DeprecatedAt = e.DeprecatedAt
		}
		addRow(row)
	}

	for _, f := range facts {
		if !f.Configured && !f.Tested {
			continue // no facts: the name is not part of the report
		}
		key := f.Provider + ":" + f.Model
		if e, st := c.Lookup(f.Provider, f.Model, at); st != provider.StatusUnknown {
			// A known name (exact or alias): fold into its canonical row.
			key = e.Provider + ":" + e.Model
		}
		r, ok := rows[key]
		if !ok {
			r = &ModelLifecycleRow{
				Provider:      f.Provider,
				Model:         f.Model,
				Available:     c.ProviderAdmitted(f.Provider, at),
				CatalogStatus: c.Status(f.Provider, f.Model, at),
			}
			addRow(r)
		}
		r.Configured = r.Configured || f.Configured
		r.Tested = r.Tested || f.Tested
	}

	report := LifecycleReport{At: at, Rows: make([]ModelLifecycleRow, 0, len(rows))}
	for _, r := range rows {
		r.State = c.Lifecycle(r.Provider, r.Model, at, r.Configured, r.Tested)
		report.Rows = append(report.Rows, *r)
	}
	sort.Slice(report.Rows, func(i, j int) bool {
		if report.Rows[i].Provider != report.Rows[j].Provider {
			return report.Rows[i].Provider < report.Rows[j].Provider
		}
		return report.Rows[i].Model < report.Rows[j].Model
	})
	for _, r := range report.Rows {
		switch r.State {
		case provider.LifecycleDiscovered:
			report.Summary.Discovered++
		case provider.LifecycleConfigured:
			report.Summary.Configured++
		case provider.LifecycleTested:
			report.Summary.Tested++
		case provider.LifecycleUnavailable:
			report.Summary.Unavailable++
		}
	}
	return report
}
